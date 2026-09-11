use super::*;
use smallvec::SmallVec;

impl<Io> Connection<Io>
where
    Io: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    /// A HEADERS frame: the start of a request field block, a trailer
    /// section, or a protocol violation.
    #[inline]
    pub(crate) fn handle_headers_frame(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        block: &[u8],
    ) {
        // During graceful shutdown, the peer must not open streams beyond
        // the id advertised in GOAWAY (RFC 9113 Section 6.8).
        if self.graceful && stream_id > self.graceful_last_stream {
            return;
        }
        let (start_new, remote_ended) = match self.streams.get_mut(&stream_id) {
            None => (true, false),
            Some(entry) => {
                if entry.remote_ended {
                    (false, true)
                } else {
                    entry.pending_end_stream = end_stream;
                    entry.extend_block(block);
                    if end_headers {
                        entry.continuation_frames = 0;
                        self.complete_blocks.push_back(stream_id);
                    }
                    (false, false)
                }
            }
        };
        if remote_ended {
            self.stream_error(stream_id, Reason::StreamClosed);
        } else if start_new {
            self.open_request_stream(stream_id, end_stream, end_headers, block);
        } else if !end_headers {
            // The request field block stays open: count this frame towards
            // the CONTINUATION-flood budget.
            self.check_continuation_flood(stream_id);
        }
    }

    /// A CONTINUATION fragment of the open field block.
    #[inline]
    pub(crate) fn handle_continuation(&mut self, stream_id: u32, end_headers: bool, block: &[u8]) {
        let Some(entry) = self.streams.get_mut(&stream_id) else {
            // The codec already rejects stray CONTINUATION frames;
            // this guard keeps the module safe on its own.
            self.goaway(Reason::ProtocolError, b"continuation on unknown stream");
            return;
        };
        entry.extend_block(block);
        if end_headers {
            entry.continuation_frames = 0;
            self.complete_blocks.push_back(stream_id);
        } else {
            self.check_continuation_flood(stream_id);
        }
    }

    /// Enforces the CONTINUATION-flood limit (CVE-2024-27919) for a stream
    /// whose field block is still open. Each frame (the opening HEADERS and
    /// every CONTINUATION) adds one; once the count passes the connection's
    /// allowed maximum the offending stream is reset with `RST_STREAM`
    /// `PROTOCOL_ERROR` and the open block is abandoned so the connection
    /// keeps serving other streams.
    #[inline]
    pub(crate) fn check_continuation_flood(&mut self, stream_id: u32) {
        let over_limit = match self.streams.get_mut(&stream_id) {
            Some(entry) => {
                entry.continuation_frames += 1;
                entry.continuation_frames > self.max_continuation_frames
            }
            None => return,
        };
        if over_limit {
            if self.decoder.block_stream() == Some(stream_id) {
                self.decoder.clear_block();
            }
            self.stream_error(stream_id, Reason::ProtocolError);
        }
    }

    /// A HEADERS block arrived on a stream with no entry: validate and
    /// open it (RFC 9113 Sections 5.1.1 and 6.2).
    #[inline]
    pub(crate) fn open_request_stream(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        block: &[u8],
    ) {
        if stream_id == 0 || stream_id.is_multiple_of(2) {
            self.goaway(Reason::ProtocolError, b"headers on invalid stream");
            return;
        }
        if stream_id <= self.highest_stream_id {
            // Stream ids must increase (RFC 9113 Section 5.1.1):
            // connection error PROTOCOL_ERROR.
            self.goaway(Reason::ProtocolError, b"non-increasing stream id");
            return;
        }
        self.highest_stream_id = stream_id;
        if self.streams.len() as u32 >= self.opts.max_concurrent_streams {
            self.writer
                .write_reset(&mut self.out, stream_id, Reason::RefusedStream.code());
            return;
        }
        // Bounded small: the message channel only ever holds a few
        // messages (headers, a handful of body chunks, trailers, close)
        // because every send wakes the drive loop, which drains it.
        // Larger bounds only preallocate memory per stream (heap profiles
        // showed ~76 MiB across 38k streams for 32/16).
        let (reset_tx, reset_rx) = kanal::bounded_async(1);
        let (msg_tx, msg_rx) = kanal::bounded_async(8);
        let mut entry = StreamEntry::new(reset_tx, msg_rx);
        entry.send_window = self.peer.initial_window_size as i64;
        entry.msg_tx = Some(msg_tx);
        entry.reset_rx = Some(reset_rx);
        // The request body channel only exists while body frames may
        // still arrive. A request that ended with HEADERS (typical GET)
        // gets `Incoming::Empty` in `spawn_request`, so skip the channel
        // entirely instead of allocating it just to signal EOF through it.
        if !end_stream {
            let (body_tx, body_rx) = kanal::bounded_async(8);
            entry.body_tx = Some(body_tx);
            entry.body_rx = Some(body_rx);
        }
        entry.wake_tx = Some(self.wake_tx.as_ref().expect("wake sender").clone());
        entry.pending_end_stream = end_stream;
        entry.extend_block(block);
        if end_headers {
            self.complete_blocks.push_back(stream_id);
        } else {
            // The opening HEADERS is the first frame of the block.
            entry.continuation_frames = 1;
        }
        self.streams.insert(stream_id, entry);
    }

    /// Removes the completed-block marker for a stream, if any. FIFO for fairness.
    #[inline]
    pub(crate) fn take_complete_block(&mut self) -> Option<u32> {
        while let Some(stream_id) = self.complete_blocks.pop_front() {
            // The stream may have been removed in the meantime (e.g.
            // stream_error); skip stale completions.
            if self.streams.contains_key(&stream_id) {
                return Some(stream_id);
            }
        }
        None
    }

    /// The field block is complete: decode it and, depending on the
    /// stream's phase, build and dispatch the request or the trailers.
    #[inline]
    pub(crate) async fn finalize_field_block<F, Fut, ResB, ResBE, ResE>(
        &mut self,
        stream_id: u32,
        request_fn: &Arc<F>,
    ) where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = Bytes, Error = ResBE> + Unpin + 'static,
        ResBE: std::error::Error + 'static,
        ResE: std::error::Error + 'static,
    {
        let Some(entry) = self.streams.get_mut(&stream_id) else {
            return;
        };
        let block = entry.take_block();
        let end_stream = entry.pending_end_stream;
        let decoded = match self
            .request_decoder
            .decode(&block, &mut entry.header_list_size)
        {
            Ok(headers) => headers,
            Err(e) => {
                if matches!(e, HpackError::HeaderListTooLarge) {
                    // A header list exceeding SETTINGS_MAX_HEADER_LIST_SIZE is
                    // a stream error (RFC 9113 Section 10.5.1), not a
                    // connection-level compression error.
                    self.stream_error(stream_id, Reason::ProtocolError);
                } else {
                    // Other compression errors are connection errors
                    // (RFC 9113 Section 4.3).
                    self.goaway(Reason::CompressionError, b"hpack decode error");
                }
                return;
            }
        };
        if entry.request_started {
            // Trailer section (RFC 9113 Section 8.1).
            let trailers = match crate::h2::stream::parse_trailers(&decoded) {
                Ok(trailers) => trailers,
                Err(MalformedRequest) => {
                    self.stream_error(stream_id, Reason::ProtocolError);
                    return;
                }
            };
            if entry.trailers_seen {
                self.stream_error(stream_id, Reason::ProtocolError);
                return;
            }
            entry.trailers_seen = true;
            if !end_stream {
                // Trailers must end the stream (RFC 9113 Section 8.1).
                self.stream_error(stream_id, Reason::ProtocolError);
                return;
            }
            if !entry.send_body(BodyMsg::Trailers(trailers)).await {
                self.mark_closed(stream_id);
                self.streams.remove(&stream_id);
                return;
            }
            if end_stream {
                self.end_request_body(stream_id).await;
            }
            return;
        }
        let parsed = match crate::h2::stream::parse_request(&decoded) {
            Ok(parsed) => parsed,
            Err(MalformedRequest) => {
                self.stream_error(stream_id, Reason::ProtocolError);
                return;
            }
        };
        if end_stream {
            // No DATA frame will follow: close the request body now so the
            // handler's body reader sees end-of-stream (RFC 9113 Section
            // 8.1). A trailing DATA frame ending the stream is handled by
            // `handle_data_frame`.
            self.end_request_body(stream_id).await;
        }
        self.spawn_request(stream_id, end_stream, parsed, request_fn);
    }

    /// Spawns the stream task for a parsed request (RFC 9113
    /// Section 8.1.1): builds the `Request<Incoming>`, boxes the
    /// handler response, and hands the channels to a [`StreamDriver`].
    #[inline]
    pub(crate) fn spawn_request<F, Fut, ResB, ResBE, ResE>(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        parsed: ParsedRequest,
        request_fn: &Arc<F>,
    ) where
        F: Fn(Request<Incoming>) -> Fut + 'static,
        Fut: Future<Output = Result<Response<ResB>, ResE>> + 'static,
        ResB: Body<Data = Bytes, Error = ResBE> + Unpin + 'static,
        ResBE: std::error::Error + 'static,
        ResE: std::error::Error + 'static,
    {
        let Some(entry) = self.streams.get_mut(&stream_id) else {
            return;
        };
        entry.request_started = true;
        entry.content_length = parsed.content_length;
        // Sender halves stay in the entry; receiver halves move to the
        // task and the request body.
        let wake_tx = entry.wake_tx.take().expect("wake sender");
        let msg_tx = entry.msg_tx.take().expect("message sender");
        let body_rx = entry.body_rx.take();
        let reset_rx = entry.reset_rx.take().expect("reset receiver");

        let send_continue = self.opts.send_continue_response && parsed.expect_continue;
        let send_continue_body = send_continue.then(|| Arc::new(AtomicBool::new(false)));
        let (early_hints, early_hints_rx) = EarlyHints::new_lazy();

        let mut request = Request::new(if parsed.is_connect {
            Incoming::Empty
        } else if let Some(body_rx) = body_rx {
            Incoming::H2(H2Body::new(body_rx, send_continue_body.clone()))
        } else {
            // The request ended with HEADERS, so no body frames can
            // arrive; expose an empty body without a channel for it.
            Incoming::Empty
        });
        *request.method_mut() = parsed.method;
        *request.uri_mut() = parsed.uri;
        *request.version_mut() = http::Version::HTTP_2;
        *request.headers_mut() = parsed.headers;
        request.extensions_mut().insert(early_hints);
        if end_stream && parsed.content_length.is_some_and(|cl| cl != 0) {
            // A request that ended without delivering its declared
            // body: stream error (RFC 9113 Section 8.1.2.6).
            self.stream_error(stream_id, Reason::ProtocolError);
            return;
        }
        if let Some(entry) = self.streams.get_mut(&stream_id) {
            entry.remote_ended = end_stream;
        }

        let date_cache = self.date_cache.clone();
        let send_date_header = self.opts.send_date_header;
        let request_fn = request_fn.clone();
        let response_fut = Box::pin(async move {
            let mut response = request_fn(request).await.map_err(e2io)?;
            sanitize_response(&mut response, send_date_header, &date_cache);
            Ok::<Response<ConnBody>, std::io::Error>(response.map(ConnBody::new))
        });

        zincio::spawn(StreamDriver::new(
            response_fut,
            reset_rx,
            msg_tx,
            wake_tx,
            early_hints_rx,
            send_continue,
            send_continue_body,
            parsed.is_connect,
        ));
    }

    /// Remembers a stream id whose stream has ended for good, so
    /// frames for it can be told apart from idle-stream frames
    /// (RFC 9113 Section 5.1). Bounded to 4096 via LRU eviction to
    /// avoid bulk-clear tail spike at the boundary.
    #[inline]
    pub(crate) fn mark_closed(&mut self, stream_id: u32) {
        if self.closed_streams.len() >= 4096 {
            if let Some(old) = self.closed_order.pop_front() {
                self.closed_streams.remove(&old);
            }
        }
        if self.closed_streams.insert(stream_id) {
            self.closed_order.push_back(stream_id);
        }
    }

    /// A DATA frame: forward to the task and restore flow-control
    /// windows (RFC 9113 Sections 6.1 and 6.9.2).
    #[inline]
    pub(crate) async fn handle_data_frame(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        data: Bytes,
    ) {
        if data.is_empty() && !end_stream {
            // Empty chunks won't be very useful...
            return;
        }
        // Sending a WINDOW_UPDATE frame with a zero delta (increment) is explicitly prohibited
        // by the HTTP/2 specification and results in a STREAM_ERROR of type PROTOCOL_ERROR
        // (Error Code 23)
        if !data.is_empty() {
            self.writer
                .write_window_update(&mut self.out, stream_id, data.len() as u32);
            self.writer
                .write_window_update(&mut self.out, 0, data.len() as u32);
        }
        let state = match self.streams.get_mut(&stream_id) {
            None => {
                if self.closed_streams.contains(&stream_id) {
                    StreamDataState::Closed
                } else {
                    StreamDataState::Idle
                }
            }
            Some(entry) => {
                if !entry.request_started || entry.remote_ended {
                    StreamDataState::Bad
                } else {
                    entry.data_sum += data.len() as u64;
                    if !entry.send_body(BodyMsg::Data(data)).await {
                        StreamDataState::Gone
                    } else {
                        StreamDataState::Ok
                    }
                }
            }
        };
        match state {
            StreamDataState::Idle => {
                // DATA on an idle stream: connection error
                // (RFC 9113 Section 5.1).
                self.goaway(Reason::ProtocolError, b"data on idle stream");
            }
            StreamDataState::Closed => {
                // DATA on a closed stream: stream error
                // (RFC 9113 Section 5.1).
                self.writer
                    .write_reset(&mut self.out, stream_id, Reason::StreamClosed.code());
            }
            StreamDataState::Bad => self.stream_error(stream_id, Reason::StreamClosed),
            StreamDataState::Gone => {
                self.mark_closed(stream_id);
                self.streams.remove(&stream_id);
            }
            StreamDataState::Ok => {
                if end_stream {
                    self.end_request_body(stream_id).await;
                }
            }
        }
    }

    /// The request body ended: close the request side and enforce the
    /// declared `content-length` (RFC 9113 Section 8.1.2.6).
    #[inline]
    pub(crate) async fn end_request_body(&mut self, stream_id: u32) {
        let (mismatch, gone) = {
            let entry = match self.streams.get_mut(&stream_id) {
                Some(entry) => entry,
                None => return,
            };
            if entry.remote_ended {
                return;
            }
            entry.remote_ended = true;
            if entry.content_length.is_some_and(|cl| entry.data_sum != cl) {
                (true, false)
            } else if entry.body_tx.is_none() {
                // No body channel (the request ended with HEADERS):
                // there is no body reader to signal EOF to.
                (false, false)
            } else {
                let ok = entry.send_body(BodyMsg::EndStream).await;
                (false, !ok)
            }
        };
        if mismatch {
            self.stream_error(stream_id, Reason::ProtocolError);
        } else if gone {
            self.mark_closed(stream_id);
            self.streams.remove(&stream_id);
        }
    }

    /// A RST_STREAM frame from the peer.
    #[inline]
    pub(crate) fn handle_reset_frame(&mut self, stream_id: u32, error_code: u32) {
        // RFC 9113 Section 5.1: RST_STREAM on a stream that never
        // existed is a connection error.
        let Some(entry) = self.streams.remove(&stream_id) else {
            if !self.closed_streams.contains(&stream_id) {
                self.goaway(Reason::ProtocolError, b"rst on idle stream");
            }
            return;
        };
        if !entry.request_started {
            // The peer reset a stream whose request we never accepted:
            // bound how many such streams a peer may churn through
            // (RFC 9113 Section 10.5.2).
            if let Some(max) = self.opts.max_pending_accept_reset_streams {
                if self.pending_accept_resets >= max {
                    self.goaway(Reason::EnhanceYourCalm, b"too many resets before accept");
                    return;
                }
            }
            self.pending_accept_resets += 1;
        }
        self.mark_closed(stream_id);
        // Unblock the task: the body reader reports the reset and the
        // task ends. Dropping the entry also severs the message
        // channel, which finishes the task if it was parked.
        if !entry.remote_ended {
            entry.send_reset(error_code);
        }
    }
    #[inline]
    pub(crate) fn apply_peer_settings(&mut self, settings: &[crate::h2::codec::Setting]) {
        for setting in settings {
            match setting.id {
                0x01 => {
                    self.peer.header_table_size = setting.value;
                    self.encoder.queue_size_update(setting.value as usize);
                }
                0x02 => self.peer.enable_push = setting.value,
                0x04 => {
                    // Each setting applies to all open streams at the
                    // moment it is processed (RFC 9113 Section 6.9.2);
                    // a window beyond 2^31-1 is a connection error.
                    let delta = setting.value as i64 - self.peer.initial_window_size as i64;
                    self.peer.initial_window_size = setting.value;
                    let mut overflow = false;
                    for entry in self.streams.values_mut() {
                        entry.send_window += delta;
                        overflow |= entry.send_window > i32::MAX as i64;
                    }
                    if overflow {
                        self.goaway(Reason::FlowControlError, b"initial window overflow");
                    }
                }
                0x05 => {
                    // SETTINGS_MAX_FRAME_SIZE: bounds-checked, since the
                    // value MUST be in [2^14, 2^24-1] (RFC 9113 Section
                    // 6.5.2). Anything else is a connection error.
                    if setting.value < DEFAULT_MAX_FRAME_SIZE as u32
                        || setting.value > MAX_FRAME_SIZE_LIMIT as u32
                    {
                        self.goaway(Reason::ProtocolError, b"invalid SETTINGS_MAX_FRAME_SIZE");
                        return;
                    }
                    self.peer.max_frame_size = setting.value as usize;
                    self.writer.max_frame_size = setting.value as usize;
                }
                0x06 => self.peer.max_header_list_size = setting.value,
                _ => {}
            }
        }
    }

    /// Queues a GOAWAY frame; the connection closes after it flushes.
    #[inline]
    pub(crate) fn goaway(&mut self, reason: Reason, debug: &[u8]) {
        self.closing = true;
        self.writer
            .write_goaway(&mut self.out, self.highest_stream_id, reason.code(), debug);
    }

    /// Begins a graceful shutdown (RFC 9113 Section 6.8): advertises the
    /// last stream id we will process and stops accepting new streams.
    /// The drain phase (finish_graceful_shutdown) closes the connection
    /// once in-flight streams finish or the drain window elapses.
    #[inline]
    pub(crate) fn begin_graceful_shutdown(&mut self) {
        if self.graceful || self.closing {
            return;
        }
        self.graceful = true;
        self.graceful_last_stream = self.highest_stream_id;
        self.writer.write_goaway(
            &mut self.out,
            self.graceful_last_stream,
            Reason::NoError.code(),
            b"graceful shutdown",
        );
    }

    /// Sends the final GOAWAY that closes the connection. Called when the
    /// graceful drain completes (all streams finished) or its window
    /// elapses; the caller flushes.
    #[inline]
    pub(crate) fn finish_graceful_shutdown(&mut self) {
        // An error already queued a GOAWAY; don't overwrite it.
        if self.closing {
            return;
        }
        self.writer.write_goaway(
            &mut self.out,
            self.graceful_last_stream,
            Reason::NoError.code(),
            b"graceful shutdown",
        );
    }

    /// Queues a RST_STREAM for a stream error and forgets the stream.
    /// The task is severed by dropping the entry's channels, so it
    /// ends on its next poll.
    #[inline]
    pub(crate) fn stream_error(&mut self, stream_id: u32, reason: Reason) {
        // Bound the RST_STREAM frames we send for the peer's protocol
        // errors (RFC 9113 Section 10.5.2): a peer that keeps making
        // errors past the limit costs the connection, not the stream.
        // InternalError is our own give-up (a stalled stream), not a
        // peer error, so it does not count.
        if reason != Reason::InternalError {
            if let Some(max) = self.opts.max_local_error_reset_streams {
                if self.local_error_resets >= max {
                    self.goaway(
                        Reason::EnhanceYourCalm,
                        b"too many resets for peer protocol errors",
                    );
                    return;
                }
            }
            self.local_error_resets += 1;
        }
        self.writer
            .write_reset(&mut self.out, stream_id, reason.code());
        self.mark_closed(stream_id);
        self.streams.remove(&stream_id);
    }

    /// A WINDOW_UPDATE frame: grow the sender window, checking for the
    /// 2^31-1 overflow (RFC 9113 Sections 6.9 and 6.9.1).
    #[inline]
    pub(crate) fn handle_window_update(&mut self, stream_id: u32, increment: u32) {
        if increment == 0 {
            return;
        }
        let inc = increment as i64;
        if stream_id == 0 {
            if self.conn_window > i32::MAX as i64 - inc {
                self.goaway(Reason::FlowControlError, b"connection window overflow");
                return;
            }
            self.conn_window += inc;
            self.drain_pending_data(None);
        } else {
            let Some(entry) = self.streams.get_mut(&stream_id) else {
                // WINDOW_UPDATE on an idle stream is a connection
                // error (RFC 9113 Section 5.1); closed streams may
                // legitimately receive it.
                if !self.closed_streams.contains(&stream_id) {
                    self.goaway(Reason::ProtocolError, b"window update on idle stream");
                }
                return;
            };
            if entry.send_window > i32::MAX as i64 - inc {
                self.stream_error(stream_id, Reason::FlowControlError);
                return;
            }
            entry.send_window += inc;
            self.drain_pending_data(Some(stream_id));
        }
    }

    /// Sends queued DATA chunks for one stream, respecting the flow
    /// control windows and the peer's max frame size. Returns when the
    /// window is exhausted or the queue is empty.
    #[inline]
    pub(crate) fn pump_stream_data(&mut self, stream_id: u32) {
        loop {
            // Decide how much (if any) of the front chunk to send.
            let (amount, limited) = match self.streams.get_mut(&stream_id) {
                None => return,
                Some(entry) => {
                    if entry.local_ended {
                        return;
                    }
                    let Some((data, end_stream)) = entry.pending_data.front() else {
                        return;
                    };
                    if data.is_empty() {
                        // Zero-length frames are not flow controlled.
                        let end = *end_stream;
                        self.writer.write_data(&mut self.out, stream_id, end, data);
                        let retire = {
                            let entry = self
                                .streams
                                .get_mut(&stream_id)
                                .expect("stream entry exists: lookup succeeded before pump");
                            entry.pending_data.pop_front();
                            if end {
                                entry.local_ended = true;
                                entry.task_done
                            } else {
                                false
                            }
                        };
                        if retire {
                            self.mark_closed(stream_id);
                            self.streams.remove(&stream_id);
                            return;
                        }
                        continue;
                    }
                    let available = self.conn_window.min(entry.send_window);
                    if available <= 0 {
                        return;
                    }
                    let orig_amount = (data.len() as u64).min(available as u64);
                    let amount = orig_amount.min(self.peer.max_frame_size as u64);
                    (amount as usize, orig_amount != amount)
                }
            };
            // Send `amount` bytes from the front chunk; the entry borrow
            // ends before we may remove the stream below.
            let (frame_end, all, chunk) = {
                let entry = self
                    .streams
                    .get_mut(&stream_id)
                    .expect("stream entry exists: lookup succeeded before pump");
                let (data, end_stream) = entry
                    .pending_data
                    .front_mut()
                    .expect("pending chunk exists: front checked before pump");
                let all = amount == data.len();
                let frame_end = *end_stream && all;
                let chunk = data.split_to(amount);
                entry.send_window -= amount as i64;
                (frame_end, all, chunk)
            };
            self.writer
                .write_data(&mut self.out, stream_id, frame_end, &chunk);
            self.conn_window -= amount as i64;
            if all {
                // The chunk is fully consumed; pop it and, if it carried
                // END_STREAM and the task is gone, retire the stream.
                let retire = {
                    let entry = self.streams.get_mut(&stream_id).unwrap();
                    entry.pending_data.pop_front();
                    if frame_end {
                        entry.local_ended = true;
                        entry.task_done
                    } else {
                        false
                    }
                };
                if retire {
                    self.mark_closed(stream_id);
                    self.streams.remove(&stream_id);
                    return;
                }
            } else if !limited {
                // The tail waits for the window to open again.
                break;
            }
        }
    }

    /// Attempts to drain every stream's queued DATA after the flow
    /// control windows opened up. For per-stream `WINDOW_UPDATE` only
    /// that stream is pumped; for connection `WINDOW_UPDATE` we use
    /// deficit round-robin (quantum = max_frame_size) for fairness so a
    /// single 10 MiB response cannot hog `conn_window` and starve
    /// small responses.
    #[inline]
    pub(crate) fn drain_pending_data(&mut self, stream_id: Option<u32>) {
        if let Some(id) = stream_id {
            self.pump_stream_data(id);
            return;
        }
        let quantum = self.peer.max_frame_size;
        // Collect streams with pending data.
        let mut ids = std::mem::take(&mut self.drain_ids);
        ids.clear();
        for (id, entry) in self.streams.iter() {
            if !entry.pending_data.is_empty() && !entry.local_ended {
                ids.push(*id);
            }
        }
        if ids.is_empty() {
            self.drain_ids = ids;
            return;
        }
        let mut next_ids = Vec::new();
        let mut progress = true;
        while progress && self.conn_window > 0 && !ids.is_empty() {
            progress = false;
            next_ids.clear();
            for &id in &ids {
                let Some(entry) = self.streams.get_mut(&id) else {
                    continue;
                };
                if entry.pending_data.is_empty() || entry.local_ended || entry.send_window <= 0 {
                    continue;
                }
                entry.deficit = entry.deficit.saturating_add(quantum);
                let before_conn = self.conn_window;
                self.pump_stream_data_drr(id);
                if self.conn_window < before_conn {
                    progress = true;
                }
                if self
                    .streams
                    .get(&id)
                    .is_some_and(|e| !e.pending_data.is_empty() && !e.local_ended)
                {
                    next_ids.push(id);
                }
                if self.conn_window <= 0 {
                    break;
                }
            }
            std::mem::swap(&mut ids, &mut next_ids);
        }
        self.drain_ids = ids;
    }

    /// Like `pump_stream_data` but capped by `deficit` and sends at most
    /// one frame (quantum) per call for DRR fairness.
    #[inline]
    fn pump_stream_data_drr(&mut self, stream_id: u32) {
        loop {
            let (amount, limited) = match self.streams.get_mut(&stream_id) {
                None => return,
                Some(entry) => {
                    if entry.local_ended {
                        return;
                    }
                    let Some((data, end_stream)) = entry.pending_data.front() else {
                        return;
                    };
                    if data.is_empty() {
                        let end = *end_stream;
                        self.writer.write_data(&mut self.out, stream_id, end, data);
                        let retire = {
                            let entry = self
                                .streams
                                .get_mut(&stream_id)
                                .expect("stream entry exists");
                            entry.pending_data.pop_front();
                            if end {
                                entry.local_ended = true;
                                entry.task_done
                            } else {
                                false
                            }
                        };
                        if retire {
                            self.mark_closed(stream_id);
                            self.streams.remove(&stream_id);
                            return;
                        }
                        continue;
                    }
                    if entry.deficit == 0 {
                        return;
                    }
                    let available = self.conn_window.min(entry.send_window);
                    if available <= 0 {
                        return;
                    }
                    let orig_amount = (data.len() as u64).min(available as u64);
                    let capped = orig_amount.min(entry.deficit as u64);
                    let amount = capped.min(self.peer.max_frame_size as u64);
                    if amount == 0 {
                        return;
                    }
                    (
                        amount as usize,
                        orig_amount != amount || capped != orig_amount,
                    )
                }
            };
            let (frame_end, all, chunk) = {
                let entry = self
                    .streams
                    .get_mut(&stream_id)
                    .expect("stream entry exists");
                let (data, end_stream) = entry
                    .pending_data
                    .front_mut()
                    .expect("pending chunk exists");
                let all = amount == data.len();
                let frame_end = *end_stream && all;
                let chunk = data.split_to(amount);
                entry.send_window -= amount as i64;
                entry.deficit -= amount;
                (frame_end, all, chunk)
            };
            self.writer
                .write_data(&mut self.out, stream_id, frame_end, &chunk);
            self.conn_window -= amount as i64;
            if all {
                let retire = {
                    let entry = self
                        .streams
                        .get_mut(&stream_id)
                        .expect("stream entry exists");
                    entry.pending_data.pop_front();
                    if frame_end {
                        entry.local_ended = true;
                        entry.task_done
                    } else {
                        false
                    }
                };
                if retire {
                    self.mark_closed(stream_id);
                    self.streams.remove(&stream_id);
                    return;
                }
            } else if !limited {
                break;
            }
            // DRR: one frame per quantum.
            break;
        }
    }

    /// Drains every stream task's outbound channel, turning messages
    /// into frames. Called after each read and whenever a wake fires.
    /// Uses reused scratch buffers so the steady state allocates nothing;
    /// cross-stream order was never defined (tasks run concurrently), but
    /// each stream's FIFO order is preserved.
    #[inline]
    pub(crate) fn drain_outbound(&mut self) {
        let mut ids = std::mem::take(&mut self.outbound_ids);
        ids.clear();
        for (id, entry) in self.streams.iter() {
            if !entry.msg_rx.is_empty() {
                ids.push(*id);
            }
        }
        let mut msgs = std::mem::take(&mut self.outbound_msgs);
        for stream_id in ids.iter() {
            let drained = match self.streams.get_mut(stream_id) {
                Some(entry) => {
                    msgs.clear();
                    while let Ok(Some(msg)) = entry.msg_rx.try_recv() {
                        msgs.push(msg);
                    }
                    !msgs.is_empty()
                }
                // Removed while draining (e.g. reset by an earlier
                // message in this same drain).
                None => false,
            };
            if !drained {
                continue;
            }
            let mut msgs_iter = msgs.drain(..).peekable();
            while let Some(mut msg) = msgs_iter.next() {
                if let (
                    StreamMsg::Data { end_stream, .. },
                    Some(StreamMsg::Data {
                        data,
                        end_stream: true,
                    }),
                ) = (&mut msg, msgs_iter.peek())
                {
                    if data.is_empty() {
                        *end_stream = true;
                        msgs_iter.next(); // Discard the blank end_stream message
                    }
                }
                self.handle_stream_msg(*stream_id, msg);
            }
        }
        self.outbound_ids = ids;
        // `msgs` was fully drained above: empty, capacity kept.
        self.outbound_msgs = msgs;
    }

    /// One response-side message from a stream task.
    #[inline]
    pub(crate) fn handle_stream_msg(&mut self, stream_id: u32, msg: StreamMsg) {
        match msg {
            StreamMsg::Informational { parts, .. } => {
                self.encode_field_block(stream_id, false, parts.status, &parts.headers);
            }
            StreamMsg::Headers {
                parts, end_stream, ..
            } => {
                let entry = self.streams.get_mut(&stream_id);
                match entry {
                    None => {}
                    Some(entry) => {
                        if entry.local_ended {
                            // No double END_STREAM (the task's body
                            // continued after the trailer section).
                            return;
                        }
                        entry.local_ended = end_stream;
                    }
                }
                self.encode_field_block(stream_id, end_stream, parts.status, &parts.headers);
            }
            StreamMsg::Data {
                data, end_stream, ..
            } => {
                let Some(entry) = self.streams.get_mut(&stream_id) else {
                    return;
                };
                if entry.local_ended {
                    // No DATA after END_STREAM (the task's body
                    // continued after the trailer section).
                    return;
                }
                if entry.pending_data.len() >= 32 {
                    // The window never opened: give up on the stream.
                    self.stream_error(stream_id, Reason::InternalError);
                    return;
                }
                entry.pending_data.push_back((data, end_stream));
                self.pump_stream_data(stream_id);
            }
            StreamMsg::Trailers { trailers, .. } => {
                let entry = match self.streams.get_mut(&stream_id) {
                    Some(entry) => entry,
                    None => return,
                };
                if entry.local_ended {
                    return;
                }
                entry.local_ended = true;
                self.frame_buffer.clear();
                let mut headers: SmallVec<[HpackHeader; 8]> =
                    SmallVec::with_capacity(trailers.len());
                for (name, value) in trailers.iter() {
                    headers.push(HpackHeader::new(
                        Bytes::copy_from_slice(name.as_str().as_bytes()),
                        Bytes::copy_from_slice(value.as_bytes()),
                    ));
                }
                self.encoder.encode(&headers, &mut self.frame_buffer);
                self.writer
                    .write_field_block(&mut self.out, stream_id, true, &self.frame_buffer);
            }
            StreamMsg::Reset { error_code, .. } => {
                self.writer
                    .write_reset(&mut self.out, stream_id, error_code);
                self.mark_closed(stream_id);
                self.streams.remove(&stream_id);
            }
            StreamMsg::Closed => {
                // The task ended for good. If the whole response was
                // already sent (END_STREAM flushed), tear down now.
                // Otherwise flow control left DATA queued in
                // `pending_data`; keep the stream alive so a later
                // WINDOW_UPDATE (via `drain_pending_data`) can flush it.
                let entry = match self.streams.get_mut(&stream_id) {
                    Some(entry) => entry,
                    None => return,
                };
                entry.task_done = true;
                if entry.local_ended {
                    self.mark_closed(stream_id);
                    self.streams.remove(&stream_id);
                }
            }
        }
    }

    /// Encodes a response (or interim) field block: a `:status` pseudo
    /// header followed by the response headers, skipping the
    /// connection-specific fields the codec would reject anyway.
    #[inline]
    pub(crate) fn encode_field_block(
        &mut self,
        stream_id: u32,
        end_stream: bool,
        status: StatusCode,
        headers: &http::HeaderMap,
    ) {
        // Fast 3-digit status without per-response `to_string` allocation.
        // Well-known codes reuse static bytes, skipping the 3-byte heap
        // copy entirely (every response pays this otherwise).
        let code = status.as_u16();
        let mut status_buf = [b'0'; 3];
        status_buf[0] = b'0' + (code / 100) as u8;
        status_buf[1] = b'0' + ((code / 10) % 10) as u8;
        status_buf[2] = b'0' + (code % 10) as u8;
        let status_value = match &status_buf {
            b"200" => Bytes::from_static(b"200"),
            b"201" => Bytes::from_static(b"201"),
            b"204" => Bytes::from_static(b"204"),
            b"301" => Bytes::from_static(b"301"),
            b"302" => Bytes::from_static(b"302"),
            b"304" => Bytes::from_static(b"304"),
            b"400" => Bytes::from_static(b"400"),
            b"401" => Bytes::from_static(b"401"),
            b"403" => Bytes::from_static(b"403"),
            b"404" => Bytes::from_static(b"404"),
            b"500" => Bytes::from_static(b"500"),
            b"502" => Bytes::from_static(b"502"),
            b"503" => Bytes::from_static(b"503"),
            _ => Bytes::copy_from_slice(&status_buf),
        };
        let mut fields: SmallVec<[HpackHeader; 8]> = SmallVec::with_capacity(headers.len() + 1);
        fields.push(HpackHeader::new(
            Bytes::from_static(b":status"),
            status_value,
        ));
        for (name, value) in headers.iter() {
            let name_bytes = name.as_str().as_bytes();
            if crate::h2::stream::is_connection_specific(name_bytes) {
                continue;
            }
            if name == http::header::TE && !crate::h2::stream::te_is_trailers(value.as_bytes()) {
                continue;
            }
            fields.push(HpackHeader::new(
                Bytes::copy_from_slice(name_bytes),
                Bytes::copy_from_slice(value.as_bytes()),
            ));
        }
        self.frame_buffer.clear();
        self.encoder.encode(&fields, &mut self.frame_buffer);
        // Ensure `out` can hold the field block without growing.
        if self.out.capacity() - self.out.len() < self.frame_buffer.len() + 9 {
            self.out.reserve(self.frame_buffer.len() + 9);
        }
        self.writer
            .write_field_block(&mut self.out, stream_id, end_stream, &self.frame_buffer);
    }

    #[inline]
    pub(crate) async fn flush(&mut self) -> std::io::Result<()> {
        if !self.out.is_empty() {
            tokio::io::AsyncWriteExt::write_all(&mut self.io, &self.out).await?;
            let _ = tokio::io::AsyncWriteExt::flush(&mut self.io).await;
            self.out.clear();
        }
        Ok(())
    }
}
