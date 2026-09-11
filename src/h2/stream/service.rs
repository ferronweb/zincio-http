use super::*;

enum ServicePoll<ResB> {
    /// The stream task is done (response fully handed over).
    Done,
    /// Waiting on a response, early hints, or peer reset.
    Pending,
    /// The final response is ready to be piped to the connection.
    Body(ResB),
}

pin_project! {
    /// Drives one stream task: runs the user's `request_fn`, forwards
    /// interim and final responses to the connection, and pipes the
    /// response body as chunks.
    ///
    /// The task stops when the response is fully handed over, when the
    /// peer resets the stream, or when the connection goes away. On
    /// every exit path it first enqueues [`StreamMsg::Closed`], so the
    /// connection can drop its per-stream state.
    pub(crate) struct StreamDriver<Fut, ResB> {
        msg_tx: kanal::AsyncSender<StreamMsg>,
        reset_rx: kanal::AsyncReceiver<u32>,
        // Pokes the connection's drive loop when a message lands in
        // the channel, so responses are delivered even while the peer
        // idles.
        wake_tx: kanal::AsyncSender<()>,
        #[pin]
        msg_tx_fut: Option<kanal::SendFuture<'static, StreamMsg>>,
        queue: VecDeque<StreamMsg>,
        // Set once the terminal StreamMsg::Closed lands in the queue;
        // the task only drains from then on.
        done: bool,
        #[pin]
        state: StreamDriverState<Fut, ResB>,
    }
}

pin_project! {
    #[project = StreamDriverProj]
    enum StreamDriverState<Fut, ResB> {
        Service {
            #[pin]
            response_fut: Fut,
            #[pin]
            early_hints_rx: EarlyHintsReceiver,
            response_done: bool,
            headers: Option<http::response::Parts>,
            body: Option<ResB>,
            send_continue: bool,
            send_continue_body: Option<Arc<AtomicBool>>,
            continue_sent: bool,
            early_hints_open: bool,
            extended_connect: bool,
        },
        Body {
            headers: Option<http::response::Parts>,
            #[pin]
            body: ResB,
            body_end: bool,
            first_frame: Option<http_body::Frame<Bytes>>,
        },
    }
}

impl<Fut, ResB> StreamDriver<Fut, ResB> {
    #[allow(clippy::too_many_arguments)]
    #[inline]
    pub(crate) fn new(
        response_fut: Fut,
        reset_rx: kanal::AsyncReceiver<u32>,
        msg_tx: kanal::AsyncSender<StreamMsg>,
        wake_tx: kanal::AsyncSender<()>,
        early_hints_rx: EarlyHintsReceiver,
        send_continue: bool,
        send_continue_body: Option<Arc<AtomicBool>>,
        extended_connect: bool,
    ) -> Self {
        Self {
            msg_tx,
            reset_rx,
            wake_tx,
            msg_tx_fut: None,
            // Grows on demand; steady state holds only a few messages.
            queue: VecDeque::new(),
            done: false,
            state: StreamDriverState::Service {
                response_fut,
                early_hints_rx,
                response_done: false,
                headers: None,
                body: None,
                send_continue,
                send_continue_body,
                continue_sent: false,
                early_hints_open: true,
                extended_connect,
            },
        }
    }
}

impl<Fut, ResB, ResBE, ResE> Future for StreamDriver<Fut, ResB>
where
    Fut: Future<Output = Result<Response<ResB>, ResE>>,
    ResB: Body<Data = Bytes, Error = ResBE> + Unpin,
    ResBE: std::error::Error + 'static,
    ResE: std::error::Error + 'static,
{
    type Output = ();

    #[inline]
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut this = self.project();
        loop {
            if let Some(msg_tx_fut) = this.msg_tx_fut.as_mut().as_pin_mut() {
                match msg_tx_fut.poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { this.msg_tx_fut.as_mut().get_unchecked_mut() };
                        uckm.take();
                        let _ = this.wake_tx.try_send(());
                    }
                    Poll::Ready(Err(_)) => {
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { this.msg_tx_fut.as_mut().get_unchecked_mut() };
                        uckm.take();
                        return Poll::Ready(());
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Drain the outbound queue first: the states are only
            // driven again once the queue is empty, so a completed
            // response or body frame is never re-read.
            if let Some(msg) = this.queue.pop_front() {
                let msg_tx_fut = this.msg_tx.send(msg);
                // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                let msg_tx_fut = unsafe {
                    std::mem::transmute::<
                        kanal::SendFuture<'_, StreamMsg>,
                        kanal::SendFuture<'static, StreamMsg>,
                    >(msg_tx_fut)
                };
                // SAFETY: Pin is re-borrowed here
                let uckm = unsafe { this.msg_tx_fut.as_mut().get_unchecked_mut() };
                *uckm = Some(msg_tx_fut);
                continue;
            }
            if *this.done {
                return Poll::Ready(());
            }
            match this.state.as_mut().project() {
                StreamDriverProj::Service {
                    response_fut,
                    early_hints_rx,
                    response_done,
                    headers,
                    body,
                    send_continue,
                    send_continue_body,
                    continue_sent,
                    early_hints_open,
                    extended_connect,
                } => {
                    match Self::poll_service(
                        this.msg_tx,
                        this.wake_tx,
                        this.msg_tx_fut.as_mut(),
                        this.reset_rx,
                        response_fut,
                        early_hints_rx,
                        response_done,
                        headers,
                        body,
                        send_continue,
                        send_continue_body,
                        continue_sent,
                        early_hints_open,
                        *extended_connect,
                        cx,
                    ) {
                        ServicePoll::Done => {}
                        ServicePoll::Pending => return Poll::Pending,
                        ServicePoll::Body(body) => {
                            let headers = headers.take();
                            this.state.set(StreamDriverState::Body {
                                headers,
                                body,
                                body_end: false,
                                first_frame: None,
                            });
                            continue;
                        }
                    }
                }
                StreamDriverProj::Body {
                    headers,
                    body,
                    body_end,
                    first_frame,
                } => {
                    match Self::poll_body(
                        this.msg_tx,
                        this.msg_tx_fut.as_mut(),
                        this.reset_rx,
                        this.wake_tx,
                        headers,
                        first_frame,
                        body,
                        body_end,
                        cx,
                    ) {
                        Poll::Ready(()) => {}
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
            // Terminal message: the outer drain loop delivers it before
            // the task exits, so the connection always sees Closed.
            this.queue.push_back(StreamMsg::Closed);
            *this.done = true;
            continue;
        }
    }
}

impl<Fut, ResB, ResBE, ResE> StreamDriver<Fut, ResB>
where
    Fut: Future<Output = Result<Response<ResB>, ResE>>,
    ResB: Body<Data = Bytes, Error = ResBE> + Unpin,
    ResBE: std::error::Error + 'static,
    ResE: std::error::Error + 'static,
{
    /// Polls the service state: the response future, peer resets, the
    /// `100 Continue` trigger and early hints. Returns only with the
    /// outbound channel drained.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn poll_service(
        msg_tx: &mut kanal::AsyncSender<StreamMsg>,
        wake_tx: &kanal::AsyncSender<()>,
        mut msg_tx_fut: Pin<&mut Option<kanal::SendFuture<'static, StreamMsg>>>,
        reset_rx: &mut kanal::AsyncReceiver<u32>,
        mut response_fut: Pin<&mut Fut>,
        mut early_hints_rx: Pin<&mut EarlyHintsReceiver>,
        response_done: &mut bool,
        headers: &mut Option<http::response::Parts>,
        body: &mut Option<ResB>,
        send_continue: &bool,
        send_continue_body: &Option<Arc<AtomicBool>>,
        continue_sent: &mut bool,
        early_hints_open: &mut bool,
        extended_connect: bool,
        cx: &mut Context<'_>,
    ) -> ServicePoll<ResB> {
        loop {
            if *response_done {
                match body.take() {
                    Some(body) => return ServicePoll::Body(body),
                    None => return ServicePoll::Done,
                }
            }
            if let Poll::Ready(result) = response_fut.as_mut().poll(cx) {
                let Ok(response) = result else {
                    // Handler error: the stream ends without a reply.
                    *response_done = true;
                    continue;
                };
                if *send_continue && !*continue_sent {
                    if !response.status().is_client_error() && !response.status().is_server_error()
                    {
                        let mut interim = Response::new(());
                        *interim.status_mut() = StatusCode::CONTINUE;
                        let (parts, _) = interim.into_parts();

                        match Self::send(
                            msg_tx,
                            msg_tx_fut.as_mut(),
                            wake_tx,
                            StreamMsg::Informational { parts },
                            cx,
                        ) {
                            Poll::Ready(()) => {}
                            Poll::Pending => return ServicePoll::Pending,
                        }
                    }
                    *continue_sent = true;
                }
                let response_is_end_stream = response.body().is_end_stream();
                let (parts, response_body) = response.into_parts();

                if response_is_end_stream || extended_connect {
                    match Self::send(
                        msg_tx,
                        msg_tx_fut.as_mut(),
                        wake_tx,
                        StreamMsg::Headers {
                            parts,
                            end_stream: response_is_end_stream,
                        },
                        cx,
                    ) {
                        Poll::Ready(()) => {}
                        Poll::Pending => return ServicePoll::Pending,
                    }
                } else {
                    *headers = Some(parts);
                }
                *body = Some(response_body);
                *response_done = true;
                continue;
            }
            match std::pin::pin!(reset_rx.recv()).poll(cx) {
                Poll::Ready(_) => return ServicePoll::Done,
                Poll::Pending => {}
            }
            if *send_continue
                && !*continue_sent
                && send_continue_body
                    .as_ref()
                    .is_some_and(|flag| flag.load(Ordering::Relaxed))
            {
                let mut interim = Response::new(());
                *interim.status_mut() = StatusCode::CONTINUE;
                let (parts, _) = interim.into_parts();
                match Self::send(
                    msg_tx,
                    msg_tx_fut.as_mut(),
                    wake_tx,
                    StreamMsg::Informational { parts },
                    cx,
                ) {
                    Poll::Ready(()) => {}
                    Poll::Pending => return ServicePoll::Pending,
                }
                *continue_sent = true;
                continue;
            }
            if *early_hints_open {
                match early_hints_rx.poll_recv(cx) {
                    Poll::Ready(Some((headers, sender))) => {
                        let mut interim = Response::new(());
                        *interim.status_mut() = StatusCode::EARLY_HINTS;
                        *interim.headers_mut() = headers;
                        let (parts, _) = interim.into_parts();
                        match Self::send(
                            msg_tx,
                            msg_tx_fut.as_mut(),
                            wake_tx,
                            StreamMsg::Informational { parts },
                            cx,
                        ) {
                            Poll::Ready(()) => {}
                            Poll::Pending => return ServicePoll::Pending,
                        }
                        // The write itself happens later on the
                        // connection task; enqueueing is the failure
                        // surface that matters here.
                        sender.into_inner().send(Ok(())).ok();
                        continue;
                    }
                    Poll::Ready(None) => {
                        *early_hints_open = false;
                        continue;
                    }
                    Poll::Pending => {}
                }
            }
            return ServicePoll::Pending;
        }
    }

    /// Enqueues one outbound message, parking until the channel has
    /// room. `Pending` means the sender is parked (by `poll_ready` it
    /// will be woken when the connection task drains); `Ready(())`
    /// means the message was delivered or the connection is gone.
    #[inline]
    fn send(
        msg_tx: &mut kanal::AsyncSender<StreamMsg>,
        mut msg_tx_fut: Pin<&mut Option<kanal::SendFuture<'static, StreamMsg>>>,
        wake_tx: &kanal::AsyncSender<()>,
        msg: StreamMsg,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        if let Some(msg_tx_fut2) = msg_tx_fut.as_mut().as_pin_mut() {
            match msg_tx_fut2.poll(cx) {
                Poll::Ready(Ok(_)) => {
                    // SAFETY: Pin is re-borrowed here
                    let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                    uckm.take();
                    let _ = wake_tx.try_send(());
                }
                Poll::Ready(Err(_)) => {
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        let msg_tx_fut2 = msg_tx.send(msg);
        // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
        let msg_tx_fut2 = unsafe {
            std::mem::transmute::<
                kanal::SendFuture<'_, StreamMsg>,
                kanal::SendFuture<'static, StreamMsg>,
            >(msg_tx_fut2)
        };
        // SAFETY: Pin is re-borrowed here
        let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
        *uckm = Some(msg_tx_fut2);

        if let Some(msg_tx_fut2) = msg_tx_fut.as_mut().as_pin_mut() {
            match msg_tx_fut2.poll(cx) {
                Poll::Ready(Ok(_)) => {
                    // SAFETY: Pin is re-borrowed here
                    let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                    uckm.take();
                    let _ = wake_tx.try_send(());
                    return Poll::Ready(());
                }
                Poll::Ready(Err(_)) => {
                    // SAFETY: Pin is re-borrowed here
                    let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                    uckm.take();
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Pending
    }

    /// Pipes the response body to the connection: DATA frames, then an
    /// END_STREAM (empty DATA when the body yields nothing more, or a
    /// HEADERS block carrying trailers).
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn poll_body(
        msg_tx: &mut kanal::AsyncSender<StreamMsg>,
        mut msg_tx_fut: Pin<&mut Option<kanal::SendFuture<'static, StreamMsg>>>,
        reset_rx: &mut kanal::AsyncReceiver<u32>,
        wake_tx: &kanal::AsyncSender<()>,
        headers: &mut Option<http::response::Parts>,
        first_frame: &mut Option<http_body::Frame<Bytes>>,
        mut body: Pin<&mut ResB>,
        end: &mut bool,
        cx: &mut Context<'_>,
    ) -> Poll<()> {
        let mut flush = false;
        loop {
            if let Some(msg_tx_fut2) = msg_tx_fut.as_mut().as_pin_mut() {
                match msg_tx_fut2.poll(cx) {
                    Poll::Ready(Ok(_)) => {
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                        uckm.take();
                        if !*end {
                            flush = true;
                        }
                    }
                    Poll::Ready(Err(_)) => {
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                        uckm.take();
                        return Poll::Ready(());
                    }
                    Poll::Pending => {
                        if flush {
                            let _ = wake_tx.try_send(());
                        }
                        return Poll::Pending;
                    }
                }
            }

            if *end {
                return Poll::Ready(());
            }

            match std::pin::pin!(reset_rx.recv()).poll(cx) {
                Poll::Ready(_) => return Poll::Ready(()),
                Poll::Pending => {}
            }
            let poll_frame = if let Some(frame) = first_frame.take() {
                Poll::Ready(Some(Ok(frame)))
            } else {
                body.as_mut().poll_frame(cx)
            };
            match poll_frame {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(headers) = headers.take() {
                        *first_frame = Some(frame);
                        let msg = StreamMsg::Headers {
                            parts: headers,
                            end_stream: false,
                        };

                        let msg_tx_fut2 = msg_tx.send(msg);
                        // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                        let msg_tx_fut2 = unsafe {
                            std::mem::transmute::<
                                kanal::SendFuture<'_, StreamMsg>,
                                kanal::SendFuture<'static, StreamMsg>,
                            >(msg_tx_fut2)
                        };
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                        *uckm = Some(msg_tx_fut2);

                        continue;
                    }

                    match frame.into_data() {
                        Ok(data) => {
                            let end_stream = body.is_end_stream();

                            if data.is_empty() && !end_stream {
                                // Reduce unnecessary data transfers
                                continue;
                            }

                            let msg = StreamMsg::Data { data, end_stream };

                            let msg_tx_fut2 = msg_tx.send(msg);
                            // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                            let msg_tx_fut2 = unsafe {
                                std::mem::transmute::<
                                    kanal::SendFuture<'_, StreamMsg>,
                                    kanal::SendFuture<'static, StreamMsg>,
                                >(msg_tx_fut2)
                            };
                            // SAFETY: Pin is re-borrowed here
                            let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                            *uckm = Some(msg_tx_fut2);
                        }
                        Err(frame) => match frame.into_trailers() {
                            Ok(trailers) => {
                                let msg_tx_fut2 = msg_tx.send(StreamMsg::Trailers { trailers });
                                // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                                let msg_tx_fut2 = unsafe {
                                    std::mem::transmute::<
                                        kanal::SendFuture<'_, StreamMsg>,
                                        kanal::SendFuture<'static, StreamMsg>,
                                    >(msg_tx_fut2)
                                };
                                // SAFETY: Pin is re-borrowed here
                                let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                                *uckm = Some(msg_tx_fut2);
                                *end = true;
                            }
                            Err(_) => return Poll::Ready(()),
                        },
                    }
                }
                Poll::Ready(Some(Err(_))) => {
                    let msg = StreamMsg::Reset {
                        error_code: crate::h2::error::Reason::InternalError.code(),
                    };
                    let msg_tx_fut2 = msg_tx.send(msg);
                    // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                    let msg_tx_fut2 = unsafe {
                        std::mem::transmute::<
                            kanal::SendFuture<'_, StreamMsg>,
                            kanal::SendFuture<'static, StreamMsg>,
                        >(msg_tx_fut2)
                    };
                    // SAFETY: Pin is re-borrowed here
                    let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                    *uckm = Some(msg_tx_fut2);
                    *end = true;
                }
                Poll::Ready(None) => {
                    if let Some(headers) = headers.take() {
                        let msg = StreamMsg::Headers {
                            parts: headers,
                            end_stream: true,
                        };

                        let msg_tx_fut2 = msg_tx.send(msg);
                        // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                        let msg_tx_fut2 = unsafe {
                            std::mem::transmute::<
                                kanal::SendFuture<'_, StreamMsg>,
                                kanal::SendFuture<'static, StreamMsg>,
                            >(msg_tx_fut2)
                        };
                        // SAFETY: Pin is re-borrowed here
                        let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                        *uckm = Some(msg_tx_fut2);
                        *end = true;

                        continue;
                    }

                    // The body has no more frames: close with an empty
                    // END_STREAM DATA frame.
                    let msg = StreamMsg::Data {
                        data: Bytes::new(),
                        end_stream: true,
                    };
                    let msg_tx_fut2 = msg_tx.send(msg);
                    // SAFETY: msg_tx_fut lives as long as msg_tx after storing in struct
                    let msg_tx_fut2 = unsafe {
                        std::mem::transmute::<
                            kanal::SendFuture<'_, StreamMsg>,
                            kanal::SendFuture<'static, StreamMsg>,
                        >(msg_tx_fut2)
                    };
                    // SAFETY: Pin is re-borrowed here
                    let uckm = unsafe { msg_tx_fut.as_mut().get_unchecked_mut() };
                    *uckm = Some(msg_tx_fut2);
                    *end = true;
                }
                Poll::Pending => {
                    if flush {
                        let _ = wake_tx.try_send(());
                    }
                    return Poll::Pending;
                }
            }
        }
    }
}
