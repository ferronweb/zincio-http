//! After the client's GOAWAY the server closes its side and reads what the client still
//! sends until the client closes too (a lingering close, as nginx's): closing with unread
//! data makes the kernel reset the connection, and the client may then never see the
//! server's last frames. On a duplex stream the reset shows as the client's late write
//! failing.

#![cfg(feature = "h2")]

use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zincio_http::codec::{FrameWriter, CLIENT_PREFACE, DEFAULT_MAX_FRAME_SIZE};
use zincio_http::{Http2, Http2Options, HttpProtocol, Incoming};

#[test]
fn a_late_frame_after_the_clients_goaway_is_read_not_refused() {
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async {
            let (mut client, server_io) = tokio::io::duplex(1 << 16);
            let server = zincio::spawn(async move {
                Http2::new(server_io, Http2Options::default())
                    .handle(|_request: Request<Incoming>| async move {
                        Ok::<_, std::io::Error>(
                            Response::new(http_body_util::Empty::<Bytes>::new()),
                        )
                    })
                    .await
            });
            let writer = FrameWriter::new(DEFAULT_MAX_FRAME_SIZE);
            let mut hello = CLIENT_PREFACE.to_vec();
            writer.write_settings(&mut hello, &[]);
            writer.write_goaway(&mut hello, 0, 0x00, b"bye");
            client.write_all(&hello).await.unwrap();
            // The PING comes in a later read than the GOAWAY.
            zincio::time::sleep(Duration::from_millis(100)).await;
            let mut ping = Vec::new();
            writer.write_ping(&mut ping, b"h2spec  ");
            client
                .write_all(&ping)
                .await
                .expect("the server still reads after the GOAWAY");
            client.shutdown().await.unwrap();
            // The server's side ends cleanly.
            let mut rest = Vec::new();
            zincio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut rest))
                .await
                .expect("the server closes")
                .expect("a clean end, not an error");
            zincio::time::timeout(Duration::from_secs(5), server)
                .await
                .expect("the connection task ends")
                .expect("the connection ended cleanly");
        });
}
