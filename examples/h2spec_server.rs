#[cfg(feature = "h2")]
mod server {
    use bytes::Bytes;
    use http::{Response, StatusCode};
    use http_body_util::Full;
    use zincio::net::TcpListener;
    use zincio::RuntimeBuilder;
    use zincio_http::{Http2, Http2Options, HttpProtocol};

    pub fn main() -> std::io::Result<()> {
        // In production, multiple zincio threads would be used...
        let runtime = RuntimeBuilder::new().enable_timer(true).build()?;
        runtime.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:8080")?;
            loop {
                let (stream, _) = listener.accept().await?;
                stream.set_nodelay(true)?;
                let conn = Http2::new(stream.into_poll()?, Http2Options::default());
                zincio::spawn(async move {
                    let _ = conn
                        .handle(|_request| async move {
                            let response = Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from_static(b"Hello World")))
                                .expect("valid response");
                            Ok::<_, std::convert::Infallible>(response)
                        })
                        .await;
                });
            }
        })
    }
}

#[cfg(feature = "h2")]
use server::*;
#[cfg(not(feature = "h2"))]
fn main() {
    unimplemented!("This example requires \"h2\" feature to be enabled.")
}
