#[cfg(all(feature = "h3", feature = "h3-quinn"))]
mod server {
    use bytes::Bytes;
    use http::{Response, StatusCode};
    use http_body_util::Full;
    use quinn::{Endpoint, ServerConfig};
    use std::convert::Infallible;
    use std::sync::Arc;
    use zincio::RuntimeBuilder;
    use zincio_http::{Http3, Http3Options, HttpProtocol};

    #[tokio::main]
    pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()])
            .expect("self-signed certificate");
        let cert_der: quinn::rustls::pki_types::CertificateDer<'static> = cert.cert.into();
        let mut tls = quinn::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert_der],
                quinn::rustls::pki_types::PrivateKeyDer::from(cert.signing_key),
            )
            .expect("tls config");
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_crypto =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls).expect("quic crypto config");
        let server_config = ServerConfig::with_crypto(Arc::new(quic_crypto));

        let addr = "0.0.0.0:4433".parse().expect("socket address");
        let endpoint = Endpoint::server(server_config, addr).expect("quinn endpoint");

        println!("h3spec_server listening on {}", addr);

        loop {
            let connecting =
                match tokio::time::timeout(std::time::Duration::from_millis(50), endpoint.accept())
                    .await
                {
                    Ok(Some(c)) => c,
                    Ok(None) => break,
                    Err(_) => continue,
                };
            let connection = match connecting.await {
                Ok(connection) => connection,
                Err(err) => {
                    eprintln!("connection failed: {err}");
                    continue;
                }
            };

            // In production, zincio runtime would be reused...
            std::thread::spawn(move || {
                let runtime = match RuntimeBuilder::new().enable_timer(true).build() {
                    Ok(runtime) => runtime,
                    Err(err) => {
                        eprintln!("zincio runtime build failed: {err}");
                        return;
                    }
                };
                let h3 = Http3::new(
                    zincio_http::quinn::Connection::new(connection),
                    Http3Options::default(),
                );
                let _ = runtime.block_on(h3.handle(|_request| async move {
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from_static(b"Hello World")))
                        .expect("valid response");
                    Ok::<_, Infallible>(response)
                }));
            });
        }
        Ok(())
    }
}

#[cfg(all(feature = "h3", feature = "h3-quinn"))]
use server::*;
#[cfg(not(all(feature = "h3", feature = "h3-quinn")))]
fn main() {
    unimplemented!("This example requires \"h3\" and \"h3-quinn\" features to be enabled.")
}
