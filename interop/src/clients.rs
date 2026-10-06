//! The registry of third-party clients in the matrix.
//!
//! Declaring capabilities conservatively is deliberate: a scenario needing
//! something a client genuinely cannot observe should be skipped with a
//! reason, not failed. Guessing in a client's favour turns a tooling
//! limitation into a phantom server bug, which is exactly the failure mode this
//! suite has to avoid.

use crate::client::{ClientSpec, Entrypoint, ImageSpec, Protocol};
use crate::scenario::Capability;

/// Capabilities curl can genuinely observe.
///
/// Notably absent: response trailers and 1xx informational responses, which
/// curl cannot surface, and concurrency, since it makes one request per
/// invocation. Claiming any of these would turn a curl limitation into a
/// phantom server bug.
const CURL_CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::Abort,
    Capability::BigHeader,
    Capability::LongUri,
    Capability::ManyHeaders,
    // curl opens a connection per invocation, so what this actually verifies
    // is that the server stays usable after a previous connection has idled
    // out and been reaped -- not that curl reuses a pooled connection.
    Capability::IdleReuse,
];

/// curl over HTTP/1.1 and HTTP/2, from the official image plus our driver.
///
/// An HTTP/3-capable curl is not registered yet: building one requires a
/// source build whose CMake configure step is still unresolved. See the
/// recipe left in `docker/curl/Dockerfile`.
///
/// curl is the client that found the 0.4.2 HTTP/3 stream reset, and it is on
/// every CI runner, so it earns its place twice: as an independent
/// HPACK/flow-control implementation and as a reproducibility anchor.
pub static CURL: ClientSpec = ClientSpec {
    id: "curl",
    name: "curl (HTTP/1.1 + HTTP/2)",
    protocols: &[Protocol::Http1, Protocol::Http2],
    capabilities: CURL_CAPABILITIES,
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-curl",
        context: "curl",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("docker/curl"),
};

/// Every client currently in the matrix.
pub static ALL_CLIENTS: &[&ClientSpec] = &[&CURL];

/// The clients to run, honouring `ZINCIO_INTEROP_CLIENTS`.
///
/// Lets a cheap lane run only the fast images while a scheduled lane builds the
/// expensive ones, without maintaining two lists that could drift.
pub fn selected() -> Vec<&'static ClientSpec> {
    let Ok(filter) = std::env::var("ZINCIO_INTEROP_CLIENTS") else {
        return ALL_CLIENTS.to_vec();
    };
    let wanted: Vec<&str> = filter
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .collect();

    let selected: Vec<&'static ClientSpec> = ALL_CLIENTS
        .iter()
        .copied()
        .filter(|client| wanted.contains(&client.id))
        .collect();

    assert!(
        !selected.is_empty(),
        "ZINCIO_INTEROP_CLIENTS={filter:?} matched no known client; known ids: {:?}",
        ALL_CLIENTS.iter().map(|c| c.id).collect::<Vec<_>>()
    );
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario;

    #[test]
    fn client_ids_are_unique() {
        let mut ids: Vec<&str> = ALL_CLIENTS.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate client id");
    }

    #[test]
    fn every_client_has_a_runnable_configuration() {
        for client in ALL_CLIENTS {
            assert!(
                client.entrypoint.is_some(),
                "{} has no driver entrypoint",
                client.id
            );
            assert!(
                client.image.is_some(),
                "{} is registered but has no image, so it cannot be started",
                client.id
            );
            assert!(
                !client.protocols.is_empty(),
                "{} speaks no protocols",
                client.id
            );
        }
    }

    #[test]
    fn every_client_image_has_a_dockerfile() {
        let docker_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docker");
        for client in ALL_CLIENTS {
            let Some(crate::client::ImageSpec::Build { context, .. }) = client.image else {
                continue;
            };
            assert!(
                docker_dir.join(context).join("Dockerfile").exists(),
                "{}: missing docker/{context}/Dockerfile",
                client.id
            );
        }
    }

    /// Protocols with no containerised client yet.
    ///
    /// Listed explicitly rather than merely tolerated, so that *removing* an
    /// entry is what closes the gap. A protocol that becomes uncovered by
    /// accident is not in this list and therefore still fails the test.
    const KNOWN_UNCOVERED_PROTOCOLS: &[Protocol] = &[Protocol::Http3];

    #[test]
    fn every_protocol_is_covered_or_listed_as_a_known_gap() {
        // A client set that quietly stops covering a protocol would let a whole
        // protocol rot without any test noticing.
        for protocol in Protocol::all() {
            let covered = ALL_CLIENTS.iter().any(|c| c.protocols.contains(&protocol));
            let known_gap = KNOWN_UNCOVERED_PROTOCOLS.contains(&protocol);
            assert!(
                covered || known_gap,
                "no client speaks {}, and it is not listed in \
                 KNOWN_UNCOVERED_PROTOCOLS",
                protocol.name()
            );
            assert!(
                !(covered && known_gap),
                "{} now has a client, so remove it from \
                 KNOWN_UNCOVERED_PROTOCOLS",
                protocol.name()
            );
        }
    }

    #[test]
    fn every_known_uncovered_protocol_really_is_uncovered() {
        // Otherwise a stale entry would let a future regression hide behind it.
        for protocol in KNOWN_UNCOVERED_PROTOCOLS {
            assert!(
                !ALL_CLIENTS.iter().any(|c| c.protocols.contains(protocol)),
                "{} is listed as uncovered but has a client",
                protocol.name()
            );
        }
    }

    #[test]
    fn at_least_one_scenario_is_runnable_by_every_client() {
        // Guards against a client declaring so few capabilities that the
        // matrix silently becomes empty for it.
        for client in ALL_CLIENTS {
            for protocol in client.protocols {
                let runnable = scenario::SCENARIOS
                    .iter()
                    .filter(|s| client.can_run(s, *protocol).is_none())
                    .count();
                assert!(
                    runnable > 0,
                    "{} can run no scenario over {}",
                    client.id,
                    protocol.name()
                );
            }
        }
    }

    #[test]
    fn curl_declares_only_what_it_can_actually_observe() {
        // curl cannot surface response trailers or 1xx informational responses.
        // If these are ever claimed, the matching scenarios would report a
        // server bug that is really a curl limitation.
        assert!(!CURL.capabilities.contains(&Capability::ResponseTrailers));
        assert!(!CURL.capabilities.contains(&Capability::EarlyHints));
        // One request per invocation, so no real concurrency.
        assert!(!CURL.capabilities.contains(&Capability::Concurrency));
    }
}
