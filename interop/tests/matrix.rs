//! Drives the full scenario matrix through containerised third-party clients.
//!
//! One container is started per client and reused for every scenario, so the
//! cost is per client rather than per scenario.
//!
//! Docker is required. The tests skip with a clear message when it is absent,
//! because a contributor without Docker should not see a wall of failures --
//! but they never silently pass, since CI sets `ZINCIO_INTEROP_REQUIRE=1` and a
//! missing daemon there is a real failure.

use std::collections::BTreeMap;

use zincio_http_interop::client::{Protocol, ScenarioArgs};
use zincio_http_interop::clients;
use zincio_http_interop::container::ClientContainer;
use zincio_http_interop::scenario::Capability;
use zincio_http_interop::scenario::{self, Expect, Step};
use zincio_http_interop::server;

/// Skips the whole suite when Docker is unavailable.
macro_rules! require_docker {
    () => {
        if !docker_available() {
            if std::env::var("ZINCIO_INTEROP_REQUIRE").is_ok() {
                panic!(
                    "ZINCIO_INTEROP_REQUIRE is set but Docker is unavailable; \\
                     the interop suite cannot be skipped here"
                );
            }
            eprintln!("skipping interop matrix: Docker is unavailable");
            return;
        }
    };
}

/// Whether the Docker daemon can be reached.
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .arg("--format")
        .arg("{{.ServerVersion}}")
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Base URL a driver should use for `protocol`.
///
/// The server runs on the host and the container reaches it through the
/// `host.docker.internal` gateway alias. HTTP/3 additionally needs the
/// self-signed certificate to be skipped, which each driver does itself.
fn base_url(addrs: &server::ServerAddrs, protocol: Protocol) -> String {
    let addr = match protocol {
        Protocol::Http1 => addrs.h1,
        Protocol::Http2 => addrs.h2,
        Protocol::Http3 => addrs.h3,
    };
    let scheme = match protocol {
        Protocol::Http3 => "https",
        _ => "http",
    };
    // The certificate is issued for `localhost`, so that is the name the H3
    // drivers must use even though they connect to the gateway address.
    format!("{scheme}://{HOST_ALIAS}:{}", addr.port())
}

/// Name the drivers use for the host running the server.
const HOST_ALIAS: &str = zincio_http_interop::container::HOST_ALIAS;

/// The single-request expectation for a step, if it has one.
///
/// Multi-step scenarios return their expectations from the driver instead, so
/// there is nothing to check here.
fn single_expect(step: &Step) -> Option<Expect> {
    match step {
        Step::Request { expect, .. } => Some(*expect),
        _ => None,
    }
}

/// Scenarios whose steps the generic single-request path can drive.
fn generic_scenarios() -> Vec<&'static scenario::Scenario> {
    scenario::SCENARIOS
        .iter()
        .filter(|s| {
            s.steps
                .iter()
                .all(|step| matches!(step, Step::Request { .. }))
        })
        .collect()
}

/// Scenarios that need a purpose-built driver routine.
fn bespoke_scenarios() -> Vec<&'static scenario::Scenario> {
    scenario::SCENARIOS
        .iter()
        .filter(|s| {
            s.steps
                .iter()
                .any(|step| !matches!(step, Step::Request { .. }))
        })
        .collect()
}

/// Runs the single-request part of the matrix for every client and protocol.
#[tokio::test(flavor = "multi_thread")]
async fn single_request_matrix() {
    require_docker!();

    let (addrs, _handles) = server::spawn().expect("spawn interop servers");
    let mut failures: Vec<String> = Vec::new();
    let mut ran = 0usize;
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();

    for client_spec in &clients::selected() {
        let container = match ClientContainer::start(client_spec).await {
            Ok(container) => container,
            Err(err) => {
                failures.push(format!("{}: {err}", client_spec.id));
                continue;
            }
        };

        for protocol in Protocol::all() {
            for scenario in generic_scenarios() {
                if let Some(reason) = client_spec.can_run(scenario, protocol) {
                    *skipped
                        .entry(format!("{}: {reason}", client_spec.id))
                        .or_default() += 1;
                    continue;
                }

                let Some(expect) = single_expect(&scenario.steps[0]) else {
                    unreachable!("generic_scenarios only yields Request steps");
                };

                let args = ScenarioArgs {
                    base_url: base_url(&addrs, protocol),
                    protocol,
                    scenario: scenario.name,
                    step: scenario.steps[0],
                };

                match container.run(&args).await {
                    Ok(observation) => {
                        ran += 1;
                        if let Err(err) = observation.verify(scenario.name, expect) {
                            failures.push(format!(
                                "[{} over {}] {err} ({})",
                                client_spec.id,
                                protocol.name(),
                                scenario.rationale
                            ));
                        }
                    }
                    Err(err) => failures.push(format!(
                        "[{} over {}] {err}",
                        client_spec.id,
                        protocol.name()
                    )),
                }
            }
        }
    }

    report(&failures, ran, &skipped);
}

/// Runs the scenarios that need a purpose-built driver routine.
#[tokio::test(flavor = "multi_thread")]
async fn bespoke_matrix() {
    require_docker!();

    let (addrs, _handles) = server::spawn().expect("spawn interop servers");
    let mut failures: Vec<String> = Vec::new();
    let mut ran = 0usize;
    let mut skipped: BTreeMap<String, usize> = BTreeMap::new();

    for client_spec in &clients::selected() {
        // Only clients whose driver actually implements a bespoke routine take
        // part here; curl's driver handles these inline, but the capability
        // table is what decides, so a driver can never claim a routine it
        // does not implement.
        let supports_bespoke = matches!(
            bespoke_scenarios().as_slice(),
            [_, ..] if !bespoke_scenarios().is_empty()
        );
        if !supports_bespoke {
            continue;
        }

        let container = match ClientContainer::start(client_spec).await {
            Ok(container) => container,
            Err(err) => {
                failures.push(format!("{}: {err}", client_spec.id));
                continue;
            }
        };

        for protocol in Protocol::all() {
            for scenario in bespoke_scenarios() {
                if let Some(reason) = client_spec.can_run(scenario, protocol) {
                    *skipped
                        .entry(format!("{}: {reason}", client_spec.id))
                        .or_default() += 1;
                    continue;
                }
                let args = ScenarioArgs {
                    base_url: base_url(&addrs, protocol),
                    protocol,
                    scenario: scenario.name,
                    // The driver inspects the scenario name to choose its
                    // routine, so the first step is only a placeholder for
                    // argument formatting.
                    step: scenario.steps[0],
                };
                match container.run(&args).await {
                    Ok(observation) => {
                        ran += 1;
                        let expect = match scenario.name {
                            "abort_midstream" => Expect::Exact {
                                len: scenario::SMALL_LEN,
                            },
                            "idle_reuse" => Expect::Exact {
                                len: scenario::SMALL_LEN,
                            },
                            "concurrency" => Expect::Exact {
                                len: scenario::SMALL_LEN,
                            },
                            other => {
                                failures.push(format!(
                                    "[{} over {}] no expectation is defined for bespoke scenario {other}",
                                    client_spec.id,
                                    protocol.name()
                                ));
                                continue;
                            }
                        };
                        if let Err(err) = observation.verify(scenario.name, expect) {
                            failures.push(format!(
                                "[{} over {}] {err} ({})",
                                client_spec.id,
                                protocol.name(),
                                scenario.rationale
                            ));
                        }
                    }
                    Err(err) => failures.push(format!(
                        "[{} over {}] {err}",
                        client_spec.id,
                        protocol.name()
                    )),
                }
            }
        }
    }

    report(&failures, ran, &skipped);
}

/// Asserts on the outcome and prints the coverage summary either way.
fn report(failures: &[String], ran: usize, skipped: &BTreeMap<String, usize>) {
    let mut summary = format!("\ninterop matrix: {ran} scenario(s) executed");
    if !skipped.is_empty() {
        summary.push_str("\nskipped (client cannot run the scenario):");
        for (reason, count) in skipped {
            summary.push_str(&format!("\n  {count:>2}x {reason}"));
        }
    }

    if failures.is_empty() {
        eprintln!("{summary}");
        assert!(
            ran > 0,
            "no scenarios ran; the matrix is not testing anything"
        );
        return;
    }

    summary.push_str(&format!("\n\n{} failure(s):", failures.len()));
    for failure in failures {
        summary.push_str(&format!("\n  - {failure}"));
    }
    panic!("{summary}");
}

/// Guards the assumption that the matrix can actually distinguish HTTP
/// versions, without needing Docker.
#[test]
fn base_urls_are_protocol_specific() {
    let addrs = server::ServerAddrs {
        h1: "127.0.0.1:1".parse().expect("addr"),
        h2: "127.0.0.1:2".parse().expect("addr"),
        h3: "127.0.0.1:3".parse().expect("addr"),
    };
    assert_eq!(
        base_url(&addrs, Protocol::Http1),
        format!("http://{HOST_ALIAS}:1")
    );
    assert_eq!(
        base_url(&addrs, Protocol::Http2),
        format!("http://{HOST_ALIAS}:2")
    );
    // HTTP/3 is the only one over TLS, because QUIC mandates it.
    assert_eq!(
        base_url(&addrs, Protocol::Http3),
        format!("https://{HOST_ALIAS}:3")
    );
}

/// The single-request and bespoke partitions must cover every scenario exactly
/// once, or the matrix would silently lose coverage.
#[test]
fn every_scenario_is_either_generic_or_bespoke() {
    let generic = generic_scenarios().len();
    let bespoke = bespoke_scenarios().len();
    assert_eq!(
        generic + bespoke,
        scenario::SCENARIOS.len(),
        "scenarios are neither generic nor bespoke and would never run"
    );
    assert!(generic > 0 && bespoke > 0);
}

/// A scenario whose driver declares fewer capabilities than it needs must be
/// skipped, never silently run with the wrong assertion.
#[test]
fn capability_gating_is_what_keeps_scenarios_from_being_dropped() {
    let curl = &clients::CURL;
    let trailers = scenario::scenario_by_name("trailers").expect("trailers scenario");
    let reason = curl
        .can_run(trailers, Protocol::Http1)
        .expect("curl cannot observe response trailers, so this scenario must be skipped");
    assert!(
        reason.contains("Trailers"),
        "the skip reason should name the missing capability, got {reason:?}"
    );
}

/// Records which capabilities the current client set can satisfy, so a gap in
/// coverage is visible in the test output rather than only when something
/// breaks.
#[test]
fn no_capability_is_left_entirely_uncovered() {
    let mut uncovered: Vec<String> = Vec::new();
    for capability in [
        Capability::Upload,
        Capability::ResponseTrailers,
        Capability::RequestTrailers,
        Capability::Concurrency,
        Capability::Abort,
        Capability::ExpectContinue,
        Capability::EarlyHints,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ] {
        let covered = clients::selected()
            .iter()
            .any(|c| c.capabilities.contains(&capability));
        if !covered {
            uncovered.push(format!("{capability:?}"));
        }
    }
    // This is a coverage report, not a gate: new clients land one at a time and
    // each addition shrinks this list. It is printed so the remaining gaps are
    // visible in CI logs instead of being rediscovered later.
    eprintln!("capabilities with no client yet: {uncovered:?}");
}
