//! `testcontainers`-backed drivers for third-party clients.
//!
//! # One container per client, reused across the whole matrix
//!
//! Each [`ClientContainer`] is started once and then `exec`'d once per
//! scenario. Starting a container per scenario would multiply the matrix by
//! its own size: with a dozen scenarios and five clients that is sixty
//! container startups per protocol, which is the difference between a usable
//! pull-request gate and one nobody waits for.
//!
//! # Reaching the host
//!
//! The scenario server runs on the host and binds `0.0.0.0`. Containers are
//! given a `host.docker.internal` alias pointing at the host gateway, so the
//! driver scripts address the server by a stable name regardless of which
//! bridge subnet docker picked.

use std::path::PathBuf;
use std::time::Duration;

use testcontainers::core::{ExecCommand, Host, ImageExt, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage};

use crate::client::{ClientSpec, ImageSpec, Observation, ScenarioArgs};

/// Hostname inside every client container that resolves to the host gateway.
pub const HOST_ALIAS: &str = "host.docker.internal";

/// Marker the driver prints when it is idle and ready for execs. Must match the
/// string in `clients/*-driver.sh`.
const READY_MARKER: &str = "interop-driver ready";

/// How long a single scenario may take before it is treated as a failure.
///
/// Generous enough for the 1 MiB and 64 MiB transfers on a loaded CI runner,
/// but bounded so a hung client cannot stall the suite indefinitely.
pub const SCENARIO_TIMEOUT: Duration = Duration::from_secs(180);

/// A running client container that can execute scenarios.
pub struct ClientContainer {
    container: ContainerAsync<GenericImage>,
    spec: &'static ClientSpec,
}

impl ClientContainer {
    /// Starts the container for `spec` and waits until it can run commands.
    pub async fn start(spec: &'static ClientSpec) -> Result<Self, String> {
        let image = match spec.image {
            Some(ImageSpec::Registry { image }) => registry_image(image),
            Some(ImageSpec::Build {
                tag,
                context,
                target,
            }) => build_image(tag, context, target)
                .map_err(|err| format!("{}: failed to build image {tag}: {err}", spec.name))?,
            None => {
                return Err(format!(
                    "{}: no container image configured, so it cannot be started",
                    spec.name
                ))
            }
        };

        // The image's entrypoint is the driver, and the harness reuses one
        // container for every scenario, so the container is started with no
        // arguments: the driver then announces readiness and idles. Waiting for
        // that marker means a broken image surfaces as one clear start failure
        // rather than as every scenario in the matrix failing for the same
        // reason.
        let container = image
            .with_wait_for(WaitFor::message_on_stdout(READY_MARKER))
            .with_cmd(std::iter::empty::<String>())
            .with_host(HOST_ALIAS, Host::HostGateway)
            .with_startup_timeout(Duration::from_secs(120))
            .start()
            .await
            .map_err(|err| format!("{}: failed to start container: {err}", spec.name))?;

        Ok(Self { container, spec })
    }

    /// The client this container represents.
    pub fn spec(&self) -> &'static ClientSpec {
        self.spec
    }

    /// Runs one scenario inside the container and parses its observation.
    ///
    /// The driver script is expected to print a single observation line; a
    /// missing or unparsable line is itself a failure, because it means the
    /// driver broke rather than that the server misbehaved.
    pub async fn run(&self, args: &ScenarioArgs) -> Result<Observation, String> {
        let entrypoint = self
            .spec
            .entrypoint
            .clone()
            .ok_or_else(|| format!("{}: no driver entrypoint configured", self.spec.name))?;

        let mut cmd: Vec<String> = vec![entrypoint.program.to_owned()];
        cmd.extend(entrypoint.args.iter().map(|arg| (*arg).to_owned()));
        cmd.extend(args.to_argv());

        let mut result =
            tokio::time::timeout(SCENARIO_TIMEOUT, self.container.exec(ExecCommand::new(cmd)))
                .await
                .map_err(|_| {
                    format!(
                        "{}: {} over {} did not finish within {SCENARIO_TIMEOUT:?}",
                        self.spec.name,
                        args.scenario,
                        args.protocol.name()
                    )
                })?
                .map_err(|err| format!("{}: exec failed: {err}", self.spec.name))?;

        let stdout = result
            .stdout_to_vec()
            .await
            .map_err(|err| format!("{}: reading stdout failed: {err}", self.spec.name))?;
        let stderr = result
            .stderr_to_vec()
            .await
            .map_err(|err| format!("{}: reading stderr failed: {err}", self.spec.name))?;

        let stdout = String::from_utf8_lossy(&stdout).to_string();
        let line = stdout
            .lines()
            .find(|line| line.starts_with("status="))
            .ok_or_else(|| {
                format!(
                    "{}: {} over {} printed no observation line\nstdout: {}\nstderr: {}",
                    self.spec.name,
                    args.scenario,
                    args.protocol.name(),
                    stdout.trim(),
                    String::from_utf8_lossy(&stderr).trim()
                )
            })?;

        Observation::parse(line).map_err(|err| {
            format!(
                "{}: {} over {}: {err}",
                self.spec.name,
                args.scenario,
                args.protocol.name()
            )
        })
    }
}

/// Splits a pinned registry reference into an image and a tag.
///
/// Splitting on the last colon keeps registry references that carry a port or
/// a digest separator working; an untagged reference falls back to `latest`.
fn split_reference(reference: &str) -> (&str, &str) {
    reference.rsplit_once(':').unwrap_or((reference, "latest"))
}

/// Builds an image handle from a pinned registry reference.
fn registry_image(reference: &str) -> GenericImage {
    let (image, tag) = split_reference(reference);
    GenericImage::new(image, tag)
}

/// Builds an image from a checked-in Dockerfile under `interop/docker/`.
///
/// This shells out to `docker build` rather than using testcontainers'
/// `GenericBuildableImage`. That builder copies sources in through its own
/// context mechanism, which does not fit the multi-stage builds the HTTP/3 and
/// nghttp2 images need, and shelling out gets docker's normal layer cache --
/// which is what makes these builds cheap enough to run on every pull request.
/// testcontainers still owns the container lifecycle, which is the part that
/// actually benefits from its abstraction.
fn build_image(tag: &str, context: &str, target: &str) -> Result<GenericImage, String> {
    // The build context is the whole crate, not the Dockerfile's own
    // directory, so driver scripts can stay in one shared `clients/` tree
    // instead of being duplicated per image.
    let context_dir = crate_dir();
    let dockerfile = docker_dir().join(context).join("Dockerfile");
    if !dockerfile.exists() {
        return Err(format!("missing Dockerfile {}", dockerfile.display()));
    }

    let output = std::process::Command::new("docker")
        .arg("build")
        .arg("--tag")
        // Tag explicitly: an empty tag would make the reference invalid.
        .arg(format!("{tag}:latest"))
        // Stopping at the named stage means a cheap image never drags in the
        // stages a more expensive sibling needs.
        .arg("--target")
        .arg(target)
        .arg("--file")
        .arg(&dockerfile)
        .arg(&context_dir)
        .output()
        .map_err(|err| format!("could not run `docker build`: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "`docker build` failed for {}:\n{}",
            dockerfile.display(),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    Ok(GenericImage::new(tag, "latest"))
}

/// Locates `interop/docker` relative to this crate's manifest directory.
fn docker_dir() -> PathBuf {
    crate_dir().join("docker")
}

/// Root of this crate, used as the docker build context.
fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_references_split_into_image_and_tag() {
        assert_eq!(
            split_reference("curlimages/curl:8.21.0"),
            ("curlimages/curl", "8.21.0")
        );
        assert_eq!(split_reference("golang:1.24"), ("golang", "1.24"));
    }

    #[test]
    fn untagged_registry_references_fall_back_to_latest() {
        assert_eq!(split_reference("golang"), ("golang", "latest"));
    }

    #[test]
    fn a_digest_pinned_reference_is_not_mistaken_for_a_tag() {
        // The part after the last colon is the digest, which is exactly what we
        // want passed through as the tag.
        assert_eq!(
            split_reference("curlimages/curl@sha256:abc123"),
            ("curlimages/curl@sha256", "abc123")
        );
    }

    #[test]
    fn the_docker_build_context_exists() {
        // A typo in a build context would only surface as a container start
        // failure deep into the matrix, so it is checked directly.
        assert!(docker_dir().exists(), "{} missing", docker_dir().display());
        for context in ["curl"] {
            assert!(
                docker_dir().join(context).join("Dockerfile").exists(),
                "missing Dockerfile for {context}"
            );
        }
    }
}
