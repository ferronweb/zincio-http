//! Standalone entry point for the interop scenario server.
//!
//! Prints the bound ports and a `READY` line on stdout so a shell harness or
//! CI step can wait for startup deterministically instead of sleeping.
//!
//! ```text
//! cargo run --bin interop-server -- --h1-port 0 --h2-port 0 --h3-port 0
//! ```

use std::process::ExitCode;

use zincio_http_interop::server;

const USAGE: &str = "\
usage: interop-server [--h1-port N] [--h2-port N] [--h3-port N]

Every port defaults to 0, which binds an ephemeral port. The chosen ports are
printed as `h1=<port> h2=<port> h3=<port>` followed by a `READY` line.
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("interop-server: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (h1_port, h2_port, h3_port) = parse_args()?;

    let (addrs, _handles) = server::spawn_on_ports(h1_port, h2_port, h3_port)
        .map_err(|err| format!("failed to start servers: {err}"))?;

    println!(
        "h1={} h2={} h3={}",
        addrs.h1.port(),
        addrs.h2.port(),
        addrs.h3.port()
    );
    println!("READY");
    // Flushed explicitly: a CI step reading this pipe must not block waiting
    // for a line that is sitting in a buffer.
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // Serve until the process is signalled. The accept loops are detached
    // threads that die with the process, so there is nothing to join here.
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3_600));
    }
}

/// Parses `--hN-port N` flags. Unknown flags are an error rather than being
/// ignored, so a typo in a CI script fails loudly.
fn parse_args() -> Result<(u16, u16, u16), String> {
    let mut ports = [0u16; 3];
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--help" || arg == "-h" {
            print!("{USAGE}");
            std::process::exit(0);
        }
        let index = match arg.as_str() {
            "--h1-port" => 0,
            "--h2-port" => 1,
            "--h3-port" => 2,
            other => return Err(format!("unknown argument {other:?}\n\n{USAGE}")),
        };
        let value = args
            .next()
            .ok_or_else(|| format!("{arg} requires a value"))?;
        ports[index] = value
            .parse()
            .map_err(|_| format!("{arg} expects a port number, got {value:?}"))?;
    }
    Ok((ports[0], ports[1], ports[2]))
}
