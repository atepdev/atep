//! `atep-monitor`: follow an ATEP transparency log and raise alerts.
//!
//!   atep-monitor --log http://127.0.0.1:8480 --watch-domain example.com \
//!       --authorized atep:... --root atep:... --once

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use atep_core::keys::AgentId;
use atep_log::unix_now;
use atep_monitor::{DirSource, HttpSource, LogSource, Monitor, MonitorConfig};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "atep-monitor",
    version,
    about = "Follow an ATEP transparency log and alert on anomalies (spec section 9)"
)]
struct Args {
    /// Log to follow: an http:// URL of atep-logd, or a log data directory.
    #[arg(long)]
    log: String,
    /// Pin the log's Agent ID (otherwise the first checkpoint's signer is trusted).
    #[arg(long)]
    log_id: Option<String>,
    /// DNS name to watch for domain-control attestations (repeatable; covers subdomains).
    #[arg(long = "watch-domain")]
    watch_domain: Vec<String>,
    /// Agent ID the operator authorizes for the watched domains (repeatable).
    #[arg(long = "authorized")]
    authorized: Vec<String>,
    /// Root issuer for delegation checks (repeatable). Without roots, issuer
    /// authority is not judged.
    #[arg(long = "root")]
    root: Vec<String>,
    /// Also alert on issuers that hold no delegation and are not roots.
    #[arg(long)]
    strict_issuers: bool,
    /// Seconds between polls.
    #[arg(long, default_value_t = 60)]
    interval: u64,
    /// Poll once and exit: 0 when there are no alerts, 3 when there are.
    #[arg(long)]
    once: bool,
    /// Print alerts as one JSON object per line.
    #[arg(long)]
    json: bool,
    /// Override the clock, Unix seconds (replaying an old log, tests).
    #[arg(long)]
    now: Option<i64>,
    /// File holding the last verified checkpoint between runs.
    #[arg(long)]
    state: Option<PathBuf>,
}

fn ids(list: &[String], what: &str) -> Result<Vec<AgentId>, String> {
    list.iter()
        .map(|s| AgentId::parse(s).map_err(|e| format!("{what} `{s}`: {e}")))
        .collect()
}

fn run<S: LogSource>(a: &Args, cfg: MonitorConfig, source: S) -> ExitCode {
    let mut m = Monitor::new(cfg, source);
    if let Some(p) = &a.state {
        if let Ok(raw) = std::fs::read(p) {
            if let Err(e) = m.trust_checkpoint(&raw, a.now.unwrap_or_else(unix_now)) {
                eprintln!("atep-monitor: ignoring saved state {}: {e}", p.display());
            }
        }
    }
    let mut any = false;
    loop {
        let now = a.now.unwrap_or_else(unix_now);
        let fresh = m.poll(now);
        for al in &fresh {
            any = true;
            if a.json {
                println!("{}", al.to_json());
            } else {
                println!("{al}");
            }
        }
        if let (Some(p), Some(c)) = (&a.state, m.last_checkpoint()) {
            let _ = std::fs::write(p, &c.raw);
        }
        if a.once {
            if !a.json {
                match m.last_checkpoint() {
                    Some(c) => eprintln!(
                        "atep-monitor: log {} at tree size {}, {} entries checked, {} alert(s)",
                        c.log,
                        c.size,
                        m.entries_seen(),
                        m.alerts().len()
                    ),
                    None => eprintln!("atep-monitor: no verified checkpoint"),
                }
            }
            return if any {
                ExitCode::from(3)
            } else {
                ExitCode::SUCCESS
            };
        }
        std::thread::sleep(Duration::from_secs(a.interval.max(1)));
    }
}

fn main() -> ExitCode {
    let a = Args::parse();
    let build = || -> Result<MonitorConfig, String> {
        let mut cfg = MonitorConfig::new();
        cfg.log_id = match &a.log_id {
            Some(s) => Some(AgentId::parse(s).map_err(|e| format!("--log-id: {e}"))?),
            None => None,
        };
        cfg.watch_domains = a.watch_domain.clone();
        cfg.authorized = ids(&a.authorized, "--authorized")?;
        cfg.roots = ids(&a.root, "--root")?;
        cfg.strict_issuers = a.strict_issuers;
        Ok(cfg)
    };
    let cfg = match build() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("atep-monitor: {e}");
            return ExitCode::from(2);
        }
    };
    if a.log.starts_with("http://") {
        match HttpSource::new(&a.log) {
            Ok(s) => run(&a, cfg, s),
            Err(e) => {
                eprintln!("atep-monitor: {e}");
                ExitCode::from(2)
            }
        }
    } else if a.log.starts_with("https://") {
        eprintln!(
            "atep-monitor: https is not supported, use a local TLS proxy or a data directory"
        );
        ExitCode::from(2)
    } else {
        run(&a, cfg, DirSource(PathBuf::from(&a.log)))
    }
}
