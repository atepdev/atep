//! `atep-logd`: the ATEP transparency log server.
//!
//!   atep-logd --data-dir ./log-data --listen 127.0.0.1:8480

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use atep_log::client::{exchange_remote, LogClient};
use atep_log::http::spawn;
use atep_log::{unix_now, Log, LogConfig};
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "atep-logd",
    version,
    about = "ATEP transparency log server (spec section 9)"
)]
struct Args {
    /// Data directory: identity key, entries, checkpoints (created if missing).
    #[arg(long)]
    data_dir: PathBuf,
    /// Listen address, plain HTTP (put TLS in a reverse proxy).
    #[arg(long, default_value = "127.0.0.1:8480")]
    listen: String,
    /// Issue a fresh checkpoint at least this often, seconds (spec: hourly).
    #[arg(long, default_value_t = 3600)]
    checkpoint_interval: i64,
    /// Operator name published in the log policy.
    #[arg(long)]
    operator: Option<String>,
    /// Largest accepted envelope, bytes.
    #[arg(long)]
    max_envelope_bytes: Option<usize>,
    /// Retention statement published in the log policy.
    #[arg(long)]
    retention: Option<String>,
    /// Availability statement published in the log policy.
    #[arg(long)]
    availability: Option<String>,
    /// Key custody statement published in the log policy.
    #[arg(long)]
    key_custody: Option<String>,
    /// Peer log URL for checkpoint gossip (repeatable).
    #[arg(long = "peer")]
    peers: Vec<String>,
    /// Seconds between gossip rounds with each peer.
    #[arg(long, default_value_t = 300)]
    gossip_interval: u64,
    /// Open the log, verify it, print its Agent ID and exit.
    #[arg(long)]
    check: bool,
}

fn main() -> ExitCode {
    let a = Args::parse();
    let mut cfg = LogConfig {
        checkpoint_interval_secs: a.checkpoint_interval,
        ..LogConfig::default()
    };
    if let Some(v) = a.operator {
        cfg.operator = v;
    }
    if let Some(v) = a.max_envelope_bytes {
        cfg.max_envelope_bytes = v;
    }
    if let Some(v) = a.retention {
        cfg.retention = v;
    }
    if let Some(v) = a.availability {
        cfg.availability = v;
    }
    if let Some(v) = a.key_custody {
        cfg.key_custody = v;
    }
    let log = match Log::open(&a.data_dir, cfg, unix_now()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("atep-logd: cannot open {}: {e}", a.data_dir.display());
            return ExitCode::FAILURE;
        }
    };
    let id = log.log_id();
    let _ = std::fs::write(a.data_dir.join("log.pub"), log.identity().public().encode());
    println!("log id: {id}");
    println!(
        "entries: {}, checkpoints: {}, public bundle: {}",
        log.tree_size(),
        log.checkpoints().len(),
        a.data_dir.join("log.pub").display()
    );
    if a.check {
        println!("verified");
        return ExitCode::SUCCESS;
    }
    let log = Arc::new(Mutex::new(log));
    let handle = match spawn(log.clone(), &a.listen, Arc::new(unix_now)) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("atep-logd: cannot listen on {}: {e}", a.listen);
            return ExitCode::FAILURE;
        }
    };
    println!("listening on http://{}", handle.addr);
    for p in a.peers {
        let log = log.clone();
        let every = Duration::from_secs(a.gossip_interval.max(1));
        std::thread::spawn(move || {
            let Ok(client) = LogClient::new(&p) else {
                eprintln!("atep-logd: bad peer URL {p}");
                return;
            };
            loop {
                match exchange_remote(&log, &client, unix_now()) {
                    Ok(r) => {
                        for ev in &r.splits {
                            eprintln!(
                                "atep-logd: SPLIT VIEW detected for log {}: {}",
                                ev.log, ev.reason
                            );
                        }
                    }
                    Err(e) => eprintln!("atep-logd: gossip with {p} failed: {e}"),
                }
                std::thread::sleep(every);
            }
        });
    }
    // Serve until killed. All writes are fsynced, so a kill is safe.
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
