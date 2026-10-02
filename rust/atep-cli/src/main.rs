//! `atep` command line tool (milestones M1 and M2).

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use atep_core::attestation::{self, claims, Attestation, AttestationParams};
use atep_core::cbor::Value;
use atep_core::consts::{CT_ATTESTATION, CT_DATA, HDR_ATTESTATIONS};
use atep_core::envelope::{with_unprotected, SignMode, SignParams, SignedEnvelope};
use atep_core::keys::{fill_random, sha256, AgentId, Identity, PublicBundle};
use atep_core::srl::{
    self, FileSrlCache, MemorySrlCache, RevocationEntry, RevokedId, Srl, SrlCache,
};
use atep_core::trust::{self, Rule, Step9Input, TrustPolicy};
use atep_core::{json, verify, Policy, Revocation, RevocationReason, Verified};
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "atep",
    version,
    about = "ATEP (Autonomy Trust Envelope Protocol) tool, Draft 02"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate a key bundle and write the secret key file and public bundle file
    Keygen(KeygenArgs),
    /// Print the Agent ID of a secret key file or public bundle file
    Id(IdArgs),
    /// Sign a payload into a COSE_Sign envelope (tag 98)
    Sign(SignArgs),
    /// Verify an envelope (spec section 10); with --policy or --root also evaluate step 9
    Verify(VerifyArgs),
    /// Issue an attestation (spec section 7)
    Attest(AttestArgs),
    /// Build a signed revocation list (spec section 8)
    #[command(alias = "revoke")]
    Srl(SrlArgs),
    /// Print the attestation chain behind a claim
    Chain(ChainArgs),
    /// Encrypt a signed envelope to a recipient bundle (COSE_Encrypt, tag 96)
    Encrypt(EncryptArgs),
    /// Decrypt an encrypted envelope and write the inner signed envelope
    Decrypt(DecryptArgs),
    /// Print the JSON debug view of any ATEP CBOR file
    View(ViewArgs),
}

#[derive(Args)]
struct KeygenArgs {
    /// Output path for the secret key file (CBOR, written with mode 0600)
    #[arg(long, short = 'k')]
    out: PathBuf,
    /// Output path for the public bundle file (canonical CBOR). Default: <out>.pub
    #[arg(long = "pub")]
    pub_out: Option<PathBuf>,
    /// Do not generate the X25519 + ML-KEM-768 encryption keys
    #[arg(long)]
    no_enc: bool,
    /// Overwrite existing files
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct IdArgs {
    /// Secret key file or public bundle file
    file: PathBuf,
    /// Print the did:atep: alias instead of the atep: form
    #[arg(long)]
    did: bool,
}

#[derive(Args)]
struct SignArgs {
    /// Secret key file of the signer
    #[arg(long, short = 'k')]
    key: PathBuf,
    /// Payload file, or `-` for stdin
    #[arg(long = "in", short = 'i')]
    input: PathBuf,
    /// Output envelope file
    #[arg(long, short = 'o')]
    out: PathBuf,
    /// Content type header (3)
    #[arg(long, default_value = CT_DATA)]
    content_type: String,
    /// issued-at, Unix seconds (default: now)
    #[arg(long)]
    issued_at: Option<i64>,
    /// expires-at, Unix seconds
    #[arg(long, conflicts_with = "expires_in")]
    expires_at: Option<i64>,
    /// expires-at as seconds after issued-at
    #[arg(long)]
    expires_in: Option<i64>,
    /// Detach the payload (the envelope carries nil)
    #[arg(long)]
    detached: bool,
    /// Do not embed the signer's public bundle in the unprotected header
    #[arg(long)]
    no_bundle: bool,
    /// 16 byte nonce as 32 hex characters (default: random)
    #[arg(long)]
    nonce_hex: Option<String>,
    /// Use deterministic ML-DSA signing instead of hedged signing
    #[arg(long)]
    deterministic: bool,
    /// Attestation file to carry in the unprotected header (-70009); repeatable
    #[arg(long = "attach")]
    attach: Vec<PathBuf>,
    /// ATEP-R command class (header -70014)
    #[arg(long)]
    command_class: Option<String>,
}

/// Trust inputs shared by `verify` and `chain`.
#[derive(Args)]
struct TrustArgs {
    /// Trust policy file (JSON, see rust/README.md)
    #[arg(long)]
    policy: Option<PathBuf>,
    /// Trusted root Agent ID; repeatable, added to the policy's roots
    #[arg(long = "root")]
    roots: Vec<String>,
    /// SRL envelope file; repeatable
    #[arg(long = "srl")]
    srls: Vec<PathBuf>,
    /// Directory used as a file-backed SRL cache (read, and written with --srl files)
    #[arg(long = "srl-dir")]
    srl_dir: Option<PathBuf>,
    /// Further attestation files the verifier knows; repeatable
    #[arg(long = "attestation")]
    attestations: Vec<PathBuf>,
    /// Enforce the ATEP-R command class table (spec section 17)
    #[arg(long = "atep-r")]
    atep_r: bool,
}

#[derive(Args)]
struct AttestArgs {
    /// Secret key file of the issuer
    #[arg(long, short = 'k')]
    key: PathBuf,
    /// Subject: an Agent ID, or a secret key or public bundle file
    #[arg(long)]
    subject: String,
    /// Claim type: a URI or a short name (`audited`, `fleet-member`, `robotics/peer-motion`)
    #[arg(long)]
    claim: String,
    /// Claim data as a JSON object (`{"$hex": "..."}` makes a byte string)
    #[arg(long)]
    data: Option<String>,
    /// Claim data from a JSON file
    #[arg(long, conflicts_with = "data")]
    data_file: Option<PathBuf>,
    /// Evidence: file whose SHA-256 becomes the evidence hash
    #[arg(long)]
    evidence_file: Option<PathBuf>,
    /// Evidence hash as 64 hex characters
    #[arg(long, conflicts_with = "evidence_file")]
    evidence_hex: Option<String>,
    /// Evidence URI
    #[arg(long)]
    evidence_uri: Option<String>,
    /// issued-at, Unix seconds (default: now)
    #[arg(long)]
    issued_at: Option<i64>,
    /// expires-at, Unix seconds
    #[arg(long, conflicts_with_all = ["expires_in", "days"])]
    expires_at: Option<i64>,
    /// expires-at as seconds after issued-at
    #[arg(long, conflicts_with = "days")]
    expires_in: Option<i64>,
    /// Lifetime in days (default 90)
    #[arg(long)]
    days: Option<i64>,
    /// Attestation id as 32 hex characters (default: random)
    #[arg(long)]
    id_hex: Option<String>,
    /// Do not embed the issuer's public bundle
    #[arg(long)]
    no_bundle: bool,
    /// Allow more than 180 days for a claim that is not audit-backed (400 days stays the maximum)
    #[arg(long)]
    allow_long: bool,
    /// Use deterministic ML-DSA signing
    #[arg(long)]
    deterministic: bool,
    /// Output attestation file
    #[arg(long, short = 'o')]
    out: PathBuf,
}

#[derive(Args)]
struct SrlArgs {
    /// Secret key file of the issuer
    #[arg(long, short = 'k')]
    key: PathBuf,
    /// Output SRL file
    #[arg(long, short = 'o')]
    out: PathBuf,
    /// Previous SRL of this issuer: its entries are kept and the sequence is incremented
    #[arg(long)]
    prev: Option<PathBuf>,
    /// Attestation to revoke: an attestation file or its id as 32 hex characters; repeatable
    #[arg(long = "attestation")]
    attestations: Vec<String>,
    /// Identity to list as compromised (an Agent ID); repeatable
    #[arg(long = "identity")]
    identities: Vec<String>,
    /// Reason text for the new entries (default: withdrawn, or compromised for identities)
    #[arg(long)]
    reason: Option<String>,
    /// revoked-at for the new entries, Unix seconds (default: now)
    #[arg(long)]
    revoked_at: Option<i64>,
    /// issued-at, Unix seconds (default: now)
    #[arg(long)]
    issued_at: Option<i64>,
    /// next-update as seconds after issued-at (default 86400)
    #[arg(long, default_value_t = 86_400)]
    valid_for: i64,
    /// Sequence number (default: previous + 1, or 1)
    #[arg(long)]
    sequence: Option<i64>,
    /// Do not embed the issuer's public bundle
    #[arg(long)]
    no_bundle: bool,
}

#[derive(Args)]
struct ChainArgs {
    /// Attestation file (prints its chain), or any envelope verified under the policy
    #[arg(long = "in", short = 'i')]
    input: PathBuf,
    #[command(flatten)]
    trust: TrustArgs,
    /// Recipient secret key file (for encrypted envelopes)
    #[arg(long, short = 'k')]
    key: Option<PathBuf>,
    /// Verification time, Unix seconds (default: now)
    #[arg(long)]
    now: Option<i64>,
    /// Print the result as JSON
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct VerifyArgs {
    /// Envelope file
    #[arg(long = "in", short = 'i')]
    input: PathBuf,
    /// Recipient secret key file (needed for encrypted envelopes)
    #[arg(long, short = 'k')]
    key: Option<PathBuf>,
    /// Known signer bundle file(s), used when the envelope has no inline bundle
    #[arg(long = "bundle")]
    bundles: Vec<PathBuf>,
    /// Verification time, Unix seconds (default: now)
    #[arg(long)]
    now: Option<i64>,
    /// Detached payload file
    #[arg(long)]
    detached: Option<PathBuf>,
    /// Nonce (32 hex chars) that was already seen; repeatable
    #[arg(long = "seen-nonce")]
    seen_nonces: Vec<String>,
    /// Revoked identity as `<agent-id>:<retired|compromised>:<revoked-at>`; repeatable
    #[arg(long = "revoked")]
    revoked: Vec<String>,
    /// Write the verified payload to this file (`-` for stdout)
    #[arg(long = "payload-out")]
    payload_out: Option<PathBuf>,
    /// Print the result as JSON
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    trust: TrustArgs,
}

#[derive(Args)]
struct EncryptArgs {
    /// Signed envelope (tag 98) to encrypt
    #[arg(long = "in", short = 'i')]
    input: PathBuf,
    /// Recipient public bundle file (must contain encryption keys)
    #[arg(long = "to")]
    to: PathBuf,
    /// Output file
    #[arg(long, short = 'o')]
    out: PathBuf,
}

#[derive(Args)]
struct DecryptArgs {
    /// Encrypted envelope (tag 96)
    #[arg(long = "in", short = 'i')]
    input: PathBuf,
    /// Recipient secret key file
    #[arg(long, short = 'k')]
    key: PathBuf,
    /// Output file for the inner signed envelope
    #[arg(long, short = 'o')]
    out: PathBuf,
}

#[derive(Args)]
struct ViewArgs {
    /// CBOR file
    file: PathBuf,
}

type Res<T> = Result<T, String>;

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn read(path: &Path) -> Res<Vec<u8>> {
    if path == Path::new("-") {
        let mut v = Vec::new();
        std::io::stdin()
            .read_to_end(&mut v)
            .map_err(|e| format!("reading stdin: {e}"))?;
        return Ok(v);
    }
    fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn write(path: &Path, data: &[u8], force: bool) -> Res<()> {
    if path == Path::new("-") {
        return std::io::stdout()
            .write_all(data)
            .map_err(|e| format!("writing stdout: {e}"));
    }
    if !force && path.exists() {
        return Err(format!(
            "{} already exists (use --force to overwrite)",
            path.display()
        ));
    }
    fs::write(path, data).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

fn write_secret(path: &Path, data: &[u8], force: bool) -> Res<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut o = fs::OpenOptions::new();
        o.write(true).mode(0o600);
        if force {
            o.create(true).truncate(true);
        } else {
            o.create_new(true);
        }
        let mut f = o.open(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "{} already exists (use --force to overwrite)",
                    path.display()
                )
            } else {
                format!("cannot write {}: {e}", path.display())
            }
        })?;
        f.write_all(data)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    write(path, data, force)
}

fn load_identity(path: &Path) -> Res<Identity> {
    let data = read(path)?;
    Identity::from_secret_file(&data)
        .map_err(|e| format!("{} is not a valid secret key file: {e}", path.display()))
}

fn load_bundle(path: &Path) -> Res<PublicBundle> {
    let data = read(path)?;
    PublicBundle::decode(&data)
        .map_err(|e| format!("{} is not a valid public bundle file: {e}", path.display()))
}

fn parse_hex16(s: &str, what: &str) -> Res<[u8; 16]> {
    hex::decode(s)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or_else(|| format!("{what} must be 32 hex characters (16 bytes)"))
}

fn parse_subject(s: &str) -> Res<AgentId> {
    if s.starts_with("atep:") || s.starts_with("did:atep:") {
        return AgentId::parse(s).map_err(|e| e.to_string());
    }
    let data = read(Path::new(s))?;
    match Identity::from_secret_file(&data) {
        Ok(i) => Ok(i.agent_id()),
        Err(_) => PublicBundle::decode(&data)
            .map(|b| b.agent_id())
            .map_err(|e| format!("{s} is not an Agent ID, secret key file or public bundle: {e}")),
    }
}

/// An attestation id given as 32 hex characters or as an attestation file.
fn attestation_id(arg: &str) -> Res<[u8; 16]> {
    if let Some(id) = hex::decode(arg)
        .ok()
        .and_then(|v| <[u8; 16]>::try_from(v).ok())
    {
        return Ok(id);
    }
    let data = read(Path::new(arg))?;
    let env = SignedEnvelope::decode(&data).map_err(|e| format!("{arg}: {e}"))?;
    let payload = env
        .payload
        .ok_or_else(|| format!("{arg}: attestation payload is detached"))?;
    Attestation::from_payload(&payload)
        .map(|a| a.id)
        .map_err(|e| format!("{arg}: {e}"))
}

struct TrustSetup {
    trust: Option<TrustPolicy>,
    attestations: Vec<Vec<u8>>,
    cache: Option<Box<dyn SrlCache>>,
}

fn setup_trust(a: &TrustArgs, bundles: &[PublicBundle], now: i64) -> Res<TrustSetup> {
    let mut trust = match &a.policy {
        Some(p) => {
            let data = read(p)?;
            let j: serde_json::Value = serde_json::from_slice(&data)
                .map_err(|e| format!("{} is not valid JSON: {e}", p.display()))?;
            Some(TrustPolicy::from_json(&j).map_err(|e| format!("{}: {e}", p.display()))?)
        }
        None if !a.roots.is_empty() || a.atep_r => Some(TrustPolicy::default()),
        None => None,
    };
    if let Some(t) = trust.as_mut() {
        for r in &a.roots {
            let id = AgentId::parse(r).map_err(|e| format!("--root {r}: {e}"))?;
            if !t.roots.contains(&id) {
                t.roots.push(id);
            }
        }
        if a.atep_r {
            t.atep_r = true;
        }
    }
    let attestations = a
        .attestations
        .iter()
        .map(|p| read(p))
        .collect::<Res<Vec<_>>>()?;
    let mut cache: Option<Box<dyn SrlCache>> = None;
    if let Some(dir) = &a.srl_dir {
        let (c, skipped) =
            FileSrlCache::open(dir, bundles, now).map_err(|e| format!("--srl-dir: {e}"))?;
        for s in skipped {
            eprintln!("warning: skipped cache file {s}");
        }
        cache = Some(Box::new(c));
    } else if !a.srls.is_empty() {
        cache = Some(Box::new(MemorySrlCache::new()));
    }
    if let Some(c) = cache.as_mut() {
        for p in &a.srls {
            let raw = read(p)?;
            // The local attestation store is part of the context: a list from
            // an issuer that has retired cannot be loaded (spec section 8).
            let cx = srl::LoadContext {
                attestations: &attestations,
                ..srl::LoadContext::bundles(bundles)
            };
            srl::ingest_in(c.as_mut(), &raw, &cx, now)
                .map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    Ok(TrustSetup {
        trust,
        attestations,
        cache,
    })
}

fn short(claim: &str) -> &str {
    claim.strip_prefix(claims::NS).unwrap_or(claim)
}

fn print_claims(v: &Verified) {
    for c in &v.claims {
        println!(
            "claim:        {} (issuer {}, root {}, good until {})",
            short(&c.claim),
            c.issuer,
            c.root,
            c.expires_at
        );
        for (i, l) in c.chain.iter().enumerate() {
            println!(
                "  {}. {} for {}, issued by {} (id {}, expires {})",
                i + 1,
                short(&l.claim),
                l.subject,
                l.issuer,
                hex::encode(l.id),
                l.expires_at
            );
        }
    }
    if let Some(cp) = &v.checkpoint {
        println!(
            "checkpoint:   log {} tree-size {} root {}",
            cp.log,
            cp.tree_size,
            hex::encode(cp.root_hash)
        );
    }
    if let Some(c) = &v.command_class {
        println!("class:        {c}");
    }
    for w in &v.warnings {
        println!("warning:      {w}");
    }
}

fn parse_inline(files: &[PathBuf]) -> Res<Vec<Value>> {
    files
        .iter()
        .map(|p| Value::decode(&read(p)?).map_err(|e| format!("{}: {e}", p.display())))
        .collect()
}

fn run(cli: Cli) -> Res<ExitCode> {
    match cli.cmd {
        Cmd::Keygen(a) => {
            let id = Identity::generate(!a.no_enc).map_err(|e| e.to_string())?;
            let pub_path = a.pub_out.unwrap_or_else(|| {
                let mut s = a.out.clone().into_os_string();
                s.push(".pub");
                PathBuf::from(s)
            });
            write_secret(&a.out, &id.to_secret_file(), a.force)?;
            write(&pub_path, &id.public().encode(), a.force)?;
            println!("{}", id.agent_id());
            eprintln!("secret key: {}", a.out.display());
            eprintln!("public bundle: {}", pub_path.display());
        }
        Cmd::Id(a) => {
            let data = read(&a.file)?;
            let id = match Identity::from_secret_file(&data) {
                Ok(i) => i.agent_id(),
                Err(_) => PublicBundle::decode(&data)
                    .map_err(|e| {
                        format!(
                            "{} is neither a secret key file nor a public bundle: {e}",
                            a.file.display()
                        )
                    })?
                    .agent_id(),
            };
            println!("{}", if a.did { id.to_did() } else { id.to_text() });
        }
        Cmd::Sign(a) => {
            let id = load_identity(&a.key)?;
            let payload = read(&a.input)?;
            let issued = a.issued_at.unwrap_or_else(now_secs);
            let nonce = match &a.nonce_hex {
                Some(h) => parse_hex16(h, "--nonce-hex")?,
                None => {
                    let mut n = [0u8; 16];
                    fill_random(&mut n).map_err(|e| e.to_string())?;
                    n
                }
            };
            let mut p = SignParams::new(&payload, &a.content_type, nonce, issued);
            p.expires_at = a.expires_at.or(a.expires_in.map(|s| issued + s));
            p.detached = a.detached;
            p.include_bundle = !a.no_bundle;
            p.mode = if a.deterministic {
                SignMode::Deterministic
            } else {
                SignMode::Hedged
            };
            p.command_class = a.command_class.as_deref();
            let mut env = atep_core::sign(&id, &p).map_err(|e| e.to_string())?;
            if !a.attach.is_empty() {
                let list = parse_inline(&a.attach)?;
                env = with_unprotected(&env, vec![(HDR_ATTESTATIONS, Some(Value::Array(list)))])
                    .map_err(|e| e.to_string())?;
            }
            write(&a.out, &env, true)?;
            eprintln!("signed as {} ({} bytes)", id.agent_id(), env.len());
        }
        Cmd::Verify(a) => {
            let env = read(&a.input)?;
            let recipient = a.key.as_deref().map(load_identity).transpose()?;
            let now = a.now.unwrap_or_else(now_secs);
            let mut pol = Policy {
                recipient: recipient.as_ref(),
                ..Policy::default()
            };
            for b in &a.bundles {
                pol.known_bundles.push(load_bundle(b)?);
            }
            let setup = setup_trust(&a.trust, &pol.known_bundles, now)?;
            pol.trust = setup.trust;
            pol.attestations = setup.attestations;
            pol.srls = setup.cache.as_deref();
            if let Some(d) = &a.detached {
                pol.detached_payload = Some(read(d)?);
            }
            for n in &a.seen_nonces {
                pol.seen_nonces.push(parse_hex16(n, "--seen-nonce")?);
            }
            for r in &a.revoked {
                let parts: Vec<&str> = r.rsplitn(3, ':').collect();
                if parts.len() != 3 {
                    return Err(format!(
                        "--revoked expects <agent-id>:<retired|compromised>:<revoked-at>, got `{r}`"
                    ));
                }
                let reason = match parts[1] {
                    "retired" => RevocationReason::Retired,
                    "compromised" => RevocationReason::Compromised,
                    o => return Err(format!("unknown revocation reason `{o}`")),
                };
                pol.revocations.push(Revocation {
                    id: AgentId::parse(parts[2]).map_err(|e| e.to_string())?,
                    reason,
                    revoked_at: parts[0]
                        .parse()
                        .map_err(|_| format!("bad revoked-at in `{r}`"))?,
                });
            }
            let result = verify(&env, &pol, now);
            if a.json {
                let j = json::verify_result(&result);
                println!("{}", serde_json::to_string_pretty(&j).unwrap());
            }
            match result {
                Ok(v) => {
                    if !a.json {
                        println!("OK");
                        println!("signer:       {}", v.signer);
                        println!("content-type: {}", v.content_type);
                        println!("issued-at:    {}", v.issued_at);
                        if let Some(e) = v.expires_at {
                            println!("expires-at:   {e}");
                        }
                        println!("encrypted:    {}", v.encrypted);
                        println!("payload:      {} bytes", v.payload.len());
                        print_claims(&v);
                    }
                    if let Some(p) = &a.payload_out {
                        write(p, &v.payload, true)?;
                    }
                }
                Err(r) => {
                    if !a.json {
                        eprintln!(
                            "REJECTED at step {} ({}): {}",
                            r.step,
                            r.code.as_str(),
                            r.detail
                        );
                        if let Some(c) = &r.cause {
                            eprintln!(
                                "  caused by step {} ({}): {}",
                                c.step,
                                c.code.as_str(),
                                c.detail
                            );
                        }
                    }
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Cmd::Attest(a) => {
            let id = load_identity(&a.key)?;
            let subject = parse_subject(&a.subject)?;
            let issued = a.issued_at.unwrap_or_else(now_secs);
            let expires = a
                .expires_at
                .or(a.expires_in.map(|s| issued + s))
                .unwrap_or_else(|| issued + a.days.unwrap_or(90) * 86_400);
            let mut p = AttestationParams::new(subject, &a.claim, issued, expires)
                .map_err(|e| e.to_string())?;
            let data_json = match (&a.data, &a.data_file) {
                (Some(d), _) => Some(d.clone()),
                (None, Some(f)) => {
                    Some(String::from_utf8(read(f)?).map_err(|e| format!("{}: {e}", f.display()))?)
                }
                _ => None,
            };
            if let Some(d) = data_json {
                let j: serde_json::Value =
                    serde_json::from_str(&d).map_err(|e| format!("--data is not JSON: {e}"))?;
                p.data = attestation::json_to_cbor(&j).map_err(|e| e.to_string())?;
            }
            if let Some(f) = &a.evidence_file {
                p.evidence = Some(sha256(&read(f)?));
            } else if let Some(h) = &a.evidence_hex {
                p.evidence = Some(
                    hex::decode(h)
                        .ok()
                        .and_then(|v| v.try_into().ok())
                        .ok_or("--evidence-hex must be 64 hex characters")?,
                );
            }
            p.evidence_uri = a.evidence_uri.clone();
            if let Some(h) = &a.id_hex {
                p.id = parse_hex16(h, "--id-hex")?;
            }
            p.include_bundle = !a.no_bundle;
            p.allow_long_default = a.allow_long;
            if a.deterministic {
                p.mode = SignMode::Deterministic;
            }
            let env = attestation::issue(&id, &p).map_err(|e| e.to_string())?;
            write(&a.out, &env, true)?;
            println!("{}", hex::encode(p.id));
            eprintln!(
                "attested {} for {} as {} (id above, {} bytes)",
                short(&p.claim),
                subject,
                id.agent_id(),
                env.len()
            );
        }
        Cmd::Srl(a) => {
            let id = load_identity(&a.key)?;
            let now = now_secs();
            let issued = a.issued_at.unwrap_or(now);
            let revoked_at = a.revoked_at.unwrap_or(now);
            let mut revoked: Vec<RevocationEntry> = Vec::new();
            let mut sequence = 1;
            if let Some(prev) = &a.prev {
                let raw = read(prev)?;
                let old = srl::load(&raw, &srl::LoadContext::bundles(&[]), now)
                    .map_err(|e| format!("{}: {e}", prev.display()))?;
                if old.issuer != id.agent_id() {
                    return Err(format!(
                        "{} belongs to {}, not to this key",
                        prev.display(),
                        old.issuer
                    ));
                }
                sequence = old.sequence + 1;
                revoked = old.revoked;
            }
            if let Some(s) = a.sequence {
                sequence = s;
            }
            for t in &a.attestations {
                let aid = attestation_id(t)?;
                revoked.push(RevocationEntry {
                    id: RevokedId::Attestation(aid),
                    reason: a.reason.clone().unwrap_or_else(|| "withdrawn".into()),
                    revoked_at,
                });
            }
            for t in &a.identities {
                let who = AgentId::parse(t).map_err(|e| format!("--identity {t}: {e}"))?;
                revoked.push(RevocationEntry {
                    id: RevokedId::Identity(who),
                    reason: a.reason.clone().unwrap_or_else(|| "compromised".into()),
                    revoked_at,
                });
            }
            let mut seen = Vec::new();
            revoked.retain(|e| {
                let dup = seen.contains(&e.id);
                seen.push(e.id);
                !dup
            });
            let s = Srl {
                issuer: id.agent_id(),
                sequence,
                issued_at: issued,
                next_update: issued + a.valid_for,
                revoked,
            };
            let mut nonce = [0u8; 16];
            fill_random(&mut nonce).map_err(|e| e.to_string())?;
            let env = srl::create(&id, &s, nonce, SignMode::Hedged, !a.no_bundle)
                .map_err(|e| e.to_string())?;
            write(&a.out, &env, true)?;
            eprintln!(
                "SRL sequence {} for {} with {} entries ({} bytes), next update {}",
                s.sequence,
                id.agent_id(),
                s.revoked.len(),
                env.len(),
                s.next_update
            );
        }
        Cmd::Chain(a) => {
            let raw = read(&a.input)?;
            let recipient = a.key.as_deref().map(load_identity).transpose()?;
            let now = a.now.unwrap_or_else(now_secs);
            let setup = setup_trust(&a.trust, &[], now)?;
            let mut pol = Policy {
                recipient: recipient.as_ref(),
                trust: setup.trust.or_else(|| Some(TrustPolicy::default())),
                attestations: setup.attestations,
                ..Policy::default()
            };
            pol.srls = setup.cache.as_deref();
            // An attestation file: show the chain of its own claim.
            let as_attestation = SignedEnvelope::decode(&raw).ok().and_then(|e| {
                (e.headers.content_type == CT_ATTESTATION)
                    .then_some(e.payload)
                    .flatten()
                    .and_then(|p| Attestation::from_payload(&p).ok())
            });
            let result: Result<Verified, atep_core::error::Rejection> = match as_attestation {
                Some(att) => {
                    let tp = pol.trust.clone().unwrap_or_default();
                    trust::evaluate(
                        &pol,
                        &tp,
                        Step9Input {
                            signer: att.subject,
                            inline: vec![raw.clone()],
                            requirements: vec![vec![vec![Rule::new(&att.claim)]]],
                            relax_expiry: false,
                            srl: tp.srl,
                        },
                        now,
                    )
                    .map(|o| Verified {
                        signer: att.subject,
                        content_type: CT_ATTESTATION.to_string(),
                        issued_at: 0,
                        expires_at: None,
                        nonce: [0; 16],
                        encrypted: false,
                        claims: o.claims,
                        checkpoint: o.checkpoint,
                        command_class: None,
                        warnings: o.warnings,
                        payload: Vec::new(),
                    })
                }
                None => verify(&raw, &pol, now),
            };
            if a.json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json::verify_result(&result)).unwrap()
                );
            }
            match result {
                Ok(v) => {
                    if !a.json {
                        println!("subject:      {}", v.signer);
                        print_claims(&v);
                        if v.claims.is_empty() {
                            println!("no claims were required by the policy");
                        }
                    }
                }
                Err(r) => {
                    if !a.json {
                        eprintln!(
                            "NO CHAIN at step {} ({}): {}",
                            r.step,
                            r.code.as_str(),
                            r.detail
                        );
                        if let Some(c) = &r.cause {
                            eprintln!(
                                "  caused by step {} ({}): {}",
                                c.step,
                                c.code.as_str(),
                                c.detail
                            );
                        }
                    }
                    return Ok(ExitCode::from(1));
                }
            }
        }
        Cmd::Encrypt(a) => {
            let env = read(&a.input)?;
            let to = load_bundle(&a.to)?;
            if to.enc.is_none() {
                return Err(format!(
                    "{} has no encryption keys; the recipient must generate keys without --no-enc",
                    a.to.display()
                ));
            }
            let out = atep_core::encrypt::encrypt_random(&env, &to).map_err(|e| e.to_string())?;
            write(&a.out, &out, true)?;
            eprintln!("encrypted to {} ({} bytes)", to.agent_id(), out.len());
        }
        Cmd::Decrypt(a) => {
            let env = read(&a.input)?;
            let id = load_identity(&a.key)?;
            let inner = atep_core::decrypt(&env, &id).map_err(|e| e.to_string())?;
            write(&a.out, &inner, true)?;
            eprintln!("decrypted for {} ({} bytes)", id.agent_id(), inner.len());
        }
        Cmd::View(a) => {
            let data = read(&a.file)?;
            let j = json::view(&data).map_err(|e| e.to_string())?;
            println!("{}", serde_json::to_string_pretty(&j).unwrap());
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
