//! Domain binding check: what a `domain-control` issuer verifies before it
//! issues the attestation (spec section 4, "Domain records"; section 7,
//! "Checking a domain binding").
//!
//! The record parsers, the [`DomainFetcher`] trait and
//! [`check_domain_binding`] are in `atep_core::domain` (they have no network
//! code and the domain binding vectors run them); this module re-exports them
//! and adds a small `std::net` fetcher behind the `net-fetch` feature. The
//! result is evidence for the issuer, not for a verifier: the log cannot see
//! DNS, so a verifier still trusts the issuer's `domain-control` attestation,
//! and monitors watch for mis-issuance (spec section 9).

pub use atep_core::domain::*;

#[cfg(feature = "net-fetch")]
pub mod net {
    //! A small fetcher on `std::net`. It speaks plain HTTP only, because the
    //! standard library has no TLS, and has no DNS client, so it can serve
    //! lab setups and deployments that reach the domain through a local TLS
    //! terminating proxy (`base` names the proxy, for example
    //! `http://127.0.0.1:8081`, and the `Host` header carries the domain). A
    //! production issuer plugs in a fetcher with real HTTPS and DNSSEC aware
    //! DNS. It never follows redirects.

    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use super::{DomainFetcher, FetchError, TxtAnswer, WellKnownResponse, MAX_DOC_BYTES};

    pub struct StdHttpFetcher {
        /// `host:port` of the proxy that serves every domain.
        pub proxy: String,
        pub timeout: Duration,
    }

    impl StdHttpFetcher {
        pub fn new(proxy: &str) -> StdHttpFetcher {
            StdHttpFetcher {
                proxy: proxy.to_string(),
                timeout: Duration::from_secs(10),
            }
        }
    }

    impl DomainFetcher for StdHttpFetcher {
        fn fetch_well_known(&self, domain: &str) -> Result<WellKnownResponse, FetchError> {
            let un = |e: std::io::Error| FetchError::Unavailable(e.to_string());
            let mut s = TcpStream::connect(&self.proxy).map_err(un)?;
            s.set_read_timeout(Some(self.timeout)).map_err(un)?;
            s.set_write_timeout(Some(self.timeout)).map_err(un)?;
            let req = format!(
                "GET /.well-known/atep.json HTTP/1.1\r\nHost: {domain}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).map_err(un)?;
            let mut buf = Vec::new();
            s.take(MAX_DOC_BYTES as u64 + 16 * 1024)
                .read_to_end(&mut buf)
                .map_err(un)?;
            let end = buf
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .ok_or_else(|| FetchError::Unavailable("malformed response".into()))?;
            let head = String::from_utf8_lossy(&buf[..end]).into_owned();
            let mut lines = head.split("\r\n");
            let status = lines
                .next()
                .and_then(|l| l.split(' ').nth(1))
                .and_then(|c| c.parse::<u16>().ok())
                .ok_or_else(|| FetchError::Unavailable("malformed status line".into()))?;
            let content_type = lines.find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-type")
                    .then(|| v.trim().to_string())
            });
            Ok(WellKnownResponse {
                status,
                final_url: super::well_known_url(domain),
                content_type,
                body: buf[end + 4..].to_vec(),
            })
        }

        fn fetch_txt(&self, _name: &str) -> Result<TxtAnswer, FetchError> {
            Err(FetchError::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::ident;
    use atep_core::keys::AgentId;
    use serde_json::Value as J;
    use std::cell::RefCell;

    /// A fake fetcher with canned answers and a call log.
    struct Fake {
        wk: Result<WellKnownResponse, FetchError>,
        txt: Result<TxtAnswer, FetchError>,
        calls: RefCell<Vec<String>>,
    }

    fn json_ok(domain: &str, body: &J) -> Result<WellKnownResponse, FetchError> {
        Ok(WellKnownResponse {
            status: 200,
            final_url: well_known_url(domain),
            content_type: Some("application/json; charset=utf-8".into()),
            body: serde_json::to_vec(body).unwrap(),
        })
    }

    fn txt_ok(records: &[String], dnssec: bool) -> Result<TxtAnswer, FetchError> {
        Ok(TxtAnswer {
            records: records.to_vec(),
            dnssec_validated: dnssec,
        })
    }

    impl DomainFetcher for Fake {
        fn fetch_well_known(&self, domain: &str) -> Result<WellKnownResponse, FetchError> {
            self.calls.borrow_mut().push(format!("wk {domain}"));
            self.wk.clone()
        }
        fn fetch_txt(&self, name: &str) -> Result<TxtAnswer, FetchError> {
            self.calls.borrow_mut().push(format!("txt {name}"));
            self.txt.clone()
        }
    }

    fn fake(wk: Result<WellKnownResponse, FetchError>, txt: Result<TxtAnswer, FetchError>) -> Fake {
        Fake {
            wk,
            txt,
            calls: RefCell::new(Vec::new()),
        }
    }

    const D: &str = "example.com";

    fn agent(n: u8) -> AgentId {
        ident(n).agent_id()
    }

    #[test]
    fn well_known_lists_the_agent() {
        let doc = well_known_document(
            &[agent(1), agent(2)],
            Some("https://example.com/s"),
            1_790_000_000,
        );
        let f = fake(json_ok(D, &doc), Err(FetchError::NotFound));
        let r = check_domain_binding(D, &agent(2), &f);
        assert_eq!(r.outcome, Outcome::Bound);
        assert_eq!(r.well_known, SourceResult::Listed);
        assert_eq!(r.dns, SourceResult::Absent);
        assert_eq!(r.updated, Some(1_790_000_000));
        assert_eq!(r.srl_url.as_deref(), Some("https://example.com/s"));
        assert_eq!(
            *f.calls.borrow(),
            vec!["wk example.com", "txt _atep.example.com"]
        );
        // Another agent is not bound.
        let r = check_domain_binding(D, &agent(3), &f);
        assert_eq!(r.outcome, Outcome::NotBound);
        assert_eq!(r.well_known, SourceResult::NotListed);
    }

    #[test]
    fn did_form_in_the_document_counts() {
        let did = agent(1).to_text().replace("atep:", "did:atep:");
        let doc = serde_json::json!({"version": 1, "agents": [did]});
        let f = fake(json_ok(D, &doc), Err(FetchError::NotFound));
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::Bound
        );
    }

    #[test]
    fn txt_records_union_and_unrelated_records_ignored() {
        let recs = vec![
            "google-site-verification=abc".to_string(),
            txt_record(&[agent(1)]),
            format!(
                "{TXT_VERSION_TERM} id={} id={} foo=bar srl=https://example.com/s",
                agent(2).to_text(),
                agent(3).to_text()
            ),
        ];
        let f = fake(Err(FetchError::NotFound), txt_ok(&recs, true));
        for n in [1, 2, 3] {
            let r = check_domain_binding(D, &agent(n), &f);
            assert_eq!(r.outcome, Outcome::Bound, "agent {n}");
            assert_eq!(r.dns, SourceResult::Listed);
            assert!(r.warnings.is_empty());
        }
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).srl_url.as_deref(),
            Some("https://example.com/s")
        );
        assert_eq!(
            check_domain_binding(D, &agent(4), &f).outcome,
            Outcome::NotBound
        );
    }

    #[test]
    fn txt_without_atep_records_is_absent() {
        let f = fake(
            Err(FetchError::NotFound),
            txt_ok(&["v=spf1 -all".to_string()], false),
        );
        let r = check_domain_binding(D, &agent(1), &f);
        assert_eq!(r.dns, SourceResult::Absent);
        assert_eq!(r.outcome, Outcome::NotBound);
    }

    #[test]
    fn dnssec_warning_and_requirement() {
        let recs = vec![txt_record(&[agent(1)])];
        let f = fake(Err(FetchError::NotFound), txt_ok(&recs, false));
        let r = check_domain_binding(D, &agent(1), &f);
        assert_eq!(r.outcome, Outcome::Bound);
        assert_eq!(r.warnings.len(), 1);
        let r = check_domain_binding_with(
            D,
            &agent(1),
            &f,
            BindingOptions {
                require_dnssec: true,
                ..Default::default()
            },
        );
        assert_eq!(r.outcome, Outcome::NotBound);
        assert!(matches!(r.dns, SourceResult::Invalid(_)));
    }

    #[test]
    fn failures_follow_the_rules() {
        // Unavailable source and nothing else listing: indeterminate.
        let f = fake(
            Err(FetchError::Unavailable("timeout".into())),
            Err(FetchError::NotFound),
        );
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::Indeterminate
        );
        // Unavailable source but the other lists the agent: bound.
        let recs = vec![txt_record(&[agent(1)])];
        let f = fake(
            Err(FetchError::Unavailable("5xx".into())),
            txt_ok(&recs, true),
        );
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::Bound
        );
        // Unavailable plus a valid source that does not list the agent: indeterminate.
        let f = fake(
            Err(FetchError::Unavailable("5xx".into())),
            txt_ok(&recs, true),
        );
        assert_eq!(
            check_domain_binding(D, &agent(2), &f).outcome,
            Outcome::Indeterminate
        );
        // Nothing anywhere: not bound.
        let f = fake(Err(FetchError::NotFound), Err(FetchError::NotFound));
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::NotBound
        );
    }

    #[test]
    fn sources_that_disagree_fail_closed() {
        let doc = well_known_document(&[agent(2)], None, 1);
        let recs = vec![txt_record(&[agent(1)])];
        let f = fake(json_ok(D, &doc), txt_ok(&recs, true));
        let r = check_domain_binding(D, &agent(1), &f);
        assert!(r.conflict);
        assert_eq!(r.outcome, Outcome::NotBound);
        // Agreeing sources are fine, and require_both works.
        let doc = well_known_document(&[agent(1)], None, 1);
        let f = fake(json_ok(D, &doc), txt_ok(&recs, true));
        let opts = BindingOptions {
            require_both: true,
            ..Default::default()
        };
        assert_eq!(
            check_domain_binding_with(D, &agent(1), &f, opts).outcome,
            Outcome::Bound
        );
        let f = fake(json_ok(D, &doc), Err(FetchError::NotFound));
        assert_eq!(
            check_domain_binding_with(D, &agent(1), &f, opts).outcome,
            Outcome::NotBound
        );
        let f = fake(json_ok(D, &doc), Err(FetchError::Unavailable("x".into())));
        assert_eq!(
            check_domain_binding_with(D, &agent(1), &f, opts).outcome,
            Outcome::Indeterminate
        );
    }

    fn with(body: serde_json::Value, edit: impl FnOnce(&mut WellKnownResponse)) -> Fake {
        let mut r = json_ok(D, &body).unwrap();
        edit(&mut r);
        fake(Ok(r), Err(FetchError::NotFound))
    }

    #[test]
    fn well_known_transport_and_format_rules() {
        let good = serde_json::json!({"version": 1, "agents": [agent(1).to_text()]});
        // Redirect to another host.
        let f = with(good.clone(), |r| {
            r.final_url = "https://evil.example.net/.well-known/atep.json".into()
        });
        let r = check_domain_binding(D, &agent(1), &f);
        assert!(matches!(r.well_known, SourceResult::Invalid(_)));
        assert_eq!(r.outcome, Outcome::NotBound);
        // A subdomain host is not the domain either.
        let f = with(good.clone(), |r| {
            r.final_url = "https://www.example.com/.well-known/atep.json".into()
        });
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Invalid(_)
        ));
        // Plain http.
        let f = with(good.clone(), |r| {
            r.final_url = "http://example.com/.well-known/atep.json".into()
        });
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Invalid(_)
        ));
        // Content type.
        let f = with(good.clone(), |r| r.content_type = Some("text/html".into()));
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Invalid(_)
        ));
        // Redirect status left unfollowed.
        let f = with(good.clone(), |r| r.status = 301);
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Invalid(_)
        ));
        // 404 and 5xx.
        let f = with(good.clone(), |r| r.status = 404);
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Absent
        );
        let f = with(good.clone(), |r| r.status = 503);
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Unavailable(_)
        ));
        // Oversize.
        let f = with(good.clone(), |r| r.body = vec![b' '; MAX_DOC_BYTES + 1]);
        assert!(matches!(
            check_domain_binding(D, &agent(1), &f).well_known,
            SourceResult::Invalid(_)
        ));
        // Version, domain member, shape.
        for bad in [
            serde_json::json!({"version": 2, "agents": []}),
            serde_json::json!({"agents": [agent(1).to_text()]}),
            serde_json::json!({"version": 1, "domain": "other.com", "agents": [agent(1).to_text()]}),
            serde_json::json!({"version": 1, "agents": "atep:x"}),
            serde_json::json!([1]),
        ] {
            let f = with(bad, |_| {});
            let r = check_domain_binding(D, &agent(1), &f);
            assert!(matches!(r.well_known, SourceResult::Invalid(_)), "{r:?}");
            assert_eq!(r.outcome, Outcome::NotBound);
        }
        // The domain member may match.
        let f = with(
            serde_json::json!({"version": 1, "domain": D, "agents": [agent(1).to_text()]}),
            |_| {},
        );
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::Bound
        );
    }

    #[test]
    fn junk_entries_are_ignored_and_reported() {
        let doc = serde_json::json!({"version": 1, "agents": ["nope", 7, agent(1).to_text()], "srl-url": "http://x"});
        let f = fake(json_ok(D, &doc), Err(FetchError::NotFound));
        let r = check_domain_binding(D, &agent(1), &f);
        assert_eq!(r.outcome, Outcome::Bound);
        assert_eq!(r.warnings.len(), 2);
        assert!(r.srl_url.is_none());
    }

    #[test]
    fn subdomains_are_checked_by_their_own_name() {
        let f = fake(Err(FetchError::NotFound), Err(FetchError::NotFound));
        check_domain_binding("a.example.com", &agent(1), &f);
        assert_eq!(
            *f.calls.borrow(),
            vec!["wk a.example.com", "txt _atep.a.example.com"]
        );
    }

    #[test]
    fn bad_domain_names_are_refused_before_any_fetch() {
        let f = fake(Err(FetchError::NotFound), Err(FetchError::NotFound));
        for d in ["Example.com", "example.com.", "-a.com", "a b.com", ""] {
            let r = check_domain_binding(d, &agent(1), &f);
            assert_eq!(r.outcome, Outcome::NotBound, "{d}");
        }
        assert!(f.calls.borrow().is_empty());
    }

    #[test]
    fn txt_limits() {
        let long = format!(
            "{TXT_VERSION_TERM} id={} {}",
            agent(1).to_text(),
            "x".repeat(MAX_TXT_BYTES)
        );
        let f = fake(Err(FetchError::NotFound), txt_ok(&[long], true));
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).dns,
            SourceResult::Absent
        );
        // Only the first 16 records are read.
        let mut recs: Vec<String> = (0..MAX_TXT_RECORDS).map(|_| "junk".to_string()).collect();
        recs.push(txt_record(&[agent(1)]));
        let f = fake(Err(FetchError::NotFound), txt_ok(&recs, true));
        assert_eq!(
            check_domain_binding(D, &agent(1), &f).outcome,
            Outcome::NotBound
        );
        // Three Agent IDs fit in one 255 byte character-string.
        assert!(txt_record(&[agent(1), agent(2), agent(3)]).len() <= 255);
    }

    #[cfg(feature = "net-fetch")]
    #[test]
    fn std_http_fetcher_reads_a_local_proxy() {
        use std::io::{Read, Write};
        let doc = serde_json::to_string(&well_known_document(&[agent(1)], None, 5)).unwrap();
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        let t = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            let mut b = [0u8; 1024];
            let n = s.read(&mut b).unwrap();
            let req = String::from_utf8_lossy(&b[..n]).into_owned();
            assert!(req.starts_with("GET /.well-known/atep.json HTTP/1.1"));
            assert!(req.contains("Host: example.com"));
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{doc}",
                doc.len()
            );
            s.write_all(resp.as_bytes()).unwrap();
        });
        let fetcher = net::StdHttpFetcher::new(&addr);
        let r = check_domain_binding(D, &agent(1), &fetcher);
        t.join().unwrap();
        assert_eq!(r.well_known, SourceResult::Listed);
        assert_eq!(r.outcome, Outcome::Bound);
    }
}
