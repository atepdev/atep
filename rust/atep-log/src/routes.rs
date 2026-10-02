//! The route table: the one list of HTTP routes the server implements.
//!
//! [`resolve`] maps a request to a [`RouteId`], the router in `http.rs`
//! dispatches on that enum (so a route without a handler does not compile),
//! and `openapi.rs` builds `GET /openapi.json` from [`ROUTES`] (and has an
//! exhaustive `match` over [`RouteId`], so a route without documentation does
//! not compile either). Tests check the table against the served document and
//! the checked in copy `docs/openapi.json`.

use crate::http::percent_decode;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RouteId {
    Index,
    OpenApi,
    Submit,
    CheckpointGet,
    CheckpointPost,
    Checkpoints,
    ProofInclusion,
    ProofConsistency,
    Entries,
    Lookup,
    Issuers,
    ClaimsDirectory,
    ClaimResolve,
    Policy,
    GossipGet,
    GossipPost,
    ClaimsIndex,
    ClaimRobotics,
    ClaimCore,
}

#[derive(Clone, Copy, Debug)]
pub struct Route {
    pub id: RouteId,
    /// Upper case. `HEAD` is answered for every `GET` route and not listed.
    pub method: &'static str,
    /// OpenAPI path template. `{claim}` is a tail parameter: it takes the
    /// rest of the path, so a percent-encoded or a plain URI both match.
    pub path: &'static str,
}

const fn r(id: RouteId, method: &'static str, path: &'static str) -> Route {
    Route { id, method, path }
}

/// Every route, most specific first.
pub const ROUTES: [Route; 19] = [
    r(RouteId::Index, "GET", "/"),
    r(RouteId::OpenApi, "GET", "/openapi.json"),
    r(RouteId::Submit, "POST", "/v1/submit"),
    r(RouteId::CheckpointGet, "GET", "/v1/checkpoint"),
    r(RouteId::CheckpointPost, "POST", "/v1/checkpoint"),
    r(RouteId::Checkpoints, "GET", "/v1/checkpoints"),
    r(RouteId::ProofInclusion, "GET", "/v1/proof/inclusion"),
    r(RouteId::ProofConsistency, "GET", "/v1/proof/consistency"),
    r(RouteId::Entries, "GET", "/v1/entries"),
    r(RouteId::Lookup, "GET", "/v1/lookup"),
    r(RouteId::Issuers, "GET", "/v1/issuers"),
    r(RouteId::ClaimsDirectory, "GET", "/v1/claims"),
    r(RouteId::ClaimResolve, "GET", "/v1/claims/{claim}"),
    r(RouteId::Policy, "GET", "/v1/policy"),
    r(RouteId::GossipGet, "GET", "/v1/gossip"),
    r(RouteId::GossipPost, "POST", "/v1/gossip"),
    r(RouteId::ClaimsIndex, "GET", "/claims"),
    r(RouteId::ClaimRobotics, "GET", "/claims/robotics/{name}"),
    r(RouteId::ClaimCore, "GET", "/claims/{name}"),
];

/// Path parameters of a resolved route, percent-decoded.
pub type Params = Vec<(&'static str, String)>;

fn param_name(seg: &'static str) -> Option<&'static str> {
    seg.strip_prefix('{').and_then(|s| s.strip_suffix('}'))
}

fn match_path(template: &'static str, path: &str) -> Option<Params> {
    let t: Vec<&'static str> = template.split('/').collect();
    let p: Vec<&str> = path.split('/').collect();
    let mut params = Vec::new();
    for (i, seg) in t.iter().enumerate() {
        let tail = i + 1 == t.len() && *seg == "{claim}";
        if tail {
            let rest = p.get(i..)?.join("/");
            if rest.is_empty() {
                return None;
            }
            params.push(("claim", percent_decode(&rest)));
            return Some(params);
        }
        let got = p.get(i)?;
        match param_name(seg) {
            Some(name) => {
                if got.is_empty() {
                    return None;
                }
                params.push((name, percent_decode(got)));
            }
            None if seg == got => {}
            None => return None,
        }
    }
    (t.len() == p.len()).then_some(params)
}

/// Find the route of a request. `HEAD` resolves like `GET`.
pub fn resolve(method: &str, path: &str) -> Option<(RouteId, Params)> {
    let method = if method == "HEAD" { "GET" } else { method };
    let path = if path.len() > 1 && path.starts_with("/claims") {
        path.trim_end_matches('/')
    } else {
        path
    };
    ROUTES
        .iter()
        .filter(|rt| rt.method == method)
        .find_map(|rt| match_path(rt.path, path).map(|p| (rt.id, p)))
}

/// Fill the templates of a route with sample values (for tests).
pub fn sample_path(route: &Route) -> String {
    route
        .path
        .replace("{claim}", "audited")
        .replace("{name}", "audited")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_static_and_params() {
        assert_eq!(resolve("GET", "/").unwrap().0, RouteId::Index);
        assert_eq!(resolve("HEAD", "/v1/policy").unwrap().0, RouteId::Policy);
        assert!(resolve("DELETE", "/v1/policy").is_none());
        assert!(resolve("POST", "/v1/policy").is_none());
        let (id, p) = resolve("GET", "/claims/robotics/peer-motion").unwrap();
        assert_eq!(id, RouteId::ClaimRobotics);
        assert_eq!(p, vec![("name", "peer-motion".to_string())]);
        assert_eq!(
            resolve("GET", "/claims/audited").unwrap().0,
            RouteId::ClaimCore
        );
        assert_eq!(resolve("GET", "/claims/").unwrap().0, RouteId::ClaimsIndex);
        assert!(resolve("GET", "/claims/a/b/c").is_none());
    }

    #[test]
    fn claim_tail_takes_encoded_and_plain_uris() {
        let enc = "/v1/claims/https%3A%2F%2Fatep.dev%2Fclaims%2Faudited";
        let (id, p) = resolve("GET", enc).unwrap();
        assert_eq!(id, RouteId::ClaimResolve);
        assert_eq!(p[0].1, "https://atep.dev/claims/audited");
        let (_, p) = resolve("GET", "/v1/claims/https://atep.dev/claims/audited").unwrap();
        assert_eq!(p[0].1, "https://atep.dev/claims/audited");
        assert!(resolve("GET", "/v1/claims/").is_none());
    }

    #[test]
    fn table_has_no_duplicates() {
        for (i, a) in ROUTES.iter().enumerate() {
            for b in &ROUTES[i + 1..] {
                assert!(a.id != b.id, "{:?} twice", a.id);
                assert!(!(a.method == b.method && a.path == b.path));
            }
        }
    }
}
