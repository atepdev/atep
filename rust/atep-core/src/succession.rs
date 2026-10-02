//! Succession chains in a log (spec section 9, monitor alert `successor_chain`).
//!
//! A verifier follows exactly one hop of succession (section 7), so a chain of
//! two or more hops is something a monitor should tell the operator about: the
//! verifier will never inherit across it. The finder is a pure function of the
//! logged `successor` attestations so that the reference monitor and the
//! vector checker share it.

use crate::keys::AgentId;

/// A logged `successor` attestation: its entry index, issuer (the old
/// identity) and subject (the new identity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuccessorLink {
    pub entry: u64,
    pub issuer: AgentId,
    pub subject: AgentId,
}

/// The links that make a chain of two or more hops: those whose `issuer` is
/// itself the `subject` of another logged `successor` attestation (the later
/// link of the chain). In entry order. A link whose subject equals its issuer
/// is not a succession and is ignored. A single hop yields nothing.
pub fn chain_links(links: &[SuccessorLink]) -> Vec<SuccessorLink> {
    let mut out: Vec<SuccessorLink> = links
        .iter()
        .filter(|l| l.issuer != l.subject)
        .filter(|l| {
            links
                .iter()
                .any(|k| k.entry != l.entry && k.issuer != k.subject && k.subject == l.issuer)
        })
        .copied()
        .collect();
    out.sort_by_key(|l| l.entry);
    out.dedup_by_key(|l| l.entry);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(n: u8) -> AgentId {
        AgentId([n; 32])
    }

    fn link(entry: u64, from: u8, to: u8) -> SuccessorLink {
        SuccessorLink {
            entry,
            issuer: id(from),
            subject: id(to),
        }
    }

    #[test]
    fn one_hop_is_not_a_chain() {
        assert!(chain_links(&[link(0, 1, 2)]).is_empty());
        // Two unrelated rotations.
        assert!(chain_links(&[link(0, 1, 2), link(1, 3, 4)]).is_empty());
        // One identity naming two successors is a fork, not a chain.
        assert!(chain_links(&[link(0, 1, 2), link(1, 1, 3)]).is_empty());
    }

    #[test]
    fn the_later_link_is_reported_whatever_the_log_order() {
        let a = link(0, 1, 2);
        let b = link(1, 2, 3);
        assert_eq!(chain_links(&[a, b]), vec![b]);
        // Logged in the other order: still the link whose issuer is a subject.
        let a = link(1, 1, 2);
        let b = link(0, 2, 3);
        assert_eq!(chain_links(&[b, a]), vec![b]);
        // Three hops: the second and third links.
        let c = link(2, 3, 4);
        assert_eq!(chain_links(&[link(0, 1, 2), link(1, 2, 3), c]).len(), 2);
    }

    #[test]
    fn a_self_succession_is_ignored() {
        assert!(chain_links(&[link(0, 1, 1), link(1, 1, 2)]).is_empty());
    }
}
