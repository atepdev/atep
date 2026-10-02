//! ATEP-R enforcement (spec section 17): command classes, the minimum claims
//! table, the e-stop rule and the fail-safe revocation behavior.
//!
//! Enabled by `TrustPolicy::atep_r`. [`crate::verify::verify`] then requires
//! sign-then-encrypt, a valid `command-class` header (-70014) and the claims of
//! the class, in addition to the ordinary rules of the policy.

use crate::attestation::claims::robotics as rc;
use crate::cbor::Value;
use crate::error::Rejection;
use crate::keys::AgentId;
use crate::srl::SrlPolicy;
use crate::trust::Rule;
use crate::verify::{verify, Policy, Verified};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommandClass {
    Telemetry,
    Sensor,
    Coordination,
    Motion,
    Actuation,
    Safety,
    Maintenance,
}

impl CommandClass {
    pub const ALL: [CommandClass; 7] = [
        CommandClass::Telemetry,
        CommandClass::Sensor,
        CommandClass::Coordination,
        CommandClass::Motion,
        CommandClass::Actuation,
        CommandClass::Safety,
        CommandClass::Maintenance,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            CommandClass::Telemetry => "telemetry",
            CommandClass::Sensor => "sensor",
            CommandClass::Coordination => "coordination",
            CommandClass::Motion => "motion",
            CommandClass::Actuation => "actuation",
            CommandClass::Safety => "safety",
            CommandClass::Maintenance => "maintenance",
        }
    }

    pub fn parse(s: &str) -> Option<CommandClass> {
        CommandClass::ALL.into_iter().find(|c| c.as_str() == s)
    }

    /// Motion, actuation and maintenance fail closed on a stale or missing SRL.
    /// Telemetry, sensor and coordination may continue with a warning, as may
    /// an e-stop. Non e-stop safety commands (geofence changes) fail closed:
    /// the spec names only motion and actuation, the rest is provisional.
    fn fails_closed(self, estop: bool) -> bool {
        match self {
            CommandClass::Motion | CommandClass::Actuation | CommandClass::Maintenance => true,
            CommandClass::Safety => !estop,
            _ => false,
        }
    }
}

/// An e-stop is a `safety` payload that is a CBOR map with `command` equal to
/// `"e-stop"`. The spec does not say how an e-stop is recognized (see
/// docs/implementation-findings/rust-findings.md); anything else is treated as an ordinary safety command.
pub fn is_estop(payload: &[u8]) -> bool {
    Value::decode(payload)
        .ok()
        .and_then(|v| {
            v.as_map()?
                .iter()
                .find(|(k, _)| k.as_text() == Some("command"))
                .and_then(|(_, v)| v.as_text().map(|t| t == "e-stop"))
        })
        .unwrap_or(false)
}

/// What a class demands: alternatives of rule sets, plus how to treat expiry
/// and stale revocation lists.
#[derive(Debug)]
pub struct Requirements {
    pub groups: Vec<Vec<Rule>>,
    pub relax_expiry: bool,
    pub srl: SrlPolicy,
}

/// The minimum-claims table of section 17. `local` is the receiving agent,
/// needed to evaluate `peer-motion` delegations.
pub fn requirements(class: CommandClass, estop: bool, local: Option<AgentId>) -> Requirements {
    let one = |c: &str| vec![Rule::new(c)];
    let mut relax_expiry = false;
    let groups = match class {
        CommandClass::Telemetry | CommandClass::Coordination => vec![one(rc::FLEET_MEMBER)],
        CommandClass::Sensor => vec![vec![
            Rule::new(rc::FLEET_MEMBER),
            Rule::new(rc::SENSOR_SOURCE),
        ]],
        CommandClass::Motion => {
            let mut g = vec![one(rc::FLEET_CONTROLLER)];
            if let Some(me) = local {
                let mut peer = Rule::new(rc::PEER_MOTION);
                peer.data_contains = Some(("peers".to_string(), Value::bytes(&me.0)));
                g.push(vec![Rule::new(rc::FLEET_MEMBER), peer]);
            }
            g
        }
        CommandClass::Actuation => vec![vec![
            Rule::new(rc::FLEET_CONTROLLER),
            Rule::new(rc::SAFETY_CERTIFIED),
        ]],
        CommandClass::Safety if estop => {
            // Accepted from any fleet-member with safety-certified, even if
            // other claims have expired.
            relax_expiry = true;
            vec![
                one(rc::SAFETY_AUTHORITY),
                vec![Rule::new(rc::FLEET_MEMBER), Rule::new(rc::SAFETY_CERTIFIED)],
            ]
        }
        CommandClass::Safety => vec![one(rc::SAFETY_AUTHORITY)],
        CommandClass::Maintenance => vec![one(rc::MAINTENANCE_AUTHORITY)],
    };
    Requirements {
        groups,
        relax_expiry,
        srl: if class.fails_closed(estop) {
            SrlPolicy::STRICT
        } else {
            SrlPolicy::LENIENT
        },
    }
}

/// The receiving robot's decision.
#[derive(Debug)]
pub enum Outcome {
    /// Verified and authorized: act on the payload.
    Honor(Box<Verified>),
    /// Not verifiable: ignore the message and continue the last safe behavior.
    Ignore(Rejection),
}

/// Verify an ATEP-R envelope and turn the result into the fail-safe decision.
/// `policy.trust` must have `atep_r` set.
pub fn enforce(data: &[u8], policy: &Policy, now: i64) -> Outcome {
    match verify(data, policy, now) {
        Ok(v) => Outcome::Honor(Box::new(v)),
        Err(r) => Outcome::Ignore(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn class_names_round_trip() {
        for c in CommandClass::ALL {
            assert_eq!(CommandClass::parse(c.as_str()), Some(c));
        }
        assert_eq!(CommandClass::parse("Motion"), None);
        assert_eq!(CommandClass::parse(""), None);
    }

    #[test]
    fn estop_detection() {
        let p = Value::Map(vec![(Value::text("command"), Value::text("e-stop"))]).encode();
        assert!(is_estop(&p));
        let q = Value::Map(vec![(Value::text("command"), Value::text("geofence"))]).encode();
        assert!(!is_estop(&q));
        assert!(!is_estop(b"\xff"));
        assert!(!is_estop(&Value::Int(1).encode()));
    }

    #[test]
    fn table_shape() {
        let local = AgentId([1; 32]);
        assert_eq!(
            requirements(CommandClass::Telemetry, false, None)
                .groups
                .len(),
            1
        );
        assert_eq!(
            requirements(CommandClass::Sensor, false, None).groups[0].len(),
            2
        );
        assert_eq!(
            requirements(CommandClass::Motion, false, None).groups.len(),
            1
        );
        assert_eq!(
            requirements(CommandClass::Motion, false, Some(local))
                .groups
                .len(),
            2
        );
        assert_eq!(
            requirements(CommandClass::Actuation, false, None).groups[0].len(),
            2
        );
        let estop = requirements(CommandClass::Safety, true, None);
        assert!(estop.relax_expiry);
        assert_eq!(estop.groups.len(), 2);
        let geo = requirements(CommandClass::Safety, false, None);
        assert!(!geo.relax_expiry);
        assert_eq!(geo.groups.len(), 1);
        // fail-safe SRL handling
        assert_eq!(
            requirements(CommandClass::Motion, false, None).srl,
            SrlPolicy::STRICT
        );
        assert_eq!(
            requirements(CommandClass::Actuation, false, None).srl,
            SrlPolicy::STRICT
        );
        assert_eq!(
            requirements(CommandClass::Telemetry, false, None).srl,
            SrlPolicy::LENIENT
        );
        assert_eq!(
            requirements(CommandClass::Safety, true, None).srl,
            SrlPolicy::LENIENT
        );
    }
}
