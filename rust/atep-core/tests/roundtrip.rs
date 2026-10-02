use atep_core::consts::*;
use atep_core::envelope::{sign, SignMode, SignParams};
use atep_core::keys::{Identity, Seeds};
use atep_core::{decrypt, encrypt, verify, EncryptRandomness, ErrorCode, Policy};

fn ident(n: u8, enc: bool) -> Identity {
    Identity::from_seeds(Seeds {
        ed25519: [n; 32],
        mldsa65: [n + 1; 32],
        x25519: enc.then_some([n + 2; 32]),
        mlkem768: enc.then_some([n + 3; 64]),
    })
    .unwrap()
}

#[test]
fn sign_and_verify_trust_doc() {
    let a = ident(1, false);
    let mut p = SignParams::new(b"hello", CT_ATTESTATION, [7; 16], 1_000);
    p.expires_at = Some(2_000);
    p.mode = SignMode::Deterministic;
    let env = sign(&a, &p).unwrap();
    let v = verify(&env, &Policy::default(), 1_500).unwrap();
    assert_eq!(v.signer, a.agent_id());
    assert_eq!(v.payload, b"hello");
    let again = sign(&a, &p).unwrap();
    assert_eq!(env, again);
}

#[test]
fn hedged_signatures_still_verify() {
    let a = ident(1, false);
    let mut p = SignParams::new(b"hello", CT_SRL, [7; 16], 1_000);
    p.mode = SignMode::Hedged;
    let e1 = sign(&a, &p).unwrap();
    let e2 = sign(&a, &p).unwrap();
    assert_ne!(e1, e2);
    verify(&e1, &Policy::default(), 1_000).unwrap();
}

#[test]
fn encrypted_round_trip() {
    let a = ident(1, false);
    let b = ident(10, true);
    let mut p = SignParams::new(b"secret cmd", CT_DATA, [9; 16], 1_000);
    p.mode = SignMode::Deterministic;
    let signed = sign(&a, &p).unwrap();
    let rnd = EncryptRandomness {
        x25519_ephemeral: [5; 32],
        mlkem_m: [6; 32],
        iv: [7; 12],
    };
    let ct = encrypt(&signed, b.public(), &rnd).unwrap();
    assert_eq!(decrypt(&ct, &b).unwrap(), signed);
    let pol = Policy {
        recipient: Some(&b),
        ..Policy::default()
    };
    let v = verify(&ct, &pol, 1_000).unwrap();
    assert!(v.encrypted);
    // wrong recipient and no recipient
    let c = ident(20, true);
    let pol_c = Policy {
        recipient: Some(&c),
        ..Policy::default()
    };
    assert_eq!(verify(&ct, &pol_c, 1_000).unwrap_err().step, 2);
    assert_eq!(verify(&ct, &Policy::default(), 1_000).unwrap_err().step, 2);
    // unencrypted data envelope is refused
    let e = verify(&signed, &Policy::default(), 1_000).unwrap_err();
    assert_eq!(
        (e.step, e.code),
        (1, ErrorCode::UnencryptedNonTrustDocument)
    );
}

#[test]
fn single_signature_and_tampering_rejected() {
    use atep_core::cbor::Value;
    let a = ident(1, false);
    let mut p = SignParams::new(b"x", CT_SRL, [1; 16], 1_000);
    p.mode = SignMode::Deterministic;
    let env = sign(&a, &p).unwrap();
    // drop the ML-DSA signature
    let mut v = Value::decode(&env).unwrap();
    if let Value::Tag(_, inner) = &mut v {
        if let Value::Array(arr) = inner.as_mut() {
            if let Value::Array(sigs) = &mut arr[3] {
                sigs.truncate(1);
            }
        }
    }
    let e = verify(&v.encode(), &Policy::default(), 1_000).unwrap_err();
    assert_eq!((e.step, e.code), (1, ErrorCode::SignatureCountInvalid));
    // flip a bit in the middle of the envelope bytes
    let mut bad = env.clone();
    let mid = bad.len() / 2;
    bad[mid] ^= 0x40;
    assert!(verify(&bad, &Policy::default(), 1_000).is_err());
    // trailing garbage is rejected as malformed CBOR
    let mut trail = env;
    trail.push(0);
    let e = verify(&trail, &Policy::default(), 1_000).unwrap_err();
    assert_eq!((e.step, e.code), (1, ErrorCode::MalformedCbor));
}

#[test]
fn sizes_match_spec() {
    let a = ident(1, false);
    let payload = vec![0u8; 1024];
    let mut p = SignParams::new(&payload, CT_SRL, [1; 16], 1_000);
    p.include_bundle = false;
    p.mode = SignMode::Deterministic;
    let env = sign(&a, &p).unwrap();
    // spec section 5: roughly 4.5 KB for a 1 KB payload
    assert!(env.len() > 4_300 && env.len() < 4_800, "{}", env.len());
    assert_eq!(a.public().mldsa65.len(), 1952);
}
