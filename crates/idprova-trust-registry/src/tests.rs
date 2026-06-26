#![cfg(test)]

use crate::authority::TrustAuthority;
use crate::federation::{self, MerkleLog};
use crate::model::{Issuer, IssuerStatus};
use crate::resolver::{AgentRef, CrossStandardResolver, DidAidBackend};
use crate::store::{SqliteTrustStore, TrustStore};
use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use idprova_core::trust::level::TrustLevel;
use rand::rngs::OsRng;
use std::sync::Arc;

fn make_issuer(did: &str, status: IssuerStatus, claim: &str) -> Issuer {
    Issuer {
        did: did.to_string(),
        name: "Test Issuer".to_string(),
        jurisdiction: "US".to_string(),
        status,
        trust_level: TrustLevel::L2,
        credential_types: vec![claim.to_string()],
        valid_from: Utc::now() - Duration::days(1),
        valid_until: Utc::now() + Duration::days(1),
    }
}

#[test]
fn publish_and_verify_round_trip() {
    let store = SqliteTrustStore::new_in_memory().expect("Failed to create store");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer1",
            IssuerStatus::Active,
            "claim_a",
        ))
        .expect("upsert failed");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer2",
            IssuerStatus::Active,
            "claim_b",
        ))
        .expect("upsert failed");

    let authority = TrustAuthority::new(SigningKey::generate(&mut OsRng));
    let signed = authority.publish(&store).expect("Publish failed");
    let vk = authority.signing_key.verifying_key();

    assert!(TrustAuthority::verify_signed_list(&signed, &vk));
}

#[test]
fn tamper_fails_verification() {
    let store = SqliteTrustStore::new_in_memory().expect("Failed to create store");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer1",
            IssuerStatus::Active,
            "claim_a",
        ))
        .expect("upsert failed");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer2",
            IssuerStatus::Active,
            "claim_b",
        ))
        .expect("upsert failed");

    let authority = TrustAuthority::new(SigningKey::generate(&mut OsRng));
    let mut signed = authority.publish(&store).expect("Publish failed");
    let vk = authority.signing_key.verifying_key();

    signed.list.entries[0].name = "TAMPERED".into();
    assert!(!TrustAuthority::verify_signed_list(&signed, &vk));
}

#[test]
fn store_round_trip_and_filter() {
    let store = SqliteTrustStore::new_in_memory().expect("Failed to create store");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer1",
            IssuerStatus::Active,
            "claim_a",
        ))
        .expect("upsert failed");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer2",
            IssuerStatus::Active,
            "claim_b",
        ))
        .expect("upsert failed");

    let got = store
        .get_issuer("did:aid:example.com:issuer1")
        .expect("get failed");
    assert!(got.is_some());
    assert_eq!(got.unwrap().did, "did:aid:example.com:issuer1");

    assert_eq!(store.list_issuers(None).expect("list failed").len(), 2);
    assert_eq!(
        store
            .list_issuers(Some("claim_a"))
            .expect("list filter failed")
            .len(),
        1
    );
}

#[test]
fn may_attest_rules() {
    let store = SqliteTrustStore::new_in_memory().expect("Failed to create store");

    let active_did = "did:aid:example.com:active";
    store
        .upsert_issuer(&make_issuer(active_did, IssuerStatus::Active, "claim_a"))
        .expect("upsert failed");

    let suspended_did = "did:aid:example.com:suspended";
    store
        .upsert_issuer(&make_issuer(
            suspended_did,
            IssuerStatus::Suspended,
            "claim_a",
        ))
        .expect("upsert failed");

    let expired_did = "did:aid:example.com:expired";
    let mut expired_issuer = make_issuer(expired_did, IssuerStatus::Active, "claim_a");
    expired_issuer.valid_from = Utc::now() - Duration::days(2);
    expired_issuer.valid_until = Utc::now() - Duration::days(1);
    store.upsert_issuer(&expired_issuer).expect("upsert failed");

    assert!(store.may_attest(active_did, "claim_a"));
    assert!(!store.may_attest(suspended_did, "claim_a"));
    assert!(!store.may_attest(expired_did, "claim_a"));
    assert!(!store.may_attest(active_did, "claim_b"));
}

#[test]
fn merkle_inclusion() {
    let mut log = MerkleLog::new();
    let entries: Vec<Vec<u8>> = (0..5).map(|i| format!("e{}", i).into_bytes()).collect();
    for entry in &entries {
        log.append(entry);
    }
    let root = log.root();

    for i in 0..5u64 {
        let p = log.inclusion_proof(i).expect("inclusion proof failed");
        let entry_bytes = &entries[i as usize];
        let mut leaf_input = Vec::with_capacity(1 + entry_bytes.len());
        leaf_input.push(0x00u8);
        leaf_input.extend_from_slice(entry_bytes);
        let leaf = idprova_core::crypto::hash::blake3_hash_bytes(&leaf_input);

        assert!(federation::verify_inclusion(&leaf, &p, &root));
    }

    let wrong_leaf = [1u8; 32];
    let p0 = log.inclusion_proof(0).expect("inclusion proof failed");
    assert!(!federation::verify_inclusion(&wrong_leaf, &p0, &root));
}

#[test]
fn merkle_consistency() {
    let entries: Vec<Vec<u8>> = (0..7).map(|i| format!("e{}", i).into_bytes()).collect();

    let mut old_log = MerkleLog::new();
    for entry in &entries[0..3] {
        old_log.append(entry);
    }
    let old_root = old_log.root();

    let mut log = MerkleLog::new();
    for entry in &entries {
        log.append(entry);
    }
    let new_root = log.root();

    let proof = log
        .consistency_proof(3, 7)
        .expect("consistency proof failed");
    assert!(federation::verify_consistency(&old_root, &new_root, &proof));

    let wrong_old_root = [0u8; 32];
    assert!(!federation::verify_consistency(
        &wrong_old_root,
        &new_root,
        &proof
    ));
}

#[test]
fn merkle_consistency_complete_subtree() {
    // Exercises the `b && m == n` complete-subtree seed branch (old size is a power of two,
    // so the old root is omitted from the proof and seeded from `old_root`): 4->7 and 2->3.
    for (m, n) in [(4usize, 7usize), (2usize, 3usize)] {
        let entries: Vec<Vec<u8>> = (0..n).map(|i| format!("e{}", i).into_bytes()).collect();

        let mut old_log = MerkleLog::new();
        for entry in &entries[0..m] {
            old_log.append(entry);
        }
        let old_root = old_log.root();

        let mut log = MerkleLog::new();
        for entry in &entries {
            log.append(entry);
        }
        let new_root = log.root();

        let proof = log
            .consistency_proof(m as u64, n as u64)
            .expect("consistency proof failed");
        assert!(
            federation::verify_consistency(&old_root, &new_root, &proof),
            "consistency {}->{} should verify",
            m,
            n
        );
        // Tampering the new root must fail.
        assert!(
            !federation::verify_consistency(&old_root, &[9u8; 32], &proof),
            "consistency {}->{} with wrong new_root must fail",
            m,
            n
        );
    }
}

#[test]
fn sth_sign_verify() {
    let sk = SigningKey::generate(&mut OsRng);
    let root = [7u8; 32];
    let sth = federation::sign_tree_head(5, &root, 1, &sk);

    assert!(federation::verify_tree_head(&sth, &sk.verifying_key()));

    let wrong_sk = SigningKey::generate(&mut OsRng);
    assert!(!federation::verify_tree_head(
        &sth,
        &wrong_sk.verifying_key()
    ));
}

#[test]
fn resolver_did_aid() {
    let store = SqliteTrustStore::new_in_memory().expect("Failed to create store");
    store
        .upsert_issuer(&make_issuer(
            "did:aid:example.com:issuer1",
            IssuerStatus::Active,
            "claim_a",
        ))
        .expect("upsert failed");

    let store_arc: Arc<dyn TrustStore> = Arc::new(store);
    let backend = DidAidBackend {
        store: store_arc.clone(),
    };
    let resolver = CrossStandardResolver {
        backends: vec![Box::new(backend)],
    };

    assert!(resolver
        .resolve(&AgentRef::DidAid("did:aid:example.com:issuer1".into()))
        .is_some());
    assert!(resolver
        .resolve(&AgentRef::DidAid("not-a-did".into()))
        .is_none());
    assert!(resolver.resolve(&AgentRef::Ap2Issuer("x".into())).is_none());
}

#[test]
fn mirror_is_boundary_stub() {
    let peer = federation::FederationPeer {
        url: "https://peer.example.com".into(),
        pubkey: "x".into(),
    };
    let result = federation::mirror(&peer);
    assert!(result.is_err());
}
