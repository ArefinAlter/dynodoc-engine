//! Provenance Contract & Counterexamples Regression Suite (October 2026 Direction).
//!
//! Enforces key provenance security invariants:
//! 1. Counterexample 1: Divergence between author identity and recorder key signature.
//! 2. Counterexample 2: Lapsed reviews applied to subsequent revisions.
//! 3. Counterexample 3: Out-of-order review decision application.
//! 4. Counterexample 4: Tampered signature on change request / ref receipt.

use engine_core::{
    repository::{
        attestation::{Pin, Receipt, Scope, SignedReceipt},
        Head,
    },
    shared_checkpoint::Address,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use uuid::Uuid;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn sample_scope(project: Uuid) -> Scope {
    Scope {
        authority: Uuid::from_u128(0x42),
        project,
        branch: "main".into(),
    }
}

fn commit_addr(byte: u8) -> Address {
    Address::try_from(format!("{:02x}", byte).repeat(32)).unwrap()
}

// ----------------------------------------------------------------------------
// Counterexample 1: Divergence between author identity and recorder key signature
// ----------------------------------------------------------------------------

#[test]
fn counterexample_1_author_and_recorder_key_divergence() {
    let project = Uuid::new_v4();
    let scope = sample_scope(project);

    let author_key = key(1);
    let unauthorized_key = key(2);

    let author_pub = hex(author_key.public_key().as_ref());
    let unauthorized_pub = hex(unauthorized_key.public_key().as_ref());

    assert_ne!(
        author_pub, unauthorized_pub,
        "test keys must be distinct identities"
    );

    // 1. A legitimate receipt signed by the author key verifies cleanly.
    let valid_receipt = Receipt {
        version: 1,
        scope: scope.clone(),
        head: Head {
            commit: commit_addr(0x11),
            generation: 1,
        },
        previous: None,
        issued_at_ms: 1_760_000_000_000,
        issuer_key: author_pub.clone(),
    };
    let signed_valid =
        SignedReceipt::sign(valid_receipt.clone(), &author_key).expect("signing succeeds");
    assert!(
        signed_valid.verify().is_ok(),
        "valid author signature must verify"
    );

    // 2. Counterexample: An unauthorized signer creates a receipt, and attempts
    // to forge attribution by setting receipt.issuer_key to author_pub.
    let mut forged_signed =
        SignedReceipt::sign(valid_receipt, &unauthorized_key).expect("signing succeeds");
    forged_signed.receipt.issuer_key = author_pub.clone();
    assert!(
        forged_signed.verify().is_err(),
        "signature made with unauthorized key must fail verification when attributed to author key"
    );

    // 3. Client pinning: If a client pins author_pub as the trusted authority key,
    // a receipt signed by unauthorized_key (with issuer_key = unauthorized_pub) is rejected.
    let other_receipt = Receipt {
        version: 1,
        scope: scope.clone(),
        head: Head {
            commit: commit_addr(0x11),
            generation: 1,
        },
        previous: None,
        issued_at_ms: 1_760_000_000_000,
        issuer_key: unauthorized_pub.clone(),
    };
    let signed_other =
        SignedReceipt::sign(other_receipt, &unauthorized_key).expect("signing succeeds");
    let pin_err = Pin::trust_checkpoint(&scope, &author_pub, signed_other);
    assert!(
        pin_err.is_err(),
        "pinned client must reject receipt from divergent/untrusted key"
    );
}

// ----------------------------------------------------------------------------
// Counterexample 2: Lapsed reviews cannot apply to subsequent content revisions
// ----------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct ReviewRecord {
    reviewer_id: Uuid,
    verdict: String,
    draft_revision: Option<i64>,
    created_at_ms: i64,
}

#[derive(Debug, Clone)]
struct DraftRecord {
    revision: i64,
    content_revision: i64,
    content_changed_at_ms: i64,
}

/// Evaluates whether a review verdict is still fresh (migration 0045 rule).
fn is_review_fresh(review: &ReviewRecord, draft: &DraftRecord) -> bool {
    match review.draft_revision {
        Some(rev) => rev >= draft.content_revision,
        None => review.created_at_ms > draft.content_changed_at_ms,
    }
}

#[test]
fn counterexample_2_lapsed_reviews_cannot_apply_to_subsequent_content_revisions() {
    let reviewer = Uuid::new_v4();

    // 1. Contributor submits revision 1.
    let mut draft = DraftRecord {
        revision: 1,
        content_revision: 1,
        content_changed_at_ms: 1_000,
    };

    // 2. Reviewer reviews revision 1 and approves.
    let review_rev1 = ReviewRecord {
        reviewer_id: reviewer,
        verdict: "approved".into(),
        draft_revision: Some(1),
        created_at_ms: 1_100,
    };
    assert!(
        is_review_fresh(&review_rev1, &draft),
        "approval given for revision 1 must be fresh on revision 1"
    );

    // 3. Counterexample: Contributor updates content to revision 2.
    draft.revision = 2;
    draft.content_revision = 2;
    draft.content_changed_at_ms = 1_200;

    // The review for revision 1 must NOT count on revision 2.
    assert!(
        !is_review_fresh(&review_rev1, &draft),
        "approval given for revision 1 must lapse when content_revision advances to 2"
    );

    // 4. Contrast: Manager performs a partial merge or metadata update that advances `revision`
    // to 3, but leaves content untouched (so content_revision stays 2).
    let review_rev2 = ReviewRecord {
        reviewer_id: reviewer,
        verdict: "approved".into(),
        draft_revision: Some(2),
        created_at_ms: 1_300,
    };
    assert!(is_review_fresh(&review_rev2, &draft));

    draft.revision = 3;
    // content_revision is intentionally UNCHANGED (no content change)
    assert!(
        is_review_fresh(&review_rev2, &draft),
        "partial merge or metadata increment without content change does not lapse approval"
    );
}

// ----------------------------------------------------------------------------
// Counterexample 3: Out-of-order review decision application
// ----------------------------------------------------------------------------

#[allow(dead_code)]
#[derive(Debug, Clone)]
struct SequencedReview {
    reviewer_id: Uuid,
    verdict: &'static str,
    draft_revision: Option<i64>,
    seq: i64,
    created_at_ms: i64,
}

/// Resolves the latest counted verdict for a reviewer according to migration 0045:
/// ordered by (draft_revision is not null) desc, seq desc, created_at desc.
fn resolve_latest_counted(reviews: &[SequencedReview]) -> Option<&SequencedReview> {
    reviews.iter().max_by(|a, b| {
        let a_has_rev = a.draft_revision.is_some();
        let b_has_rev = b.draft_revision.is_some();
        a_has_rev
            .cmp(&b_has_rev)
            .then_with(|| a.seq.cmp(&b.seq))
            .then_with(|| a.created_at_ms.cmp(&b.created_at_ms))
    })
}

#[test]
fn counterexample_3_out_of_order_review_decision_resolution() {
    let reviewer = Uuid::new_v4();

    // Two concurrent submissions from the same reviewer in two browser tabs:
    // Tab 1 started at t=2000 with "approved", but transaction committed at seq=10.
    // Tab 2 started at t=1000 with "changes_requested", but transaction committed later at seq=11.
    let review_tab1 = SequencedReview {
        reviewer_id: reviewer,
        verdict: "approved",
        draft_revision: Some(2),
        seq: 10,
        created_at_ms: 2000,
    };
    let review_tab2 = SequencedReview {
        reviewer_id: reviewer,
        verdict: "changes_requested",
        draft_revision: Some(2),
        seq: 11,
        created_at_ms: 1000,
    };

    let all_reviews = vec![review_tab1, review_tab2];

    // Under created_at order, Tab 1 (t=2000) would wrongly override Tab 2.
    // Under commit-order `seq`, Tab 2 (seq=11) correctly wins.
    let resolved = resolve_latest_counted(&all_reviews).expect("review exists");
    assert_eq!(
        resolved.verdict, "changes_requested",
        "commit sequence seq=11 must take precedence over wall-clock timestamp"
    );
    assert_eq!(resolved.seq, 11);
}

// ----------------------------------------------------------------------------
// Counterexample 4: Tampered signature on change request / ref receipt
// ----------------------------------------------------------------------------

#[test]
fn counterexample_4_tampered_signature_on_receipt_is_rejected() {
    let project = Uuid::new_v4();
    let scope = sample_scope(project);
    let keypair = key(9);
    let pubkey = hex(keypair.public_key().as_ref());

    let receipt = Receipt {
        version: 1,
        scope: scope.clone(),
        head: Head {
            commit: commit_addr(0xAA),
            generation: 1,
        },
        previous: None,
        issued_at_ms: 1_760_000_000_000,
        issuer_key: pubkey.clone(),
    };

    let valid_signed = SignedReceipt::sign(receipt, &keypair).unwrap();
    assert!(valid_signed.verify().is_ok());

    // 4a. Tampering with commit address
    let mut tampered_commit = valid_signed.clone();
    tampered_commit.receipt.head.commit = commit_addr(0xBB);
    assert!(
        tampered_commit.verify().is_err(),
        "tampering with commit address must fail signature verification"
    );

    // 4b. Tampering with generation counter
    let mut tampered_gen = valid_signed.clone();
    tampered_gen.receipt.head.generation = 2;
    assert!(
        tampered_gen.verify().is_err(),
        "tampering with generation counter must fail signature verification"
    );

    // 4c. Tampering with scope (branch name)
    let mut tampered_branch = valid_signed.clone();
    tampered_branch.receipt.scope.branch = "feature".into();
    assert!(
        tampered_branch.verify().is_err(),
        "tampering with branch scope must fail signature verification"
    );

    // 4d. Tampering with cryptographic signature bytes
    let mut tampered_sig = valid_signed.clone();
    let mut sig_bytes = tampered_sig.signature.into_bytes();
    sig_bytes[0] = if sig_bytes[0] == b'a' { b'b' } else { b'a' };
    tampered_sig.signature = String::from_utf8(sig_bytes).unwrap();
    assert!(
        tampered_sig.verify().is_err(),
        "flipped signature byte must fail cryptographic verification"
    );

    // 4e. Pin continuity: Pin rejects skipped generation or broken previous hash.
    let pin = Pin::trust_checkpoint(&scope, &pubkey, valid_signed.clone()).unwrap();

    let skipped_gen_receipt = Receipt {
        version: 1,
        scope: scope.clone(),
        head: Head {
            commit: commit_addr(0xAB),
            generation: 3, // Skipped generation 2!
        },
        previous: Some(valid_signed.verify().unwrap()),
        issued_at_ms: 1_760_000_001_000,
        issuer_key: pubkey.clone(),
    };
    let signed_skipped = SignedReceipt::sign(skipped_gen_receipt, &keypair).unwrap();
    // Pin rejects non-consecutive generation
    let advance_res = pin.advance(std::slice::from_ref(&signed_skipped));
    assert!(
        advance_res.is_err(),
        "pin must reject skipped generation counter"
    );
}
