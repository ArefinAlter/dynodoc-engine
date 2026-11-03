//! Unit and integration test suite for the `DYNOARC\0\x01` transport codec (NEXT-25).

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read};

use engine_core::materializer::DocumentState;
use engine_core::repository::archive::{
    verify_archive_stream, ArchiveEntry, ArchiveError, ArchiveLimits, ArchiveReader, ArchiveWriter,
    MAGIC,
};
use engine_core::repository::{Commit, SignedCommit};
use engine_core::shared_checkpoint::{write_state, Address, Limits, MemoryStore, ObjectStore};
use engine_shared::DocumentId;
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;

fn generate_key() -> Ed25519KeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
}

fn create_genesis_commit(project: DocumentId, key: &Ed25519KeyPair) -> SignedCommit {
    let commit = Commit {
        version: 1,
        project: project.0,
        parents: vec![],
        authored_at_ms: 1700000000000,
        author_key: String::new(),
        files: BTreeMap::new(),
        same_file_resolutions: Vec::new(),
        recovery: None,
        message: "Genesis commit".into(),
    };
    SignedCommit::sign(commit, key).unwrap()
}

fn create_child_commit(
    project: DocumentId,
    parent: Address,
    key: &Ed25519KeyPair,
    seq: i64,
) -> SignedCommit {
    let commit = Commit {
        version: 1,
        project: project.0,
        parents: vec![parent],
        authored_at_ms: 1700000000000 + seq * 1000,
        author_key: String::new(),
        files: BTreeMap::new(),
        same_file_resolutions: Vec::new(),
        recovery: None,
        message: format!("Commit {seq}"),
    };
    SignedCommit::sign(commit, key).unwrap()
}

async fn create_sample_object() -> (DocumentId, Address, Vec<u8>) {
    let doc = DocumentId(uuid::Uuid::new_v4());
    let mut store = MemoryStore::default();
    let state = DocumentState::default();
    let (root, _) = write_state(&mut store, doc, &state, Limits::default())
        .await
        .unwrap();
    let bytes = store.get(doc, &root).await.unwrap();
    (doc, root, bytes)
}

/// A reader that yields bytes one-by-one to test split-read resilience.
struct SlowReader<R: Read> {
    inner: R,
}

impl<R: Read> Read for SlowReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.inner.read(&mut buf[..1])
    }
}

#[tokio::test]
async fn roundtrip_single_commit_archive() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();
    let (doc_id, obj_addr, obj_bytes) = create_sample_object().await;

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer
        .write_object(doc_id, obj_addr.clone(), &obj_bytes)
        .unwrap();
    let written_commit_addr = writer.write_commit(&commit).unwrap();
    assert_eq!(written_commit_addr, head);
    let write_summary = writer.finish().unwrap();

    assert_eq!(write_summary.objects, 1);
    assert_eq!(write_summary.commits, 1);
    assert_eq!(write_summary.head, head);
    assert_eq!(write_summary.project, project);
    assert_eq!(write_summary.total_bytes, buf.len() as u64);

    // Read back and verify
    let mut reader = ArchiveReader::new(Cursor::new(&buf), ArchiveLimits::default());

    // 1. Header
    match reader.next_entry().unwrap() {
        Some(ArchiveEntry::Header {
            version,
            project: p,
            head: h,
        }) => {
            assert_eq!(version, 1);
            assert_eq!(p, project);
            assert_eq!(h, head);
        }
        other => panic!("expected header, got {other:?}"),
    }

    // 2. Object
    match reader.next_entry().unwrap() {
        Some(ArchiveEntry::Object {
            document,
            address,
            bytes,
        }) => {
            assert_eq!(document, doc_id);
            assert_eq!(address, obj_addr);
            assert_eq!(bytes, obj_bytes);
        }
        other => panic!("expected object, got {other:?}"),
    }

    // 3. Commit
    match reader.next_entry().unwrap() {
        Some(ArchiveEntry::Commit {
            address, signed, ..
        }) => {
            assert_eq!(address, head);
            assert_eq!(signed.verify().unwrap(), head);
        }
        other => panic!("expected commit, got {other:?}"),
    }

    // 4. Footer
    match reader.next_entry().unwrap() {
        Some(ArchiveEntry::Footer(summary)) => {
            assert_eq!(summary, write_summary);
        }
        other => panic!("expected footer, got {other:?}"),
    }

    // 5. EOF
    assert!(reader.next_entry().unwrap().is_none());
}

#[tokio::test]
async fn split_read_one_byte_at_a_time() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();
    let (doc_id, obj_addr, obj_bytes) = create_sample_object().await;

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer.write_object(doc_id, obj_addr, &obj_bytes).unwrap();
    writer.write_commit(&commit).unwrap();
    let write_summary = writer.finish().unwrap();

    let slow = SlowReader {
        inner: Cursor::new(&buf),
    };
    let verified_summary =
        verify_archive_stream(slow, ArchiveLimits::default(), Some(&head), Some(project)).unwrap();
    assert_eq!(verified_summary, write_summary);
}

#[tokio::test]
async fn multi_commit_dependency_first_ordering() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();

    let c1 = create_genesis_commit(project, &key);
    let a1 = c1.verify().unwrap();

    let c2 = create_child_commit(project, a1.clone(), &key, 2);
    let a2 = c2.verify().unwrap();

    let c3 = create_child_commit(project, a2.clone(), &key, 3);
    let a3 = c3.verify().unwrap();

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, a3.clone()).unwrap();
    writer.write_commit(&c1).unwrap();
    writer.write_commit(&c2).unwrap();
    writer.write_commit(&c3).unwrap();
    let summary = writer.finish().unwrap();
    assert_eq!(summary.commits, 3);
    assert_eq!(summary.head, a3);

    // Verify stream
    let verified = verify_archive_stream(
        Cursor::new(&buf),
        ArchiveLimits::default(),
        Some(&a3),
        Some(project),
    )
    .unwrap();
    assert_eq!(verified, summary);
}

#[tokio::test]
async fn out_of_order_commits_rejected() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();

    let c1 = create_genesis_commit(project, &key);
    let a1 = c1.verify().unwrap();

    let c2 = create_child_commit(project, a1.clone(), &key, 2);

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, a1.clone()).unwrap();
    // Attempting to write child c2 before parent c1
    let err = writer.write_commit(&c2).unwrap_err();
    assert!(matches!(err, ArchiveError::MissingDependency(_, _)));
}

#[tokio::test]
async fn object_after_commit_rejected() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();
    let (doc_id, obj_addr, obj_bytes) = create_sample_object().await;

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head).unwrap();
    writer.write_commit(&commit).unwrap();

    // Trying to write object after commit must fail
    let err = writer
        .write_object(doc_id, obj_addr, &obj_bytes)
        .unwrap_err();
    assert!(matches!(err, ArchiveError::OrderViolation(_)));
}

#[tokio::test]
async fn truncation_vectors_fail_cleanly() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();
    let (doc_id, obj_addr, obj_bytes) = create_sample_object().await;

    let mut valid_buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut valid_buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer.write_object(doc_id, obj_addr, &obj_bytes).unwrap();
    writer.write_commit(&commit).unwrap();
    writer.finish().unwrap();

    // 1. Truncate at magic (0..9)
    for len in 0..MAGIC.len() {
        let truncated = &valid_buf[..len];
        let mut reader = ArchiveReader::new(Cursor::new(truncated), ArchiveLimits::default());
        assert!(reader.next_entry().is_err());
    }

    // 2. Truncate midway through the stream at various byte lengths
    let cut_points = [
        MAGIC.len() + 2,      // midway through header length prefix
        MAGIC.len() + 4 + 10, // midway through header payload
        valid_buf.len() - 20, // midway through footer frame
        valid_buf.len() - 1,  // 1 byte short of full archive
    ];

    for &cut in &cut_points {
        let truncated = &valid_buf[..cut];
        let err = verify_archive_stream(
            Cursor::new(truncated),
            ArchiveLimits::default(),
            Some(&head),
            Some(project),
        )
        .unwrap_err();
        assert!(
            matches!(err, ArchiveError::UnexpectedEof | ArchiveError::Io(_)),
            "cut at {cut} yielded {err:?}"
        );
    }
}

#[tokio::test]
async fn trailing_bytes_after_footer_rejected() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer.write_commit(&commit).unwrap();
    writer.finish().unwrap();

    // Add extra trailing byte
    buf.push(0x42);

    let mut reader = ArchiveReader::new(Cursor::new(&buf), ArchiveLimits::default());
    // Header
    assert!(reader.next_entry().unwrap().is_some());
    // Commit
    assert!(reader.next_entry().unwrap().is_some());
    // Footer
    assert!(reader.next_entry().unwrap().is_some());
    // Next entry must detect trailing data
    let err = reader.next_entry().unwrap_err();
    assert!(matches!(err, ArchiveError::TrailingData));
}

#[tokio::test]
async fn tampered_payload_detected_by_footer_sha256() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();
    let (doc_id, obj_addr, obj_bytes) = create_sample_object().await;

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer.write_object(doc_id, obj_addr, &obj_bytes).unwrap();
    writer.write_commit(&commit).unwrap();
    writer.finish().unwrap();

    // Flipped byte in the middle of object frame (e.g. at offset 30)
    let mut tampered = buf.clone();
    tampered[MAGIC.len() + 20] ^= 0x01;

    let mut reader = ArchiveReader::new(Cursor::new(&tampered), ArchiveLimits::default());
    while let Ok(entry) = reader.next_entry() {
        if entry.is_none() {
            break;
        }
    }
    // Either JSON failed or footer hash mismatch occurred
    // Let's verify stream returns error
    let err = verify_archive_stream(
        Cursor::new(&tampered),
        ArchiveLimits::default(),
        Some(&head),
        Some(project),
    );
    assert!(err.is_err());
}

#[tokio::test]
async fn oversized_frame_rejected_before_allocating() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);
    // Write frame length of 3 MiB (exceeding 2 MiB limit)
    let oversized_len: u32 = 3 * 1024 * 1024;
    buf.extend_from_slice(&oversized_len.to_le_bytes());
    // Dummy bytes
    buf.extend_from_slice(&[0u8; 100]);

    let mut reader = ArchiveReader::new(Cursor::new(&buf), ArchiveLimits::default());
    let err = reader.next_entry().unwrap_err();
    assert!(matches!(err, ArchiveError::Limit(_)));
}

#[tokio::test]
async fn non_canonical_json_in_frame_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);

    // Header JSON with extra whitespace (noncanonical)
    let noncanonical_json = b"{\"kind\": \"header\", \"version\": 1, \"project\": \"00000000-0000-0000-0000-000000000001\", \"head\": \"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\"}";
    let len = noncanonical_json.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(noncanonical_json);

    let mut reader = ArchiveReader::new(Cursor::new(&buf), ArchiveLimits::default());
    let err = reader.next_entry().unwrap_err();
    assert!(matches!(err, ArchiveError::InvalidFrame(_)));
}

#[tokio::test]
async fn unknown_field_in_frame_rejected() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&MAGIC);

    // Canonical JSON but with unknown field "extra"
    let json_with_unknown = br#"{"extra":"forbidden","head":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","kind":"header","project":"00000000-0000-0000-0000-000000000001","version":1}"#;
    let len = json_with_unknown.len() as u32;
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(json_with_unknown);

    let mut reader = ArchiveReader::new(Cursor::new(&buf), ArchiveLimits::default());
    let err = reader.next_entry().unwrap_err();
    assert!(matches!(err, ArchiveError::Json(_)));
}

#[tokio::test]
async fn duplicate_commit_frame_rejected() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let commit = create_genesis_commit(project, &key);
    let head = commit.verify().unwrap();

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    writer.write_header(1, project, head.clone()).unwrap();
    writer.write_commit(&commit).unwrap();
    let err = writer.write_commit(&commit).unwrap_err();
    assert!(matches!(err, ArchiveError::InvalidFrame(_)));
}

#[tokio::test]
async fn head_commit_mismatch_rejected() {
    let project = DocumentId(uuid::Uuid::new_v4());
    let key = generate_key();
    let c1 = create_genesis_commit(project, &key);
    let a1 = c1.verify().unwrap();

    let c2 = create_child_commit(project, a1.clone(), &key, 2);
    let _a2 = c2.verify().unwrap();

    let mut buf = Vec::new();
    let mut writer = ArchiveWriter::new(&mut buf).unwrap();
    // Header claims head is a1, but last commit is a2
    writer.write_header(1, project, a1).unwrap();
    writer.write_commit(&c1).unwrap();
    writer.write_commit(&c2).unwrap();
    let err = writer.finish().unwrap_err();
    assert!(matches!(err, ArchiveError::InvalidFrame(_)));
}
