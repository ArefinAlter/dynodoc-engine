//! `DYNOENC` at-rest envelopes: header parsing never panics; opening under a fixed key fails
//! cleanly for anything the fuzzer did not seal.
#![no_main]
use engine_core::at_rest::{open, Context, DataKey, Dek, Header};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::parse(data) {
        let key = DataKey::new(header.dek_id, header.kek_version, Dek::from_bytes([7; 32]));
        let ctx = Context::new(Uuid::nil(), "checkpoint_object", "bytes", b"row").expect("ctx");
        let _ = open(&key, &ctx, data);
    }
});
