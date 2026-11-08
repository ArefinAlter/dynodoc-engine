//! Signed project commits (v1 to v4, with sealed fields) as JSON from the network.
#![no_main]
use engine_core::repository::SignedCommit;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(signed) = serde_json::from_slice::<SignedCommit>(data) {
        let _ = signed.commit.validate();
        let _ = signed.verify();
        if let Some(sealed) = &signed.commit.sealed {
            let _ = sealed.validate(&signed.commit);
        }
    }
});
