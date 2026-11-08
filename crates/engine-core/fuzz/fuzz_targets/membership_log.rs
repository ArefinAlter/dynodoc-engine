//! Membership logs and epoch records as a server could serve them: replay is total.
#![no_main]
use engine_core::e2ee::records::{verify_epochs, EpochRecord, Log, Pin, SignedEntry};
use libfuzzer_sys::fuzz_target;
use uuid::Uuid;

fuzz_target!(|data: &[u8]| {
    let Ok((entries, records)) =
        serde_json::from_slice::<(Vec<SignedEntry>, Vec<(EpochRecord, String)>)>(data)
    else {
        return;
    };
    let project = entries.first().map_or(Uuid::nil(), |e| e.entry.project);
    if let Ok(log) = Log::replay(project, &entries) {
        if verify_epochs(&log, &records).is_ok() {
            let plain: Vec<EpochRecord> = records.into_iter().map(|(r, _)| r).collect();
            let _ = Pin::default().advance(&log, &plain);
        }
    }
});
