//! Every stored checkpoint object format through the service's one entry point.
#![no_main]
use engine_core::shared_checkpoint::{references, validate_stored, Address};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // The address is taken from the input's first 64 bytes when they are hex, else derived.
    let (head, rest) = data.split_at(data.len().min(64));
    let Ok(text) = std::str::from_utf8(head) else {
        return;
    };
    let Ok(address) = Address::try_from(text.to_owned()) else {
        return;
    };
    if validate_stored(&address, rest).is_ok() {
        references(&address, rest).expect("a valid object has references");
    }
});
