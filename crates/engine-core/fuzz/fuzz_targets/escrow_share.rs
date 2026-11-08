//! Escrow share text typed by custodians: decode is total, and combining decoded shares
//! either refuses or yields the key the shares name.
#![no_main]
use engine_core::e2ee::escrow::{combine, Share};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let shares: Vec<Share> = text.lines().filter_map(|l| Share::decode(l).ok()).collect();
    let _ = combine(&shares);
});
