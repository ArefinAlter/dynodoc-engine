//! `DYNOSEAL` headers as the service parses them: never a panic, and a parsed header always
//! re-validates under its own address.
#![no_main]
use engine_core::e2ee::seal;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok((header, body)) = seal::Header::parse(data) {
        assert!(body <= data.len());
        let address = seal::address(data).expect("address");
        assert_eq!(seal::validate(&address, data).expect("valid"), header);
        let _ = seal::references(&address, data);
    }
});
