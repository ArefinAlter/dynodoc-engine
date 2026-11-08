//! Typed v4 structural objects of sealed documents: decode is total and canonical.
#![no_main]
use engine_core::e2ee::state;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(address) = state::address(data) else {
        return;
    };
    if let Ok(object) = state::decode(&address, data) {
        let (again, bytes) = state::encode(&object).expect("re-encode");
        assert_eq!((again, bytes.as_slice()), (address.clone(), data));
        let _ = state::references(&address, data);
    }
});
