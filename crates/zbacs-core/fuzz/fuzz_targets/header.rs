//! Z-1.C.3 target 1: raw bytes -> magic/length/CBOR/signature/limits (spec §4 step 1).
//! Almost every input dies before signature verification; this target guards the framing
//! and CBOR decoding surface (T18).
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = zbacs_core::inspect(Cursor::new(data));
    let _ = zbacs_core::Header::decode_verified(data);
});
