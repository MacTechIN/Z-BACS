//! Z-1.C.3 target 3: structured mutations of a valid container (bit flips, truncation,
//! byte insertion) opened with the right key. Property: never panics, and any accepted
//! output equals the original plaintext (T18, T19).
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;
use std::sync::OnceLock;
use zbacs_core::{OwnerKeys, SealOptions};

#[derive(Arbitrary, Debug)]
enum Op {
    Flip { at: u16, bit: u8 },
    Set { at: u16, val: u8 },
    Truncate { len: u16 },
    Insert { at: u16, val: u8 },
    Delete { at: u16 },
}

#[derive(Arbitrary, Debug)]
struct Case {
    base: u8,
    ops: Vec<Op>,
}

struct Base {
    owner: OwnerKeys,
    plain: Vec<u8>,
    sealed: Vec<u8>,
}

fn bases() -> &'static Vec<Base> {
    static B: OnceLock<Vec<Base>> = OnceLock::new();
    B.get_or_init(|| {
        [(0usize, 16usize), (1, 16), (16, 4), (100, 32), (1000, 64)]
            .into_iter()
            .map(|(len, chunk)| {
                let owner = OwnerKeys::generate().unwrap();
                let plain: Vec<u8> = (0..len).map(|i| (i * 7 % 251) as u8).collect();
                let mut opts = SealOptions::new(b"acct", "f.txt");
                opts.chunk_size = chunk;
                let mut sealed = Vec::new();
                zbacs_core::seal(Cursor::new(&plain), &mut sealed, &owner, &opts).unwrap();
                Base { owner, plain, sealed }
            })
            .collect()
    })
}

fuzz_target!(|case: Case| {
    let bases = bases();
    let base = &bases[case.base as usize % bases.len()];
    let mut data = base.sealed.clone();
    for op in case.ops.iter().take(16) {
        if data.is_empty() {
            break;
        }
        match *op {
            Op::Flip { at, bit } => {
                let i = at as usize % data.len();
                data[i] ^= 1 << (bit % 8);
            }
            Op::Set { at, val } => {
                let i = at as usize % data.len();
                data[i] = val;
            }
            Op::Truncate { len } => data.truncate(len as usize % (data.len() + 1)),
            Op::Insert { at, val } => {
                let i = at as usize % (data.len() + 1);
                data.insert(i, val);
            }
            Op::Delete { at } => {
                let i = at as usize % data.len();
                data.remove(i);
            }
        }
    }
    let mut out = Vec::new();
    if zbacs_core::open(Cursor::new(&data), &mut out, &base.owner.sealing).is_ok() {
        assert_eq!(out, base.plain, "mutated container accepted with different plaintext");
    }
});
