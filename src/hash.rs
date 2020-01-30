use wasm_bindgen::prelude::*;
use crate::*;
use js_sys::{Uint8Array};

pub type Digest = Key;

#[wasm_bindgen]
extern "C" {
	fn crypto_hash_sha256(m: Uint8Array) -> Uint8Array;
}

pub fn hash(m: &[u8]) -> Digest {
	let mut buf = [0u8; 32];
	crypto_hash_sha256(Uint8Array::from(m)).copy_to(&mut buf);
	Key(buf)
}

