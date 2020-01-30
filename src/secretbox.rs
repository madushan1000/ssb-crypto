use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array};


#[wasm_bindgen]
extern "C" {
	fn crypto_box_seal(key: Uint8Array, nonce: Uint8Array, tag: Uint8Array) -> Uint8Array;
	fn crypto_box_seal_open(key: Uint8Array, nonce: Uint8Array, tag: Uint8Array) -> Uint8Array;
}

#[derive(Copy, Clone)]
pub struct Nonce(pub [u8; 24]);
pub struct Key(pub [u8; 24]);

pub fn seal(m: &[u8], n: &Nonce, k: &Key) -> Vec<u8> {
	let mut buf: Vec<u8> = vec!{};
	crypto_box_seal(Uint8Array::from(&k.0[..]), Uint8Array::from(&n.0[..]), Uint8Array::from(m)).copy_to(&mut buf[..]);
	buf.to_vec()
}

pub fn open(c: &[u8], n: &Nonce, k: &Key) -> Result<Vec<u8>, ()> {
	let mut buf: Vec<u8> = vec!{};
	crypto_box_seal_open(Uint8Array::from(&k.0[..]), Uint8Array::from(&n.0[..]), Uint8Array::from(c)).copy_to(&mut buf[..]);
	Ok(buf)
}

impl Key {
	pub fn from_slice(bs: &[u8]) -> Option<Key> {
        let mut n = Key([0u8; 24]);
        n.0.copy_from_slice(bs);
        Some(n)
    }
}