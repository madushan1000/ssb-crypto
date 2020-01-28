use wasm_bindgen::prelude::*;

#[derive(Copy, Clone)]
pub struct Nonce(pub [u8; 24]);
pub struct Key(pub [u8; 24]);

//#[wasm_bindgen]
pub fn seal(m: &[u8], n: &Nonce, k: &Key) -> Vec<u8> {
	vec!{ 1 }
}

pub fn open(c: &[u8], n: &Nonce, k: &Key) -> Result<Vec<u8>, ()> {
	Ok(vec!{1})
}

impl Key {
	pub fn from_slice(bs: &[u8]) -> Option<Key> {
        let mut n = Key([0u8; 24]);
        n.0.copy_from_slice(bs);
        Some(n)
    }
}