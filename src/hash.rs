use wasm_bindgen::prelude::*;
use js_sys::{Uint8Array};

pub type Digest = [u8; 32];

#[wasm_bindgen]
extern "C" {
	//#[wasm_bindgen(js_namespace = sodium)]
	//pub fn hash(m: Uint8Array) -> Uint8Array;
}

pub fn hash(m: &[u8]) -> Digest {
	[0u8; 32]
}