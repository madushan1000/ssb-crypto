use crate::*;
use js_sys::{Uint8Array};
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};
use std::cmp::PartialEq;

#[derive(Debug, Copy, Clone)]
pub struct Nonce(pub [u8; 24]);
#[derive(Debug)]
pub struct Key(pub [u8; 32]);

pub fn seal(m: &[u8], n: &Nonce, k: &Key) -> Vec<u8> {
    let mut buf: Vec<u8> = vec!{};
    let clen = m.len() + 16;

    buf.resize(clen, 0);
	crypto_secretbox_easy(Uint8Array::from(m), Uint8Array::from(&n.0[..]), Uint8Array::from(&k.0[..])).copy_to(&mut buf[..]);
	buf.to_vec()
}

pub fn open(c: &[u8], n: &Nonce, k: &Key) -> Result<Vec<u8>, ()> {
	let mut buf: Vec<u8> = vec!{};
    let mlen = c.len() - 16;

    buf.resize(mlen, 0);
	crypto_secretbox_open_easy(Uint8Array::from(c), Uint8Array::from(&n.0[..]), Uint8Array::from(&k.0[..])).copy_to(&mut buf[..]);
	Ok(buf)
}

impl Key {
	pub fn from_slice(bs: &[u8]) -> Option<Key> {
        let mut n = Key([0u8; 32]);
        n.0.copy_from_slice(bs);
        Some(n)
    }
}

impl PartialEq for Key {
	fn eq(&self, other: &Key) -> bool {
		self.0 == other.0
	}
}

impl PartialEq for Nonce {
	fn eq(&self, other: &Nonce) -> bool {
		self.0 == other.0
	}
}

impl Index<Range<usize>> for Key {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeTo<usize>> for Key {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeFrom<usize>> for Key {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeFull> for Key {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<Range<usize>> for Nonce {
    type Output = [u8];
    fn index(&self, _index: Range<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeTo<usize>> for Nonce {
    type Output = [u8];
    fn index(&self, _index: RangeTo<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeFrom<usize>> for Nonce {
    type Output = [u8];
    fn index(&self, _index: RangeFrom<usize>) -> &[u8] {
        self.0.index(_index)
    }
}

impl Index<RangeFull> for Nonce {
    type Output = [u8];
    fn index(&self, _index: RangeFull) -> &[u8] {
        self.0.index(_index)
    }
}