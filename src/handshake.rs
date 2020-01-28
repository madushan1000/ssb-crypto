use crate::*;
use std::ops::{Index, Range, RangeTo, RangeFrom, RangeFull};

pub struct HandshakeKeys {
    pub read_key: secretbox::Key,
    pub read_noncegen: NonceGen,

    pub write_key: secretbox::Key,
    pub write_noncegen: NonceGen,
}

#[derive(Copy, Clone)]
pub struct Key(pub [u8; 32]);

pub type EphPublicKey = Key;
pub type EphSecretKey = Key;
pub type SharedSecret = Key;

#[wasm_bindgen]
pub struct  EphKeyPair {
    publicKey: [u8; 32],
    privateKey: [u8; 32],
    keyType: String,
}
pub fn generate_ephemeral_keypair() -> (EphPublicKey, EphSecretKey) {
    let ephkeypair = crypto_box_keypair();
    (Key(ephkeypair.publicKey),Key(ephkeypair.privateKey))
}

pub fn derive_shared_secret(
    our_sec: &EphSecretKey,
    their_pub: &EphPublicKey,
) -> Option<SharedSecret> {
    // Benchmarks suggest that these "copies" get optimized away.
    let mut buf = [0u8; 32];
    crypto_scalarmult(Uint8Array::from(&our_sec[..]), Uint8Array::from(&their_pub[..])).copy_to(&mut buf);
    Some(Key(buf))
}

pub fn derive_shared_secret_pk(sk: &EphSecretKey, pk: &PublicKey) -> Option<SharedSecret> {
    pk_to_curve(&pk).and_then(|c| derive_shared_secret(&sk, &c))
}

pub fn derive_shared_secret_sk(sk: &SecretKey, pk: &PublicKey) -> Option<SharedSecret> {
    sk_to_curve(&sk).and_then(|c| derive_shared_secret(&c, &pk))
}

fn pk_to_curve(k: &PublicKey) -> Option<EphPublicKey> {
    let mut buf = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(Uint8Array::from(&k[..])).copy_to(&mut buf);
    Some(Key(buf))
}

fn sk_to_curve(k: &SecretKey) -> Option<EphSecretKey> {
    let mut buf = [0u8; 32];
    crypto_sign_ed25519_sk_to_curve25519(Uint8Array::from(&k[..])).copy_to(&mut buf);
    Some(Key(buf))
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

impl Key {
    pub fn from_slice(bs: &[u8]) -> Option<Key> {
        let mut n = Key([0u8; 32]);
        n.0.copy_from_slice(bs);
        Some(n)
    }
}