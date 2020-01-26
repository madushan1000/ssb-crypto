use crate::*;

pub struct HandshakeKeys {
    pub read_key: [u8; 32],
    pub read_noncegen: NonceGen,

    pub write_key: [u8; 32],
    pub write_noncegen: NonceGen,
}

#[wasm_bindgen]
pub struct  EphKeyPair {
    publicKey: [u8; 32],
    privateKey: [u8; 32],
    keyType: String,
}
pub fn generate_ephemeral_keypair() -> ([u8; 32], [u8; 32]) {
    let ephkeypair = crypto_box_keypair();
    (ephkeypair.publicKey, ephkeypair.privateKey)
}

pub fn derive_shared_secret(
    our_sec: &[u8; 32],
    their_pub: &[u8; 32],
) -> Option<[u8; 32]> {
    // Benchmarks suggest that these "copies" get optimized away.
    let mut buf = [0u8; 32];
    crypto_scalarmult(Uint8Array::from(our_sec as &[u8]), Uint8Array::from(their_pub as &[u8])).copy_to(&mut buf);
    Some(buf)
}

pub fn derive_shared_secret_pk(sk: &[u8; 32], pk: &[u8; 32]) -> Option<[u8; 32]> {
    pk_to_curve(&pk).and_then(|c| derive_shared_secret(&sk, &c))
}

pub fn derive_shared_secret_sk(sk: &[u8; 64], pk: &[u8; 32]) -> Option<[u8; 32]> {
    sk_to_curve(&sk).and_then(|c| derive_shared_secret(&c, &pk))
}

fn pk_to_curve(k: &[u8; 32]) -> Option<[u8; 32]> {
    let mut buf = [0u8; 32];
    crypto_sign_ed25519_pk_to_curve25519(Uint8Array::from(k as &[u8])).copy_to(&mut buf);
    Some(buf)
}

fn sk_to_curve(k: &[u8; 64]) -> Option<[u8; 32]> {
    let mut buf = [0u8; 32];
    crypto_sign_ed25519_sk_to_curve25519(Uint8Array::from(k as &[u8])).copy_to(&mut buf);
    Some(buf)
}
