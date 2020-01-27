use wasm_bindgen::prelude::*;
use core::mem::size_of;
use ::std::convert::{TryInto};
use js_sys::{Promise, Uint8Array};
use handshake::EphKeyPair;


#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = sodium)]
    fn ready() -> Promise;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_sign_keypair() -> KeyPair;
    #[wasm_bindgen(js_namespace = sodium)]
    fn randombytes_buf(len: usize) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_auth(msg: &[u8], key: &Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_auth_verify(mac: Uint8Array, msg: &[u8], key: &Uint8Array) -> bool;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_box_keypair() -> EphKeyPair;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_scalarmult(privateKey: Uint8Array, publicKey: Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_sign_ed25519_pk_to_curve25519(publicKey: Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn crypto_sign_ed25519_sk_to_curve25519(privateKey: Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn sign_detached(m: Uint8Array, sk: Uint8Array) -> Uint8Array;
    #[wasm_bindgen(js_namespace = sodium)]
    fn verify_detached(sig: Uint8Array, m: Uint8Array, pk: Uint8Array) -> bool;
}

pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 64];
pub type Signature = [u8; 64];
pub type AuthTag = [u8; 32];
pub type Digest = [u8; 32];


#[wasm_bindgen]
pub struct KeyPair {
    publicKey: [u8; 32],
    privateKey: [u8; 64],
    keyType: String
}

pub mod handshake;
pub mod hash;
pub mod utils;
pub mod secretbox;

pub async fn init() {
    wasm_bindgen_futures::JsFuture::from(ready()).await.unwrap();
}

pub fn generate_longterm_keypair() -> ([u8; 32], [u8; 64]) {
    let keypair = crypto_sign_keypair();
    (keypair.publicKey, keypair.privateKey)
}

/// 32-byte network key, known by client and server. Usually `NetworkKey::SSB_MAIN_NET`
#[derive(Clone, Debug, PartialEq)]
pub struct NetworkKey([u8; 32]);
impl NetworkKey {
    pub const SSB_MAIN_NET: NetworkKey = NetworkKey([
        0xd4, 0xa1, 0xcb, 0x88, 0xa6, 0x6f, 0x02, 0xf8, 0xdb, 0x63, 0x5c, 0xe2, 0x64, 0x41, 0xcc,
        0x5d, 0xac, 0x1b, 0x08, 0x42, 0x0c, 0xea, 0xac, 0x23, 0x08, 0x39, 0xb7, 0x55, 0x84, 0x5a,
        0x9f, 0xfb,
    ]);

    pub fn random() -> NetworkKey {
        let mut buf = randombytes_buf(NetworkKey::size());
        NetworkKey::from_slice(&buf.to_vec()).unwrap()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0[..]
    }
    pub fn from_slice(b: &[u8]) -> Option<NetworkKey> {
        Some(NetworkKey(b.try_into().expect("incorrect length")))
    }

    pub fn authenticate(&self, data: &[u8]) -> [u8; 32] {
        let mut buf = [0u8; 32];
        crypto_auth(data, &Uint8Array::from(&self.0 as &[u8])).copy_to(&mut buf);
        buf
    }

    pub fn verify(&self, tag: [u8; 32], data: &[u8]) -> bool {
        crypto_auth_verify(Uint8Array::from(&tag as &[u8]), data, &Uint8Array::from(&self.0 as &[u8]))
    }

    pub const fn size() -> usize {
        size_of::<[u8; 32]>()
    }
}

pub struct NonceGen {
    next_nonce: secretbox::Nonce,
}

impl NonceGen {
    pub fn new(pk: &[u8; 32], net_id: &NetworkKey) -> NonceGen {
        let mut hmac = [0u8; 32];
        crypto_auth(&pk[..], &Uint8Array::from(&net_id.0 as &[u8])).copy_to(&mut hmac);
        const N: usize = size_of::<[u8; 24]>();
        NonceGen {
            next_nonce: hmac[..N].try_into().unwrap(),
        }
    }

    /// #Examples
    /// ```rust
    /// use ssb_crypto::NonceGen;
    /// use sodiumoxide::crypto::secretbox::Nonce;
    ///
    /// let nonce_bytes = [0, 0, 0, 0, 0, 0, 0, 0,
    ///                    0, 0, 0, 0, 0, 0, 0, 0,
    ///                    0, 0, 0, 0, 0, 0, 255, 255];
    /// let mut gen = NonceGen::with_starting_nonce(Nonce::from_slice(&nonce_bytes).unwrap());
    /// let n1 = gen.next();
    /// assert_eq!(&n1[..], &nonce_bytes);
    /// let n2 = gen.next();
    /// assert_eq!(&n2[..], [0, 0, 0, 0, 0, 0, 0, 0,
    ///                      0, 0, 0, 0, 0, 0, 0, 0,
    ///                      0, 0, 0, 0, 0, 1, 0, 0]);
    /// ```
    pub fn with_starting_nonce(nonce: [u8; 24]) -> NonceGen {
        NonceGen { next_nonce: nonce }
    }

    pub fn next(&mut self) -> [u8; 24] {
        let n = self.next_nonce;

        // Increment the nonce as a big-endian u24
        for byte in self.next_nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    extern crate wasm_bindgen_test;
    use wasm_bindgen_test::*;
    use super::{generate_longterm_keypair, handshake::*, NetworkKey};
    use core::mem::size_of;

    #[wasm_bindgen_test]
    fn networkkey_random() {
        let a = NetworkKey::random();
        let b = NetworkKey::random();

        assert_ne!(a, b);
        assert_ne!(
            a,
            NetworkKey::from_slice(&[0u8; NetworkKey::size()]).unwrap()
        );
    }

    #[wasm_bindgen_test]
    fn shared_secret_with_zero() {
        let (c_eph_pk, _) = generate_ephemeral_keypair();
        let (c_pk, _) = generate_longterm_keypair();


        let (_, s_eph_sk) = generate_ephemeral_keypair();
        let (_, s_sk) = generate_longterm_keypair();

        assert!(derive_shared_secret(&s_eph_sk, &c_eph_pk).is_some());
        let zero_eph_pk = [0u8; 32];
        assert!(derive_shared_secret(&s_eph_sk, &zero_eph_pk).is_none());

        assert!(derive_shared_secret_pk(&s_eph_sk, &c_pk).is_some());
        let zero_pk = &[0; size_of::<[u8; 32]>()];
        assert!(derive_shared_secret_pk(&s_eph_sk, &zero_pk).is_none());

        assert!(derive_shared_secret_sk(&s_sk, &c_eph_pk).is_some());
        assert!(derive_shared_secret_sk(&s_sk, &zero_eph_pk).is_none());
    }
}
