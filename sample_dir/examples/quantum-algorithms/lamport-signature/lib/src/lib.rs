use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

const KEY_SIZE: usize = 256;
const HASH_SIZE: usize = 256;

type PrivateKey = [[Vec<u8>; 2]; KEY_SIZE];

type PublicKey = [[Vec<u8>; 2]; KEY_SIZE];

#[derive(Serialize, Deserialize)]
struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

// Implement the Sign trait for LamportSigner
pub struct LamportSigner {
    key_pair: KeyPair,
}

trait Sign<S> {
    fn sign(&self, message: &str) -> S;
}

// Implement the Verify trait for LamportVerifier
pub struct LamportVerifier {
    public_key: PublicKey,
}

trait Verify<S> {
    fn verify_signature(&self, message: &str, signature: S) -> bool;
}

impl KeyPair {
    pub fn new() {
        let mut rng = rand::thread_rng();
        let mut private_key = [[vec![], vec![]]; HASH_SIZE];
        let mut public_key = [[vec![], vec![]]; HASH_SIZE];

        for i in 0..HASH_SIZE {
            // Generate two random 256-bit values for each bit
            let sk1: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            let sk2: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
            private_key[i] = [sk1.clone(), sk2.clone()];

            // Hash the private key values to create the public key
            public_key[i] = [Sha256::digest(&sk1).to_vec(), Sha256::digest(&sk2).to_vec()];
        }

        KeyPair {
            private_key,
            public_key,
        }
    }
}

impl Sign<Vec<Vec<u8>>> for LamportSigner {
    fn sign(&self, message: &str) -> Vec<Vec<u8>> {
        let message_hash = Sha256::digest(message);
        let mut signature = Vec::new();

        for (i, &bit) in message_hash
            .iter()
            .flat_map(|byte| (0..8).rev().map(move |b| (byte >> b) & 1))
            .enumerate()
        {
            signature.push(self.key_pair.private_key[i][bit as usize].clone());
        }

        signature
    }
}

impl Verify<Vec<Vec<u8>>> for LamportVerifier {
    fn verify_signature(&self, message: &str, signature: Vec<Vec<u8>>) -> bool {
        let message_hash = Sha256::digest(message.as_bytes());

        for (i, byte) in message_hash.iter().enumerate() {
            for bit in (0..8).rev() {
                let bit_value = (byte >> bit) & 1;
                let expected_hash = Sha256::digest(&signature[i * 8 + (7 - bit)]).to_vec();

                if expected_hash != self.public_key[i][bit_value as usize] {
                    return false;
                }
            }
        }
        true
    }
}

pub extern "C" fn generate_key_pair() -> *mut c_char {
    let keypair = KeyPair::new();
    let key_pair_json = serde_json::to_string(&keypair).unwrap();
    CString::new(key_pair_json).unwrap().into_raw()
}

/*

pub extern "C" fn sign(message: *const c_char, public_key: *const c_char) -> *mut c_char {
    let message = unsafe { CStr::from_ptr(message).to_string_lossy() };
    let public_key = unsafe { CStr::from_ptr(public_key).to_string_lossy() };
    let key_pair: KeyPair = serde_json::from_str(&key_pair).unwrap();
    let signature = key_pair.sign(&message);
    let signature_json = serde_json::to_string(&signature).unwrap();
    CString::new(signature_json).unwrap().into_raw()
}
*/

// The following two functions are expected by the custom wasm glue for microcraft as it does not use wasm-bindgen

#[no_mangle]
pub extern "C" fn malloc(size: usize) -> *mut u8 {
    let mut buf = Vec::with_capacity(size);
    let ptr = buf.as_mut_ptr();
    std::mem::forget(buf); // Prevent Rust from freeing the memory
    ptr
}

#[no_mangle]
pub extern "C" fn free(ptr: *mut u8, size: usize) {
    unsafe {
        let _ = Vec::from_raw_parts(ptr, 0, size);
    }
}
