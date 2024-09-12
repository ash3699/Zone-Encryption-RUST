 
extern crate aes_gcm_siv;
extern crate rand;
extern crate sha2;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv; // AES-256-GCM-SIV
use pairing::bls12_381::G2;
use sha2::digest::consts::U12;
use sha2::digest::generic_array;
use sha2::{Digest, Sha256};

extern crate bit_vec;
extern crate rand_core;
extern crate blake2;
extern crate byteorder;

use mcore::bn254::ecp2::ECP2;

use crate::util::hash_g2_to_aes_key;

pub fn generate_key(g2: &ECP2) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let key = hash_g2_to_aes_key(&g2);
    GenericArray::clone_from_slice(&key)
}
// Function to generate an IV from a key and a cipher
pub fn generate_iv(
    Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
) -> GenericArray<u8, generic_array::typenum::U12> {
    let mut hasher = Sha256::new();
    hasher.update(&Zpk);
    let result = hasher.finalize();
    GenericArray::clone_from_slice(&result[0..12])
}

// Function to encrypt a message
pub fn encrypt(
    Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
) -> (Vec<u8>, GenericArray<u8, U12>) {
    // println!("type of nonce {}", type_of(nonce));
    let cipher = Aes128GcmSiv::new(&Zpk);
    let iv = generate_iv(Zpk);
    let kp_bytes = kp.as_slice();
    let ciphertext = cipher
        .encrypt(&iv, kp_bytes.as_ref())
        .expect("DAE encryption failure!");

    (ciphertext, iv)
}

pub fn decrypt(
    Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    cipher_text: (GenericArray<u8, generic_array::typenum::U12>, Vec<u8>),
) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let (nonce, ciphertext) = cipher_text;
    let cipher = Aes128GcmSiv::new(&Zpk);
    let plain_key = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("DAE decryption failure!");
    let iv = generate_iv(Zpk);
    if nonce == iv {
        println!("DAE Authentication sucessful!\n");
    } else {
        println!("DAE Authentication fail!");
    }

    GenericArray::clone_from_slice(&plain_key)
}
