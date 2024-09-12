extern crate aes_gcm_siv;
extern crate rand;

use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes128GcmSiv; // AES-256-GCM-SIV
use rand::Rng;
use sha2::digest::consts::U12;
// use std::any::type_name;

// fn type_of<T>(_: &T) -> &'static str {
//     type_name::<T>()
// }

pub fn generate_key() -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let mut rng = rand::thread_rng();
    let key: [u8; 16] = rng.gen();
    GenericArray::clone_from_slice(&key)
}

// Function to encrypt a message
pub fn encrypt(
    kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    payload: &str,
) -> (Vec<u8>, GenericArray<u8, U12>) {
    let nonce = GenericArray::from_slice(&[0u8; 12]);
    // println!("type of nonce {}", type_of(nonce));
    let cipher = Aes128GcmSiv::new(&kp);
    let payload_bytes = payload.as_bytes();
    let ciphertext = cipher
        .encrypt(&nonce, payload_bytes.as_ref())
        .expect("SE encryption failure!");

    (ciphertext, *nonce)
}

// Function to decrypt a message
pub fn decrypt(
    kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
    ciphertext: &[u8],
) -> String {
    let cipher = Aes128GcmSiv::new(&kp);
    let plaintext_bytes = cipher
        .decrypt(&nonce, ciphertext.as_ref())
        .expect("SE decryption failure!");

    String::from_utf8(plaintext_bytes).expect("Invalid UTF-8")
}
