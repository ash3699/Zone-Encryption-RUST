extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use rand::XorShiftRng;
use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;

use crate::util::*;

// Key generation
pub fn pke_key_gen(rng: &mut XorShiftRng) -> (ECP2, BIG) {
    let g2 = ecp2::ECP2::generator();
    let sk = gen_random_fr();
    let vk = mul_g2_fr(&g2, &sk);
    (vk, sk)
}

pub fn pke_encrypt(pk: ECP2, plaintext: ECP2) -> (ECP2, ECP2) {
    let g = ecp2::ECP2::generator();
    let k = gen_random_fr();
    let c_1 = mul_g2_fr(&g, &k);
    let c_2 = add_g2_g2(&mut mul_g2_fr(&pk, &k), &plaintext);

    (c_1, c_2)
}

pub fn pke_decrypt(sk: &BIG, ciphertext: (ECP2, ECP2)) -> ECP2 {
    let (c_1, C_21) = ciphertext;
    let mut c_2 = C_21;
    let mut c_1_sk = mul_g2_fr(&c_1, &sk);

    let plaintext = add_g2_g2(&mut c_2, g2_neg(&mut c_1_sk));

    plaintext
}
