extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use std::collections::HashSet;

use pairing::bls12_381::*;
use pairing::*;
use rand::{SeedableRng, XorShiftRng};

use crate::util::*;

extern crate bit_vec;
extern crate rand_core;

use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::dbig::DBIG;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::fp;
use mcore::bn254::fp12::FP12;
use mcore::bn254::pair;
use mcore::bn254::rom;
use mcore::rand::{RAND,RAND_impl};

use rand::Rng;
use bit_vec::BitVec;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use sha2::digest::generic_array::GenericArray;

use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::Aes128GcmSiv;
use itertools::Itertools;
use rand::{Rand};
use std::time::{Duration, Instant};

// Key generation
pub fn bls_key_gen() -> (ECP2, BIG) {
    // let mut rng = XorShiftRng::from_seed([0x5dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let g2 = ecp2::ECP2::generator();
    
    let sk = gen_random_fr();

    let vk = mul_g2_fr(&g2, &sk);

    (vk, sk)
}

pub fn bls_sign_vid_vpk(sk: &BIG, vid: u128, vk: &ECP2, sete: &mut HashSet<u128>) -> Option<ECP> {
    if sete.contains(&vid) {
        println!("Error: {} is already in the set", vid);
        None
    } else {
        sete.insert(vid);
        let mut vk_vid__vec = g2_to_vec_u128(vk);
        vk_vid__vec.push(vid);
        let h = hash_vec_to_g1(vk_vid__vec);
        let sig = mul_g1_fr(&h, &sk);
        Some(sig)
    }
}

pub fn bls_verify_vid_vpk(pk: &ECP2, vid: u128, vk: ECP2, sign: &ECP) -> bool {
    let g2 = ecp2::ECP2::generator();
    let mut vk_vid__vec = g2_to_vec_u128(&vk);
    vk_vid__vec.push(vid);
    let h = hash_vec_to_g1(vk_vid__vec);
    let left_pair = do_pairing(&sign, &g2);
    let right_pair = do_pairing(&h, &pk);

    left_pair.equals(&right_pair)
}

pub fn bls_sign_epoch(sk: &BIG, e: u128) -> ECP {
    let h = hash_int_to_g1(e);
    let sig = mul_g1_fr(&h, &sk);
    sig
}

pub fn bls_verify_epoch(pk: &ECP2, e: u128, sign: &ECP) -> bool {
    let g2 = ecp2::ECP2::generator();
    let h = hash_int_to_g1(e);
    let left_pair = do_pairing(&sign, &g2);
    let right_pair = do_pairing(&h, &pk);
    left_pair.equals(&right_pair)
}
