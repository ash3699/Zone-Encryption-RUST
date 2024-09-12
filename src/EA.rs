extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::util::*;
use crate::BLS;
use rand::{Rng, SeedableRng, XorShiftRng};
use std::collections::{HashMap, HashSet};
use std::mem;
use std::time::{Duration, Instant};

extern crate bit_vec;
extern crate rand_core;
extern crate blake2;
extern crate byteorder;

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

use bit_vec::BitVec;
use sha2::{Digest, Sha256};
use std::convert::TryInto;
use sha2::digest::generic_array::GenericArray;

use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::Aes128GcmSiv;
use itertools::Itertools;
use rand::Rand;

pub struct EA {
    e_sk: BIG,
    pub e_pk: ECP2,
    e_set: HashSet<u128>,
}

impl EA {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        EA {
            e_sk: fr_zero(), // Initialize sk to zero (or any default value)
            e_pk: ecp2::ECP2::generator(), // Initialize pk to zero (or any default value)
            e_set: HashSet::new(),
        }
    }

    // Key generation function for EA
    pub fn EA_key_gen(&mut self) {
        // Generate a random secret key
        let (pk, sk) = BLS::bls_key_gen();
        let mut set: HashSet<u128> = HashSet::new();
        self.e_sk = sk;
        self.e_pk = pk;
        self.e_set = set;
    }

    pub fn SIG_sig(&mut self, vid1: u128, v_pk: &ECP2) -> Option<ECP> {
        let signature_e = BLS::bls_sign_vid_vpk(&self.e_sk, vid1, &v_pk, &mut self.e_set);
        if let Some(sig) = &signature_e {
            println!("Signing Successful for vehicle {}\n", vid1);
        } else {
            println!("Signing Failed for vehicle {}\n", vid1);
        }
        signature_e
    }
    
}
