extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::{
    util::{self, combine_vec_u128, g2_to_vec_u128, gen_random_fr, mul_g1_fr},
    BLS, DAE,
};
use aes_gcm_siv::{aead::NewAead, Aes128GcmSiv};
use rand::{Rng, SeedableRng, XorShiftRng};
use sha2::digest::generic_array::GenericArray;
use std::collections::{HashMap, HashSet};
use std::mem;
use std::time::{Duration, Instant};
use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;

pub struct Zone {
    pub zone_id: u128,
    pub zone_pre_sk: ECP2,
    pub zone_sk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
}

impl Zone {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        Zone {
            zone_id: 0,
            zone_pre_sk: ecp2::ECP2::generator(), // Initialize sk to zero (or any default value)
            zone_sk: GenericArray::default(), // Initialize pk to zero (or any default value)
        }
    }

    // Key generation function for EA
    pub fn Zone_key_gen(&mut self, zid: u128) -> ECP2 {
        // Generate a random secret key
        let sk_fr = gen_random_fr();
        let g = ecp2::ECP2::generator();
        let zone_pre_sk = util::mul_g2_fr(&g, &sk_fr);
        self.zone_id = zid;
        self.zone_pre_sk = zone_pre_sk.clone();
        zone_pre_sk
    }

    pub fn generate_zone_sk_key(
        &mut self,
        zone_pre_sk: &ECP2,
    ) -> (GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>) {
        let zone_sk = DAE::generate_key(zone_pre_sk);
        self.zone_sk = zone_sk;
        zone_sk
    }
}
