extern crate aes_gcm_siv;
extern crate pairing;
extern crate rand;
extern crate sha2;

use crate::{
    util::{
        combine_vec_u128, g2_to_vec_u128, gen_random_fr, mul_g1_fr, CertV, IAPublicKey, IASecretKey, fr_zero
    },
    BLS, DGSA,
};

use rand::{Rng, SeedableRng, XorShiftRng};
use std::{
    collections::{HashMap, HashSet},
    option,
};
use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;

pub struct IA {
    IASecretKey: IASecretKey,
    pub IAPublicKey: IAPublicKey,
    pub set_i: HashMap<(u128, u128), BIG>,
}

impl IA {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        IA {
            IASecretKey: IASecretKey {
                sk_x2: fr_zero(),
                sk_id: fr_zero(),
                sk_epoch: fr_zero(),
                sk_k1: fr_zero(),
            },
            IAPublicKey: IAPublicKey {
                pk_X2: ecp2::ECP2::generator(),
                pk_id: ecp2::ECP2::generator(),
                pk_epoch: ecp2::ECP2::generator(),
                pk_K1: ecp2::ECP2::generator(),
                g2: ecp2::ECP2::generator(),
            },
            set_i: HashMap::new(),
        }
    }

    // Key generation function for EA
    pub fn IA_key_gen(&mut self) {
        // Generate a random secret key
        let attribute = 1;
        let (sk_x2, sk_id, sk_epoch, sk_k1, pk_X2, pk_id, pk_epoch, pk_K1, g2) =
            DGSA::keygen(attribute);
        let mut set_i: HashMap<(u128, u128), BIG> = HashMap::new();

        self.IASecretKey = IASecretKey {
            sk_x2,
            sk_id,
            sk_epoch,
            sk_k1,
        };
        self.IAPublicKey = IAPublicKey {
            pk_X2,
            pk_id,
            pk_epoch,
            pk_K1,
            g2,
        };
        self.set_i = set_i;
    }

    pub fn verify_authorization(
        e_pk: &ECP2,
        vid: u128,
        v_pk: &ECP2,
        epoch: u128,
        sig_e: &ECP,
        sig_v: &ECP,
    ) -> bool {
        let check_vid_vpk = BLS::bls_verify_vid_vpk(e_pk, vid, v_pk.clone(), sig_e);
        let check_e = BLS::bls_verify_epoch(v_pk, epoch, sig_v);

        check_e && check_vid_vpk
    }

    pub fn compute_sigma(
        &mut self,
        mut rng: &mut XorShiftRng,
        vid: u128,
        epoch: u128,
    ) -> Option<(BIG, ECP, ECP)> {
        if let Some(((a_dash, h, sigma_2), updated_set)) =
            DGSA::issue_i(&self.IASecretKey, &vid, &epoch, &mut self.set_i)
        {
            self.set_i = updated_set.clone();
            let sigma = (a_dash.clone(), h.clone(), sigma_2.clone());
            println!("DGSA Issuance Successful");
            Some(sigma)
        } else {
            println!("DGSA Issuance Failed: Key (id, epoch) is present in the map");
            None
        }
    }
}
