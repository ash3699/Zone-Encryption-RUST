extern crate aes_gcm_siv;
extern crate rand;
extern crate sha2;

use crate::{
    util::{self, combine_vec_u128, g2_to_vec_u128, gen_random_fr, mul_g1_fr, CertV, IAPublicKey, fr_zero},
    BLS, DAE, DGSA, PKE, SE,
};
use aes_gcm_siv::{
    aead::{Aead, NewAead, Payload},
    Aes128GcmSiv,
};

use rand::{Rng, SeedableRng, XorShiftRng};
use sha2::digest::{
    consts::U12,
    generic_array::{self, GenericArray},
};
use std::mem;
use std::time::{Duration, Instant};
use std::{
    collections::{HashMap, HashSet},
    string,
};
use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;

pub struct Veh {
    pub v_id: u128,
    v_sk: BIG,
    pub v_pk: ECP2,
    pub sig_e: ECP,
    pub cred: (u128, u128, (BIG, ECP, ECP)),
    pub pke_ek: ECP2,
    pke_dk: BIG,
}

impl Veh {
    // Constructor for EA that initializes sk and pk to default values
    pub fn new() -> Self {
        Veh {
            v_id: 0,
            v_sk: fr_zero(), // Initialize sk to zero (or any default value)
            v_pk: ecp2::ECP2::generator(), // Initialize pk to zero (or any default value)
            sig_e: ecp::ECP::generator(),
            cred: (0, 0, (fr_zero(), ecp::ECP::generator(), ecp::ECP::generator())),
            pke_ek: ecp2::ECP2::generator(),
            pke_dk: fr_zero(),
        }
    }

    // Key generation function for EA
    pub fn Veh_key_gen(&mut self, rng: &mut XorShiftRng, id: u128) {
        // Generate a random secret key
        let (pk, sk) = BLS::bls_key_gen();
        self.v_sk = sk;
        self.v_pk = pk;
        self.v_id = id;
    }

    pub fn SIG_verify(&mut self, e_pk: &ECP2, sig: &ECP) -> Option<CertV> {
        let verify = BLS::bls_verify_vid_vpk(e_pk, self.v_id, self.v_pk.clone(), sig);
        if verify {
            self.sig_e = sig.clone();
            println!("Verification Successful for vehicle {}\n", self.v_id);
            Some(CertV {
                sk: self.v_sk,
                pk: self.v_pk.clone(),
                sig_e: sig.clone(),
            })
        } else {
            println!("Verification Failed for vehicle {}\n", self.v_id);
            None
        }
    }

    pub fn SIG_sig_epoch(&mut self, epoch: u128) -> ECP {
        let signature_epoch = BLS::bls_sign_epoch(&self.v_sk, epoch);
        if let sig = &signature_epoch {
            println!("Signing Successful for epcoch {}\n", epoch);
        } else {
            println!("Signing Failed for epoch {}\n", epoch);
        }
        signature_epoch
    }

    pub fn get_cred(
        &mut self,
        sigma: &(BIG, ECP, ECP),
        IAPublicKey: &IAPublicKey,
        epoch: u128,
    ) -> Option<(u128, u128, (BIG, ECP, ECP))> {
        let result = DGSA::issue_v(&sigma, &self.v_id, &epoch, self.v_pk.clone(), IAPublicKey);
        // println!("Verification result: {:?}", result);

        if result {
            let cred = Some((self.v_id.clone(), epoch.clone(), sigma.clone()));
            self.cred = cred.clone().unwrap();
            cred
        } else {
            println!("Verification Failed\n");
            None
        }
    }

    pub fn Vehicle_PKE_Key_gen(&mut self, rng: &mut XorShiftRng) -> (ECP2, BIG) {
        let (pke_pk, pke_sk) = PKE::pke_key_gen(rng);
        self.pke_ek = pke_pk.clone();
        self.pke_dk = pke_sk;
        (pke_pk, pke_sk)
    }

    fn create_m_from_pk(&mut self) -> (u128, (BIG, ECP, ECP), u128, u128) {
        let (cred_vid, cred_epoch, sigma) = self.cred.clone();
        let pke_pk_u128_vec = util::g2_to_vec_u128(&self.pke_ek);
        let pke_pk_u128 = util::combine_vec_u128(&pke_pk_u128_vec);

        let m = cred_vid + cred_epoch + pke_pk_u128;
        (m, sigma, cred_epoch, cred_vid)
    }

    fn create_m_from_encrypted_zk(
        &mut self,
        zpk_encrypt_ct: u128,
    ) -> (u128, (BIG, ECP, ECP), u128, u128) {
        let (cred_wid, cred_wepoch, sigma_w) = self.cred.clone();
        let m = cred_wid + cred_wepoch + zpk_encrypt_ct;
        (m, sigma_w, cred_wepoch, cred_wid)
    }

    pub fn generate_token_m(
        &mut self,
        rng: &mut XorShiftRng,
        IAPublicKey: &IAPublicKey,
        f: bool,
        zpk_encrypt_ct: u128,
    ) -> ((ECP, ECP, (BIG, (BIG, BIG))), u128) {
        let m;
        let sigma;
        let cred_epoch;
        let cred_id;
        if f {
            (m, sigma, cred_epoch, cred_id) = self.create_m_from_pk();
        } else {
            (m, sigma, cred_epoch, cred_id) = self.create_m_from_encrypted_zk(zpk_encrypt_ct);
        }
        
        let token = DGSA::auth(rng, &m, &sigma, &cred_id, &cred_epoch, &IAPublicKey);


        (token, m)
    }

    pub fn verify_token(
        token: (ECP, ECP, (BIG, (BIG, BIG))),
        IAPublicKey: &IAPublicKey,
        message: u128,
        epoch: u128,
    ) -> bool {
        let (sigma_v1_dash, sigma_v2_dash, pie_v) = token;
        let is_valid = DGSA::Vf(
            &sigma_v1_dash,
            &sigma_v2_dash,
            &pie_v,
            IAPublicKey.clone(),
            message,
            &epoch,
        );

        is_valid
    }

    pub fn Zone_sk_PKE_encryption(rng: &mut XorShiftRng, pke_ek: ECP2, zone_pre_sk: &ECP2) -> (ECP2, ECP2) {
        let (zpk_encrypted_c1, zpk_encrypted_c2) = PKE::pke_encrypt( pke_ek, zone_pre_sk.clone());
        (zpk_encrypted_c1, zpk_encrypted_c2)
    }

    pub fn Zone_sk_PKE_decryption(pke_dk: BIG, zpk_encrypted_c1: ECP2, zpk_encrypted_c2: ECP2) -> ECP2 {
        PKE::pke_decrypt(&pke_dk, (zpk_encrypted_c1, zpk_encrypted_c2))
    }
    pub fn SE_Key_gen(
        rng: &mut XorShiftRng,
    ) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
        let key: [u8; 16] = rng.gen();
        let kp = GenericArray::clone_from_slice(&key);
        kp
    }
    pub fn SE_encryption(
        payload: &str,
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    ) -> (Vec<u8>, GenericArray<u8, U12>) {
        let (cipher_payload_v, nonce_payload_v) = SE::encrypt(kp, payload);
        (cipher_payload_v, nonce_payload_v)
    }

    pub fn SE_decryption(
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        nonce: &GenericArray<u8, <Aes128GcmSiv as Aead>::NonceSize>,
        ciphertext: &[u8],
    ) -> String {
        let payload = SE::decrypt(kp, &nonce, &ciphertext);
        payload
    }

    pub fn DAE_encryption(
        Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        kp: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
    ) -> (Vec<u8>, GenericArray<u8, U12>) {
        DAE::encrypt(Zpk, kp)
    }

    pub fn DAE_decryption(
        Zpk: GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>,
        cipher_kp: (GenericArray<u8, generic_array::typenum::U12>, Vec<u8>),
    ) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
        let decrypted_kp = DAE::decrypt(Zpk, cipher_kp);
        decrypted_kp
    }
}
