extern crate bit_vec;
extern crate blake2;
extern crate byteorder;
extern crate pairing;
extern crate rand;

use rand::{SeedableRng, XorShiftRng};
use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::util::{self, *};
//use crate::IA;

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


pub fn keygen( k: usize) -> (BIG, BIG, BIG, BIG, ECP2, ECP2, ECP2, ECP2, ECP2) {
    let g2 = ecp2::ECP2::generator();

    // sk
    let x2 = gen_random_fr();
    let y_id = gen_random_fr();
    let y_epoch = gen_random_fr();
    let y_k1 = gen_random_fr();

    // pk
    let X2 = mul_g2_fr(&g2, &x2);
    let Y_id = mul_g2_fr(&g2, &y_id);
    let Y_epoch = mul_g2_fr(&g2, &y_epoch);
    let Y_K1 = mul_g2_fr(&g2, &y_k1);

    (x2, y_id, y_epoch, y_k1, X2, Y_id, Y_epoch, Y_K1, g2)
}
pub fn issue_i<'a>(
    IASecretKey: &IASecretKey,
    id: &u128,
    epoch: &u128,
    set: &mut HashMap<(u128, u128), BIG>,
) -> Option<((BIG, ECP, ECP), HashMap<(u128, u128), BIG>)> {
    let a_dash = gen_random_fr();

    if set.contains_key(&(*id, *epoch)) {
        println!("The key (id, epoch) is present in the map.");
        return None; // Exit the function early if the key is present
    } else {
        // println!("The key (id, epoch) is not present in the map.");
        set.insert((*id, *epoch), a_dash.clone());
    }

    let h = ecp::ECP::generator();

    // converting id and epoch to field element
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);

    let mut pw = IASecretKey.sk_x2.clone();
    pw = add_fr_fr(pw, &mul_fr_fr(&id_fr, &IASecretKey.sk_id));
    pw = add_fr_fr(pw, &mul_fr_fr(&epoch_fr, &IASecretKey.sk_epoch));
    pw = add_fr_fr(pw, &mul_fr_fr(&a_dash, &IASecretKey.sk_k1));

    let sigma_2 = mul_g1_fr(&h, &pw);

    let sigma = (a_dash, h, sigma_2);

    // println!("{}", { "\nISSUE_I......\n" });
    //  print_fr("a_dash", &a_dash);
    //  print_g1("h", &h);
    //  print_fr("pw", &pw);
    //  print_g1("sigma_2", &sigma_2);

    Some((sigma, set.clone()))
}
pub fn issue_v(
    sigma: &(BIG, ECP, ECP),
    id: &u128,
    epoch: &u128,
    ek: ECP2,
    IAPublicKey: &IAPublicKey,
) -> bool {
    // converting id and epoch to field element
    let (a_dash, h, sigma_2) = sigma;
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);
    let ek_u128_vec = convert_g2_to_fr(&ek);

    let mut XYY = IAPublicKey.pk_X2.clone();

    XYY = add_g2_g2(&mut XYY, &mul_g2_fr(&IAPublicKey.pk_id, &id_fr));
    XYY = add_g2_g2(&mut XYY, &mul_g2_fr(&IAPublicKey.pk_epoch, &epoch_fr));
    XYY = add_g2_g2(&mut XYY, &mul_g2_fr(&IAPublicKey.pk_K1, a_dash));

    let pair1 = do_pairing(&h, &XYY);
    let pair2 = do_pairing(&sigma_2, &IAPublicKey.g2);

    pair1.equals(&pair2)
}

pub fn auth(
    rng: &mut XorShiftRng,
    m: &u128,
    sigma: &(BIG, ECP, ECP),
    id: &u128,
    epoch: &u128,
    IAPublicKey: &IAPublicKey,
) -> (ECP, ECP, (BIG, (BIG, BIG))) {
    let start = Instant::now();
    let (a_dash, sigma_1, sigma_2) = sigma;
    let id_fr = int_to_fr(id);
    let epoch_fr = int_to_fr(epoch);

    let r = gen_random_fr();

    let sigma_1_dash = mul_g1_fr(sigma_1, &r);
    let sigma_2_dash = mul_g1_fr(sigma_2, &r);
    
    let s_id = gen_random_fr();
    let s_a_dash = gen_random_fr();

    let mut p1 = do_pairing(
        &mul_g1_fr(&sigma_1_dash, &s_id),
        &IAPublicKey.pk_id
    );
    let p2 = do_pairing(
        &mul_g1_fr(&sigma_1_dash, &s_a_dash),
        &IAPublicKey.pk_K1
    );

    let mut u = mul_fq12_fq12(&mut p1, &p2);
    // println!("u: {:?}\n", u);
    // println!("m: {:?}", m);
        
    
    let c = combine_to_fr(
        &mut u,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &IAPublicKey.pk_X2,
        &IAPublicKey.pk_epoch,
        &IAPublicKey.pk_id,
        &IAPublicKey.pk_K1,
    );

    // let test0 = util::minus_fr_fr(int_to_fr(&1), &int_to_fr(&1));
    // println!("test0: {:?}\n", test0);

    let vid = minus_fr_fr(s_id, &mul_fr_fr(&c, &id_fr));
    let va_dash = minus_fr_fr(s_a_dash, &mul_fr_fr(&c, &a_dash));
    // println!("vid {:?}\n", vid);
    // println!("va_dash {:?}\n", va_dash);

    ////////////////////////////////////////////////////////////////////////

    /////////////////////////////////////////////////////////////
    let v = (vid, va_dash);

    let pie = (c, v);

    // println!("pie {:?}\n", pie);
    let token = (sigma_1_dash, sigma_2_dash, pie);
    let duration_v = start.elapsed();

    println!("Time taken for auth**************************11111111111111111111111************** : {:.2?}", duration_v);

    // Output the results
    // println!("{}", { "\nAUTH......\n" });
    token
}

pub fn Vf(
    sigma_1_dash: &ECP,
    sigma_2_dash: &ECP,
    pie: &(BIG, (BIG, BIG)),
    IAPublicKey: IAPublicKey,
    m: u128,
    epoch: &u128,
) -> bool {
    // println!("pie {:?}\n", pie);
    // println!("sigma_1_dash {:?}\n", sigma_1_dash);
    // println!("sigma_2_dash {:?}\n", sigma_2_dash);
    let start = Instant::now();
    let (c, v) = pie; // Destructure the tuple into its components

    let (vid, va_dash) = v;
    // println!("vid {:?}\n", vid);
    // println!("va_dash {:?}\n", va_dash);
    let epoch_fr = int_to_fr(epoch);

    let mut p1 = do_pairing(
        &mul_g1_fr(sigma_1_dash, &vid),
        &IAPublicKey.pk_id
    );

    let mut p2 = do_pairing(
        &mul_g1_fr(sigma_1_dash, &va_dash),
        &IAPublicKey.pk_K1
    );

    let mut p3 = do_pairing(
        &mul_g1_fr(sigma_2_dash, &c),
        &IAPublicKey.g2
    );

    // let inv: u128 = -1;
    let mut XY_inverse = mul_g2_fr(&IAPublicKey.pk_X2, &int_to_fr_negate(&1));

    let mut temp = epoch_fr.clone();

    let mut epoch_neg = fr_inv(&mut temp);
    
    XY_inverse = add_g2_g2(&mut XY_inverse, &mul_g2_fr(&IAPublicKey.pk_epoch, &epoch_neg));

    let mut p4 = do_pairing(
        &mul_g1_fr(sigma_1_dash, &c),
        &XY_inverse
    );

    let mut u1 = mul_fq12_fq12(&mut p1, &mut mul_fq12_fq12(&mut p2, &mut mul_fq12_fq12(&mut p3, &mut p4)));
    // println!("{:?}", u1);
    // println!("u1: {:?}\n", u1);
    // println!("m: {:?}", m);
    let c1 = combine_to_fr(
        &mut u1,
        &epoch_fr,
        &m,
        &sigma_1_dash,
        &sigma_2_dash,
        &IAPublicKey.pk_X2,
        &IAPublicKey.pk_epoch,
        &IAPublicKey.pk_id,
        &IAPublicKey.pk_K1,
    );

    // println!("{}", { "\nVF......\n" });

    // print_fr("c", c);
    // print_fr("c1", &c1);
    //  print_fr("c2", &c2);
    let duration_v = start.elapsed();
    println!("Time taken for verification**************************11111111111111111111111************** : {:.2?}", duration_v);
    fr_equals(c, &c1)
}
