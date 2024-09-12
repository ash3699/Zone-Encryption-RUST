extern crate bit_vec;
extern crate rand_core;
extern crate rand;
extern crate blake2;
extern crate byteorder;

use mcore::bn254::big;
use mcore::bn254::big::BIG;
use mcore::bn254::dbig::DBIG;
use mcore::bn254::ecp;
use mcore::bn254::ecp::ECP;
use mcore::bn254::ecp2;
use mcore::bn254::ecp2::ECP2;
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

pub const MODBYTES: usize = 32;
pub const BASEBITS: usize = 56;
pub const NLEN: usize = 1 + ((8 * MODBYTES - 1) / BASEBITS);
pub const DNLEN: usize = 2 * NLEN;

pub fn do_pairing(g_1: &ECP, g_2: &ECP2) -> FP12 {
    let mut p1 = pair::ate(g_2, g_1);
    p1 = pair::fexp(&p1);
    p1
}

 
pub fn gen_random_fr() -> BIG {
    let max = big::BIG::new_ints(&rom::CURVE_ORDER);
    let mut rng = RAND_impl::new();
    rng.seed(32, &rand::thread_rng().gen::<[u8; 32]>());
    let r = big::BIG::randomnum(&max, &mut rng);
    r
    
}
 
pub fn gen_random_g1() -> ECP {
    let g1 = ecp::ECP::generator();
    let r = gen_random_fr();
    mul_g1_fr(&g1, &r)
}

pub fn gen_random_g2() -> ECP2 {
    let g2 = ecp2::ECP2::generator();
    let r = gen_random_fr();
    mul_g2_fr(&g2, &r)
}

/*  
pub fn gen_random_gt(rng: &mut XorShiftRng) -> Fq12 {
    let sk = Fq12::rand(rng);
    sk
}
*/  

pub fn fr_zero() -> BIG{
    let mut z = gen_random_fr();
    z.zero();
    z
}

pub fn mul_fr_fr(a: &BIG, b: &BIG) -> BIG {
    big::BIG::smul(&a, &b)
}
    
 
pub fn mul_g1_fr(a: &ECP, b: &BIG) -> ECP {
    pair::g1mul( a, b)
}


pub fn mul_g2_fr(a: &ECP2, b: &BIG) -> ECP2 {
    pair::g2mul(a, b)
}

pub fn add_fr_fr(a: BIG, b: &BIG) -> BIG {
    a.plus(b)
}

pub fn fr_equals(r: &BIG, l: &BIG) -> bool{
    for i in 0..NLEN {
        if r.w[i] != l.w[i] { return false }
    }
    true
}
 

pub fn minus_fr_fr(a: BIG, b: &BIG) -> BIG {
    a.minus(b)
}

pub fn add_g1_g1(a: &mut ECP, b: &ECP) -> ECP {
    a.add(b);
    a.clone()
    
}

pub fn minus_g1_g1(a: &mut ECP, b: &ECP) -> ECP {
    a.sub(b);
    a.clone()
} 

pub fn add_g2_g2(a: &mut ECP2, b: &ECP2) -> ECP2 {
    a.add(b);
    a.clone()
}

/*  
pub fn add_fq12_fq12(a: FP12, b: FP12) -> FP12 {
    let mut r = &mut a.clone();
    r.add_assign(&b);
    return *r;
}
    
 
pub fn minus_fq12_fq12(a: Fq12, b: Fq12) -> Fq12 {
    let mut r = &mut a.clone();

    r.sub_assign(&b);

    return *r;
}

*/

pub fn mul_fq12_fq12(a: &mut FP12, b: &FP12) -> FP12 {
    a.mul(b);
    a.clone()
}


pub fn fr_inv(a: &mut BIG) -> &BIG {
    a.invmod2m();
    a
}
 
pub fn g1_neg(a: &mut ECP) -> &ECP {
    a.neg();
    a
}

 
pub fn g2_neg(a: &mut ECP2) -> &ECP2 {
    a.neg();
    a
}
 
pub fn fq12_inv(a: &mut FP12) -> &FP12 {
    a.inverse();
    a
}

/* 

pub fn print_fr(s: &str, a: &Fr) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element fr:{:?}", *a);
    println!();
}

pub fn print_g1(s: &str, a: &G1) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element g1:{:?}", *a);
    println!();
}

pub fn print_g2(s: &str, a: &G2) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element g2:{:?}", *a);
    println!();
}
pub fn print_gt(s: &str, a: &Fq12) -> () {
    if s != "" {
        println!("This is:{:?}", s);
    }
    println!("element gt:{:?}", *a);
    println!();
}

*/


pub fn int_to_fr(i: &u128) -> BIG {
    big::BIG::fromstring(i.to_string())
}

 
pub fn int_to_fr_negate(i: &i64) -> BIG {
    let mut neg = big::BIG::fromstring(i.to_string());
    let mut z = big::BIG::new();
    z.zero();
    z.minus(&neg)

}

pub fn fr_neg(x: &BIG) -> BIG {
    let mut z = big::BIG::new();
    z.zero();
    z.minus(&x)
}



// Function to convert Fq element to bytes
pub fn fq_to_bytes(a: &mut FP12) -> [u8; 12*(big::MODBYTES as usize)] {
    const MB:usize = 12*(big::MODBYTES as usize);
    let mut w: [u8; MB] = [0; MB];
    a.tobytes(&mut w);
    w
}

pub fn to_big(dbig: &DBIG) -> [BIG; 2] {
    let mut big1 = BIG { w: [0; NLEN] };
    for i in 0..NLEN {
        big1.w[i] = dbig.w[i];
    }
    let mut big2 = BIG { w: [0; NLEN] };
    for i in NLEN..DNLEN {
        big2.w[i-NLEN] = dbig.w[i];
    }
    [big1, big2]
}
 
// Function to convert bytes to BitVec
pub fn convert_to_bits(bytes: &[u8]) -> BitVec {
    let mut bits = BitVec::new();
    for &byte in bytes {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1 == 1);
        }
    }
    bits
}

 
// Function to convert Fq12 element to BitVec
pub fn fq12_to_bits(fq12: &mut FP12) -> BitVec {
    let mut bits = BitVec::new();
    bits.extend(convert_to_bits(&fq_to_bytes(fq12)));
    bits
}

 

// Function to convert Fr element to bytes
pub fn fr_to_bytes(a: &BIG) -> [u8; 32] {
    let mut w: [u8; 32] = [0; 32];
    a.tobytes(&mut w);
    w
}

pub fn g1_to_bytes(a: &ECP) -> [u8; 65] {
    let mut w: [u8; 65] = [0; 65];
    a.tobytes(&mut w, false);
    w
}

// Function to convert G1 element to BitVec
pub fn g1_to_bits(g1: &ECP) -> BitVec {
    let mut bits = BitVec::new();
    bits.extend(convert_to_bits(&g1_to_bytes(&g1)));
    bits
}

pub fn g2_to_bytes(a: &ECP2) -> [u8; 129] {
    let mut w: [u8; 129] = [0; 129];
    a.tobytes(&mut w, false);
    w
} 

// Function to convert G2 element to BitVec
pub fn g2_to_bits(g2: &ECP2) -> BitVec {
    let mut bits = BitVec::new();
    bits.extend(convert_to_bits(&g2_to_bytes(&g2)));
    bits
}


pub fn combine_to_fr(
    u: &mut FP12,
    epoch_fr: &BIG,
    m: &u128,
    sigma_1_dash: &ECP,
    sigma_2_dash: &ECP,
    X2: &ECP2,
    Y_epoch: &ECP2,
    Y_id: &ECP2,
    Y_K1: &ECP2,
) -> BIG {
    let mut combined_bits = BitVec::new();

    // Hash the combined bytes to 256 bits
    let mut hasher = Sha256::new();
    hasher.update(u.tostring());
    hasher.update(epoch_fr.tostring());
    hasher.update(m.to_le_bytes());
    hasher.update(sigma_1_dash.to_string());
    hasher.update(sigma_2_dash.to_string());
    hasher.update(X2.to_string());
    hasher.update(Y_epoch.to_string());
    hasher.update(Y_K1.to_string());
    hasher.update(Y_id.to_string());
    let hash_result = hasher.finalize();

    assert!(
        hash_result.len() == 32,
        "Hash result should be 32 bytes long"
    );

    // Create an array of u64 from the hash result
    let mut repr = [0u8; 32];
    for (i, chunk) in hash_result.chunks(1).enumerate() {
        repr[i] = u8::from_le_bytes(chunk.try_into().expect("Chunk should be 1 bytes long"));
        println!("{:?}", repr[i]);
    }
    // println!("{:?}", repr);
    // Loop through repr array and convert each element to Fr
    let mut combined_fr = big::BIG::new();
    
    let fr_value = big::BIG::frombytes(&repr);
    combined_fr.add(&fr_value);
    
    combined_fr
}



/// Hashes an element in G2 to a GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize>
pub fn hash_g2_to_aes_key(g2: &ECP2) -> GenericArray<u8, <Aes128GcmSiv as NewAead>::KeySize> {
    let bits = g2_to_bits(g2);
    let element_bytes: Vec<u8> = bits.iter().map(|bit| if bit { 1 } else { 0 }).collect();

    // Hash the bytes using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&element_bytes);
    let result = hasher.finalize();

    let truncated_result = &result[..16]; // Take the first 16 bytes

    let key = GenericArray::clone_from_slice(truncated_result);

    key
}

 

pub fn hash_vec_to_g1(vec: Vec<u128>) -> ECP {
    let id_vk = vec.into_iter().fold(0u128, |acc, x| acc.wrapping_add(x));
    hash_int_to_g1(id_vk)
} 

pub fn hash_int_to_g1(id: u128) -> ECP {
    let id_fr = int_to_fr(&id);
    let h = ecp::ECP::generator();
    mul_g1_fr(&h, &id_fr)
}



pub fn g2_to_vec_u128(g2: &ECP2) -> Vec<u128> {
    let g2_bitvec = g2_to_bits(&g2);
    let g2_vec = bitvec_to_vec_u128(&g2_bitvec);
    g2_vec
}

 

pub fn combine_vec_u128(vec: &Vec<u128>) -> u128 {
    // Check the length of the vector and handle accordingly
    if vec.is_empty() {
        return 0; // or handle as needed for an empty vector
    } else if vec.len() == 1 {
        return vec[0]; // Only one element, return it as is
    }

    // Combine the first two elements
    let high = vec[0];
    let low = vec[1];

    // Shift the high part and OR with the low part
    (high << 64) | low
}

pub fn bitvec_to_vec_u128(bits: &BitVec) -> Vec<u128> {
    let mut result = Vec::new();
    let mut chunk: u128 = 0;
    let mut count = 0;

    for bit in bits.iter() {
        // Set the corresponding bit in the current chunk
        if bit {
            chunk |= 1 << (count % 128);
        }

        // Increment the count
        count += 1;

        // If we've processed 128 bits, push the chunk to the result vector
        if count % 128 == 0 {
            result.push(chunk);
            chunk = 0;
        }
    }

    // If there are remaining bits, push the last chunk
    if count % 128 != 0 {
        result.push(chunk);
    }

    result
}

 
pub fn convert_g2_to_fr(ek: &ECP2) -> BIG {
    let ek_u128_vec = g2_to_vec_u128(ek);
    let mut ek_u128 = combine_vec_u128(&ek_u128_vec);
    int_to_fr(&ek_u128)
}
 
pub fn Hash_into_Fr(commit: ECP, Y: Vec<ECP>) -> (BIG) {
    let mut combined_bits = BitVec::new();

    combined_bits.extend(g1_to_bits(&commit));

    for i in Y {
        combined_bits.extend(g1_to_bits(&i));
    }

    let combined_bytes = combined_bits.to_bytes();

    let mut hasher = Sha256::new();
    hasher.update(&combined_bytes);
    let hash_result = hasher.finalize();

    assert!(
        hash_result.len() == 32,
        "Hash result should be 32 bytes long"
    );

    let mut repr = [0u8; 32];
    for (i, chunk) in hash_result.chunks(1).enumerate() {
        repr[i] = u8::from_le_bytes(chunk.try_into().expect("Chunk should be 1 bytes long"));
        println!("{:?}", repr[i]);
    }
    
    let mut combined_fr = big::BIG::new();
    
    let fr_value = big::BIG::frombytes(&repr);
    combined_fr.add(&fr_value);
    
    combined_fr
}

 
pub fn MP_Hash_into_Fr(u: &mut FP12, p1: &ECP, p2: &ECP, s1: &ECP, s2: &ECP, c1: &ECP, c2: &ECP,  pk: &PS_pk ) -> BIG{
    let mut combined_bits = BitVec::new();

    combined_bits.extend(fq12_to_bits(u));
    combined_bits.extend(g1_to_bits(&p1));
    combined_bits.extend(g1_to_bits(&p2));
    combined_bits.extend(g1_to_bits(&s1));
    combined_bits.extend(g1_to_bits(&s2));
    combined_bits.extend(g1_to_bits(&c1));
    combined_bits.extend(g1_to_bits(&c2)); 
    combined_bits.extend(g1_to_bits(&pk.g));
    combined_bits.extend(g2_to_bits(&pk.g_dash));
    combined_bits.extend(g2_to_bits(&pk.X_dash));
    for i in &pk.Y {
        combined_bits.extend(g1_to_bits(&i));
    }
    for i in &pk.Y_dash {
        combined_bits.extend(g2_to_bits(&i));
    }
    

    let combined_bytes = combined_bits.to_bytes();

    let mut hasher = Sha256::new();
    hasher.update(&combined_bytes);
    let hash_result = hasher.finalize();

    assert!(
        hash_result.len() == 32,
        "Hash result should be 32 bytes long"
    );

    let mut repr = [0u64; 4];
    for (i, chunk) in hash_result.chunks(8).enumerate() {
        repr[i] = u64::from_le_bytes(chunk.try_into().expect("Chunk should be 8 bytes long"));
    }

    let mut repr = [0u8; 32];
    for (i, chunk) in hash_result.chunks(1).enumerate() {
        repr[i] = u8::from_le_bytes(chunk.try_into().expect("Chunk should be 1 bytes long"));
        println!("{:?}", repr[i]);
    }
    
    let mut combined_fr = big::BIG::new();
    
    let fr_value = big::BIG::frombytes(&repr);
    combined_fr.add(&fr_value);
    
    combined_fr
}

 
pub fn wt_Hash_into_Fr(r21: &ECP, r22: &ECP, r3: &mut FP12, a2_hat: &ECP2, b1_hat: &ECP, b2_hat: &ECP, g_hat: &ECP, h2: &ECP2 , h_hat: &ECP2) -> BIG{
    let mut combined_bits = BitVec::new();

    combined_bits.extend(fq12_to_bits(r3));
    combined_bits.extend(g1_to_bits(&r21));
    combined_bits.extend(g1_to_bits(&r22));
    combined_bits.extend(g1_to_bits(&b1_hat));
    combined_bits.extend(g1_to_bits(&b2_hat));
    combined_bits.extend(g1_to_bits(&g_hat));
    combined_bits.extend(g2_to_bits(&a2_hat));
    combined_bits.extend(g2_to_bits(&h2));
    combined_bits.extend(g2_to_bits(&h_hat));

    let combined_bytes = combined_bits.to_bytes();

    let mut hasher = Sha256::new();
    hasher.update(&combined_bytes);
    let hash_result = hasher.finalize();

    assert!(
        hash_result.len() == 32,
        "Hash result should be 32 bytes long"
    );

    let mut repr = [0u64; 4];
    for (i, chunk) in hash_result.chunks(8).enumerate() {
        repr[i] = u64::from_le_bytes(chunk.try_into().expect("Chunk should be 8 bytes long"));
    }

    let mut repr = [0u8; 32];
    for (i, chunk) in hash_result.chunks(1).enumerate() {
        repr[i] = u8::from_le_bytes(chunk.try_into().expect("Chunk should be 1 bytes long"));
        println!("{:?}", repr[i]);
    }
    
    let mut combined_fr = big::BIG::new();
    
    let fr_value = big::BIG::frombytes(&repr);
    combined_fr.add(&fr_value);
    
    combined_fr
}


/* 
pub fn get_random_rng() -> XorShiftRng{
   let mut rng = thread_rng();
   let seed: [u32; 4] = rng.gen();
   XorShiftRng::from_seed(seed)

}
   */
 
#[derive(Clone, Debug)]
pub struct CertV {
    pub sk: BIG,
    pub pk: ECP2,
    pub sig_e: ECP,
}
#[derive(Clone, Debug)]
pub struct IASecretKey {
    pub sk_x2: BIG,
    pub sk_id: BIG,
    pub sk_epoch: BIG,
    pub sk_k1: BIG,
}
#[derive(Clone, Debug)]
pub struct IAPublicKey {
    pub pk_X2: ECP2,
    pub pk_id: ECP2,
    pub pk_epoch: ECP2,
    pub pk_K1: ECP2,
    pub g2: ECP2,
}

pub struct PS_sk {
    pub X: ECP,
}
#[derive(Clone, Debug)]
pub struct PS_pk {
    pub g: ECP,
    pub g_dash: ECP2,
    pub Y: Vec<ECP>,
    pub X_dash: ECP2,
    pub Y_dash: Vec<ECP2>,
}


