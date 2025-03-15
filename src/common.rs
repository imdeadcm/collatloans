use sha2::{digest::Digest, Sha256};

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G2Projective, G2Affine, G1Affine, Scalar,
};
use bls12_381::{multi_miller_loop, G1Projective, G2Prepared, Gt};

use crate::schnorradaptor::SchnorrPreSig;
use crate::wes::WESCiphertext;

use rand::rngs::OsRng;

use secp256kfun::{g,  Scalar as ChainScalar, G, Point};
use secp256kfun::marker::*;

use group::Group;
use ff::Field;

pub struct Precomp{
    pub c1: G1Affine,
    pub c3: [u8; 32],
    pub r1: Scalar,
    pub r2:Gt,
    pub ri: ChainScalar,
    pub ri_pub: Point
}

pub struct MessagesAL{
    pub j: usize,
    pub state: String,
    pub transition: String,
    pub statement: Point,
    pub witness: ChainScalar,

}


pub fn wes_precompute(g2_prepared: &G2Prepared) -> Precomp {

    let ri = sample_rand_chain_scalar();
    let ri_pub = g!(ri * G).normalize();

    let r1 = sample_rand_scalar();
    let r2 = sample_rand_gt(g2_prepared);

    let c1 = G1Affine::from(G1Affine::generator() * &r1);

    let mut h_xor_sec = gt_to_bytes(&r2);

    for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(&ri.to_bytes()) {
        *xor_byte ^= ri_byte
    }

    let c3 = h_xor_sec.try_into().unwrap();

    Precomp{
        c1,
        c3,
        r1,
        r2,
        ri,
        ri_pub,
    }

}

pub fn sample_rand_gt( g2prepared: &G2Prepared)-> Gt{
    let gt_elem = {
        let g1 = G1Affine::from(G1Projective::random(&mut OsRng));
        multi_miller_loop(&[(&g1, g2prepared)]).final_exponentiation()
    };

    gt_elem

}

pub fn sample_rand_scalar()-> Scalar{

    let scalar =  Scalar::random(&mut OsRng);

    scalar
}

pub fn sample_rand_chain_scalar()-> ChainScalar{

    let scalar =  ChainScalar::random(&mut OsRng);

    scalar
}

pub fn gt_to_bytes(r2: &Gt)-> [u8; 32]{

    let r2_bytes_t = Sha256::default()
        .chain(r2.to_compressed())
        .finalize();

    let r2_bytes = r2_bytes_t.try_into().unwrap();

    r2_bytes
    
}


pub fn hash_to_g2(m: &str)->G2Affine{

    <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(m,b"bls-sig").into()

}

fn bytes_to_bits(bytes: &[u8]) -> Vec<bool> {
    let mut bits = Vec::new();
    for byte in bytes {
        for i in 0..8 {
            bits.push((byte >> (7 - i)) & 1 == 1);
        }
    }
    bits
}

// For the moment, it does not take the WES ciphertexts as input, I will modify it at a later moment.

pub fn hash_to_bits(cis:&Vec<WESCiphertext>, ri_pub:Vec<Point>, c_omega: ChainScalar<Secret, Zero>, xa: Point, xw: Point, y_pub: Point, sigma_tilde: &SchnorrPreSig ) ->Vec<bool>{

    // Step 1: Serialize all inputs into bytes
    let mut serialized_data = Vec::new();

    // Serialize ci's
    for ci in cis {
        let c1_bytes = Sha256::default()
        .chain(ci.c1.to_compressed())
        .finalize();
        serialized_data.extend(c1_bytes);
        let c2_bytes = gt_to_bytes(&ci.c2);
        serialized_data.extend(c2_bytes);
        serialized_data.extend(ci.c3);
    }

    // Serialize ri_pub
    for point in ri_pub {
        let point_bytes = point.to_bytes();
        serialized_data.extend(point_bytes);
    }

    // Serialize c_omega
    let scalar_bytes = c_omega.to_bytes();
    serialized_data.extend(scalar_bytes);

    // Serialize xa
    let xa_bytes = xa.to_bytes();
    serialized_data.extend(xa_bytes);

    // Serialize xb
    let xw_bytes = xw.to_bytes();
    serialized_data.extend(xw_bytes);

    // Serialize y_pub
    let y_pub_bytes = y_pub.to_bytes();
    serialized_data.extend(y_pub_bytes);

    // Serialize presig
    let sigmas_bytes = sigma_tilde.s.to_bytes();
    serialized_data.extend(sigmas_bytes);
    let sigmar_bytes = sigma_tilde.r.to_bytes();
    serialized_data.extend(sigmar_bytes);

    // Step 2: Hash the concatenated serialized data
    let mut hasher = Sha256::new();
    hasher.update(&serialized_data);
    let hash_result = hasher.finalize();

 
    // Step 3: Convert the hash output to bits
    bytes_to_bits(&hash_result)



}

pub fn schnorr_hash(pk:Point, rand:Point, m:&str) -> ChainScalar {


    // Step 1. Serialize inputs
    let mut serialized_data = Vec::new();

    // Serialize pk
    let pk_bytes = pk.to_bytes();
    serialized_data.extend(pk_bytes);

    // Serialize rand
    let rand_bytes = rand.to_bytes();
    serialized_data.extend(rand_bytes);

    // Serialize message
    let m_bytes = m.bytes();
    serialized_data.extend(m_bytes);

    // Step 2: Hash the concatenated serialized data
    let mut hasher = Sha256::new();
    hasher.update(&serialized_data);
    let hash_result = hasher.finalize(); 

    // Step 3: transform from bytes to scalar

    let r = ChainScalar::from_bytes_mod_order(hash_result.try_into().unwrap()).expect_nonzero("the output of the hash cannot be known in advance");

    r

}


pub fn message_creator(installments:usize) -> Vec<MessagesAL> {
   
    let mut tuples = Vec::new();

    for i in 1..=installments {
        for j in 0..i {

            let transition = format!("transition {}-{}", j, i);
            let state = format!("state {}", i);

            let witness = sample_rand_chain_scalar();        
            let statement = g!(witness * G).normalize();

            let entry = MessagesAL{
                j,
                state,
                transition,
                statement,
                witness,
            };
    
            tuples.push(entry);
        }
    }

    tuples
}


pub fn message_creator_involved_oracle(installments:usize) -> Vec<MessagesAL> {
   
    let mut tuples = Vec::new();

    for j in 1..=installments {
        
            let transition = format!("transition passing {}", j);
            let state = format!("state {}", j);

            let witness = sample_rand_chain_scalar();        
            let statement = g!(witness * G).normalize();

            let entry = MessagesAL{
                j,
                state,
                transition,
                statement,
                witness,
            };
    
            tuples.push(entry);
    }

    tuples
}
