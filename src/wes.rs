use bls12_381::{
    pairing, G1Affine, G2Affine, Scalar, Gt, G2Projective, G2Prepared
};

use crate::common::{hash_to_g2, gt_to_bytes, sample_rand_chain_scalar, sample_rand_scalar, sample_rand_gt};

use secp256kfun::{Scalar as ChainScalar, g, Point, G};
use secp256kfun::marker::*;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct WESCiphertext {
    pub c1: G1Affine,
    pub c2: Gt,
    pub c3: [u8; 32],
}

#[derive(Clone)]
pub struct PreComp{
    pub c1: G1Affine,
    pub c3: [u8; 32],
    pub r1: Scalar,
    pub r2:Gt,
    pub ri: ChainScalar,
    pub ri_pub: Point
}



impl WESCiphertext{

    // Function to precompute all randomness used in WES. This is useful when the message to encrypt is a random scalar.
    pub fn precompute() -> PreComp {

        let g2_prepared = G2Prepared::from(G2Affine::generator());

        let ri = sample_rand_chain_scalar();
        let ri_pub = g!(ri * G).normalize();

        let r1 = sample_rand_scalar();
        let r2 = sample_rand_gt(&g2_prepared);

        let c1 = G1Affine::from(G1Affine::generator() * &r1);

        let mut h_xor_sec = gt_to_bytes(&r2);

        for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(&ri.to_bytes()) {
            *xor_byte ^= ri_byte
        }

        let c3 = h_xor_sec.try_into().unwrap();

        PreComp{
            c1,
            c3,
            r1,
            r2,
            ri,
            ri_pub,
        }

    }

    // Function to encrypt sec, using as encryption key pk and m.
    pub fn new(pk: G1Affine, m: &str, sec:ChainScalar) -> (WESCiphertext, Scalar, Gt) {

        let g2_prepared = G2Prepared::from(G2Affine::generator());

        let r1 = sample_rand_scalar();
        let r2 = sample_rand_gt(&g2_prepared);

        let c1 = G1Affine::from(G1Affine::generator() * r1);

        let c2 = pairing(&pk, &hash_to_g2(m))*r1 + r2;

        let mut h_xor_sec = gt_to_bytes(&r2);

        for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(sec.to_bytes()) {
            *xor_byte ^= ri_byte
        }

        let c3 = h_xor_sec.try_into().unwrap();

        (WESCiphertext{
            c1,
            c2,
            c3
        },
        r1,
        r2)

    }

    // Function to produce a ciphertext on a random message using as encryption key pk and m.
    pub fn new_from_precom(pre:PreComp, m: Gt) -> WESCiphertext {

        let c2 = m*pre.r1 + pre.r2;

        let c1 = pre.c1;

        let c3 = pre.c3;

        WESCiphertext{
            c1,
            c2,
            c3
        }

    }

    pub fn new_from_precom_vector_m(pre:PreComp, m: Gt) -> WESCiphertext {
        
        let c2 = m*pre.r1 + pre.r2;

        let c1 = pre.c1;

        let c3 = pre.c3;

        WESCiphertext{
            c1,
            c2,
            c3
        }

    }


    // Function to decrypt a WES ciphertext using signature sig.
    pub fn decrypt(self, sig:G2Affine)-> ChainScalar {

        let r = self.c2 - pairing(&self.c1, &sig );

        let mut sec_bytes = gt_to_bytes(&r);

        for (xor_byte, pad_byte) in sec_bytes.iter_mut().zip(self.c3) {
            *xor_byte ^= pad_byte
        }

        let sec = ChainScalar::from_bytes_mod_order(sec_bytes.try_into().unwrap()).expect_nonzero("The scalar should be random, different from zero");

        sec

        }

    // Given the random secret and the random coins, check if a given ciphertext is well-formed (for a vector of messages)
    pub fn reconstruct(self, m: Gt, sec:ChainScalar, r1: Scalar, r2: Gt) -> () {

        let new_c1 = G1Affine::from(G1Affine::generator() * r1);

        

        let new_c2 = m*r1 + r2;

        let mut h_xor_sec = gt_to_bytes(&r2);

        for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(sec.to_bytes()) {
            *xor_byte ^= ri_byte
        }

        let new_c3:[u8;32] = h_xor_sec.try_into().unwrap();

        assert!(self.c1 == new_c1, "C1 is invalid");
        assert!(self.c2 == new_c2, "C2 is invalid");
        assert!(self.c3 == new_c3, "C3 is invalid");

    }

    pub fn reconstruct_vector_m(self, m: Gt, sec:ChainScalar, r1: Scalar, r2: Gt) -> () {

        let new_c1 = G1Affine::from(G1Affine::generator() * r1);

        // let mut agg_m_hash = G2Projective::identity();
        // for att in m{

        //     let affine = hash_to_g2(&att);

        //     agg_m_hash = agg_m_hash + G2Projective::from(affine);

        // }

        // let agg_m_hash = G2Affine::from(agg_m_hash);

        let new_c2 = m*r1 + r2;

        let mut h_xor_sec = gt_to_bytes(&r2);

        for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(sec.to_bytes()) {
            *xor_byte ^= ri_byte
        }

        let new_c3:[u8;32] = h_xor_sec.try_into().unwrap();

        assert!(self.c1 == new_c1, "C1 is invalid");
        assert!(self.c2 == new_c2, "C2 is invalid");
        assert!(self.c3 == new_c3, "C3 is invalid");

    }

}



// WES in which c1, c2 have been precomputed
pub fn wes_enc_precom(pk: G1Affine, m: &str, r1: Scalar, r2: Gt, c1: G1Affine, c3: [u8; 32]) -> WESCiphertext {
    
    let c2 = pairing(&pk, &hash_to_g2(m))*r1 + r2;

    WESCiphertext{
        c1,
        c2,
        c3
    }

}

// WES in which c1, c2 have been precomputed, and m is a vector of strings
pub fn wes_enc_precom_vector(pk: G1Affine, m: &Vec<String>, r1: Scalar, r2: Gt, c1: G1Affine, c3: [u8; 32]) -> WESCiphertext {


    let mut agg_m_hash = G2Projective::identity();
    for att in m{

        let affine = hash_to_g2(att);

        agg_m_hash = agg_m_hash + G2Projective::from(affine);

    }

    let agg_m_hash = G2Affine::from(agg_m_hash);
    
    let c2 = pairing(&pk, &agg_m_hash)*r1 + r2;

    WESCiphertext{
        c1,
        c2,
        c3
    }

}

// WES, with r1 and r2 computed outside to facilitated vf_enc_cs
pub fn wes_enc(pk: G1Affine, m: &str, sec:ChainScalar, r1: Scalar, r2: Gt ) -> WESCiphertext {

    let c1 = G1Affine::from(G1Affine::generator() * r1);

    let c2 = pairing(&pk, &hash_to_g2(m))*r1 + r2;

    let mut h_xor_sec = gt_to_bytes(&r2);

    for (xor_byte, ri_byte) in h_xor_sec.iter_mut().zip(sec.to_bytes()) {
        *xor_byte ^= ri_byte
    }

    let c3 = h_xor_sec.try_into().unwrap();

    WESCiphertext{
        c1,
        c2,
        c3
    }

}


pub fn wes_dec(sig:G2Affine, c: WESCiphertext)-> ChainScalar<Secret, Zero> {

    let r = c.c2 - pairing(&c.c1, &sig );

    let mut sec_bytes = gt_to_bytes(&r);

    for (xor_byte, pad_byte) in sec_bytes.iter_mut().zip(c.c3) {
        *xor_byte ^= pad_byte
    }

    let sec = ChainScalar::from_bytes_mod_order(sec_bytes.try_into().unwrap());

    sec

    
}