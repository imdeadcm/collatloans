use bls12_381::{
    pairing, G1Affine, G2Affine, Scalar, Gt
};

use crate::common::{hash_to_g2, gt_to_bytes};

use secp256kfun::Scalar as ChainScalar;
use secp256kfun::marker::*;

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct WESCiphertext {
    pub c1: G1Affine,
    pub c2: Gt,
    pub c3: [u8; 32],
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