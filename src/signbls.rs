use bls12_381::{
    pairing, G1Affine, G2Affine, Scalar,
};

use crate::common::hash_to_g2;

use rand::rngs::OsRng;
use ff::Field;


pub struct MyBLSPair {
    sk: Scalar,
    pub pk: G1Affine,
}

pub fn kgen() -> MyBLSPair {

    let sk =  Scalar::random(&mut OsRng);
    let pk = G1Affine::from(G1Affine::generator() * sk);

    MyBLSPair {
        sk,
        pk,
    }

}


pub fn sign(kp:&MyBLSPair, m: &str)-> G2Affine {
    
    G2Affine::from(hash_to_g2(m) * kp.sk)
}

pub fn verify(pk: G1Affine, m: &str, s:G2Affine) ->bool {

    let gt = pairing(&G1Affine::generator(), &s);

    let expected = pairing(&pk, &hash_to_g2(m));

    gt == expected
}