use secp256kfun::{g,s,  Scalar as ChainScalar, G, Point};

use crate::common::{sample_rand_chain_scalar, schnorr_hash};


// implementation taken from https://eprint.iacr.org/2020/476.pdf
// extract not implemented because we dont need it

pub struct SchnorrPair {
    sk: ChainScalar,
    pub pk: Point,
}

pub struct SchnorrSig {
    s: ChainScalar,
    r: ChainScalar,
}

#[derive(Clone)]
pub struct SchnorrPreSig {
    pub s: ChainScalar,
    pub r: ChainScalar,
}


pub fn kgen() -> SchnorrPair {

    let sk =  sample_rand_chain_scalar();
    let pk = g!(sk * G).normalize();

    SchnorrPair {
        sk,
        pk,
    }

}


pub fn sign(kp:&SchnorrPair, m: &str)-> SchnorrSig {

    let k =  sample_rand_chain_scalar();
    let big_k = g!(k * G).normalize();

    let r = schnorr_hash(kp.pk, big_k, m);    
    
    let mut s = s!(r * kp.sk);

    s = s!(k + s).expect_nonzero("unlikely that k, which is random and s add up to zero");

    SchnorrSig{
        s,
        r
    }

}

pub fn verify(pk: Point, m: &str, sig:SchnorrSig) ->bool {

    let mut rand = g!(sig.r * pk).normalize();
    let gs = g!(sig.s*G).normalize();
    rand = g!(gs-rand).normalize().expect_nonzero(" ");

    let got = schnorr_hash(pk, rand, m);

    got == sig.r
}

pub fn pre_sign(kp:&SchnorrPair, m: &str, y_pub:&Point)-> SchnorrPreSig {

    let k =  sample_rand_chain_scalar();
    let mut big_k = g!(k * G).normalize();
    big_k = g!(y_pub + big_k).normalize().expect_nonzero(" ");

    let r = schnorr_hash(kp.pk, big_k, m);    
    
    let mut s = s!(r * kp.sk);

    s = s!(k + s).expect_nonzero(" ");

    SchnorrPreSig{
        s,
        r
    }

}

pub fn pre_verify(pk: Point, m: &str, pre_sig:&SchnorrPreSig, y_pub:&Point) ->bool {

    let mut rand = g!(pre_sig.r * pk).normalize();
    let gs = g!(pre_sig.s*G).normalize();
    rand = g!(gs - rand).normalize().expect_nonzero(" ");
    rand = g!(rand+y_pub).normalize().expect_nonzero(" ");

    let got = schnorr_hash(pk, rand, m);

    got == pre_sig.r
}

pub fn adapt(pre_sig:&SchnorrPreSig, y:&ChainScalar)-> SchnorrSig{

    let s = s!(pre_sig.s + y).expect_nonzero(" ");
    let r = pre_sig.r.clone();

    SchnorrSig{
        s,
        r
    }
}