use bls12_381::{
    pairing, G1Affine, G2Affine, Scalar, G2Projective,
};

use crate::common::hash_to_g2;

use rand::rngs::OsRng;
use ff::Field;


#[derive(Copy, Clone)]
pub struct BLSKeyPair {
    sk: Scalar,
    pub pk: G1Affine,
}


impl BLSKeyPair{

    pub fn new() -> BLSKeyPair{

        let sk =  Scalar::random(&mut OsRng);
        let pk = G1Affine::from(G1Affine::generator() * sk);

        BLSKeyPair {
            sk,
            pk,
        }

    }

    pub fn sign(self, m: &str)-> G2Affine {
    
        G2Affine::from(hash_to_g2(m) * self.sk)
    }


    pub fn verify(self, m: &str, s:G2Affine) ->bool {

        let gt = pairing(&G1Affine::generator(), &s);
    
        let expected = pairing(&self.pk, &hash_to_g2(m));
    
        gt == expected
    }

    pub fn agg_sign(self, m:Vec<String>) ->G2Affine{
        // given a list of messages, computes the aggregated signature on those messages.

        let mut agg_m_hash = G2Projective::identity();
        for att in m{

            let affine = hash_to_g2(&att);

            agg_m_hash = agg_m_hash + G2Projective::from(affine);

        }

        let agg_sig = G2Affine::from(agg_m_hash*self.sk); 

        agg_sig


    }
}