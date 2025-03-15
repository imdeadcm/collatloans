use crate::common::{message_creator, sample_rand_chain_scalar, message_creator_involved_oracle};

use bls12_381::{
    G1Affine,
};

use secp256kfun::{Scalar as ChainScalar};

use crate::cves::{precompute_enc_cs, enc_cs_with_precomputation, enc_cs_with_precomputation_vector, CVESCiphertext};
use rayon::prelude::*;

use crate::schnorradaptor::SchnorrPair;


pub fn prepare_loan(gamma: usize, installments:usize, pk:G1Affine, bank_kp:&SchnorrPair) -> Vec<CVESCiphertext> {

    let conditions = message_creator(installments);

    let w0 = sample_rand_chain_scalar(); 

    let loan_ciphertexts: Vec<CVESCiphertext> = conditions
        .par_iter()
        .map(| condition| {

            let precom = precompute_enc_cs(gamma.clone());

            if condition.j == 0{
                let c_ves = enc_cs_with_precomputation(gamma.clone(), pk, w0.clone() , &condition.transition, condition.witness.clone(), &bank_kp, &condition.state, &precom);
                c_ves

            }else{

                let c_ves = enc_cs_with_precomputation(gamma.clone(), pk, condition.witness.clone(), &condition.transition, conditions[condition.j].witness.clone(), &bank_kp, &condition.state, &precom);
                c_ves

            }
            
            
            
        })
        .collect();

        

    loan_ciphertexts
}

pub fn prepare_loan_involved_oracle(gamma: usize, installments:usize, pk:G1Affine, bank_kp:&SchnorrPair) -> Vec<CVESCiphertext> {

    let conditions = message_creator_involved_oracle(installments);

    let w0 = sample_rand_chain_scalar(); 

    let loan_ciphertexts: Vec<CVESCiphertext> = conditions
        .par_iter()
        .map(| condition| {

            let precom = precompute_enc_cs(gamma.clone());

            if condition.j == 1{
                let c_ves = enc_cs_with_precomputation(gamma.clone(), pk, w0.clone() , &condition.transition, condition.witness.clone(), &bank_kp, &condition.state, &precom);
                c_ves

            }else{

                // Here, we also need a vector of witnesses in the part of condition.j

                let (m_vector, mut w_vector): (Vec<String>, Vec<ChainScalar>) = conditions
                    .iter() 
                    .take(condition.j)
                    .map(|condition| (condition.transition.clone(), condition.witness.clone())) 
                    .collect(); 

                w_vector.truncate(w_vector.len() - 1);

                let c_ves = enc_cs_with_precomputation_vector(gamma.clone(), pk, w_vector, m_vector, condition.witness.clone(), &bank_kp, &condition.state, &precom, condition.j);
                c_ves

            }           
             
        })
        .collect();

        

    loan_ciphertexts
}