use crate::common::{message_creator, sample_rand_chain_scalar, message_creator_involved_oracle};

use bls12_381::{
    G1Affine,
};

use secp256kfun::{Scalar as ChainScalar};

use crate::cves::{precompute_enc_cs, enc_cs_with_precomputation, enc_cs_with_precomputation_vector, CVESCiphertext, CVESCiphertext2};
use rayon::prelude::*;

use crate::cvesfig5::CVESCiphertextFig5;

use crate::schnorradaptor::SchnorrPair;


pub fn prepare_loan(gamma: usize, installments:usize, pk:G1Affine, bank_kp:SchnorrPair) -> Vec<CVESCiphertextFig5> {

    let conditions = message_creator(installments);

    let w0 = sample_rand_chain_scalar(); 

    let loan_ciphertexts: Vec<CVESCiphertextFig5> = conditions
        .par_iter()
        .map(| condition| {

            let precom_fig5 = CVESCiphertextFig5::precompute(gamma.clone());

            if condition.j == 0{
                // let c_ves = enc_cs_with_precomputation(gamma.clone(), pk, w0.clone() , &condition.transition, condition.witness.clone(), &bank_kp, &condition.state, &precom);
                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, w0.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);
                cves_fig5

            }else{

                // let c_ves = enc_cs_with_precomputation(gamma.clone(), pk, conditions[condition.j].witness.clone(), &condition.transition, condition.witness.clone(), &bank_kp, &condition.state, &precom);

                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, conditions[condition.j].witness.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);

                cves_fig5

            }
            
            
            
        })
        .collect();

        

    loan_ciphertexts
}