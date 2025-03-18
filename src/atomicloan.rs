use crate::common::{message_creator, sample_rand_chain_scalar};

use bls12_381::{
    G1Affine,
};

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

                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, w0.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);
                cves_fig5

            }else{

                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, conditions[condition.j].witness.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);

                cves_fig5

            }
            
            
            
        })
        .collect();

        

    loan_ciphertexts
}