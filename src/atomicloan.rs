use crate::common::{message_creator, sample_rand_chain_scalar, MessagesAL};

use bls12_381::{
    G1Affine,
    G2Affine,
};

use rayon::prelude::*;

use crate::cvesfig5::CVESCiphertextFig5;

use crate::schnorradaptor::{SchnorrPair, SchnorrSig};

use secp256kfun::{Scalar as ChainScalar};


pub fn prepare_loan(gamma: usize, installments:usize, pk:G1Affine, bank_kp:SchnorrPair) -> (Vec<CVESCiphertextFig5>, Vec<MessagesAL>, ChainScalar) {

    let conditions = message_creator(installments);

    let w0 = sample_rand_chain_scalar(); 

    let loan_ciphertexts: Vec<CVESCiphertextFig5> = conditions
        .par_iter()
        .map(| condition| {

            let precom_fig5 = CVESCiphertextFig5::precompute(gamma.clone());

            if condition.origin == 0{

                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, w0.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);
                cves_fig5

            }else{

                let cves_fig5 = CVESCiphertextFig5::enc_cs_from_precom(gamma.clone(), pk, conditions[condition.origin].witness.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &precom_fig5);

                cves_fig5

            }
            
            
            
        })
        .collect();

        

    (loan_ciphertexts, conditions, w0)
}

pub fn verify_loan(gamma: usize, cves:Vec<CVESCiphertextFig5>)-> () {
    cves
    .iter()
    .for_each(|cve|{

        cve.clone().verify(gamma);

    });

}

pub fn decrypt_state(cves:Vec<CVESCiphertextFig5>, sig:G2Affine, m:&str, wa:ChainScalar)-> (ChainScalar, SchnorrSig) {

    if let Some(output) = cves
    .iter()
    .filter(|cve| cve.m == m)
    .find_map(|cve|{
        Some(cve.clone().decrypt(sig.clone(), wa.clone()))
    }){
        return output
    }else{
        panic!("Decryption failed");
    } ;

}