use sha2::{digest::Digest, Sha256};

use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    G2Projective, G2Affine, G1Affine, Scalar,
};
use bls12_381::{multi_miller_loop, G1Projective, G2Prepared, Gt};

use crate::schnorradaptor::{SchnorrPreSig,SchnorrPair};
use crate::wes::{WESCiphertext, PreComp};
use crate::oblivious::CVESCiphertextOb;

use crate::signbls::BLSKeyPair;

use rayon::prelude::*;

use rand::rngs::OsRng;

use secp256kfun::{g,  Scalar as ChainScalar, G, Point};

use group::Group;
use ff::Field;

use std::time::Instant;
use std::mem::size_of_val;

#[derive(Clone)]
pub struct MessagesAL{
    pub origin: usize,
    pub end: usize,
    pub state: String,
    pub transition: String,
    pub statement: Point,
    pub witness: ChainScalar,
    pub precomp: Vec<PreComp>

}

pub struct LoanContractIn{
    pub state: Vec<String>,
    pub transition: Vec<String>,
    pub statement: Vec<Point>,
    pub witness: Vec<ChainScalar>,

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

pub fn hash_to_bits(cis:&Vec<WESCiphertext>, ri_pub:Vec<Point>, c_omega: ChainScalar, xa: Point, xw: Point, y_pub: Point, sigma_tilde: &SchnorrPreSig ) ->Vec<bool>{

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


pub fn hash_to_bits_in(cis:&Vec<Vec<WESCiphertext>>, ri_pub:&Vec<Vec<Point>>, c_omega: &Vec<Vec<ChainScalar>>, x: &Vec<Point>, y_pub: &Vec<Vec<Point>>, sigma_tilde: &Vec<Vec<SchnorrPreSig>> ) ->Vec<bool>{

        // Step 1: Serialize all inputs into bytes
        let mut serialized_data = Vec::new();

        // Serialize cis
        for ci in cis {
            for c in ci{
                let c1_bytes = Sha256::default()
                .chain(c.c1.to_compressed())
                .finalize();
                serialized_data.extend(c1_bytes);
                let c2_bytes = gt_to_bytes(&c.c2);
                serialized_data.extend(c2_bytes);
                serialized_data.extend(c.c3);

            }
            
        }
    
        // Serialize ri_pub
        for points in ri_pub {
            for point in points{

                let point_bytes = point.to_bytes();
                serialized_data.extend(point_bytes);

            }
            
        }
    
        // Serialize c_omega
        for omegas in c_omega{
            for omega in omegas{

                let scalar_bytes = omega.to_bytes();
                serialized_data.extend(scalar_bytes);

            }
        }
        
    
        // Serialize x
        for xa in x{
            let xa_bytes = xa.to_bytes();
            serialized_data.extend(xa_bytes);

        }
    
        // Serialize y_pub
        for points in y_pub{
            for point in points{

                let y_pub_bytes = point.to_bytes();
                serialized_data.extend(y_pub_bytes);

            }
        }
        
    
        // Serialize presig
        for pss in sigma_tilde{
            for ps in pss{

                let sigmas_bytes = ps.s.to_bytes();
                serialized_data.extend(sigmas_bytes);
                let sigmar_bytes = ps.r.to_bytes();
                serialized_data.extend(sigmar_bytes);

            }
        }
    
        // Step 2: Hash the concatenated serialized data
        let mut hasher = Sha256::new();
        hasher.update(&serialized_data);
        let hash_result = hasher.finalize();
    
     
        // Step 3: Convert the hash output to bits
        bytes_to_bits(&hash_result)



}


pub fn schnorr_hash(pk:&Point, rand:Point, m:&str) -> ChainScalar {


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


pub fn message_creator(installments:usize, gamma:usize) -> Vec<MessagesAL> {
   
    let mut tuples = Vec::new();

    for i in 1..=installments {
        for j in 0..i {

            let transition = format!("transition {}-{}", j, i);
            let state = format!("state {}", i);

            let witness = sample_rand_chain_scalar();        
            let statement = g!(witness * G).normalize();
            let precomp = CVESCiphertextOb::precompute(gamma);

            let entry = MessagesAL{
                origin:j,
                end:i,
                state,
                transition,
                statement,
                witness,
                precomp
            };
    
            tuples.push(entry);
        }
    }

    tuples
}


pub fn message_creator_involved_oracle(installments:usize) -> LoanContractIn {


    let (state, transition, mut statement, mut witness):(Vec<String>, Vec<String>, Vec<Point>, Vec<ChainScalar>) = (1..=installments)
    .map(|i|{

        let transition = format!("transition passing {}", i);
        let state = format!("state {}", i);
        let witness = sample_rand_chain_scalar();        
        let statement = g!(witness * G).normalize();

        (
            state,
            transition,
            statement,
            witness,
        )



    })
    .collect();

    let w0 = sample_rand_chain_scalar();
    let x0 = g!(w0 * G).normalize();

    statement.insert(0, x0);
    witness.insert(0, w0);

    LoanContractIn{
        state,
        transition,
        statement,
        witness,
    }

   
}

pub fn prepare_loan(gamma: usize, conditions:Vec<MessagesAL>, pk:G1Affine, bank_kp:SchnorrPair) -> (Vec<CVESCiphertextOb>,  ChainScalar) {

    let w0 = sample_rand_chain_scalar(); 

    
    let loan_ciphertexts: Vec<CVESCiphertextOb> = conditions
        .par_iter()
        .map(| condition| {

            if condition.origin == 0{

                let cves_ob = CVESCiphertextOb::enc_cs_from_precom(gamma.clone(), pk, w0.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &condition.precomp);


                cves_ob

                

            }else{


                let cves_ob = CVESCiphertextOb::enc_cs_from_precom(gamma.clone(), pk, conditions[condition.origin].witness.clone(), &condition.transition, condition.witness.clone(), bank_kp.clone(), &condition.state, &condition.precomp);

                cves_ob

            }
            
           
            
            
            
        })
        .collect();

        
    
    (loan_ciphertexts, w0)
}

pub fn verify_loan(cves:Vec<CVESCiphertextOb>)-> () {
    cves
    .iter()
    .for_each(|cve|{

        cve.clone().verify();

    });

}


pub fn time_size_oracle(kp:BLSKeyPair)->() {

    let start = Instant::now();
    let results: Vec<G2Affine> = (0..2000).into_par_iter()
        .map(|_| kp.sign(&"transaction"))
        .collect();
    let end = start.elapsed();

    let total_size: usize = results.iter()
        .map(|result| size_of_val(&result.to_compressed()))
        .sum();


    println!("Size of 2000 attestations: {} kB", total_size/1000);

    println!(
        "Time to attest 2000 transactions: {:?}",
        end
    );    

}
