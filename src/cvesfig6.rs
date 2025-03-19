use bls12_381::{
    G1Affine, G2Affine, Scalar, Gt,
};

use crate::common::{sample_rand_chain_scalar, hash_to_bits};
use crate::wes::{WESCiphertext, PreComp};

use crate::schnorradaptor::{SchnorrPair, SchnorrPreSig, SchnorrSig};

use secp256kfun::{g,s,  Scalar as ChainScalar, G, Point};

use rayon::prelude::*;


#[derive(Clone)]
pub struct CVESCiphertextFig6 {
    pub m_cis: Vec<Vec<WESCiphertext>>,
    pub c_omega: Vec<Vec<ChainScalar>>,
    pub sop: Vec<Vec<SopUnitFig6>>,
    pub suop: Vec<Vec<SuopUnitFig6>>,
    pub m_ri_pub: Vec<Vec<Point>>,
    pub x: Vec<Point>,
    pub y_pub: Vec<Vec<Point>>,
    pub sigma_tilde: Vec<Vec<SchnorrPreSig>>,
    pub m: Vec<String>,
    pub pk: G1Affine,
    pub tx: Vec<String>,
    pub vk: Point,
}

#[derive(Clone, Debug)]
pub struct SopUnitFig6 {
    pub i: usize,
    pub j:usize,
    pub ri: ChainScalar,
    pub rho: (Scalar, Gt),
}

#[derive(Clone, Debug)]
pub struct SuopUnitFig6 {
    pub i: usize,
    pub j: usize,
    pub si: Vec<ChainScalar>,
    pub ci: WESCiphertext,
}

impl CVESCiphertextFig6{

    pub fn precompute(gamma: usize, l: usize) -> Vec<Vec<PreComp>> {

        let vprecom: Vec<Vec<PreComp>> = (0..l)
        .map(|_|{        
            let precom: Vec<PreComp> = (0..gamma)
            .into_par_iter() // 
            .map(|_| {
        
                WESCiphertext::precompute()
            })
            .collect();

        precom

    })
    .collect();

    vprecom

    }    



    pub fn enc_cs_from_precom(gamma: usize, pk: G1Affine, w: Vec<ChainScalar>, m: Vec<String>, a_kp:SchnorrPair, tx:Vec<String>, precom: &Vec<Vec<PreComp>>) -> CVESCiphertextFig6{

        // w has scalars w0 until wi. wi is w[w.len()-1] and is the secret.
        // We encrypt with respect to all w from 0 to w.len()-2

        let vk = a_kp.pk;

        let l_m = m.len();
        let l_tx = tx.len();
        let l_w = w.len();

        assert!(l_m == l_tx, "The two message lists must be of equal length");
        assert!(l_m == l_w-1, "The witness list is one element longer than the message list");


        // We have to produce as many ciphertexts as states (l_tx)
        let (m_cis, m_ri_pub): (Vec<Vec<WESCiphertext>>, Vec<Vec<Point>>) = (1..l_tx+1)
        .map(|i|{
        let (cis, v_ri_pub): (Vec<WESCiphertext>, Vec<Point> ) = (0..gamma)
        .into_par_iter() 
        .map(|j| {
    
            // Get precomputed data
            let precom_inst = precom[i-1][j].clone();

            let ri_pub = precom_inst.ri_pub.clone();

            // all messages up to i

            let mut m_par = m.clone();

            let first_i: Vec<String> = m_par.drain(..i).collect();
    
            // finalize WES ciphertexts
            (WESCiphertext::new_from_precom_vector_m(precom_inst, pk, first_i),
            ri_pub)
    
        })
        .collect();

        (cis, v_ri_pub)

        })
        .collect();

        // Encryption and adaptor it loops for all possible transitions.

        let (y, sigma_tilde, y_pub, c_omega): (Vec<Vec<ChainScalar>>, Vec<Vec<SchnorrPreSig>>, Vec<Vec<Point>>, Vec<Vec<ChainScalar>>) = (1..(l_tx+1))
        .map(|i|{
            // println!("{}", i);
            let (y_i, sigma_tilde_i, y_pub_i, c_omega_i):(Vec<ChainScalar>, Vec<SchnorrPreSig>, Vec<Point>, Vec<ChainScalar>) = (0..i)
            .map(|j|{
                // points
                
                let sec = &w[i];
                let y_ij = sample_rand_chain_scalar();
                let y_pub_ij = g!(y_ij * G).normalize();
                let wa = &w[j];
                let xa = g!(wa * G).normalize();
                let y_tilde_pub_ij = g!(y_pub_ij + xa).normalize().expect_nonzero("They are random points");

                // adaptor
                // let sigma_tilde_ij = pre_sign(&a_kp, &tx[i-1], &y_tilde_pub_ij); 

                let sigma_tilde_ij = a_kp.clone().pre_sign(&tx[i-1], &y_tilde_pub_ij); 

                // encryption. replace in future by PKE
                let mut c_omega_ij = s!(y_ij + wa).expect_nonzero("random scalar");    
                c_omega_ij = s!(c_omega_ij + sec).expect_nonzero(" random scalars");
                (
                    y_ij,
                    sigma_tilde_ij,
                    y_pub_ij,
                    c_omega_ij
                )

            })
            .collect();

            (y_i, sigma_tilde_i, y_pub_i, c_omega_i)

        })
        .collect();

        // produce the statement vector
        let x:Vec<Point> = (0..l_w)
        .map(|i|{

            let w = &w[i];
            let x = g!(w * G).normalize();

            x

        })
        .collect();


        // For the moment, does not take the full matrix.

        let bits = hash_to_bits(&m_cis[l_tx-1], m_ri_pub[l_tx-1].clone(), c_omega[l_tx-1][0].clone(), x[l_tx-1], x[0], y_pub[l_tx-1][0], &sigma_tilde[l_tx-1][0]);


        // Prepare SOP
        let sop: Vec<Vec<SopUnitFig6>> = (0..gamma)
        .map(|k|{

            let sop_k: Vec<SopUnitFig6> = (1..l_tx+1)
            .filter_map(|i|{

                let bit = bits[k];

                if bit {
                    let r1 = precom[i-1][k].r1;
                    let r2 = precom[i-1][k].r2;
                    let ri = precom[i-1][k].ri.clone();
        
                    let rho = (r1, r2);

                    Some(SopUnitFig6{
                        i: k,
                        j: i,
                        ri,
                        rho
                    })
    
                    } else{
                        None
                    }
            }).collect();

            sop_k

        })
        .collect();

        // Prepare SUOP

        let suop: Vec<Vec<SuopUnitFig6>> = (0..gamma)
        .map(|k|{

            let suop_k: Vec<SuopUnitFig6> = (1..l_tx+1)
            .filter_map(|i|{

                let bit = bits[k];

                if !bit {
                    let si: Vec<ChainScalar> = (0..i)
                    .map(|j|{

                        

                        let y = y[i-1][j].clone();
                        let ri = precom[i-1][k].ri.clone();

                        let sij = s!(y+ri).expect_nonzero("they should be two random scalars");

                        sij

                    })
                    .collect();

                    let ci = m_cis[i-1][k].clone();

                    Some( SuopUnitFig6{
                        i:k,
                        j:i,
                        si,
                        ci
                    })
    
                    } else{

                       None
                    

                    }
            }).collect();

            suop_k

        })
        .collect();

        CVESCiphertextFig6 {
            m_cis,
            c_omega,
            sop,
            suop,
            m_ri_pub,
            x,
            y_pub,
            sigma_tilde,
            m ,
            pk,
            tx ,
            vk,
        }
 
 
    }

    pub fn verify(self, gamma: usize) ->() {

        let l_tx = self.tx.len();

        // For the moment, does not take the full matrix.

        let bits = hash_to_bits(&self.m_cis[l_tx-1], self.m_ri_pub[l_tx-1].clone(), self.c_omega[l_tx-1][0].clone(), self.x[l_tx-1], self.x[0], self.y_pub[l_tx-1][0], &self.sigma_tilde[l_tx-1][0]);

        // Check encryption and adaptor

        for i in 1..l_tx+1{
            for j in 0..i{

                let c_omega_ij = &self.c_omega[i-1][j];
                let xw = self.x[i].clone();
                let xa = self.x[j].clone();
                let y1 = &self.y_pub[i-1][j];

                let gc_omega = g!(c_omega_ij * G).normalize();
    
                let mut check = g!(xa + y1).normalize().expect_nonzero("");
                
                check = g!(check + xw).normalize().expect_nonzero("");
            
                assert!(gc_omega == check, "CVES verification failed: invalid encryption");

                let y_tilde_pub_ij = g!(y1 + xa).normalize().expect_nonzero("");

                let tx_i= &self.tx[i-1];
                let sigma_tilde_ij = &self.sigma_tilde[i-1][j];

                sigma_tilde_ij.clone().pre_verify(&self.vk, tx_i, &y_tilde_pub_ij);

            }
        }


        // Verify cut and choose

        (0..gamma).into_par_iter().for_each(|idx|{
            
                let bit = bits[idx];
        
                // Check that SOP and SUOP have the correct indices
                if bit {
                    // Bit is 1 (true)

                    let sop_list = self.sop.clone();

                    let matching_sops:Vec<&SopUnitFig6> = sop_list
                    .iter()
                    .flatten()
                    .filter(|sop_u| sop_u.i == idx)
                    .collect();

                    for sop_u in matching_sops{

                        let mut m_par = self.m.clone();

                        let first_i: Vec<String> = m_par.drain(..sop_u.j).collect();

                        self.m_cis[sop_u.j-1][sop_u.i].reconstruct_vector_m(self.pk, first_i, sop_u.ri.clone(), sop_u.rho.0, sop_u.rho.1);

                    }


                } else {

                    let suop_list = self.suop.clone();

                    let matching_suops:Vec<&SuopUnitFig6> = suop_list
                    .iter()
                    .flatten()
                    .filter(|suop_u| suop_u.i == idx)
                    .collect();

                    for suop_u in matching_suops{

                        for i in 1..suop_u.j{

                            let si = suop_u.si[i-1].clone();

                            let gs = g!(si * G).normalize();

                            let y_pub_ij = self.y_pub[suop_u.j-1][i-1].clone();
                            let ri_pub = self.m_ri_pub[suop_u.j-1][idx].clone();

                            let check = g!(y_pub_ij + ri_pub).normalize().expect_nonzero("");

                            assert!(check == gs, "Invalid one time pad");


                        }


                    }

                }

                });


    }


    pub fn decrypt(self, sig:G2Affine, wa:ChainScalar, origin: usize, state: usize) -> (ChainScalar, SchnorrSig) {

        let xa = g!(wa * G).normalize();

        assert!(xa == self.x[origin].clone(), "origin and wa must match");
        assert!(origin<state, "origin must be smaller than state");

        let xw = self.x[state+1].clone();

        if let Some(output) = self.suop.iter()
        .flatten()
        .filter(|suop_u| suop_u.j == state+1)
        .find_map(|suop_u|{

            let r = suop_u.ci.clone().decrypt(sig);

            let s = suop_u.si[origin].clone();

            let y = s!(s - r).expect_nonzero("");

            let y_tilde = s!(y + wa).expect_nonzero("");

            let c_omega = self.c_omega[state][origin].clone();

            let sec = s!(c_omega - y_tilde).expect_nonzero("");

            let sig = self.sigma_tilde[state][origin].clone().adapt(&y_tilde);

            let gsec = g!(sec * G).normalize();  
            

            sig.clone().verify(&self.vk, &self.tx[state]);
            assert!(gsec== xw, "Invalid witness");


            Some((sec, sig.clone()))
            

        })  {

            return output

        } else{
            panic!("Decryption failed");
        } ;




    }

}