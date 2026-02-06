use bls12_381::{
    G1Affine, G2Affine, G2Projective, Scalar, Gt, pairing
};

use crate::common::{sample_rand_chain_scalar, hash_to_bits_in, hash_to_g2};
use crate::wes::{WESCiphertext, PreComp};

use crate::schnorradaptor::{SchnorrPair, SchnorrPreSig, SchnorrSig};

use secp256kfun::{g,s,  Scalar as ChainScalar, G, Point};

use rayon::prelude::*;


#[derive(Clone)]
pub struct CVESCiphertextIn {
    pub m_cis: Vec<Vec<WESCiphertext>>,
    pub c_omega: Vec<ChainScalar>,
    pub sop: Vec<Vec<SopUnitIn>>,
    pub suop: Vec<Vec<SuopUnitIn>>,
    pub m_ri_pub: Vec<Vec<Point>>,
    pub x: Vec<Point>,
    pub y_pub: Vec<Point>,
    pub sigma_tilde: Vec<SchnorrPreSig>,
    pub m: Vec<String>,
    pub pk: G1Affine,
    pub tx: Vec<String>,
    pub vk: Point,
}

#[derive(Clone, Debug)]
pub struct SopUnitIn {
    pub i: usize,
    pub j:usize,
    pub ri: ChainScalar,
    pub rho: (Scalar, Gt),
}

#[derive(Clone, Debug)]
pub struct SuopUnitIn {
    pub i: usize,
    pub j: usize,
    pub si: ChainScalar,
    pub ci: WESCiphertext,
}

impl CVESCiphertextIn{

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



    pub fn enc_cs_from_precom(gamma: usize, pk: G1Affine, w: Vec<ChainScalar>, m: Vec<String>, a_kp:SchnorrPair, tx:Vec<String>, precom: &Vec<Vec<PreComp>>) -> CVESCiphertextIn{

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
            // all messages up to i

            let mut m_par = m.clone();

            let first_i: Vec<String> = m_par.drain(..i).collect();

            let mut agg_m_hash = G2Projective::identity();
            for att in first_i{

                let affine = hash_to_g2(&att);

                agg_m_hash = agg_m_hash + G2Projective::from(affine);

            }

            let agg_m_hash = G2Affine::from(agg_m_hash);

            let pair = pairing(&pk, &agg_m_hash);
        let (cis, v_ri_pub): (Vec<WESCiphertext>, Vec<Point> ) = (0..gamma)
        .into_par_iter() 
        .map(|j| {
    
            // Get precomputed data
            let precom_inst = precom[i-1][j].clone();

            let ri_pub = precom_inst.ri_pub.clone();

            
    
            // finalize WES ciphertexts
            (WESCiphertext::new_from_precom_vector_m(precom_inst, pair),
            ri_pub)
    
        })
        .collect();

        (cis, v_ri_pub)

        })
        .collect();

        // Encryption and adaptor, one for each state.

        let (y, sigma_tilde, y_pub, c_omega): (Vec<ChainScalar>, Vec<SchnorrPreSig>, Vec<Point>, Vec<ChainScalar>) = (1..(l_tx+1))
        .map(|i|{

                let sec = &w[i];
                let y_i = sample_rand_chain_scalar();
                let y_pub_i = g!(y_i * G).normalize();
                let wa = &w[0];
                let xa = g!(wa * G).normalize();
                let y_tilde_pub_i = g!(y_pub_i + xa).normalize().expect_nonzero("They are random points");

                // adaptor

                let sigma_tilde_i = a_kp.clone().pre_sign(&tx[i-1], &y_tilde_pub_i); 

                // encryption
                let mut c_omega_i = s!(y_i + wa).expect_nonzero("random scalar");    
                c_omega_i = s!(c_omega_i + sec).expect_nonzero(" random scalars");
            

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


        let bits = hash_to_bits_in(&m_cis, &m_ri_pub, &c_omega, &x, &y_pub, &sigma_tilde);


        // Prepare SOP
        let sop: Vec<Vec<SopUnitIn>> = (0..gamma)
        .map(|k|{

            let sop_k: Vec<SopUnitIn> = (1..l_tx+1)
            .filter_map(|i|{

                let bit = bits[k];

                if bit {
                    let r1 = precom[i-1][k].r1;
                    let r2 = precom[i-1][k].r2;
                    let ri = precom[i-1][k].ri.clone();
        
                    let rho = (r1, r2);

                    Some(SopUnitIn{
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

        let suop: Vec<Vec<SuopUnitIn>> = (0..gamma)
        .map(|k|{

            let suop_k: Vec<SuopUnitIn> = (1..l_tx+1)
            .filter_map(|i|{

                let bit = bits[k];

                if !bit {
                    let mut sij = precom[0][k].ri.clone();

                    for idx in 2..i {
                        
                        let ri = precom[idx-1][k].ri.clone();

                        sij = s!(sij+ri).expect_nonzero("they should be two random scalars");
                        
                    }

                    let y = y[i-1].clone();
                    let si = s!(sij+y).expect_nonzero("they should be two random scalars");

                    let ci = m_cis[i-1][k].clone();

                    Some( SuopUnitIn{
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

        CVESCiphertextIn {
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

    pub fn verify(self) ->() {

        let l_tx = self.tx.len();

        let bits = hash_to_bits_in(&self.m_cis, &self.m_ri_pub, &self.c_omega, &self.x, &self.y_pub, &self.sigma_tilde);

        // Check encryption and adaptor

        for i in 1..l_tx+1{
            

                let c_omega_i = &self.c_omega[i-1];
                let xw = self.x[i].clone();
                let xa = self.x[0].clone();
                let y1 = &self.y_pub[i-1];

                let gc_omega = g!(c_omega_i * G).normalize();
    
                let mut check = g!(xa + y1).normalize().expect_nonzero("");
                
                check = g!(check + xw).normalize().expect_nonzero("");
            
                assert!(gc_omega == check, "CVES verification failed: invalid encryption");

                let y_tilde_pub_i = g!(y1 + xa).normalize().expect_nonzero("");

                let tx_i= &self.tx[i-1];
                let sigma_tilde_i = &self.sigma_tilde[i-1];

                sigma_tilde_i.clone().pre_verify(&self.vk, tx_i, &y_tilde_pub_i);


        }


        // Prepare the pairings of each state for the aggregated messages

        let mut pairs:Vec<Gt>= vec![];

        for i in 1..l_tx+1{

            let mut m_par = self.m.clone();

            let first_i: Vec<String> = m_par.drain(..i).collect();

            let mut agg_m_hash = G2Projective::identity();
            for att in first_i{

                let affine = hash_to_g2(&att);

                agg_m_hash = agg_m_hash + G2Projective::from(affine);

            }

            let agg_m_hash = G2Affine::from(agg_m_hash);

            let pair = pairing(&self.pk, &agg_m_hash);

            pairs.push(pair);
        
        }


        // Verify cut and choose


        let _ = self.sop
        .into_par_iter()
        .flatten()
        .for_each(|sop_u|{

            assert!(bits[sop_u.i], "Invalid SOP");

            let my_pair = pairs[sop_u.j-1].clone();

            self.m_cis[sop_u.j-1][sop_u.i].reconstruct_vector_m(my_pair, sop_u.ri.clone(), sop_u.rho.0, sop_u.rho.1);

        });

        let _ = self.suop
        .into_par_iter()
        .flatten()
        .for_each(|suop_u|{

            assert!(!bits[suop_u.i], "Invalid SUOP");

            // for i in 1..suop_u.j{

                let si = suop_u.si.clone();

                let gs = g!(si * G).normalize();

                let y_pub_i = self.y_pub[suop_u.j-1].clone();

                let mut ri_pub_acc = self.m_ri_pub[0][suop_u.i].clone();

                for idx in 2..suop_u.j {
                        
                        let ri_pub = self.m_ri_pub[idx-1][suop_u.i].clone();

                        ri_pub_acc = g!(ri_pub_acc+ri_pub).normalize().expect_nonzero("");
                        
                    }

                // let ri_pub = self.m_ri_pub[suop_u.j-1][suop_u.i].clone();

                let check = g!(y_pub_i + ri_pub_acc).normalize().expect_nonzero("");

                assert!(check == gs, "Invalid one time pad");


            // }

        });

    }


    pub fn decrypt(self, sig:G2Affine, wa:ChainScalar, state: usize) -> (ChainScalar, SchnorrSig) {

        let xa = g!(wa * G).normalize();

        assert!(xa == self.x[0].clone(), "origin and wa must match");

        let xw = self.x[state].clone();

        if let Some(output) = self.suop.iter()
        .flatten()
        .filter(|suop_u| suop_u.j == state)
        .find_map(|suop_u|{

            let r = suop_u.ci.clone().decrypt(sig);

            let s = suop_u.si.clone();

            let y = s!(s - r).expect_nonzero("");

            let y_tilde = s!(y + wa).expect_nonzero("");

            let c_omega = self.c_omega[state-1].clone();

            let sec = s!(c_omega - y_tilde).expect_nonzero("");

            let sig = self.sigma_tilde[state-1].clone().adapt(&y_tilde);

            let gsec = g!(sec * G).normalize();  

            assert!(gsec== xw, "Invalid witness");
            

            sig.clone().verify(&self.vk, &self.tx[state-1]);
            


            Some((sec, sig.clone()))
            

        })  {

            return output

        } else{
            panic!("Decryption failed");
        } ;




    }

}