use bls12_381::{
    G1Affine, G2Affine, Scalar, Gt, pairing
};

use crate::common::{sample_rand_chain_scalar, hash_to_bits,hash_to_g2};
use crate::wes::{WESCiphertext, PreComp};

use crate::schnorradaptor::{SchnorrPair, SchnorrPreSig, SchnorrSig};

use secp256kfun::{g,s,  Scalar as ChainScalar, G, Point};

use rayon::prelude::*;

#[derive(Clone)]
pub struct CVESCiphertextOb {
    pub cis: Vec<WESCiphertext>,
    pub c_omega: ChainScalar,
    pub sop: Vec<SopUnitOb>,
    pub suop: Vec<SuopUnitOb>,
    pub v_ri_pub: Vec<Point>,
    pub xa: Point,
    pub xw: Point,
    pub y_pub: Point,
    pub sigma_tilde: SchnorrPreSig,
    pub m: String,
    pub pk: G1Affine,
    pub tx: String,
    pub vk: Point,
}

#[derive(Clone)]
pub struct SopUnitOb {
    pub i: usize,
    pub ri: ChainScalar,
    pub rho: (Scalar, Gt),
}

#[derive(Clone)]
pub struct SuopUnitOb {
    pub i: usize,
    pub si: ChainScalar,
    pub ci: WESCiphertext,
}

impl CVESCiphertextOb {

    // precompute parameters
    pub fn precompute(gamma: usize) -> Vec<PreComp> {

        let precom: Vec<PreComp> = (0..gamma)
        .into_par_iter() // 
        .map(|_| {
    
            WESCiphertext::precompute()
        })
        .collect();

        precom

    }

    // Finalice encryption from precomputation
    pub fn enc_cs_from_precom(gamma: usize, pk: G1Affine, wa: ChainScalar, m: &str, sec:ChainScalar, a_kp:SchnorrPair, tx:&str, precom: &Vec<PreComp>) -> CVESCiphertextOb{

        let vk = a_kp.pk;

        let pair = pairing(&pk, &hash_to_g2(m));

        // Parallelize the loop using rayon to produce all WES ciphertexts
        let (cis, v_ri_pub): (Vec<WESCiphertext>, Vec<Point> ) = (0..gamma)
        .into_par_iter() // 
        .map(|i| {
    
            // Get precomputed data
            let precom = precom[i].clone();

            let ri_pub = precom.ri_pub.clone();
    
            // finalize WES ciphertexts
            (WESCiphertext::new_from_precom(precom, pair),
            ri_pub)
    
        })
        .collect();

        // Encryption and adaptor

        let y = sample_rand_chain_scalar();
        let y_pub = g!(y * G).normalize();
    
        let xa = g!(wa * G).normalize();
        let xw = g!(sec * G).normalize();
        let y_tilde_pub = g!(y_pub + xa).normalize().expect_nonzero("They are random points");

        let sigma_tilde = a_kp.pre_sign(tx, &y_tilde_pub); 
         
        let mut c_omega = s!(y + wa).expect_nonzero("random scalar");    
        c_omega = s!(c_omega +sec).expect_nonzero(" random scalars");

         // Produce some bits for cut and choose.
 
        let bits = hash_to_bits(&cis, v_ri_pub.clone(), c_omega.clone(), xa, xw, y_pub, &sigma_tilde);
    
        let mut sop=Vec::<SopUnitOb>::new();
        let mut suop=Vec::<SuopUnitOb>::new();

        for i in 0..gamma {
 
            let bit = bits[i];
    
            if bit {
                // Bit is 1 (true), fill SOP
    
                let r1 = precom[i].r1;
                let r2 = precom[i].r2;
                let ri = precom[i].ri.clone();
    
                let rho = (r1, r2);
    
                sop.push(SopUnitOb {i, ri, rho});
            } else {
                // Bit is 0 (false), fill SUOP
    
                let ri = &precom[i].ri;
    
                let si = s!(y + ri).expect_nonzero("");
    
                let ci = cis[i].clone();
    
                suop.push(SuopUnitOb {i,si, ci});
            }
        }

        CVESCiphertextOb {
            cis,
            c_omega,
            sop,
            suop,
            v_ri_pub,
            xa,
            xw,
            y_pub,
            sigma_tilde,
            m: m.to_string(),
            pk,
            tx: tx.to_string(),
            vk,
        }
 
 
    }


    // Verify a CVES ciphertext. Assume that the user checks that the public elements (m, tx, pk, vk) in the ciphertext are correct.
    pub fn verify(self) ->() {

        let pair = pairing(&self.pk, &hash_to_g2(&self.m));

        let bits = hash_to_bits(&self.cis, self.v_ri_pub.clone(), self.c_omega.clone(), self.xa, self.xw, self.y_pub.clone(), &self.sigma_tilde );

        // Check one time pad
        let gc_omega = g!(self.c_omega* G).normalize();
    
        let mut check = g!(self.xa + self.xw).normalize().expect_nonzero("");
        let y1 = &self.y_pub;
        check = g!(check + y1).normalize().expect_nonzero("");
    
        assert!(gc_omega == check, "CVES verification failed: invalid encryption");

        // Check presignature
        let y2=&self.y_pub;
    
        let y_tilde_pub = g!(y2 + self.xa).normalize().expect_nonzero("");
    

        self.sigma_tilde.pre_verify(&self.vk, &self.tx,&y_tilde_pub);
    

        // Cut and choose verification

        // SOP verify
        let _ = self.sop
        .into_par_iter()
        .for_each(|sop_u|{
            assert!(bits[sop_u.i], "Invalid SOP");

            self.cis[sop_u.i].reconstruct(pair, sop_u.ri.clone(), sop_u.rho.0, sop_u.rho.1);

        });

        // SUOP verify

        let _ = self.suop
        .into_par_iter()
        .for_each(|suop_u|{

            assert!(!bits[suop_u.i], "Invalid SUOP");

            let gs = g!(suop_u.si * G).normalize();
    
            let ri_pub = self.v_ri_pub[suop_u.i];

            let check2 = g!(self.y_pub + ri_pub).normalize().expect_nonzero("They should be two random points");

            assert!(gs == check2, "CVES verification failed: invalid si");

        });

        // (0..gamma).into_par_iter().for_each(|idx|{
            
        //     let bit = bits[idx];
    
        //     // Check that SOP and SUOP have the correct indices
        //     if bit {
        //         // Bit is 1 (true)
    
        //         if let Some(sop_unit) = self.sop.iter().find(|unit| unit.i == idx) {

        //             self.cis[idx].reconstruct(pair, sop_unit.ri.clone(), sop_unit.rho.0, sop_unit.rho.1);    
                    
        //         } else {
        //             panic!("CVES verification failed")
        //         }
    
                
        //     } else {
        //         // Bit is 0 (false)
    
        //         if let Some(suop_unit) = self.suop.iter().find(|unit| unit.i == idx) {
    
        //             let gs = g!(suop_unit.si * G).normalize();
    
        //             let ri_pub = self.v_ri_pub[idx];
    
        //             let check2 = g!(self.y_pub + ri_pub).normalize().expect_nonzero("They should be two random points");
    
        //             assert!(gs == check2, "CVES verification failed: invalid si");
                    
        //         } else {
        //             panic!("CVES verification failed")
        //         }
    
                
        //     }
    
    
        // });

    }


    // Decrypt a CVES ciphertext with a signature and a witness.
    pub fn decrypt(self, sig:G2Affine, wa:ChainScalar)-> (ChainScalar, SchnorrSig) {
    
        for (_index, suopunit) in self.suop.iter().enumerate() {

            let ri = suopunit.ci.decrypt(sig);
    
            let got = g!(ri * G).normalize();
    
            if got == self.v_ri_pub[suopunit.i] {
    
                let y = s!(suopunit.si - ri).expect_nonzero("");
    
                let sec = s!(self.c_omega - y).expect_nonzero("");
    
                let final_sec = s!(sec - wa).expect_nonzero("");

                let gsec = g!(final_sec * G).normalize(); 
    
                let y_tilde = s!(y + wa).expect_nonzero("");

                let sig = self.sigma_tilde.adapt(&y_tilde);

                sig.clone().verify(&self.vk, &self.tx);

                assert!(gsec== self.xw, "Invalid witness");
    
                return (final_sec, sig);
            }
        }
    
        panic!("Decryption failed")


    }


    }