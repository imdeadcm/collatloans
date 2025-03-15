use bls12_381::{
    G1Affine, G2Affine, Scalar, Gt, G2Prepared,
};

use crate::common::{sample_rand_gt,sample_rand_scalar, sample_rand_chain_scalar, hash_to_bits, Precomp, wes_precompute};
use crate::wes::{wes_enc, wes_dec, WESCiphertext, wes_enc_precom, wes_enc_precom_vector};

use crate::schnorradaptor::{pre_sign, pre_verify, adapt, SchnorrPair, SchnorrPreSig, SchnorrSig};

use secp256kfun::{g,s,  Scalar as ChainScalar, G, Point};
use secp256kfun::marker::*;

use rayon::prelude::*;


pub struct SopUnit {
    pub i: usize,
    pub ri: ChainScalar,
    pub rho: (Scalar, Gt),
    pub ci: WESCiphertext,
}


pub struct SuopUnit {
    pub i: usize,
    pub si: ChainScalar<Secret, Zero>,
    pub ci: WESCiphertext,
}

pub struct CVESCiphertext {
    pub cis: Vec<WESCiphertext>,
    pub c_omega: ChainScalar<Secret, Zero>,
    pub sop: Vec<SopUnit>,
    pub suop: Vec<SuopUnit>,
    pub v_ri_pub: Vec<Point>,
    pub xa: Point,
    pub xw: Point,
    pub y_pub: Point,
    pub sigma_tilde: SchnorrPreSig,
}

pub fn enc_cs(gamma: usize, pk: G1Affine, wa: ChainScalar, m: &str, sec:ChainScalar, a_kp:&SchnorrPair, tx:&str) -> CVESCiphertext {


    let g2_prepared = G2Prepared::from(G2Affine::generator());
   
   // Parallelize the loop using rayon
   let (v_ri_pub, results): (Vec<Point>, Vec<(ChainScalar, WESCiphertext, Scalar, Gt)>) = (0..gamma)
   .into_par_iter() // 
   .map(|_| {

        // Line 2(a) sample secrets
        let ri = sample_rand_chain_scalar();
        let ri_pub = g!(ri * G).normalize();

        // Line 2(b) compute WES

        // sample random coins outside to use them in cut-and-choose
        let r1 = sample_rand_scalar();
        let r2 = sample_rand_gt(&g2_prepared);
        
        // WES encrypt ri
        let ci = wes_enc(pk, &m, ri.clone(), r1, r2);

        // Return the results as a tuple
        (ri_pub, (ri, ci, r1, r2))
   })
   .collect();

   let mut cis = Vec::<WESCiphertext>::new();

   for result in &results{

    cis.push(result.1);

   }

    // Line 3: Sample y Y

    let y = sample_rand_chain_scalar();
    let y_pub = g!(y * G).normalize();

    let xa = g!(wa * G).normalize();
    let xw = g!(sec * G).normalize();
    let y_tilde_pub = g!(y_pub + xa).normalize().expect_nonzero("");

    // Line 4 presignature;

    let sigma_tilde = pre_sign(a_kp, tx, &y_tilde_pub);

    // Line 5: One time pad to hide sec

    let mut c_omega = s!(y + wa);

    c_omega = s!(c_omega +sec);

    // Line 8: run H2 to get some bits.

    let bits = hash_to_bits(&cis, v_ri_pub.clone(), c_omega.clone(), xa, xw, y_pub, &sigma_tilde);

    let mut sop=Vec::<SopUnit>::new();
    let mut suop=Vec::<SuopUnit>::new();

    for i in 0..gamma {

        let bit = bits[i];

        // Perform actions based on the bit value
        if bit {
            // Bit is 1 (true), fill SOP

            let r1 = results[i].2;
            let r2 = results[i].3;
            let ri = results[i].0.clone();
            let ci = results[i].1.clone();

            let rho = (r1, r2);

            sop.push(SopUnit {i, ri, rho, ci});
        } else {
            // Bit is 0 (false), fill SUOP

            let ri = &results[i].0;

            let si = s!(y + ri);

            let ci = results[i].1.clone();

            suop.push(SuopUnit {i,si, ci});
        }
    }

    CVESCiphertext {
        cis,
        c_omega,
        sop,
        suop,
        v_ri_pub,
        xa,
        xw,
        y_pub,
        sigma_tilde,
    }

}


pub fn dec_cs(c: CVESCiphertext, sig:G2Affine, wa: ChainScalar)-> (ChainScalar<Secret, Zero>, SchnorrSig) {

    let vector = c.suop;

    for (_index, suopunit) in vector.iter().enumerate() {

        let ri = wes_dec(sig, suopunit.ci);

        let got = g!(ri * G).normalize();

        if got == c.v_ri_pub[suopunit.i] {

            let y = s!(suopunit.si - ri).expect_nonzero("");

            let sec = s!(c.c_omega - y);

            let final_sec = s!(sec - wa);

            let y_tilde = s!(y + wa).expect_nonzero("");

            let sig = adapt(&c.sigma_tilde, &y_tilde);

            return (final_sec, sig);
        }
    }

    panic!("Decryption failed")
   
}


pub fn vf_enc_cs(gamma: usize, pk: G1Affine, xa: Point, xw:Point, m: &str, c:&CVESCiphertext, a_pk:Point, tx:&str) ->bool{

    let bits = hash_to_bits(&c.cis, c.v_ri_pub.clone(), c.c_omega.clone(), xa, xw, c.y_pub.clone(), &c.sigma_tilde );

    // Check one time pad
    let gc_omega = g!(c.c_omega * G).normalize();

    let mut check = g!(xa+xw).normalize();
    let y1 = &c.y_pub;
    check = g!(check + y1).normalize();

    if gc_omega != check{
        panic!("CVES verification failed")
    }

    // Check presignature
    let y2=&c.y_pub;

    let y_tilde_pub = g!(y2 + xa).normalize().expect_nonzero("");

    let a_res =  pre_verify(a_pk, tx, &c.sigma_tilde, &y_tilde_pub);

    if a_res != true{
        panic!("Invalid presignature")
    }

    // for idx in 0..gamma {

    (0..gamma).into_par_iter().for_each(|idx|{
        
        let bit = bits[idx];

        // Check that SOP and SUOP have the correct indices
        if bit {
            // Bit is 1 (true)

            if let Some(sop_unit) = c.sop.iter().find(|unit| unit.i == idx) {


                let got = wes_enc(pk, &m, sop_unit.ri.clone(), sop_unit.rho.0, sop_unit.rho.1);

                if got != sop_unit.ci{

                    panic!("CVES verification failed")

                } 
                
            } else {
                panic!("CVES verification failed")
            }

            
        } else {
            // Bit is 0 (false)

            if let Some(suop_unit) = c.suop.iter().find(|unit| unit.i == idx) {

                let gs = g!(suop_unit.si * G).normalize();

                let ri_pub = c.v_ri_pub[idx];

                let check2 = g!(c.y_pub + ri_pub);

                if gs != check2{

                    panic!("CVES verification failed")

                }
                
            } else {
                panic!("CVES verification failed")
            }

            
        }


    });

    true



}


pub fn precompute_enc_cs(gamma: usize)->Vec<Precomp> {

    let g2_prepared = G2Prepared::from(G2Affine::generator());
   
    // Parallelize the loop using rayon
    let precom: Vec<Precomp> = (0..gamma)
    .into_par_iter() // 
    .map(|_| {
 
        wes_precompute(&g2_prepared)
    })
    .collect();

    precom

}

pub fn enc_cs_with_precomputation(gamma: usize, pk: G1Affine, wa: ChainScalar, m: &str, sec:ChainScalar, a_kp:&SchnorrPair, tx:&str, precom: &Vec<Precomp>) -> CVESCiphertext {

   
   // Parallelize the loop using rayon
   let (v_ri_pub, results): (Vec<Point>, Vec<(ChainScalar, WESCiphertext, Scalar, Gt)>) = (0..gamma)
   .into_par_iter() // 
   .map(|i| {

        // Get precomputed data
        let ri = precom[i].ri.clone();
        let ri_pub = precom[i].ri_pub;

        let r1 = precom[i].r1;
        let r2 = precom[i].r2;

        let c1 = precom[i].c1;
        let c3 = precom[i].c3;

        // finalize WES ciphertexts
        let ci = wes_enc_precom(pk, &m, r1, r2, c1, c3);

        // Return the results as a tuple
        (ri_pub, (ri, ci, r1, r2))
   })
   .collect();

   let mut cis = Vec::<WESCiphertext>::new();

   for result in &results{

    cis.push(result.1);

   }

    // Line 3: Sample y Y

    let y = sample_rand_chain_scalar();
    let y_pub = g!(y * G).normalize();

    let xa = g!(wa * G).normalize();
    let xw = g!(sec * G).normalize();
    let y_tilde_pub = g!(y_pub + xa).normalize().expect_nonzero("");

    // Line 4 presignature;

    let sigma_tilde = pre_sign(a_kp, tx, &y_tilde_pub);

    // Line 5: One time pad to hide sec

    let mut c_omega = s!(y + wa);

    c_omega = s!(c_omega +sec);

    // Line 8: run H2 to get some bits.

    let bits = hash_to_bits(&cis, v_ri_pub.clone(), c_omega.clone(), xa, xw, y_pub, &sigma_tilde);

    let mut sop=Vec::<SopUnit>::new();
    let mut suop=Vec::<SuopUnit>::new();

    for i in 0..gamma {

        let bit = bits[i];

        // Perform actions based on the bit value
        if bit {
            // Bit is 1 (true), fill SOP

            let r1 = results[i].2;
            let r2 = results[i].3;
            let ri = results[i].0.clone();
            let ci = results[i].1.clone();

            let rho = (r1, r2);

            sop.push(SopUnit {i, ri, rho, ci});
        } else {
            // Bit is 0 (false), fill SUOP

            let ri = &results[i].0;

            let si = s!(y + ri);

            let ci = results[i].1.clone();

            suop.push(SuopUnit {i,si, ci});
        }
    }

    CVESCiphertext {
        cis,
        c_omega,
        sop,
        suop,
        v_ri_pub,
        xa,
        xw,
        y_pub,
        sigma_tilde,
    }

}


pub fn enc_cs_with_precomputation_vector(gamma: usize, pk: G1Affine, wa: Vec<ChainScalar>, m: Vec<String>, sec:ChainScalar, a_kp:&SchnorrPair, tx:&str , precom: &Vec<Precomp>, end:usize) -> CVESCiphertext {

   
    // Parallelize the loop using rayon
    let (v_ri_pub, results): (Vec<Point>, Vec<(ChainScalar, WESCiphertext, Scalar, Gt)>) = (0..gamma)
    .into_par_iter() // 
    .map(|i| {
 
         // Get precomputed data
         let ri = precom[i].ri.clone();
         let ri_pub = precom[i].ri_pub;
 
         let r1 = precom[i].r1;
         let r2 = precom[i].r2;
 
         let c1 = precom[i].c1;
         let c3 = precom[i].c3;
 
         // finalize WES ciphertexts
         let ci = wes_enc_precom_vector(pk, &m, r1, r2, c1, c3);
 
         // Return the results as a tuple
         (ri_pub, (ri, ci, r1, r2))
    })
    .collect();
 
    let mut cis = Vec::<WESCiphertext>::new();
 
    for result in &results{
 
     cis.push(result.1);
 
    }

    // THESE LINES BELOW NEED TO CHANGE. I HAVE TEMPORARILY CHANGE WA TO Y SO THAT IT DOES NOT BREAK
 
     // Line 3: Sample y Y
 
     let y = sample_rand_chain_scalar();
     let y_pub = g!(y * G).normalize();
 
     let xa = g!(y * G).normalize();
     let xw = g!(sec * G).normalize();
     let y_tilde_pub = g!(y_pub + xa).normalize().expect_nonzero("");
 
     // Line 4 presignature;
 
     let sigma_tilde = pre_sign(a_kp, tx, &y_tilde_pub);
 
     // Line 5: One time pad to hide sec
 
     let mut c_omega = s!(y + y);
 
     c_omega = s!(c_omega +sec);
 
     // Line 8: run H2 to get some bits.
 
     let bits = hash_to_bits(&cis, v_ri_pub.clone(), c_omega.clone(), xa, xw, y_pub, &sigma_tilde);
 
     let mut sop=Vec::<SopUnit>::new();
     let mut suop=Vec::<SuopUnit>::new();

    //  NOTE: HERE WE NEED TO CHANGE A FEW THINGS AS WELL, AND IT REQUIRES A NEW DECRYPTION AND VERIFICATION IMPLEMENTATION
 
     for i in 0..gamma {
 
         let bit = bits[i];
 
         // Perform actions based on the bit value
         if bit {
             // Bit is 1 (true), fill SOP
 
             let r1 = results[i].2;
             let r2 = results[i].3;
             let ri = results[i].0.clone();
             let ci = results[i].1.clone();
 
             let rho = (r1, r2);
 
             sop.push(SopUnit {i, ri, rho, ci});
         } else {
             // Bit is 0 (false), fill SUOP
 
             let ri = &results[i].0;
 
             let si = s!(y + ri);
 
             let ci = results[i].1.clone();
 
             suop.push(SuopUnit {i,si, ci});
         }
     }
 
     CVESCiphertext {
         cis,
         c_omega,
         sop,
         suop,
         v_ri_pub,
         xa,
         xw,
         y_pub,
         sigma_tilde,
     }
 
 }
