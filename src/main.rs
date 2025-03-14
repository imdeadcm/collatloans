use atomic_loans::signbls::{ kgen, sign}; 

use atomic_loans::common::{sample_rand_chain_scalar};

use atomic_loans::cves::{dec_cs, vf_enc_cs, precompute_enc_cs, enc_cs_with_precomputation};

use atomic_loans::schnorradaptor::{kgen as adaptor_kgen, verify as adaptor_verify};

use atomic_loans::atomicloan::prepare_loan;

use secp256kfun::{g,  G};

use std::time::Instant;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Set the value of gamma
    #[clap(short = 'g', long = "gamma", default_value_t = 30)]
    gamma: usize,
}


fn main() {

    let args = Args::parse();

    
    
    // Oracle key and message
    let kp = kgen();

    let msg = "Alice pay bank installment 1BTC";

    let sig = sign(&kp, &msg);

    // Bank adaptor keys

    let bank_kp = adaptor_kgen();

    let tx = "pay alice 1 BTC";

    

    println!("\nEvaluation cves");

       
    // Secrets a and w

    let wa = sample_rand_chain_scalar();
    let ww = sample_rand_chain_scalar(); 

    let xa = g!(wa * G).normalize();
    let xw = g!(ww * G).normalize();

   

    // Encrypt CVES
  
    let start_cves_enc = Instant::now();

    // let c_ves = enc_cs(args.gamma.clone(), kp.pk, wa.clone(), &msg, ww.clone(), &bank_kp, &tx);

    let precom = precompute_enc_cs(args.gamma.clone());

    let end_cves_pre = start_cves_enc.elapsed();

    let c_ves = enc_cs_with_precomputation(args.gamma.clone(), kp.pk, wa.clone(), &msg, ww.clone(), &bank_kp, &tx, &precom);
    
    let end_cves_enc = start_cves_enc.elapsed();

    
    
    
    // Verify CVES
    let start_cves_vf = Instant::now();
    let result = vf_enc_cs(args.gamma.clone(), kp.pk, xa, xw, &msg, &c_ves, bank_kp.pk, &tx);
    let end_cves_vf = start_cves_vf.elapsed();


    

    println!("CVES verify?: {}", result);

    // Decryption

    let start_cves_dec = Instant::now();
    let (dec_sec, a_sig) = dec_cs(c_ves, sig, wa);
    let end_cves_dec = start_cves_dec.elapsed();

    

    let check2 = dec_sec ==ww;
    println!("Correct witness Decrypted? {}",check2);
    let a_result = adaptor_verify(bank_kp.pk, &tx, a_sig);

    println!("Correct signature Decrypted?: {}", a_result);


    println!(
        "Encryption time: {:?}",
        end_cves_enc
    );
    println!(
        "Encryption time with precomp: {:?}",
        (end_cves_enc - end_cves_pre)
    );

    println!(
        "Verification time: {:?}",
        end_cves_vf
    );

    println!(
        "Decryption time: {:?}",
        end_cves_dec
    );

    println!(
        "Total time: {:?}",
        (end_cves_enc + end_cves_vf + end_cves_dec)
    );

    println!(
        "Total time with precomputation: {:?}",
        (end_cves_enc + end_cves_vf + end_cves_dec - end_cves_pre)
    );

    println!("\nEvaluation: loan setup --dumb oracle");

    let start_loan = Instant::now();

    let installments = 3;

    let loan_ciphertexts = prepare_loan(args.gamma.clone(), installments, kp.pk, &bank_kp);

    let end_loan = start_loan.elapsed();

    println!(
        "Total loan setup time: {:?} for {} installments",
        end_loan, installments
    );
    println!("Number of CVES ciphertexts prepared: {}", loan_ciphertexts.len());


}
