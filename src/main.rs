use atomic_loans::signbls::BLSKeyPair; 

use atomic_loans::common::{message_creator_involved_oracle};

use atomic_loans::schnorradaptor::SchnorrPair;

use atomic_loans::atomicloan::{prepare_loan};

use atomic_loans::cvesfig6::CVESCiphertextFig6;

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
    
    // Oracle key and bank keys

    let kp = BLSKeyPair::new();

    let bank_kp = SchnorrPair::new();

    let installments = 3;

    println!("\nEvaluation: loan setup --oblivious oracle");

    let start_loan = Instant::now();  

    let loan_ciphertexts = prepare_loan(args.gamma.clone(), installments, kp.pk, bank_kp.clone());

    let end_loan = start_loan.elapsed();

    println!(
        "Total loan setup time: {:?} for {} installments",
        end_loan, installments
    );
    println!("Number of CVES ciphertexts prepared: {}", loan_ciphertexts.len());

    println!("\nEvaluation: loan setup --involved oracle");



    let start_loan_2 = Instant::now();
    let contract_details = message_creator_involved_oracle(installments);

    let precom_fig6 = CVESCiphertextFig6::precompute(args.gamma.clone(), installments);

    let cves_fig6 = CVESCiphertextFig6::enc_cs_from_precom(args.gamma.clone(), kp.pk, contract_details.witness.clone(), contract_details.transition.clone(), bank_kp.clone(), contract_details.state, &precom_fig6);

    let end_loan_2 = start_loan_2.elapsed();

    
    println!(
        "Total loan setup time: {:?} for {} installments",
        end_loan_2, installments
    );
    println!("Number of CVES ciphertexts prepared: {}", cves_fig6.m_cis.len());

    let verify_loan_2 = Instant::now();

    cves_fig6.clone().verify(args.gamma.clone());

    println!(
        "Total loan vf time: {:?}",
        verify_loan_2.elapsed()
    );


    // transition 1 - 2:

    let wa = contract_details.witness[1].clone();

    let agg_sig = kp.clone().agg_sign(contract_details.transition.clone());

    let decrypt_loan_2 = Instant::now();

    let (_, _) = cves_fig6.clone().decrypt(agg_sig, wa, 1, 2);
    println!(
        "Total loan decrypt time: {:?}",
        decrypt_loan_2.elapsed()
    );

}
