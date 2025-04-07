use atomic_loans::signbls::BLSKeyPair; 

use atomic_loans::common::{message_creator_involved_oracle, message_creator,prepare_loan, verify_loan};

use atomic_loans::schnorradaptor::SchnorrPair;

use atomic_loans::involved::CVESCiphertextIn;

use std::time::Instant;

use clap::Parser;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Set the value of gamma
    #[clap(short = 'g', long = "gamma", default_value_t = 256)]
    gamma: usize,

    /// Set the number of states
    #[clap(short = 's', long = "states", default_value_t = 6)]
    states: usize,
}


fn main() {

    let args = Args::parse();    
    
    // Oracle key and bank keys

    let kp = BLSKeyPair::new();

    let bank_kp = SchnorrPair::new();

    let installments = args.states;

    println!(
        "\nNumber of states: {}",
        installments
    );
    println!("\n-----Oblivious oracle-----");
    
    

    let conditions = message_creator(installments, args.gamma.clone());

    let start_loan = Instant::now();      

    let (loan_ciphertexts, _w0) = prepare_loan(args.gamma.clone(), conditions.clone(), kp.pk, bank_kp.clone());

    let end_loan = start_loan.elapsed();
    println!("Number of CVES ciphertexts prepared: {}", loan_ciphertexts.len());

    println!(
        "Setup time with precomputation: {:?}",
        end_loan
    );
    


    let verify_loan_a = Instant::now();

    verify_loan(loan_ciphertexts.clone());

    println!(
        "Verification time: {:?}",
        verify_loan_a.elapsed()
    );

    // transition 1

    let transition = conditions[2].clone();

    let wa = conditions[transition.origin].witness.clone();

    let m_sig = kp.clone().sign(&transition.transition.clone());

    let cves = loan_ciphertexts[2].clone();

    let decrypt_loan_a = Instant::now();

    let (_,_) = cves.decrypt(m_sig, wa);
    println!(
        "Decryption time: {:?}",
        decrypt_loan_a.elapsed()
    );



    println!("\n-----Involved oracle-----");

    
    let contract_details = message_creator_involved_oracle(installments);

    let precom_in = CVESCiphertextIn::precompute(args.gamma.clone(), installments);

    let start_loan_2 = Instant::now();
    let cves_in = CVESCiphertextIn::enc_cs_from_precom(args.gamma.clone(), kp.pk, contract_details.witness.clone(), contract_details.transition.clone(), bank_kp.clone(), contract_details.state, &precom_in);

    let end_loan_2 = start_loan_2.elapsed();

    println!("Number of CVES ciphertexts prepared: {}", cves_in.m_cis.len());
    
    println!(
        "Setup time with precomputation: {:?}",
        end_loan_2
    );
    

    let verify_loan_2 = Instant::now();

    cves_in.clone().verify();

    println!(
        "Verification time: {:?}",
        verify_loan_2.elapsed()
    );


    // transition 1 - 2:

    let wa = contract_details.witness[1].clone();

    let first_2: Vec<String> = contract_details.transition.clone().drain(..3).collect();

    let agg_sig = kp.clone().agg_sign(first_2);

    let decrypt_loan_2 = Instant::now();

    let (_, _) = cves_in.clone().decrypt(agg_sig, wa, 1, 2);
    println!(
        "Decryption time: {:?}",
        decrypt_loan_2.elapsed()
    );

}
