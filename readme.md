# Cryptographic Collateralized Loan without Smart Contracts

Implementation for the primitive VGES of the paper _Cryptographic Collateralized Loan without Smart Contracts_.
We provide two implementations, the transitive tournament and the linear graph implementation. The code also computes the time it takes for the oracle to attest a full block (3000 transactions) and the total size of these signatures.

## How to run

It takes two values as input:
- g: the security parameter used in cut and choose. Set to the highest (256) by default.
- s: The number of installments of the loan. By default, set to 6.

Prepare the ciphertext for a loan with security parameter 256 and 6 installments:

```
cargo run --release -- -g 256 -s 6
```

