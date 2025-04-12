# Cryptographic Collateralized Loan without Smart Contracts

Implementation for the primitive VCMwE of the paper _Cryptographic Collateralized Loan without Smart Contracts_.
We provide two implementations, baseline and efficient.

## How to run

It takes two values as input:
- g: the security parameter used in cut and choose. Set to the highest (256) by default.
- s: The number of installments of the loan. By default, set to 12.

Prepare the ciphertext for a loan with security parameter 256 and 6 installments:

```
cargo run --release -- -g 256 --n-outcomes 6
```
