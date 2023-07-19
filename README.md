# DLEQ Proof Example

This is an example that uses Arkworks to generate and verify a DLEQ proof. It uses Shake128 to hash values and operates over curve BLS12-381.

## Setup

- `cargo build`
- `cargo run`

## Run

This crate exposes two functions, `prepare_proof` and `verify_proof` that allow for a secret scalar to be used to prepare and verify a proof.

``` rust
fn example_verify_x() {
    let mut rng = ChaCha20Rng::from_seed([1;32]);
    let x: Fr = Fr::rand(&mut rng);
    let pk: K = K::rand(&mut rng);
    let d: K = pk.mul(x).into();
    // generate DLEQ proof
    let proof = prepare_proof(x, d, pk);
    // check validity
    let is_valid = verify_proof(pk, d, proof);
    // should be valid
    assert!(is_valid);
}
```

## TODOs

- [ ] make generic in regards to the curve used
- [ ] add tests