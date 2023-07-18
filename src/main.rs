//  
// An example DLEQ prover and verifier using Arkworks
// @author @driemworks <driemworks@idealabs.network>
//
use ark_ec::AffineRepr;
use sha3::{digest::{Update, ExtendableOutput, XofReader}};
use ark_ff::{PrimeField, UniformRand};
use ark_bls12_381::Fr;
use ark_serialize::CanonicalSerialize;
use ark_std::{
    rand::SeedableRng,
    ops::Mul,
};

use rand_chacha::ChaCha20Rng;

type K = ark_bls12_381::G1Affine;

/// 
pub struct Proof<K, S> {
    pub commitment: K,
    pub witness: S,
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
///
pub fn prepare_proof(x: Fr) -> Proof<K, Fr> {
    // PROVER
    // setup a rng
    let mut rng = ChaCha20Rng::from_seed([2;32]);
    // a generator of the group G1
    let g: K = K::generator();
    // sample random point in the scalar field
    let r: Fr = Fr::rand(&mut rng);
    // create a commitment point
    let commitment: K = g.mul(r).into();
    let c: Fr = prepare_witness(commitment);
    // calculate s 
    let s = r + x * c;
    Proof {commitment, witness: s }
}

/// verify the proof was generated on the given input
/// 
/// * `x`: The scalar to verify (if the proof is valid for x)
/// * `proof`: The DLEQ proof to verify 
/// 
pub fn verify_proof(x: Fr, proof: Proof<K, Fr>) -> bool {
    let g: K = K::generator();
    // what we would expect R to equal
    let commitment_verifier: K = g.mul(x).into();
    let c = prepare_witness(proof.commitment);
    let check: K = (g.mul(proof.witness) - commitment_verifier.mul(c)).into();
    check == proof.commitment
}

/// Prepare a witness for the proof using Shake128
/// 
/// `p`: A point in the group G1 
/// 
fn prepare_witness(p: K) -> Fr {
    let mut bytes = Vec::with_capacity(p.compressed_size());
    p.serialize_compressed(&mut bytes).unwrap();

    let mut h = sha3::Shake128::default();
    h.update(bytes.as_slice());
    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    Fr::from_be_bytes_mod_order(&o)
}


fn main() {
    // create a random secret
    let mut rng = ChaCha20Rng::from_seed([1;32]);
    let x: Fr = Fr::rand(&mut rng);
    // generate DLEQ proof
    let proof = prepare_proof(x);
    // check validity
    let is_valid = verify_proof(x, proof);
    // should be valid
    assert!(is_valid);
}
