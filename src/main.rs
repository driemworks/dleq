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

pub struct Proof<K, S> {
    pub commitment_1: K,
    pub commitment_2: K,
    pub witness: S,
    pub out: K,
}

/// Prepare a DLEQ proof of knowledge of the value 'x'
/// 
/// * `x`: The secret (scalar)
///
pub fn prepare_proof(x: Fr, d: K, pk: K) -> Proof<K, Fr> {
    let mut rng = ChaCha20Rng::from_seed([2;32]);
    let r: Fr = Fr::rand(&mut rng);
    // "rG1"
    let commitment_1: K = K::generator().mul(r).into();
    // "rQ"
    let commitment_2: K = pk.mul(r).into();
    // "xG1"
    let pk: K = K::generator().mul(x).into();
    // d = "xQ"
    let c: Fr = prepare_witness(vec![commitment_1, commitment_2, pk, d]);
    let s = r + x * c;
    Proof {
        commitment_1, 
        commitment_2, 
        witness: s, 
        out: pk
    }
}

/// verify the proof was generated on the given input
/// 
/// * `q`: The group element such that d = xq for the secret q
/// * `d`: The 'secret'
/// * `proof`: The DLEQ proof to verify 
/// 
pub fn verify_proof(q: K, d: K, proof: Proof<K, Fr>) -> bool {
    let c = prepare_witness(vec![proof.commitment_1, proof.commitment_2, proof.out, d]);
    // c(xG1) - sG1 = R1
    let check_x: K = (proof.out.mul(c) - K::generator().mul(proof.witness)).into();
    // c(xQ) - sQ = R2
    let check_y: K = (d.mul(c) - q.mul(proof.witness)).into();

    check_x.x.eq(&proof.commitment_1.x) &&
        check_y.x.eq(&proof.commitment_2.x)
}

/// Prepare a witness for the proof using Shake128
/// 
/// `p`: A point in the group G1 
/// 
fn prepare_witness(points: Vec<K>) -> Fr {
    let mut h = sha3::Shake128::default();

    for p in points.iter() {
        let mut bytes = Vec::with_capacity(p.compressed_size());
        p.serialize_compressed(&mut bytes).unwrap();
        h.update(bytes.as_slice());
    }
    
    let mut o = [0u8; 32];
    // get challenge from hasher
    h.finalize_xof().read(&mut o);
    Fr::from_be_bytes_mod_order(&o)
}


fn main() {
    // create a random secret
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
