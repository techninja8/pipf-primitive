extern crate curve25519_dalek;
extern crate rand;
extern crate merlin;
extern crate serde;

use pipf::*;
use curve25519_dalek::Scalar;
use rand::rngs::OsRng;
use merlin::Transcript;

fn main() {
    let n = 8;
        let gens = create_generators(n);
        
        // Random vectors a and b
        let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let r = Scalar::random(&mut OsRng);
        
        // Create commitment
        let P = pedersen_vector_commitment(&a, &b, r, &gens);
        
        // Calculate inner product
        let c = inner_product(&a, &b);
        
        // Generate proof
        let mut prover_transcript = Transcript::new(b"test-inner-product");
        let proof = generate_inner_product_proof(a.clone(), b.clone(), r, &gens, &mut prover_transcript);
        
        // Verify proof
        let mut verifier_transcript = Transcript::new(b"test-inner-product");
        let result = verify_inner_product_proof(P, c, &proof, &gens, &mut verifier_transcript);

        if result == false {
            println!("False")
        }
}