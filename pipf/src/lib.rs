#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)] 
#![allow(non_snake_case)] // For the sake of generator-scalar differentiation


use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use rand::rngs::OsRng;
use merlin::Transcript;
use bulletproofs::transcript::TranscriptProtocol;
use serde::{Serialize, Deserialize};

/// Generators required for Pedersen Vector Commitments
#[derive(Clone)]
pub struct Generators {
    /// Vector of base points for vector a components
    pub G_vec: Vec<RistrettoPoint>,
    /// Vector of base points for vector b components
    pub H_vec: Vec<RistrettoPoint>,
    /// Base point for blinding factor
    pub G: RistrettoPoint,
}

/// Complete proof for inner product argument
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InnerProductProof {
    /// L points from each round of the protocol
    pub L_vec: Vec<RistrettoPoint>,
    /// R points from each round of the protocol
    pub R_vec: Vec<RistrettoPoint>,
    /// Final value of a after compression
    pub a_final: Scalar,
    /// Final value of b after compression
    pub b_final: Scalar,
    /// Final blinding factor after compression
    pub r_final: Scalar,
}

/// Compute a Pedersen vector commitment to vectors a and b with blinding factor r
///
/// P = Sum(a_i * G_i + b_i * H_i) + r * G
pub fn pedersen_vector_commitment(
    a: &[Scalar],
    b: &[Scalar],
    r: Scalar,
    gens: &Generators
) -> RistrettoPoint {
    // Validate input dimensions
    assert_eq!(a.len(), b.len(), "Vector dimensions must match");
    assert_eq!(a.len(), gens.G_vec.len(), "Vector dimensions must match generator count");
    assert_eq!(a.len(), gens.H_vec.len(), "Vector dimensions must match generator count");

    // Compute the commitment with r*G term
    let mut P = gens.G * r;
    
    // Add the vector terms a_i*G_i + b_i*H_i
    for i in 0..a.len() {
        P += a[i] * gens.G_vec[i] + b[i] * gens.H_vec[i];
    }
    
    P
}

/// Generate a proof that vectors a and b satisfy an inner product relation
/// 
/// This implements the Σ-protocol described in the paper with logarithmic proof size
pub fn generate_inner_product_proof(
    a: Vec<Scalar>,
    b: Vec<Scalar>,
    r: Scalar,
    gens: &Generators,
    transcript: &mut Transcript
) -> InnerProductProof {
    // Validate input dimensions
    assert_eq!(a.len(), b.len(), "Vector dimensions must match");
    assert_eq!(a.len(), gens.G_vec.len(), "Vector dimensions must match generator count");
    assert_eq!(a.len(), gens.H_vec.len(), "Vector dimensions must match generator count");
    
    // Ensure vector length is a power of 2 for simplicity
    assert!(a.len().is_power_of_two(), "Vector length must be a power of 2");

    let mut a = a;
    let mut b = b;
    let mut r = r;
    let mut G_vec = gens.G_vec.clone();
    let mut H_vec = gens.H_vec.clone();
    let mut L_vec = Vec::new();
    let mut R_vec = Vec::new();
    
    // Label the proof in the transcript
    transcript.append_message(b"dom-sep", b"inner-product-proof");
    
    // Recursive compression steps
    while a.len() > 1 {
        let n = a.len();
        let (a_L, a_R) = a.split_at(n / 2);
        let (b_L, b_R) = b.split_at(n / 2);
        let (G_L, G_R) = G_vec.split_at(n / 2);
        let (H_L, H_R) = H_vec.split_at(n / 2);
        
        // Random blinding factors for L and R
        let r_L = Scalar::random(&mut OsRng);
        let r_R = Scalar::random(&mut OsRng);
        
        // Compute the L commitment according to protocol
        let mut L = gens.G * r_L;
        for i in 0..(n / 2) {
            L += a_L[i] * G_R[i] + b_R[i] * H_L[i];
        }
        
        // Compute the R commitment according to protocol
        let mut R = gens.G * r_R;
        for i in 0..(n / 2) {
            R += a_R[i] * G_L[i] + b_L[i] * H_R[i];
        }
        
        // Add L and R to the transcript and generate challenge
        transcript.append_point(b"L", &L.compress());
        transcript.append_point(b"R", &R.compress());
        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.invert();
        
        // Compress the vectors a and b
        let mut a_new = Vec::with_capacity(n / 2);
        let mut b_new = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            a_new.push(x * a_L[i] + x_inv * a_R[i]);
            b_new.push(x_inv * b_L[i] + x * b_R[i]);
        }
        a = a_new;
        b = b_new;
        
        // Compress the generators
        let mut G_new = Vec::with_capacity(n / 2);
        let mut H_new = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            G_new.push(G_L[i] * x + G_R[i] * x_inv);
            H_new.push(H_L[i] * x_inv + H_R[i] * x);
        }
        G_vec = G_new;
        H_vec = H_new;
        
        // Update the blinding factor
        r = r_L * x + r_R * x_inv;
        
        // Store L and R values for the proof
        L_vec.push(L);
        R_vec.push(R);
    }
    
    // Create the final proof
    InnerProductProof {
        L_vec,
        R_vec,
        a_final: a[0],
        b_final: b[0],
        r_final: r,
    }
}

/// Verify an inner product proof
/// 
/// Checks if the claimed inner product c = <a,b> is correct for vectors committed in P
pub fn verify_inner_product_proof(
    P: RistrettoPoint,             // The original commitment
    c: Scalar,                     // Claimed inner product value
    proof: &InnerProductProof,     // The proof to verify
    gens: &Generators,             // The generators used
    transcript: &mut Transcript    // Transcript for Fiat-Shamir
) -> bool {
    // Label the proof verification in the transcript
    transcript.append_message(b"dom-sep", b"inner-product-proof");
    
    // Calculate number of rounds based on proof size
    let lg_n = proof.L_vec.len();
    let n = 1 << lg_n;
    
    // Ensure generators are correct size
    if gens.G_vec.len() != n || gens.H_vec.len() != n {
        return false;
    }
    
    // Extract the final values from the proof
    let a = proof.a_final;
    let b = proof.b_final;
    
    // Check that the claimed inner product matches the final values
    if a * b != c {
        return false;
    }
    
    // Collect all challenges for verification
    let mut challenges = Vec::with_capacity(lg_n);
    let mut challenge_inverses = Vec::with_capacity(lg_n);
    
    // Replay transcript to get same challenges as prover
    for i in 0..lg_n {
        transcript.append_point(b"L", &proof.L_vec[i].compress());
        transcript.append_point(b"R", &proof.R_vec[i].compress());
        let x_i = transcript.challenge_scalar(b"x");
        challenges.push(x_i);
        challenge_inverses.push(x_i.invert());
    }
    
    // Calculate final generators after all folding operations
    let (final_G, final_H) = calculate_final_generators(gens, &challenges, &challenge_inverses, lg_n);
    
    // Calculate the expected commitment from final values
    let final_commitment = gens.G * proof.r_final + 
                          final_G * proof.a_final + 
                          final_H * proof.b_final;
    
    // Compute the contribution from L and R terms
    let folded_commitment = fold_commitments(&proof.L_vec, &proof.R_vec, &challenges, &challenge_inverses);
    
    // The verification succeeds if the original commitment equals the computed commitment
    P == final_commitment + folded_commitment
}

/// Helper function to calculate final generators after folding
fn calculate_final_generators(
    gens: &Generators,
    challenges: &[Scalar],
    challenge_inverses: &[Scalar],
    lg_n: usize
) -> (RistrettoPoint, RistrettoPoint) {
    let n = 1 << lg_n;
    
    // Calculate which original generator maps to the first position
    let mut final_G = gens.G_vec[0];
    let mut final_H = gens.H_vec[0];
    
    // Apply all challenges to calculate the correct base points
    for j in 0..lg_n {
        let mut weight_G = Scalar::from(1u64);
        let mut weight_H = Scalar::from(1u64);
        
        // Calculate the weights based on the bit pattern
        for i in 0..lg_n {
            let bit = (j >> i) & 1;
            if bit == 1 {
                weight_G *= challenges[lg_n - i - 1];
                weight_H *= challenge_inverses[lg_n - i - 1];
            } else {
                weight_G *= challenge_inverses[lg_n - i - 1];
                weight_H *= challenges[lg_n - i - 1];
            }
        }
        
        // Apply weights to the appropriate generators
        if j > 0 {
            final_G = final_G + gens.G_vec[j] * weight_G;
            final_H = final_H + gens.H_vec[j] * weight_H;
        }
    }
    
    (final_G, final_H)
}

/// Fold all L and R values into a single commitment
fn fold_commitments(
    L_vec: &[RistrettoPoint],
    R_vec: &[RistrettoPoint],
    challenges: &[Scalar],
    challenge_inverses: &[Scalar]
) -> RistrettoPoint {
    let mut result = RistrettoPoint::identity();
    
    // Fold in each L and R with appropriate challenge factors
    for i in 0..L_vec.len() {
        // Calculate challenge products
        let mut s_L = Scalar::from(1u64);
        let mut s_R = Scalar::from(1u64);
        
        for j in 0..i {
            s_L *= challenges[j];
            s_R *= challenge_inverses[j];
        }
        
        // Add the scaled L and R terms
        result += L_vec[i] * s_L + R_vec[i] * s_R;
    }
    
    result
}

/// Create a set of generators suitable for Pedersen Vector Commitments
pub fn create_generators(n: usize) -> Generators {
    assert!(n.is_power_of_two(), "Number of generators must be a power of 2");
    
    let mut G_vec = Vec::with_capacity(n);
    let mut H_vec = Vec::with_capacity(n);
    let mut csprng = OsRng;
    
    // Generate random base points
    for _ in 0..n {
        G_vec.push(RistrettoPoint::random(&mut csprng));
        H_vec.push(RistrettoPoint::random(&mut csprng));
    }
    let G = RistrettoPoint::random(&mut csprng);
    
    Generators { G_vec, H_vec, G }
}

/// Helper function to compute inner product of two vectors
pub fn inner_product(a: &[Scalar], b: &[Scalar]) -> Scalar {
    assert_eq!(a.len(), b.len(), "Vectors must have the same length");
    
    let mut result = Scalar::from(0u64);
    for i in 0..a.len() {
        result += a[i] * b[i];
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_pedersen_vector_commitment() {
        let n = 8;
        let gens = create_generators(n);
        
        // Random vectors a and b
        let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let r = Scalar::random(&mut OsRng);
        
        // Create commitment
        let P = pedersen_vector_commitment(&a, &b, r, &gens);
        
        // Check commitment contains correct components
        let mut P_check = gens.G * r;
        for i in 0..n {
            P_check += a[i] * gens.G_vec[i] + b[i] * gens.H_vec[i];
        }
        
        assert_eq!(P, P_check, "Pedersen commitment calculation incorrect");
    }
    
    #[test]
    fn test_inner_product_proof_correctness() {
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
        
        assert!(result, "Inner product proof verification failed");
    }
    
    #[test]
    fn test_invalid_inner_product() {
        let n = 8;
        let gens = create_generators(n);
        
        // Random vectors a and b
        let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
        let r = Scalar::random(&mut OsRng);
        
        // Create commitment
        let P = pedersen_vector_commitment(&a, &b, r, &gens);
        
        // Calculate inner product
        let mut c = inner_product(&a, &b);
        
        // Modify c to make it invalid
        c += Scalar::from(1u64);
        
        // Generate proof
        let mut prover_transcript = Transcript::new(b"test-inner-product");
        let proof = generate_inner_product_proof(a.clone(), b.clone(), r, &gens, &mut prover_transcript);
        
        // Verify proof with incorrect inner product
        let mut verifier_transcript = Transcript::new(b"test-inner-product");
        let result = verify_inner_product_proof(P, c, &proof, &gens, &mut verifier_transcript);
        
        assert!(!result, "Invalid inner product should fail verification");
    }
    
    #[test]
    fn test_proof_size_logarithmic() {
        let test_sizes = [8, 16, 32, 64, 128];
        
        for &n in &test_sizes {
            let gens = create_generators(n);
            
            // Random vectors a and b
            let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
            let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
            let r = Scalar::random(&mut OsRng);
            
            // Generate proof
            let mut transcript = Transcript::new(b"test-inner-product");
            let proof = generate_inner_product_proof(a.clone(), b.clone(), r, &gens, &mut transcript);
            
            // Check proof size is log(n)
            assert_eq!(proof.L_vec.len(), proof.R_vec.len());
            assert_eq!(proof.L_vec.len(), n.trailing_zeros() as usize);
        }
    }
}