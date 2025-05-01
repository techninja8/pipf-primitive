// Pedersen-Vector Commitments with Inner Product Proofs
//
// This module implements the Pedersen Vector Commitment scheme with
// logarithmic-sized Inner Product Argument proofs based on the PIPF framework.
// The implementation uses the Ristretto group over Curve25519 for elliptic curve operations.
//
// Key features:
// - Efficient vector commitments to pairs of vectors (a, b)
// - Logarithmic-sized proofs of knowledge for inner product relation <a,b> = c
// - Based on discrete logarithm assumptions in the Ristretto group
//
// Reference: "Bulletproofs: Short Proofs for Confidential Transactions and More"
// by Bünz, Bootle, Boneh, Poelstra, Wuille, and Maxwell

#![allow(unused_variables)]
#![allow(dead_code)]
#![allow(unused_imports)] 
#![allow(non_snake_case)] // For the sake of generator-scalar differentiation


use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, MultiscalarMul};
use rand::rngs::OsRng;
use merlin::Transcript;
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha512};
use std::fmt;

/// Wrapper around RistrettoPoint to implement Debug formatting
/// 
/// This allows for cleaner debug output of RistrettoPoint values
struct DebugRistrettoPoint(RistrettoPoint);

impl fmt::Debug for DebugRistrettoPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Use the compressed representation of the RistrettoPoint for printing
        write!(f, "RistrettoPoint({:?})", self.0.compress().to_bytes())
    }
}


/// Protocol extensions for Merlin transcripts in zero-knowledge proofs
/// 
/// This trait extends Merlin transcripts with methods specific to
/// handling Ristretto points and generating challenge scalars.
pub trait TranscriptProtocol {
    /// Append a compressed Ristretto point to the transcript with the given label
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    
    /// Extract a challenge scalar from the transcript with the given label
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn append_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.append_message(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);
        Scalar::from_bytes_mod_order_wide(&buf)
    }
}

/// Derive a Ristretto point from a domain-separated hash label
/// 
/// This function creates a deterministic point from a label using SHA-512
/// to prevent chosen base point attacks.
fn hash_to_point(label: &[u8]) -> RistrettoPoint {
    let hash = Sha512::digest(label);
    RistrettoPoint::from_uniform_bytes(&hash[..64].try_into().unwrap())
}

/// Generators required for Pedersen Vector Commitments
/// 
/// This structure holds the base points needed for creating
/// vector commitments and proofs. It contains:
/// - G_vec: Base points for the first vector (a)
/// - H_vec: Base points for the second vector (b)
/// - G: Base point for the blinding factor
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
/// 
/// This structure contains all the elements needed to verify
/// an inner product relation. The proof size scales logarithmically
/// with the size of the original vectors.
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
/// Creates a commitment of the form:
/// P = Sum(a_i * G_i + b_i * H_i) + r * G
/// 
/// This commitment hides the vectors a and b while allowing proofs about their properties.
/// The blinding factor r ensures the commitment is hiding.
/// 
/// # Arguments
/// * `a` - First vector to commit to
/// * `b` - Second vector to commit to
/// * `r` - Blinding factor (randomness)
/// * `gens` - Generator points for the commitment
/// 
/// # Returns
/// * A RistrettoPoint representing the commitment
/// 
/// # Panics
/// * If vector dimensions don't match
pub fn pedersen_vector_commitment(
    a: &[Scalar],
    b: &[Scalar],
    r: Scalar,
    gens: &Generators
) -> RistrettoPoint {
    // Validate input dimensions
    // Panic for dimension mismatch
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
/// This function creates a logarithmic-sized proof that the prover knows vectors
/// a and b committed in P such that <a,b> = c, without revealing the vectors.
/// 
/// The protocol works by recursively compressing the vectors in half at each step,
/// generating proof elements L and R that allow the verifier to check correctness.
/// 
/// # Arguments
/// * `a` - First vector in the inner product
/// * `b` - Second vector in the inner product
/// * `r` - Blinding factor used in the commitment
/// * `gens` - Generator points for the commitment
/// * `transcript` - Transcript for the Fiat-Shamir transformation
/// 
/// # Returns
/// * A complete inner product proof
/// 
/// # Panics
/// * If vector dimensions don't match
/// * If vector length is not a power of 2
pub fn generate_inner_product_proof(
    a: Vec<Scalar>,
    b: Vec<Scalar>,
    r: Scalar,
    gens: &Generators,
    transcript: &mut Transcript
) -> InnerProductProof {
    assert_eq!(a.len(), b.len(), "Vector dimensions must match");
    assert_eq!(a.len(), gens.G_vec.len(), "Vector dimensions must match generator count");
    assert_eq!(a.len(), gens.H_vec.len(), "Vector dimensions must match generator count");
    assert!(a.len().is_power_of_two(), "Vector length must be a power of 2");

    let mut a = a;
    let mut b = b;
    let mut r = r;
    let mut G_vec = gens.G_vec.clone();
    let mut H_vec = gens.H_vec.clone();
    let mut L_vec = Vec::new();
    let mut R_vec = Vec::new();
    
    transcript.append_message(b"dom-sep", b"inner-product-proof");
    
    while a.len() > 1 {
        let n = a.len();
        let (a_L, a_R) = a.split_at(n / 2);
        let (b_L, b_R) = b.split_at(n / 2);
        let (G_L, G_R) = G_vec.split_at(n / 2);
        let (H_L, H_R) = H_vec.split_at(n / 2);
        
        let r_L = Scalar::random(&mut OsRng);
        let r_R = Scalar::random(&mut OsRng);
        
        let mut L = gens.G * r_L;
        for i in 0..(n / 2) {
            L += a_L[i] * G_R[i] + b_R[i] * H_L[i];
        }
        
        let mut R = gens.G * r_R;
        for i in 0..(n / 2) {
            R += a_R[i] * G_L[i] + b_L[i] * H_R[i];
        }
        
        transcript.append_point(b"L", &L.compress());
        transcript.append_point(b"R", &R.compress());
        
        let x = transcript.challenge_scalar(b"x");
        let x_inv = x.invert();
        
        let mut a_new = Vec::with_capacity(n / 2);
        let mut b_new = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            a_new.push(x * a_L[i] + x_inv * a_R[i]);
            b_new.push(x_inv * b_L[i] + x * b_R[i]);
        }
        a = a_new;
        b = b_new;
        
        let mut G_new = Vec::with_capacity(n / 2);
        let mut H_new = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            G_new.push(G_L[i] * x + G_R[i] * x_inv);
            H_new.push(H_L[i] * x_inv + H_R[i] * x);
        }
        G_vec = G_new;
        H_vec = H_new;
        
        r = r_L * x + r_R * x_inv;
        
        L_vec.push(L);
        R_vec.push(R);
    }
    
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
/// This function verifies that a commitment P contains vectors a and b
/// such that <a,b> = c, using only the logarithmic-sized proof elements.
/// 
/// The verification works by folding the original commitment P according to
/// the same challenges used in proof generation, and checking that the result
/// matches what would be computed from the final values.
/// 
/// # Arguments
/// * `P` - The original Pedersen vector commitment
/// * `c` - The claimed inner product value <a,b>
/// * `proof` - The inner product proof to verify
/// * `gens` - Generator points for the commitment
/// * `transcript` - Transcript for the Fiat-Shamir transformation
/// 
/// # Returns
/// * `true` if the proof is valid, `false` otherwise
pub fn verify_inner_product_proof(
    P: RistrettoPoint,
    c: Scalar,
    proof: &InnerProductProof,
    gens: &Generators,
    transcript: &mut Transcript
) -> bool {
    transcript.append_message(b"dom-sep", b"inner-product-proof");
    
    let lg_n = proof.L_vec.len();
    let n = 1 << lg_n;
    
    if gens.G_vec.len() != n || gens.H_vec.len() != n {
        return false;
    }
    
    let a = proof.a_final;
    let b = proof.b_final;
    
    if a * b != c {
        return false;
    }
    
    let mut challenges = Vec::with_capacity(lg_n);
    let mut challenge_inverses = Vec::with_capacity(lg_n);
    
    for i in 0..lg_n {
        transcript.append_point(b"L", &proof.L_vec[i].compress());
        transcript.append_point(b"R", &proof.R_vec[i].compress());
        let x_i = transcript.challenge_scalar(b"x");
        challenges.push(x_i);
        challenge_inverses.push(x_i.invert());
    }
    
    let (final_G, final_H) = calculate_final_generators(gens, &challenges, &challenge_inverses, lg_n);
    
    let final_commitment = gens.G * proof.r_final + 
                          final_G * proof.a_final + 
                          final_H * proof.b_final;
    
    let folded_commitment = fold_commitments(&proof.L_vec, &proof.R_vec, &challenges, &challenge_inverses);
    
    P == final_commitment + folded_commitment
}

/// Helper function to calculate final generators after folding
/// 
/// This function computes the effective generators after applying
/// all the challenge factors from the proof protocol.
/// 
/// # Arguments
/// * `gens` - Original generator points
/// * `challenges` - Challenge scalars from the proof
/// * `challenge_inverses` - Inverses of the challenge scalars
/// * `lg_n` - Log base 2 of the vector dimension
/// 
/// # Returns
/// * A tuple of (final_G, final_H) generators
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
/// 
/// This function combines all the L and R proof elements according to
/// the challenge factors to compute the expected contribution to the
/// final verification equation.
/// 
/// # Arguments
/// * `L_vec` - L points from the proof
/// * `R_vec` - R points from the proof
/// * `challenges` - Challenge scalars from verification
/// * `challenge_inverses` - Inverses of the challenge scalars
/// 
/// # Returns
/// * A RistrettoPoint representing the folded commitment
fn fold_commitments(
    L_vec: &[RistrettoPoint],
    R_vec: &[RistrettoPoint],
    challenges: &[Scalar],
    challenge_inverses: &[Scalar]
) -> RistrettoPoint {
    let mut result = RistrettoPoint::identity();
    
    for i in 0..L_vec.len() {
        let mut s_L = Scalar::from(1u64);
        let mut s_R = Scalar::from(1u64);
        
        for j in 0..i {
            s_L *= challenges[j];
            s_R *= challenge_inverses[j];
        }
        
        result += L_vec[i] * s_L + R_vec[i] * s_R;
    }
    
    result
}

/// Create a set of generators suitable for Pedersen Vector Commitments
/// 
/// This function generates cryptographically secure base points for
/// use in vector commitments. The points are derived deterministically
/// from labels to ensure they have no known discrete log relationship.
/// 
/// # Arguments
/// * `n` - Number of generators to create (vector dimension)
/// 
/// # Returns
/// * A Generators struct with G_vec, H_vec, and G base points
pub fn create_generators(n: usize) -> Generators {
    let mut G_vec = Vec::with_capacity(n);
    let mut H_vec = Vec::with_capacity(n);

    for i in 0..n {
        let Gi_input = format!("G_vec_{}", i);
        let mut Gi_hasher = Sha512::new();
        Gi_hasher.update(Gi_input.as_bytes());
        let Gi = RistrettoPoint::from_hash(Gi_hasher);
        G_vec.push(Gi);

        let Hi_input = format!("H_vec_{}", i);
        let mut Hi_hasher = Sha512::new();
        Hi_hasher.update(Hi_input.as_bytes());
        let Hi = RistrettoPoint::from_hash(Hi_hasher);
        H_vec.push(Hi);
    }

    let G = hash_to_point(b"G_blinding");

    Generators { G_vec , H_vec , G }
}

/// Helper function to compute inner product of two vectors
/// 
/// Calculates the sum of element-wise products a_i * b_i
/// 
/// # Arguments
/// * `a` - First vector
/// * `b` - Second vector
/// 
/// # Returns
/// * The inner product as a Scalar
/// 
/// # Panics
/// * If vectors have different lengths
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

#[cfg(feature = "example")]
fn main() {
    use rand::rngs::OsRng;
    
    // Size of vectors (must be power of 2)
    let n = 8;
    println!("Generating Pedersen Vector Commitment for vectors of size {}", n);
    
    // Generate base points
    let gens = create_generators(n);
    
    // Create random vectors
    let a: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let b: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut OsRng)).collect();
    let r = Scalar::random(&mut OsRng);
    
    // Create commitment
    let P = pedersen_vector_commitment(&a, &b, r, &gens);
    println!("Created commitment P");
    
    // Calculate inner product
    let c = inner_product(&a, &b);
    println!("Inner product c = <a,b> calculated");
    
    // Generate proof
    let mut prover_transcript = Transcript::new(b"example-inner-product");
    let proof = generate_inner_product_proof(a.clone(), b.clone(), r, &gens, &mut prover_transcript);
    println!("Generated inner product proof with {} L/R pairs", proof.L_vec.len());
    
    // Verify proof
    let mut verifier_transcript = Transcript::new(b"example-inner-product");
    let result = verify_inner_product_proof(P, c, &proof, &gens, &mut verifier_transcript);
    println!("Verification result: {}", result);
}