use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;

pub mod ch20;
pub mod commitment;
pub mod consistency;
pub mod elgamal;
pub mod ublu;
pub mod utils;
pub mod sigma;

/// Concrete curve
pub type CC = Bls12_381;

/// Concrete field
pub type CF = <Bls12_381 as Pairing>::ScalarField;

/// Concrete group 1
pub type CG1 = <Bls12_381 as Pairing>::G1;
