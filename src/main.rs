use ark_ec::{pairing::Pairing, Group};
use ark_ff::Field;

pub struct LinearPoly<G: Group> {
    poly_coeffs: Vec<G::ScalarField>,
    poly_const: G,
}

pub struct AlgLang<G: Group> {
    matrix: Vec<Vec<G::ScalarField>>,
    inst_map: LinearPoly<G>,
}

pub struct AlgInst<G: Group> {
    pub inst: Vec<G>,
}

pub struct AlgWit<G: Group> {
    pub wit: Vec<G::ScalarField>,
}

pub struct CH20CRS<P: Pairing> {
    pub e: P::G2,
}

pub struct CH20Proof<P: Pairing> {
    pub a: Vec<P::G1>,
    pub b: Vec<P::G2>,
}

pub fn ch20_prove<P: Pairing>(
    crs: CH20CRS<P>,
    lang: AlgLang<P::G1>,
    inst: AlgInst<P::G1>,
    wit: AlgWit<P::G1>,
) -> CH20Proof<P> {
    unimplemented!()
}

pub enum CH20VerifierError {
    CH20GenericError(String),
}

pub fn ch20_verify<P: Pairing>(
    crs: CH20CRS<P>,
    lang: AlgLang<P::G1>,
    inst: AlgInst<P::G1>,
) -> Result<(), CH20VerifierError> {
    unimplemented!()
}

fn main() {
    println!("Hello, world!");
}
