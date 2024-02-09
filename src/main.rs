use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::Field;
use ark_std::UniformRand;
use rand::thread_rng;

pub struct LinearPoly<G: Group> {
    poly_coeffs: Vec<G::ScalarField>,
    poly_const: G,
}

pub struct AlgLang<G: Group> {
    matrix: Vec<Vec<LinearPoly<G>>>,
    inst_map: LinearPoly<G>,
}

impl<G: Group> AlgLang<G> {
    pub fn instantiate_matrix(&self, inst: Vec<G>) -> Vec<Vec<G>> {
        unimplemented!()
    }
}

fn mul_mat_by_vec<G: Group>(mat: Vec<Vec<G>>, vec: Vec<G::ScalarField>) -> Vec<G> {
    unimplemented!()
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

pub fn ch20_setup<P: Pairing>() -> CH20CRS<P> {
    let mut rng = thread_rng();
    //let e = P::ScalarField::rand(&mut rng);
    //let e = <P as Pairing>::G2::rand(&mut rng);
    let e = unimplemented!();
    CH20CRS { e }
}

pub fn ch20_prove<P: Pairing>(
    crs: CH20CRS<P>,
    lang: AlgLang<P::G1>,
    inst: AlgInst<P::G1>,
    wit: AlgWit<P::G1>,
) -> CH20Proof<P> {
    let r: Vec<P::ScalarField> = unimplemented!();
    let matrix = lang.instantiate_matrix(inst.inst);
    let a: Vec<P::G1> = mul_mat_by_vec(matrix, r);
    //let d: Vec<P::G2> = wit
    //    .wit
    //    .iter()
    //    .zip(r.iter())
    //    .map(|(w_i, r_i)| crs.e * w_i + r_i);
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
