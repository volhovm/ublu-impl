pub trait Field {
    fn generator() -> Self;
}

pub trait Group {
    type ScalarField: Field;
}

pub trait BiGroup {
    type G1: Group;
    type G2: Group;
    type GT: Group;
    fn pairing(x: Self::G1, y: Self::G2) -> Self::GT;
}

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

pub struct CH20CRS<BG: BiGroup> {
    pub e: BG::G2,
}

pub struct CH20Proof<BG: BiGroup> {
    pub a: Vec<BG::G1>,
    pub b: Vec<BG::G2>,
}

pub fn ch20_prove<BG: BiGroup>(
    crs: CH20CRS<BG>,
    lang: AlgLang<BG::G1>,
    inst: AlgInst<BG::G1>,
    wit: AlgWit<BG::G1>,
) -> CH20Proof<BG> {
    unimplemented!()
}

pub enum CH20VerifierError {
    CH20GenericError(String),
}

pub fn ch20_verify<BG: BiGroup>(
    crs: CH20CRS<BG>,
    lang: AlgLang<BG::G1>,
    inst: AlgInst<BG::G1>,
) -> Result<(), CH20VerifierError> {
    unimplemented!()
}

fn main() {
    println!("Hello, world!");
}
