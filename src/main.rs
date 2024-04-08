use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, Group};
use ark_ff::Zero;
use ark_std::UniformRand;
use rand::thread_rng;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinearPoly<G: Group> {
    poly_coeffs: Vec<G::ScalarField>,
    poly_const: G,
}

impl<G: Group> LinearPoly<G> {
    pub fn eval_lpoly(&self, vars: &[G]) -> G {
        self.poly_const
            + vars
                .iter()
                .zip(self.poly_coeffs.iter())
                .map(|(var, coeff)| *var * coeff)
                .sum::<G>()
    }

    pub fn constant(size: usize, elem: G) -> Self {
        LinearPoly {
            poly_coeffs: vec![G::ScalarField::zero(); size],
            poly_const: elem,
        }
    }

    pub fn zero(size: usize) -> Self {
        Self::constant(size, Zero::zero())
    }

    pub fn single(size: usize, ix: usize) -> Self {
        let mut poly_coeffs: Vec<_> = vec![G::ScalarField::zero(); size];
        let poly_const = G::zero();
        poly_coeffs[ix] = G::ScalarField::from(1u64);
        LinearPoly {
            poly_coeffs,
            poly_const,
        }
    }
}

pub struct AlgLang<G: Group> {
    matrix: Vec<Vec<LinearPoly<G>>>,
}

impl<G: Group> AlgLang<G> {
    pub fn instantiate_matrix(&self, inst: &[G]) -> Vec<Vec<G>> {
        let mut res_mat: Vec<Vec<G>> = vec![];
        for i in 0..self.inst_size() {
            let mut row: Vec<G> = vec![];
            for j in 0..self.wit_size() {
                row.push((self.matrix[i][j]).eval_lpoly(inst));
            }
            res_mat.push(row);
        }
        res_mat
    }
    pub fn wit_size(&self) -> usize {
        self.matrix[0].len()
    }
    pub fn inst_size(&self) -> usize {
        self.matrix.len()
    }
    pub fn check_validity(&self, inst: &AlgInst<G>, wit: &AlgWit<G>) -> bool {
        let matrix = self.instantiate_matrix(&inst.0);
        let inst2 = mul_mat_by_vec(&matrix, &wit.0);
        inst2 == inst.0
    }
}

fn mul_mat_by_vec<G: Group>(mat: &[Vec<G>], vec: &[G::ScalarField]) -> Vec<G> {
    let n = mat.len();
    let m = mat[0].len();
    let mut res: Vec<G> = vec![Zero::zero(); n];
    for i in 0..n {
        for j in 0..m {
            res[i] += mat[i][j] * vec[j];
        }
    }
    res
}

pub struct AlgInst<G: Group>(Vec<G>);

pub struct AlgWit<G: Group>(Vec<G::ScalarField>);

pub struct CH20CRS<P: Pairing> {
    pub e: P::G2,
}

pub struct CH20Proof<P: Pairing> {
    pub a: Vec<P::G1>,
    pub d: Vec<P::G2>,
}

pub fn ch20_setup<P: Pairing>() -> CH20CRS<P>
where
    P::ScalarField: UniformRand,
{
    let mut rng = thread_rng();
    let e_td: P::ScalarField = <P::ScalarField as UniformRand>::rand(&mut rng);
    let e: P::G2 = P::G2::generator() * e_td;
    CH20CRS { e }
}

pub fn ch20_prove<P: Pairing>(
    crs: &CH20CRS<P>,
    lang: &AlgLang<P::G1>,
    inst: &AlgInst<P::G1>,
    wit: &AlgWit<P::G1>,
) -> CH20Proof<P>
where
    P::ScalarField: UniformRand,
{
    let mut rng = thread_rng();
    let r: Vec<P::ScalarField> = (0..(lang.wit_size()))
        .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
        .collect();
    let matrix = lang.instantiate_matrix(&inst.0);
    let a: Vec<P::G1> = mul_mat_by_vec(&matrix, &r);
    let d: Vec<P::G2> = wit
        .0
        .iter()
        .zip(r.iter())
        .map(|(w_i, r_i)| crs.e * w_i + P::G2::generator() * r_i)
        .collect();
    CH20Proof { a, d }
}

#[derive(Debug)]
pub enum CH20VerifierError {
    CH20GenericError(String),
}

pub fn ch20_verify<P: Pairing>(
    crs: &CH20CRS<P>,
    lang: &AlgLang<P::G1>,
    inst: &AlgInst<P::G1>,
    proof: &CH20Proof<P>,
) -> Result<(), CH20VerifierError> {
    let mut lhs: Vec<Vec<P::G1>> = vec![vec![]; lang.inst_size()];
    let mut rhs: Vec<Vec<P::G2>> = vec![vec![]; lang.inst_size()];
    let mat = lang.instantiate_matrix(&inst.0);
    println!("{mat:?}");
    for i in 0..lang.inst_size() {
        for j in 0..lang.wit_size() {
            lhs[i].push(mat[i][j]);
            rhs[i].push(proof.d[j]);
        }
        lhs[i].push(inst.0[i]);
        rhs[i].push(-crs.e);
        lhs[i].push(proof.a[i]);
        rhs[i].push(-P::G2::generator());
    }
    // TODO: for efficiency, recombine equations first with a random
    // element, this saves up quite some pairings
    for (l, r) in lhs.iter().zip(rhs.iter()) {
        let pairing_res = P::multi_pairing(l, r);
        if pairing_res != Zero::zero() {
            return Err(CH20VerifierError::CH20GenericError(From::from(
                "Pairing is nonzero",
            )));
        }
    }
    Ok(())
}

// Concrete curve
type CC = Bls12_381;
type CF = <Bls12_381 as Pairing>::ScalarField;

type CG1 = <Bls12_381 as Pairing>::G1;

fn test_ch20_correctness() {
    let mut rng = thread_rng();
    let g: CG1 = UniformRand::rand(&mut rng);
    let x: CF = UniformRand::rand(&mut rng);
    let y: CF = UniformRand::rand(&mut rng);
    let gx: CG1 = g * x;
    let gy: CG1 = g * y;
    let gz: CG1 = g * (x * y);

    let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
        vec![LinearPoly::constant(4, g), LinearPoly::zero(4)],
        vec![LinearPoly::zero(4), LinearPoly::constant(4, g)],
        vec![LinearPoly::zero(4), LinearPoly::single(4, 0)],
    ];

    let lang: AlgLang<CG1> = AlgLang { matrix };
    let inst: AlgInst<CG1> = AlgInst(vec![gx, gy, gz]);
    let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

    let lang_valid = lang.check_validity(&inst, &wit);
    println!("Language valid? {lang_valid:?}");

    let crs: CH20CRS<CC> = ch20_setup();
    let proof: CH20Proof<CC> = ch20_prove(&crs, &lang, &inst, &wit);
    let res = ch20_verify(&crs, &lang, &inst, &proof);
    println!("Result: {:?}", res);
}

fn main() {
    test_ch20_correctness();
}
