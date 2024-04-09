use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{One, Zero};
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
    pub fn contains(&self, inst: &AlgInst<G>, wit: &AlgWit<G>) -> bool {
        let matrix = self.instantiate_matrix(&inst.0);
        let inst2 = mul_mat_by_vec_g_f(&matrix, &wit.0);
        inst2 == inst.0
    }
}

fn mul_mat_by_vec_g_f<G: Group>(mat: &[Vec<G>], vec: &[G::ScalarField]) -> Vec<G> {
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

fn mul_mat_by_vec_f_g<G: Group>(mat: &[Vec<G::ScalarField>], vec: &[G]) -> Vec<G> {
    let n = mat.len();
    let m = mat[0].len();
    let mut res: Vec<G> = vec![Zero::zero(); n];
    for i in 0..n {
        for j in 0..m {
            res[i] += vec[j] * mat[i][j];
        }
    }
    res
}

fn mul_mat_by_vec_f_f<G: Group>(
    mat: &[Vec<G::ScalarField>],
    vec: &[G::ScalarField],
) -> Vec<G::ScalarField> {
    let n = mat.len();
    let m = mat[0].len();
    let mut res: Vec<G::ScalarField> = vec![Zero::zero(); n];
    for i in 0..n {
        for j in 0..m {
            res[i] += vec[j] * mat[i][j];
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
    let a: Vec<P::G1> = mul_mat_by_vec_g_f(&matrix, &r);
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

pub struct CH20Trans<P: Pairing> {
    pub t_am: Vec<Vec<P::ScalarField>>,
    pub t_aa: Vec<P::ScalarField>,
    pub t_xm: Vec<Vec<P::ScalarField>>,
    pub t_xa: Vec<P::ScalarField>,
    pub t_wm: Vec<Vec<P::ScalarField>>,
    pub t_wa: Vec<P::ScalarField>,
}

impl<P: Pairing> CH20Trans<P> {
    fn update_instance(&self, inst: &AlgInst<P::G1>) -> AlgInst<P::G1> {
        let inst_prime_e1: Vec<P::G1> = mul_mat_by_vec_f_g(&self.t_xm, &inst.0);
        let inst_prime_e2: Vec<P::G1> = self
            .t_xa
            .clone()
            .into_iter()
            .map(|x| P::G1::generator() * x)
            .collect();

        let inst_prime: Vec<P::G1> = inst_prime_e1
            .into_iter()
            .zip(inst_prime_e2)
            .map(|(x, y)| x + y)
            .collect();

        AlgInst(inst_prime)
    }

    fn update_witness(&self, wit: &AlgWit<P::G1>) -> AlgWit<P::G1> {
        let wit_prime_e1: Vec<P::ScalarField> = mul_mat_by_vec_f_f::<P::G1>(&self.t_wm, &wit.0);
        let wit_prime_e2: Vec<P::ScalarField> = self.t_wa.clone();

        let wit_prime: Vec<P::ScalarField> = wit_prime_e1
            .into_iter()
            .zip(wit_prime_e2)
            .map(|(x, y)| x + y)
            .collect();

        AlgWit(wit_prime)
    }

    /// Does a probabilistic check that the transformation is blinding
    /// compatible. If returns false, it's not. If returns true, the
    /// language is blinding compatible with some probability.
    fn is_blinding_compatible(&self, lang: &AlgLang<P::G1>, inst: &AlgInst<P::G1>) -> bool {
        let mut rng = thread_rng();
        let s: Vec<P::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
            .collect();
        let matrix1 = lang.instantiate_matrix(&inst.0);
        let mx_s = mul_mat_by_vec_g_f(&matrix1, &s);

        let lhs = mul_mat_by_vec_f_g(
            &self.t_am,
            &mx_s
                .into_iter()
                .chain(inst.0.clone())
                .collect::<Vec<P::G1>>(),
        );

        let inst2 = self.update_instance(inst);
        let matrix2 = lang.instantiate_matrix(&inst2.0);
        let wit2 = self.update_witness(&AlgWit(s));

        let rhs = mul_mat_by_vec_g_f(&matrix2, &wit2.0);

        rhs == lhs
    }
}

pub fn ch20_update<P: Pairing>(
    crs: &CH20CRS<P>,
    lang: &AlgLang<P::G1>,
    inst: &AlgInst<P::G1>,
    proof: &CH20Proof<P>,
    trans: &CH20Trans<P>,
) -> CH20Proof<P> {
    let mut rng = thread_rng();
    // FIXME Not working with random s_hat, but works with zero one
    let s_hat: Vec<P::ScalarField> = (0..(lang.wit_size()))
        .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
        .collect();
    //let s_hat: Vec<P::ScalarField> = (0..(lang.wit_size()))
    //    .map(|_i| P::ScalarField::zero())
    //    .collect();

    let a_prime_e1: Vec<P::G1> = mul_mat_by_vec_f_g(
        &trans.t_am,
        &proof
            .a
            .clone()
            .into_iter()
            .chain(inst.0.clone())
            .collect::<Vec<P::G1>>(),
    );
    let a_prime_e2: Vec<P::G1> = trans
        .t_aa
        .clone()
        .into_iter()
        .map(|x| P::G1::generator() * x)
        .collect();

    let mat = lang.instantiate_matrix(&inst.0);
    let a_prime_e3: Vec<P::G1> = mul_mat_by_vec_g_f(&mat, &s_hat);

    let a_prime: Vec<P::G1> = a_prime_e1
        .into_iter()
        .zip(a_prime_e2)
        .zip(a_prime_e3)
        .map(|((x, y), z)| x + y + z)
        .collect();

    let d_prime_e1: Vec<P::G2> = mul_mat_by_vec_f_g(&trans.t_wm, &proof.d);
    let d_prime_e2: Vec<P::G2> = trans.t_wa.clone().into_iter().map(|x| crs.e * x).collect();
    let d_prime_e3: Vec<P::G2> = trans
        .t_wa
        .clone()
        .into_iter()
        .zip(s_hat)
        .map(|(x, y)| P::G2::generator() * (x + y))
        .collect();

    let d_prime: Vec<P::G2> = d_prime_e1
        .into_iter()
        .zip(d_prime_e2)
        .zip(d_prime_e3)
        .map(|((x, y), z)| x + y + z)
        .collect();

    CH20Proof {
        a: a_prime,
        d: d_prime,
    }
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

    // g 0
    // 0 g
    // 0 x1
    let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
        vec![LinearPoly::constant(4, g), LinearPoly::zero(4)],
        vec![LinearPoly::zero(4), LinearPoly::constant(4, g)],
        vec![LinearPoly::zero(4), LinearPoly::single(4, 0)],
    ];

    let lang: AlgLang<CG1> = AlgLang { matrix };
    let inst: AlgInst<CG1> = AlgInst(vec![gx, gy, gz]);
    let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

    let lang_valid = lang.contains(&inst, &wit);
    println!("Language valid? {lang_valid:?}");

    let crs: CH20CRS<CC> = ch20_setup();
    let proof: CH20Proof<CC> = ch20_prove(&crs, &lang, &inst, &wit);
    let res = ch20_verify(&crs, &lang, &inst, &proof);
    println!("Verification result: {:?}", res);

    let trans: CH20Trans<CC> = {
        let t_xm: Vec<Vec<CF>> = vec![
            vec![CF::one(), CF::zero(), CF::zero()],
            vec![CF::zero(), CF::one(), CF::zero()],
            vec![CF::zero(), CF::zero(), CF::one()],
        ];
        let t_xa: Vec<CF> = vec![CF::zero(); 3];
        let t_wm: Vec<Vec<CF>> = vec![vec![CF::one(), CF::zero()], vec![CF::zero(), CF::one()]];
        let t_wa: Vec<CF> = vec![CF::zero(); 2];
        let emptyrow: Vec<CF> = vec![CF::zero(); 3];
        let t_am: Vec<Vec<CF>> = t_xm
            .clone()
            .into_iter()
            .map(|row| row.into_iter().chain(emptyrow.clone()).collect())
            .collect();
        let t_aa = t_xa.clone();

        CH20Trans {
            t_am,
            t_aa,
            t_xm,
            t_xa,
            t_wm,
            t_wa,
        }
    };
    let trans1: CH20Trans<CC> = {
        let delta: CF = UniformRand::rand(&mut rng);
        let gamma: CF = UniformRand::rand(&mut rng);
        let t_xm: Vec<Vec<CF>> = vec![
            vec![gamma, CF::zero(), CF::zero()],
            vec![CF::zero(), delta, CF::zero()],
            vec![CF::zero(), CF::zero(), gamma * delta],
        ];
        let t_xa: Vec<CF> = vec![CF::zero(); 3];
        let t_wm: Vec<Vec<CF>> = vec![vec![gamma, CF::zero()], vec![CF::zero(), delta]];
        let t_wa: Vec<CF> = vec![CF::zero(); 2];
        let emptyrow: Vec<CF> = vec![CF::zero(); 3];
        let t_am: Vec<Vec<CF>> = t_xm
            .clone()
            .into_iter()
            .map(|row| row.into_iter().chain(emptyrow.clone()).collect())
            .collect();
        let t_aa = t_xa.clone();

        CH20Trans {
            t_am,
            t_aa,
            t_xm,
            t_xa,
            t_wm,
            t_wa,
        }
    };
    let blinding_compatible = trans.is_blinding_compatible(&lang, &inst);
    println!("Transformaion blinding compatible? {blinding_compatible:?}");
    let inst2 = trans.update_instance(&inst);
    let wit2 = trans.update_witness(&wit);
    let blinding_compatible2 = trans.is_blinding_compatible(&lang, &inst2);
    println!("Transformaion blinding compatible wrt new inst? {blinding_compatible2:?}");
    let lang_valid_2 = lang.contains(&inst2, &wit2);
    println!("Transformed language valid? {lang_valid_2:?}");
    let proof2 = ch20_update(&crs, &lang, &inst, &proof, &trans);
    let res2 = ch20_verify(&crs, &lang, &inst2, &proof2);
    println!("Transformed proof valid?: {:?}", res2);
}

fn main() {
    test_ch20_correctness();
}
