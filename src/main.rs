#![allow(clippy::needless_range_loop)]
#![allow(dead_code)]

use ark_bls12_381::Bls12_381;
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{One, PrimeField, Zero};
use ark_std::UniformRand;
use rand::{thread_rng, RngCore};

fn binomial(n: usize, k: usize) -> usize {
    if k == 0 {
        1
    } else {
        (n * binomial(n - 1, k - 1)) / k
    }
}

fn test_binomial() {
    assert!(binomial(1, 1) == 1);
    assert!(binomial(9, 2) == 36);
    assert!(binomial(4, 3) == 4);
    assert!(binomial(5, 4) == 5);
    assert!(binomial(12, 5) == 792);
    println!("Binomial test passed")
}

fn field_pow<F: PrimeField>(base: F, exp: usize) -> F {
    let mut res: F = F::one();
    let mut exp2 = exp;
    let mut bits: Vec<bool> = vec![];
    while !exp2.is_zero() {
        bits.push((exp2 & 0x1) == 0x1);
        exp2 >>= 1;
    }
    for b in bits.iter().rev() {
        res = res * res;
        if *b {
            res *= base;
        }
    }
    res
}

fn test_field_pow() {
    let mut rng = thread_rng();
    let x: CF = UniformRand::rand(&mut rng);
    assert!(field_pow(x, 1) == x);
    assert!(field_pow(x, 2) == x * x);
    assert!(field_pow(x, 3) == x * x * x);
    assert!(field_pow(x, 4) == x * x * x * x);
    assert!(field_pow(x, 5) == x * x * x * x * x);
    println!("Field test passed")
}

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

#[derive(Debug, Clone)]
pub struct AlgInst<G: Group>(Vec<G>);

#[derive(Debug, Clone)]
pub struct AlgWit<G: Group>(Vec<G::ScalarField>);

#[derive(Debug, Clone)]
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

pub struct CH20CRS<P: Pairing> {
    pub e: P::G2,
}

pub struct CH20Proof<P: Pairing> {
    pub a: Vec<P::G1>,
    pub d: Vec<P::G2>,
}

pub fn ch20_setup<P: Pairing>(rng: &mut dyn RngCore) -> CH20CRS<P>
where
    P::ScalarField: UniformRand,
{
    let e_td: P::ScalarField = <P::ScalarField as UniformRand>::rand(rng);
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
    pub t_aa: Vec<P::G1>,
    pub t_xm: Vec<Vec<P::ScalarField>>,
    pub t_xa: Vec<P::G1>,
    pub t_wm: Vec<Vec<P::ScalarField>>,
    pub t_wa: Vec<P::ScalarField>,
}

impl<P: Pairing> CH20Trans<P> {
    /// Creates a zero (ID) transformation for a given language.
    pub fn zero_trans(lang: &AlgLang<P::G1>) -> CH20Trans<P> {
        let mut t_xm: Vec<Vec<P::ScalarField>> =
            vec![vec![P::ScalarField::zero(); lang.inst_size()]; lang.inst_size()];
        for i in 0..lang.inst_size() {
            t_xm[i][i] = P::ScalarField::one();
        }
        let mut t_wm: Vec<Vec<P::ScalarField>> =
            vec![vec![P::ScalarField::zero(); lang.wit_size()]; lang.wit_size()];
        for i in 0..lang.wit_size() {
            t_wm[i][i] = P::ScalarField::one();
        }

        let t_xa: Vec<P::G1> = vec![P::G1::zero(); lang.inst_size()];
        let t_wa: Vec<P::ScalarField> = vec![P::ScalarField::zero(); lang.wit_size()];

        let t_am: Vec<Vec<P::ScalarField>> = t_xm
            .clone()
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .chain(vec![P::ScalarField::zero(); lang.inst_size()])
                    .collect()
            })
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
    }

    pub fn update_instance(&self, inst: &AlgInst<P::G1>) -> AlgInst<P::G1> {
        let inst_prime_e1: Vec<P::G1> = mul_mat_by_vec_f_g(&self.t_xm, &inst.0);
        let inst_prime_e2: Vec<P::G1> = self.t_xa.clone();

        let inst_prime: Vec<P::G1> = inst_prime_e1
            .into_iter()
            .zip(inst_prime_e2)
            .map(|(x, y)| x + y)
            .collect();

        AlgInst(inst_prime)
    }

    pub fn update_witness(&self, wit: &AlgWit<P::G1>) -> AlgWit<P::G1> {
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
    pub fn is_blinding_compatible(&self, lang: &AlgLang<P::G1>, inst: &AlgInst<P::G1>) -> bool {
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
    let s_hat: Vec<P::ScalarField> = (0..(lang.wit_size()))
        .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
        .collect();

    let a_prime_e1: Vec<P::G1> = mul_mat_by_vec_f_g(
        &trans.t_am,
        &proof
            .a
            .clone()
            .into_iter()
            .chain(inst.0.clone())
            .collect::<Vec<P::G1>>(),
    );
    let a_prime_e2: Vec<P::G1> = trans.t_aa.clone();

    let inst_prime = trans.update_instance(inst);
    let mat_prime = lang.instantiate_matrix(&inst_prime.0);
    let a_prime_e3: Vec<P::G1> = mul_mat_by_vec_g_f(&mat_prime, &s_hat);

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

    let crs: CH20CRS<CC> = ch20_setup(&mut thread_rng());
    let proof: CH20Proof<CC> = ch20_prove(&crs, &lang, &inst, &wit);
    let res = ch20_verify(&crs, &lang, &inst, &proof);
    println!("Verification result: {:?}", res);

    let trans: CH20Trans<CC> = {
        let delta: CF = UniformRand::rand(&mut rng);
        let gamma: CF = UniformRand::rand(&mut rng);
        let t_xm: Vec<Vec<CF>> = vec![
            vec![gamma, CF::zero(), CF::zero()],
            vec![CF::zero(), delta, CF::zero()],
            vec![CF::zero(), CF::zero(), gamma * delta],
        ];
        let t_xa: Vec<CG1> = vec![CG1::zero(); 3];
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
    println!(":#? {:#?}", inst2);
    println!("Transformaion blinding compatible wrt new inst? {blinding_compatible2:?}");
    let lang_valid_2 = lang.contains(&inst2, &wit2);
    println!("Transformed language valid? {lang_valid_2:?}");
    let proof2 = ch20_update(&crs, &lang, &inst, &proof, &trans);
    let res2 = ch20_verify(&crs, &lang, &inst2, &proof2);
    println!("Transformed proof valid?: {:?}", res2);
}

pub fn test_ublu_consistency<P: Pairing>() {
    let mut rng = thread_rng();
    let g: P::G1 = UniformRand::rand(&mut rng);

    let d = 4;
    // Number of instance elements
    let n = 3 * d + 4;
    // Number of witness elements
    let m = 2 * d + 8;

    let hs: Vec<_> = (0..d + 2)
        .map(|_i| <P::G1 as UniformRand>::rand(&mut rng))
        .collect();

    let matrix = {
        let mut matrix: Vec<Vec<LinearPoly<P::G1>>> = vec![vec![LinearPoly::zero(n); m]; n];

        matrix[0][0] = LinearPoly::constant(n, g);
        matrix[0][1] = LinearPoly::constant(n, hs[0]);
        matrix[1][2] = LinearPoly::constant(n, g);
        matrix[1][3] = LinearPoly::constant(n, hs[0]);
        matrix[2][4] = LinearPoly::constant(n, g);
        matrix[2][5] = LinearPoly::constant(n, hs[0]);
        matrix[3][9] = LinearPoly::constant(n, g); // A_1 = G^{r_1};
        matrix[4][6] = LinearPoly::constant(n, g);
        matrix[4][9] = LinearPoly::constant(n, hs[1]);
        matrix[4][4] = LinearPoly::constant(n, hs[2]);
        for i in 0..d - 1 {
            matrix[5 + 2 * i][10 + i] = LinearPoly::constant(n, g);
            matrix[5 + 2 * i + 1][6] = LinearPoly::single(n, 5 + 2 * i - 1);
            matrix[5 + 2 * i + 1][9 + d + i] = LinearPoly::constant(n, -hs[1]);
            matrix[5 + 2 * i + 1][10 + i] = LinearPoly::constant(n, hs[1]);
            matrix[5 + 2 * i + 1][7] = LinearPoly::constant(n, -hs[2 + i]);
            matrix[5 + 2 * i + 1][4] = LinearPoly::constant(n, hs[3 + i]);
        }

        matrix[3 + 2 * d][2] = LinearPoly::constant(n, g);
        matrix[3 + 2 * d][0] = LinearPoly::constant(n, -g);
        matrix[3 + 2 * d][6] = LinearPoly::constant(n, -g);
        matrix[3 + 2 * d + 1][6] = LinearPoly::single(n, 2);
        matrix[3 + 2 * d + 1][7] = LinearPoly::constant(n, -g);
        matrix[3 + 2 * d + 1][8] = LinearPoly::constant(n, -hs[0]);

        for i in 0..d - 1 {
            matrix[3 + 2 * d + 2 + i][6] = LinearPoly::single(n, 3 + 2 * i);
            matrix[3 + 2 * d + 2 + i][9 + d + i] = LinearPoly::constant(n, -g);
        }
        matrix
    };

    // Instance: Tcal,Xcal,Acal,[(Ai,Di)] for 1..d, 1,1,[1..1] for 1..d-1
    // Witness: t,r_t,x,r_x,alpha,r_alpha,x-t,alpha*(x-t),r_alpha*(x-t),[r_i] for 1..d,[r_i*(x-t)] for 1..d-1
    let lang = AlgLang { matrix };
    let (inst, wit) = {
        let t: P::ScalarField = UniformRand::rand(&mut rng);
        let r_t: P::ScalarField = UniformRand::rand(&mut rng);
        let x: P::ScalarField = UniformRand::rand(&mut rng);
        let r_x: P::ScalarField = UniformRand::rand(&mut rng);
        let alpha: P::ScalarField = UniformRand::rand(&mut rng);
        let r_alpha: P::ScalarField = UniformRand::rand(&mut rng);
        let x_minus_t = x - t;
        let alpha_x_minus_t = alpha * (x_minus_t);
        let r_alpha_x_minus_t = r_alpha * (x_minus_t);

        let rs: Vec<P::ScalarField> = (0..d).map(|_i| UniformRand::rand(&mut rng)).collect();
        let rs_x_minus_t: Vec<P::ScalarField> =
            rs.iter().take(d - 1).map(|ri| *ri * x_minus_t).collect();

        let wit: AlgWit<P::G1> = AlgWit(
            vec![
                t,
                r_t,
                x,
                r_x,
                alpha,
                r_alpha,
                x_minus_t,
                alpha_x_minus_t,
                r_alpha_x_minus_t,
            ]
            .into_iter()
            .chain(rs.clone())
            .chain(rs_x_minus_t)
            .collect(),
        );

        let tcal = g * t + hs[0] * r_t;
        let xcal = g * x + hs[0] * r_x;
        let acal = g * alpha + hs[0] * r_alpha;
        let a_s: Vec<_> = rs.iter().map(|ri| g * ri).collect();
        let d_s: Vec<_> = rs
            .iter()
            .enumerate()
            .map(|(i, ri)| g * (field_pow(x - t, i + 1)) + hs[1] * ri + hs[2 + i] * alpha)
            .collect();
        let ad_s: Vec<P::G1> = a_s
            .into_iter()
            .zip(d_s)
            .flat_map(|(ai, di)| vec![ai, di])
            .collect();
        let inst: AlgInst<P::G1> = AlgInst(
            vec![tcal, xcal, acal]
                .into_iter()
                .chain(ad_s)
                .chain(vec![P::G1::zero(); d + 1])
                .collect(),
        );

        (inst, wit)
    };

    let lang_valid = lang.contains(&inst, &wit);
    println!("Language valid? {lang_valid:?}");

    // Instance: Tcal,Xcal,Acal,[(Ai,Di)] for 1..d, 1,1,[1..1] for 1..d-1
    // Witness: t,r_t,x,r_x,alpha,r_alpha,x-t,alpha*(x-t),r_alpha*(x-t),[r_i] for 1..d,[r_i*(x-t)] for 1..d-1
    let _trans: CH20Trans<P> = {
        let u_x: P::ScalarField = UniformRand::rand(&mut rng);
        let u_rx: P::ScalarField = UniformRand::rand(&mut rng);
        let u_alpha: P::ScalarField = UniformRand::rand(&mut rng);
        let u_ralpha: P::ScalarField = UniformRand::rand(&mut rng);
        let u_rs: Vec<P::ScalarField> = (0..d).map(|_i| UniformRand::rand(&mut rng)).collect();

        let mut t_xm: Vec<Vec<P::ScalarField>> = vec![vec![P::ScalarField::zero(); n]; n];
        let mut t_xa: Vec<P::G1> = vec![P::G1::zero(); m];
        let mut t_wm: Vec<Vec<P::ScalarField>> = vec![vec![P::ScalarField::zero(); m]; m];
        let mut t_wa: Vec<P::ScalarField> = vec![P::ScalarField::zero(); m];

        for i in 0..n {
            t_xm[i][i] = P::ScalarField::one();
        }
        for i in 0..m {
            t_wm[i][i] = P::ScalarField::one();
        }

        t_wa[2] = u_x; // x + U_x
        t_wa[3] = u_rx; // rx + U_rx
        t_wa[4] = u_alpha; // α + U_α
        t_wa[5] = u_ralpha; // rα + U_rα
        t_wa[6] = u_x; // (x-t) + U_x
        t_wm[7][4] = u_x; // α*(x-t) + α*U_x
        t_wm[7][6] = u_alpha; //         + (x-t)*U_α
        t_wa[7] = u_x * u_alpha; // + U_x*U_α
        t_wm[8][5] = u_x; // rα*(x-t) + rα*U_x
        t_wm[8][6] = u_ralpha; //         + (x-t)*U_rα
        t_wa[8] = u_x * u_ralpha; // + U_x*U_α

        let v_coeff = |i: usize, j: usize, x: P::ScalarField| {
            field_pow(x, i - j) * P::ScalarField::from(binomial(i, j) as u64)
        };

        for i in 0..d {
            for j in 0..i + 1 {
                t_wm[9 + i][9 + j] = v_coeff(i + 1, j + 1, u_x)
            }
            t_wa[9 + i] = u_rs[i]
        }
        for i in 0..d - 1 {
            for j in 0..i + 1 {
                t_wm[9 + d + i][9 + d + j] = v_coeff(i + 1, j + 1, u_x);
                t_wm[9 + d + i][9 + j] = u_x * v_coeff(i + 1, j + 1, u_x);
            }
            t_wm[9 + d + i][6] = u_rs[i];
            t_wa[9 + d + i] = u_rs[i] * u_x;
        }

        t_xa[1] = g * u_x + hs[0] * u_rx; // Xcal * G^{U_x} * H0^{U_rx}
        t_xa[2] = g * u_alpha + hs[0] * u_ralpha; // Acal * G^{U_α} * H0^{U_rα}

        for i in 0..d {
            for j in 0..(i + 1) {
                t_xm[3 + 2 * i][3 + 2 * j] = v_coeff(i + 1, j + 1, u_x);
                t_xm[4 + 2 * i][4 + 2 * j] = v_coeff(i + 1, j + 1, u_x);
            }
            t_xa[3 + 2 * i] = g * u_rs[i];
            // TODO what are these ws[4]???
            //let sumterm: P::G1 = (0..(i + 1))
            //    .map(|j| -hs[2 + j] * (ws[4] * v_coeff(i + 1, j + 1, u_x)))
            //    .fold(P::ScalarField::zero(), |x, y| x + y);
            //t_xa[4 + 2 * i] = g * (field_pow(u_x, i + 1))
            //    + hs[2 + i] * (ws[4] + u_alpha)
            //    + sumterm
            //    + hs[1] * u_rs[i];
        }

        //
        // //T_reduce_map = {var('U_α'): 0, var('w_α'): 0}
        // T_reduce_map = {}
        // Tx1 = Matrix(subs_mat(t_xm,T_reduce_map))
        // Tx2 = vector(subs_vec(t_xa,T_reduce_map))
        // print((Tx2[6]))
        // Tw1 = Matrix(subs_mat(t_wm,T_reduce_map))
        // Tw2 = vector(subs_vec(t_wa,T_reduce_map))
        //

        let t_am: Vec<Vec<P::ScalarField>> = t_xm
            .clone()
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .chain(vec![P::ScalarField::zero(); m])
                    .collect()
            })
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
}

fn main() {
    test_field_pow();
    test_binomial();
    test_ublu_consistency::<CC>();
    test_ch20_correctness();
}
