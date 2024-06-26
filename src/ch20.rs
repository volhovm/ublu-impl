#![allow(clippy::needless_range_loop)]

use ark_ec::{pairing::Pairing, Group};
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::{thread_rng, RngCore};
use rayon::prelude::*;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct LinearPoly<G: Group> {
    pub poly_coeffs: Vec<bool>,
    pub poly_const: G,
}

impl<G: Group> LinearPoly<G> {
    pub fn eval_lpoly(&self, vars: &[G]) -> G {
        self.poly_const
            + vars
                .iter()
                .zip(self.poly_coeffs.iter())
                .filter_map(|(val, flag)| flag.then(|| val))
                .sum::<G>()
    }

    pub fn constant(size: usize, elem: G) -> Self {
        LinearPoly {
            poly_coeffs: vec![false; size],
            poly_const: elem,
        }
    }

    pub fn zero(size: usize) -> Self {
        Self::constant(size, Zero::zero())
    }

    pub fn single(size: usize, ix: usize) -> Self {
        let mut poly_coeffs: Vec<_> = vec![false; size];
        let poly_const = G::zero();
        poly_coeffs[ix] = true;
        LinearPoly {
            poly_coeffs,
            poly_const,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AlgInst<G: Group> {
    pub instance: Vec<G>,
    pub matrix: Vec<Vec<G>>, // Preprocessed matrix from instance
}
impl<G: Group> AlgInst<G> {
    pub fn new(language: &AlgLang<G>, instance: Vec<G>) -> Self {
        let matrix = language.instantiate_matrix(&instance);
        AlgInst { instance, matrix }
    }
}

#[derive(Debug, Clone)]
pub struct AlgWit<G: Group>(pub Vec<G::ScalarField>);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlgLang<G: Group> {
    pub matrix: Vec<Vec<LinearPoly<G>>>,
}

impl<G: Group> AlgLang<G> {
    pub fn instantiate_matrix(&self, inst: &[G]) -> Vec<Vec<G>> {
        /*let mut res_mat: Vec<Vec<G>> = vec![];
        for i in 0..self.inst_size() {
            let mut row: Vec<G> = vec![];
            for j in 0..self.wit_size() {
                row.push((self.matrix[i][j]).eval_lpoly(inst));
            }
            res_mat.push(row);
        }*/
        let res_mat: Vec<Vec<G>> = self
            .matrix
            .iter() // par_iter
            .map(|row| row.iter().map(|elem| elem.eval_lpoly(inst)).collect())
            .collect();
        //assert_eq!(res_mat, mat2);
        res_mat
    }
    pub fn wit_size(&self) -> usize {
        self.matrix[0].len()
    }
    pub fn inst_size(&self) -> usize {
        self.matrix.len()
    }
    pub fn contains(&self, inst: &AlgInst<G>, wit: &AlgWit<G>) -> bool {
        let inst2 = mul_mat_by_vec_g_f(&inst.matrix, &wit.0);
        // we only compare the first inst_size elements of the instance,
        // the rest of the instance may be only needed for instantiate_matrix

        if inst2 != inst.instance[0..self.inst_size()] {
            for (idx, (i2, i)) in inst2
                .iter()
                .zip(inst.instance[0..self.inst_size()].iter())
                .enumerate()
            {
                if i2 != i {
                    println!("instances differ at position {}", idx)
                }
            }
            false
        } else {
            true
        }
    }
}

pub fn mul_mat_by_vec_g_f<G: Group>(mat: &[Vec<G>], vec: &[G::ScalarField]) -> Vec<G> {
    /*let n = mat.len();
    let m = mat[0].len();
    let mut res: Vec<G> = vec![Zero::zero(); n];

    for i in 0..n {
        for j in 0..m {
            res[i] += mat[i][j] * vec[j];
        }
    }*/
    let res: Vec<G> = mat
        .iter() // par_iter
        .map(|row| {
            row.iter()
                .zip(vec)
                .filter_map(|(m, v)| match m.is_zero() {
                    false => Some(*m * v),
                    true => None,
                })
                .sum()
        })
        .collect();
    //assert_eq!(res, res2);
    res
}

pub fn mul_mat_by_vec_f_g<G: Group>(mat: &[Vec<G::ScalarField>], vec: &[G]) -> Vec<G> {
    let n = mat.len();
    let m = mat[0].len();
    assert!(
        vec.len() == m,
        "Cannot multiply {}x{} matrix by a {} vector",
        n,
        m,
        vec.len()
    );
    /*let mut res: Vec<G> = vec![Zero::zero(); n];
    for i in 0..n {
        for j in 0..m {
            res[i] += vec[j] * mat[i][j];
        }
    }*/
    let res: Vec<G> = mat
        .iter() // par_iter
        .map(|row| {
            let el: G = row.iter().zip(vec).map(|(m, v)| *v * m).sum();
            el
        })
        .collect();
    res
}

pub fn mul_mat_by_vec_f_f<G: Group>(
    mat: &[Vec<G::ScalarField>],
    vec: &[G::ScalarField],
) -> Vec<G::ScalarField> {
    /*let n = mat.len();
    let m = mat[0].len();
    let mut res: Vec<G::ScalarField> = vec![Zero::zero(); n];
    for i in 0..n {
        for j in 0..m {
            res[i] += vec[j] * mat[i][j];
        }
    }*/
    let res: Vec<G::ScalarField> = mat
        .iter() // par_iter
        .map(|row| {
            let el: G::ScalarField = row.iter().zip(vec).map(|(m, v)| *m * v).sum();
            el
        })
        .collect();
    res
}

pub struct CH20CRS<P: Pairing> {
    pub e: P::G2,
}

impl<P: Pairing> CH20CRS<P> {
    pub fn setup(rng: &mut dyn RngCore) -> Self
    where
        P::ScalarField: UniformRand,
    {
        let e_td: P::ScalarField = <P::ScalarField as UniformRand>::rand(rng);
        let e: P::G2 = P::G2::generator() * e_td;
        CH20CRS { e }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CH20Proof<P: Pairing> {
    pub a: Vec<P::G1>,
    pub d: Vec<P::G2>,
}

#[derive(Debug)]
pub enum CH20VerifierError {
    CH20GenericError(String),
}

impl<P: Pairing> CH20Proof<P> {
    pub fn prove(
        rng: &mut dyn RngCore,
        crs: &CH20CRS<P>,
        lang: &AlgLang<P::G1>,
        inst: &AlgInst<P::G1>,
        wit: &AlgWit<P::G1>,
    ) -> CH20Proof<P>
    where
        P::ScalarField: UniformRand,
    {
        let r: Vec<P::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <P::ScalarField as UniformRand>::rand(rng))
            .collect();
        let a: Vec<P::G1> = mul_mat_by_vec_g_f(&inst.matrix, &r);
        let d: Vec<P::G2> = wit
            .0
            .iter()
            .zip(r.iter())
            .map(|(w_i, r_i)| crs.e * w_i + P::G2::generator() * r_i)
            .collect();
        CH20Proof { a, d }
    }

    pub fn verify(
        &self,
        crs: &CH20CRS<P>,
        lang: &AlgLang<P::G1>,
        inst: &AlgInst<P::G1>,
    ) -> Result<(), CH20VerifierError> {
        let mut rng = thread_rng();
        let mut lhs: Vec<P::G1> = vec![P::G1::zero(); lang.wit_size() + 2];
        let mut rhs: Vec<P::G2> = self.d.clone();
        rhs.push(-crs.e);
        rhs.push(-P::G2::generator());
        for i in 0..lang.inst_size() {
            let alpha = P::ScalarField::rand(&mut rng);
            for j in 0..lang.wit_size() {
                lhs[j] += inst.matrix[i][j] * alpha;
            }
            lhs[lang.wit_size()] += inst.instance[i] * alpha;
            lhs[lang.wit_size() + 1] += self.a[i] * alpha;
        }
        let pairing_res = P::multi_pairing(lhs, rhs);
        if pairing_res != Zero::zero() {
            return Err(CH20VerifierError::CH20GenericError(From::from(
                "Pairing is nonzero",
            )));
        }
        Ok(())
    }

    pub fn update(
        &self,
        rng: &mut dyn RngCore,
        crs: &CH20CRS<P>,
        lang: &AlgLang<P::G1>,
        inst: &AlgInst<P::G1>,
        trans: &CH20Trans<P::G1>,
    ) -> CH20Proof<P> {
        let s_hat: Vec<P::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <P::ScalarField as UniformRand>::rand(rng))
            .collect();

        let a_prime_e1: Vec<P::G1> = mul_mat_by_vec_f_g(
            &trans.t_am,
            &self
                .a
                .clone()
                .into_iter()
                .chain(inst.instance.clone())
                .collect::<Vec<P::G1>>(),
        );
        let a_prime_e2: Vec<P::G1> = trans.t_aa.clone();

        let inst_prime = trans.update_instance(lang, inst);
        let a_prime_e3: Vec<P::G1> = mul_mat_by_vec_g_f(&inst_prime.matrix, &s_hat);

        let a_prime: Vec<P::G1> = a_prime_e1
            .into_iter()
            .zip(a_prime_e2)
            .zip(a_prime_e3)
            .map(|((x, y), z)| x + y + z)
            .collect();

        let d_prime_e1: Vec<P::G2> = mul_mat_by_vec_f_g(&trans.t_wm, &self.d);
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
}

pub struct CH20Trans<G: Group> {
    pub t_am: Vec<Vec<G::ScalarField>>,
    pub t_aa: Vec<G>,
    pub t_xm: Vec<Vec<G::ScalarField>>,
    pub t_xa: Vec<G>,
    pub t_wm: Vec<Vec<G::ScalarField>>,
    pub t_wa: Vec<G::ScalarField>,
}

impl<G: Group> CH20Trans<G> {
    /// Creates a zero (ID) transformation for a given language.
    pub fn zero_trans(lang: &AlgLang<G>) -> CH20Trans<G> {
        let mut t_xm: Vec<Vec<G::ScalarField>> =
            vec![vec![G::ScalarField::zero(); lang.inst_size()]; lang.inst_size()];
        for i in 0..lang.inst_size() {
            t_xm[i][i] = G::ScalarField::one();
        }
        let mut t_wm: Vec<Vec<G::ScalarField>> =
            vec![vec![G::ScalarField::zero(); lang.wit_size()]; lang.wit_size()];
        for i in 0..lang.wit_size() {
            t_wm[i][i] = G::ScalarField::one();
        }

        let t_xa: Vec<G> = vec![G::zero(); lang.inst_size()];
        let t_wa: Vec<G::ScalarField> = vec![G::ScalarField::zero(); lang.wit_size()];

        let t_am: Vec<Vec<G::ScalarField>> = t_xm
            .clone()
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .chain(vec![G::ScalarField::zero(); lang.inst_size()])
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

    pub fn update_instance(&self, language: &AlgLang<G>, inst: &AlgInst<G>) -> AlgInst<G> {
        let inst_prime_e1: Vec<G> = mul_mat_by_vec_f_g(&self.t_xm, &inst.instance);
        let inst_prime_e2: Vec<G> = self.t_xa.clone();

        let inst_prime: Vec<G> = inst_prime_e1
            .into_iter()
            .zip(inst_prime_e2)
            .map(|(x, y)| x + y)
            .collect();

        AlgInst::new(language, inst_prime)
    }

    pub fn update_witness(&self, wit: &AlgWit<G>) -> AlgWit<G> {
        let wit_prime_e1: Vec<G::ScalarField> = mul_mat_by_vec_f_f::<G>(&self.t_wm, &wit.0);
        let wit_prime_e2: Vec<G::ScalarField> = self.t_wa.clone();

        let wit_prime: Vec<G::ScalarField> = wit_prime_e1
            .into_iter()
            .zip(wit_prime_e2)
            .map(|(x, y)| x + y)
            .collect();

        AlgWit(wit_prime)
    }

    /// Does a probabilistic check that the transformation is blinding
    /// compatible. If returns false, it's not. If returns true, the
    /// language is blinding compatible with some probability.
    pub fn is_blinding_compatible_raw(
        &self,
        lang: &AlgLang<G>,
        inst: &AlgInst<G>,
        s: Vec<G::ScalarField>,
    ) -> bool {
        let mx_s = mul_mat_by_vec_g_f(&inst.matrix, &s);

        let lhs_term1 = mul_mat_by_vec_f_g(
            &self.t_am,
            &mx_s
                .into_iter()
                .chain(inst.instance.clone())
                .collect::<Vec<G>>(),
        );

        let lhs: Vec<G> = lhs_term1
            .into_iter()
            .zip(self.t_aa.clone())
            .map(|(x, y)| x + y)
            .collect();

        let inst2 = self.update_instance(lang, inst);
        let s2 = self.update_witness(&AlgWit(s));

        let rhs = mul_mat_by_vec_g_f(&inst2.matrix, &s2.0);

        if rhs != lhs {
            println!("Not blinding compatible, indices:");
            for i in 0..rhs.len() {
                println!(
                    "  {i:?}: {}",
                    if lhs[i] != rhs[i] {
                        " --- NOT EQUAL --- "
                    } else {
                        "OK"
                    }
                );
            }
        }

        rhs == lhs
    }

    /// Does a probabilistic check that the transformation is blinding
    /// compatible. If returns false, it's not. If returns true, the
    /// language is blinding compatible with some probability.
    pub fn is_blinding_compatible(&self, lang: &AlgLang<G>, inst: &AlgInst<G>) -> bool {
        let mut rng = thread_rng();
        let s: Vec<G::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <G::ScalarField as UniformRand>::rand(&mut rng))
            .collect();

        self.is_blinding_compatible_raw(lang, inst, s)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{CC, CF, CG1};
    use ark_bls12_381::Bls12_381;
    use ark_ec::CurveGroup;

    #[test]
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
        let inst: AlgInst<CG1> = AlgInst::new(&lang, vec![gx, gy, gz]);
        let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");

        let crs: CH20CRS<CC> = CH20CRS::setup(&mut rng);
        let proof: CH20Proof<CC> = CH20Proof::prove(&mut rng, &crs, &lang, &inst, &wit);
        let res = proof.verify(&crs, &lang, &inst);
        println!("Verification result: {:?}", res);

        let trans: CH20Trans<CG1> = {
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
        let inst2 = trans.update_instance(&lang, &inst);
        let wit2 = trans.update_witness(&wit);
        let blinding_compatible2 = trans.is_blinding_compatible(&lang, &inst2);
        println!(":#? {:#?}", inst2);
        println!("Transformaion blinding compatible wrt new inst? {blinding_compatible2:?}");
        let lang_valid_2 = lang.contains(&inst2, &wit2);
        println!("Transformed language valid? {lang_valid_2:?}");
        let proof2 = proof.update(&mut rng, &crs, &lang, &inst, &trans);
        let res2 = proof2.verify(&crs, &lang, &inst2);
        println!("Transformed proof valid?: {:?}", res2);
    }

    #[test]
    fn test_matmul() {
        pub fn mul_mat_by_vec_g_f<G: Group + CurveGroup>(
            mat: &[Vec<G>],
            vec: &[G::ScalarField],
        ) -> Vec<G> {
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

        pub fn msm_mat_by_vec_g_f<G: Group + CurveGroup>(
            mat: &[Vec<G>],
            vec: &[G::ScalarField],
        ) -> Vec<G> {
            let res = mat
                .iter()
                .map(|row| {
                    let row_aff: Vec<G::Affine> = row.iter().map(|p| p.into_affine()).collect();
                    let el = G::msm(&row_aff, &vec).unwrap();
                    el
                })
                .collect();
            res
        }
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
        let inst: AlgInst<CG1> = AlgInst::new(&lang, vec![gx, gy, gz]);
        let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

        let mul = mul_mat_by_vec_g_f(&inst.matrix, &wit.0);
        let msm = msm_mat_by_vec_g_f(&inst.matrix, &wit.0);
        assert_eq!(mul, msm);
    }

    #[test]
    fn test_batch_pairing() {
        let mut rng = ark_std::test_rng();
        let s = CF::rand(&mut rng);
        let a = CG1::rand(&mut rng);
        let b = <Bls12_381 as Pairing>::G2::rand(&mut rng);
        let amul = a * s;
        let bmul = b * s;

        let pk = b * (s * s);
        // We can compute the pairing of two points on the curve, either monolithically...
        let e1 = Bls12_381::pairing(a, b);

        let ea = Bls12_381::pairing(amul, b);
        let eb = Bls12_381::pairing(a, bmul);

        assert_eq!(ea, eb);

        let ess1 = Bls12_381::pairing(amul, bmul);
        let ess2 = Bls12_381::pairing(a, pk);

        assert_eq!(ess1, ess2);

        let mpk = b * (-s * s);

        let res = Bls12_381::multi_pairing(vec![amul, a], vec![bmul, mpk]);

        assert_eq!(res, Zero::zero());

        let seprand = CF::rand(&mut rng);

        let sp = CF::rand(&mut rng);
        let ap = CG1::rand(&mut rng);
        let bp = <Bls12_381 as Pairing>::G2::rand(&mut rng);
        let amulp = ap * s;
        let bmulp = bp * s;

        let mpkp = bp * (-s * s);

        let res = Bls12_381::multi_pairing(
            vec![amulp * seprand + amul, ap * seprand + a],
            vec![bmulp * seprand + bmul, mpkp * (seprand * seprand) + mpk],
        );

        assert_eq!(res, Zero::zero());

        // test batching

        let c = CG1::rand(&mut rng);
        let d = <Bls12_381 as Pairing>::G2::rand(&mut rng);

        let prod = Bls12_381::multi_pairing(vec![a, c], vec![b, d]);
    }

    #[test]
    fn test_next_pairing() {
        let mut rng = ark_std::test_rng();

        let s = CF::rand(&mut rng);

        let m00 = CG1::rand(&mut rng);
        let m01 = CG1::rand(&mut rng);
        let v0 = <Bls12_381 as Pairing>::G2::rand(&mut rng);
        let v1 = <Bls12_381 as Pairing>::G2::rand(&mut rng);

        let e_one = Bls12_381::pairing(m00, v0);
        let e_two = Bls12_381::pairing(m01, v1);
        let e_comb = Bls12_381::multi_pairing(vec![m00, m01], vec![v0, v1]);

        assert_eq!(e_one + e_two, e_comb);

        let e_scale_1 = Bls12_381::pairing(m00 * s, v0);
        let e_scale_2 = Bls12_381::pairing(m00, v0 * s);
        let e_scale_t = e_one * s;

        assert_eq!(e_scale_1, e_scale_t);
        assert_eq!(e_scale_2, e_scale_t);

        let e_scale_12 = Bls12_381::pairing(m00 * s, v0 * s);
        let e_scale_tt = e_one * (s * s);

        assert_eq!(e_scale_12, e_scale_tt);
    }

    #[test]
    fn test_compress_pairing() {
        let mut rng = ark_std::test_rng();

        let s = CF::rand(&mut rng);

        let m00 = CG1::rand(&mut rng);
        let m10 = CG1::rand(&mut rng);
        let v0 = <Bls12_381 as Pairing>::G2::rand(&mut rng);

        let e_one = Bls12_381::pairing(m00, v0);
        let e_two = Bls12_381::pairing(m10, v0);

        let e_comb = Bls12_381::pairing(m00 + m10 * s, v0);

        assert_eq!(e_one + e_two * s, e_comb)
    }
}
