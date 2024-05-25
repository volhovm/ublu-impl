#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_range_loop)]
use std::vec;

use ark_ec::{pairing::Pairing, Group};
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::{thread_rng, RngCore};

use crate::{
    ch20::{AlgInst, AlgLang, AlgWit, CH20Proof, CH20Trans, LinearPoly, CH20CRS},
    utils::{field_pow},
};
use crate::utils::all_binomials;

/// Instance: Tcal,Xcal,Acal,[(Ai,Di)] for 1..d, 1,1,[1..1] for 1..d-1
/// Witness: t,r_t,x,r_x,alpha,r_alpha,x-t,alpha*(x-t),r_alpha*(x-t),[r_i] for 1..d,[r_i*(x-t)] for 1..d-1
pub fn consistency_lang<G: Group>(g: G, hs: &[G], d: usize) -> AlgLang<G> {
    // Number of instance elements
    let n = 3 * d + 4;
    // Number of witness elements
    let m = 2 * d + 8;
    let mut matrix: Vec<Vec<LinearPoly<G>>> = vec![vec![LinearPoly::zero(n); m]; n];

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

    AlgLang { matrix }
}

/// CORE variant
/// Instance: Tcal,Xcal,[(Ai,Di)] for 1..d, 1,[1..1] for 1..d-1
/// Witness: t,r_t,x,r_x,x-t,[r_i] for 1..d,[r_i*(x-t)] for 1..d-1
pub fn consistency_core_lang<G: Group>(g: G, hs: &[G], d: usize) -> AlgLang<G> {
    let mut matrix2: Vec<Vec<LinearPoly<G>>> = consistency_lang(g, hs, d).matrix;

    let n = 3 * d + 4;
    let m = 2 * d + 8;

    matrix2[4][4] = LinearPoly::zero(n);
    for i in 0..d - 1 {
        matrix2[5 + 2 * i + 1][4] = LinearPoly::zero(n);
        matrix2[5 + 2 * i + 1][7] = LinearPoly::zero(n);
    }

    for i in 0..n {
        for j in 0..m {
            matrix2[i][j].poly_coeffs.remove(3 + 2 * d + 1);
            matrix2[i][j].poly_coeffs.remove(2);
        }
    }

    matrix2.remove(3 + 2 * d + 1);
    matrix2.remove(2);

    for i in 0..n - 2 {
        matrix2[i].remove(8);
        matrix2[i].remove(7);
        matrix2[i].remove(5);
        matrix2[i].remove(4);
    }

    AlgLang { matrix: matrix2 }
}

pub fn consistency_wit_to_inst<G: Group>(g: G, hs: &[G], d: usize, wit: &AlgWit<G>) -> Vec<G> {
    let t: G::ScalarField = wit.0[0];
    let r_t: G::ScalarField = wit.0[1];
    let x: G::ScalarField = wit.0[2];
    let r_x: G::ScalarField = wit.0[3];
    let alpha: G::ScalarField = wit.0[4];
    let r_alpha: G::ScalarField = wit.0[5];

    let rs: Vec<G::ScalarField> = wit.0[9..9 + d].to_vec();

    let tcal = g * t + hs[0] * r_t;
    let xcal = g * x + hs[0] * r_x;
    let acal = g * alpha + hs[0] * r_alpha;
    let a_s: Vec<_> = rs.iter().map(|ri| g * ri).collect();
    let d_s: Vec<_> = rs
        .iter()
        .enumerate()
        .map(|(i, ri)| g * (field_pow(x - t, i + 1)) + hs[1] * ri + hs[2 + i] * alpha)
        .collect();
    let ad_s: Vec<G> = a_s
        .into_iter()
        .zip(d_s)
        .flat_map(|(ai, di)| vec![ai, di])
        .collect();

    vec![tcal, xcal, acal]
        .into_iter()
        .chain(ad_s)
        .chain(vec![G::zero(); d + 1])
        .collect()
}

pub fn consistency_form_wit<G: Group>(
    d: usize,
    t: G::ScalarField,
    r_t: G::ScalarField,
    x: G::ScalarField,
    r_x: G::ScalarField,
    alpha: G::ScalarField,
    r_alpha: G::ScalarField,
    rs: Vec<G::ScalarField>,
) -> AlgWit<G> {
    let x_minus_t = x - t;
    let alpha_x_minus_t = alpha * (x_minus_t);
    let r_alpha_x_minus_t = r_alpha * (x_minus_t);

    let rs_x_minus_t: Vec<G::ScalarField> =
        rs.iter().take(d - 1).map(|ri| *ri * x_minus_t).collect();

    AlgWit(
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
    )
}

pub fn consistency_gen_inst_wit<G: Group, RNG: RngCore>(
    lang: &AlgLang<G>,
    g: G,
    hs: &[G],
    d: usize,
    rng: &mut RNG,
) -> (AlgInst<G>, AlgWit<G>) {
    let t: G::ScalarField = UniformRand::rand(rng);
    let r_t: G::ScalarField = UniformRand::rand(rng);
    let x: G::ScalarField = UniformRand::rand(rng);
    let r_x: G::ScalarField = UniformRand::rand(rng);
    let alpha: G::ScalarField = From::from(0u64);
    let r_alpha: G::ScalarField = From::from(0u64);
    let rs: Vec<G::ScalarField> = (0..d).map(|_i| UniformRand::rand(rng)).collect();

    let wit = consistency_form_wit(d, t, r_t, x, r_x, alpha, r_alpha, rs);
    let inst = consistency_wit_to_inst(g, hs, d, &wit);

    (AlgInst::new(lang, inst), wit)
}

pub fn consistency_inst_to_core<G: Group>(d: usize, inst: &[G]) -> Vec<G> {
    let mut inst_core = inst.to_vec();
    inst_core.remove(4 + 2 * d);
    inst_core.remove(2);
    inst_core
}

pub fn consistency_wit_to_core<G: Group>(wit: &AlgWit<G>) -> AlgWit<G> {
    let mut wit_core = wit.clone();
    wit_core.0.remove(8);
    wit_core.0.remove(7);
    wit_core.0.remove(5);
    wit_core.0.remove(4);

    wit_core
}

pub fn consistency_core_gen_inst_wit<G: Group, RNG: RngCore>(
    lang: &AlgLang<G>,
    g: G,
    hs: &[G],
    d: usize,
    rng: &mut RNG,
) -> (AlgInst<G>, AlgWit<G>) {
    let (inst, wit) = consistency_gen_inst_wit(lang, g, hs, d, rng);

    let inst_core = consistency_inst_to_core(d, &inst.instance);
    let wit_core = consistency_wit_to_core(&wit);

    (AlgInst::new(lang, inst_core), wit_core)
}

pub fn consistency_trans<G: Group>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    u_x: G::ScalarField,
    u_rx: G::ScalarField,
    u_rs: Vec<G::ScalarField>,
    u_alpha: G::ScalarField,
    u_ralpha: G::ScalarField,
) -> CH20Trans<G> {
    let n = 3 * d + 4;
    let m = 2 * d + 8;

    let mut t_am: Vec<Vec<G::ScalarField>> = vec![vec![G::ScalarField::zero(); 2 * n]; n];
    let mut t_aa: Vec<G> = vec![G::zero(); n];
    let mut t_wm: Vec<Vec<G::ScalarField>> = vec![vec![G::ScalarField::zero(); m]; m];
    let mut t_wa: Vec<G::ScalarField> = vec![G::ScalarField::zero(); m];

    for i in 0..n {
        t_am[i][i] = G::ScalarField::one();
    }
    for i in 0..m {
        t_wm[i][i] = G::ScalarField::one();
    }

    // x' = x + U_x
    t_wa[2] = u_x;

    // r_x' = r_x + U_rx
    t_wa[3] = u_rx;

    // α' = U_α
    t_wm[4][4] = G::ScalarField::zero();
    t_wa[4] = u_alpha;

    // α' = U_α
    t_wm[5][5] = G::ScalarField::zero();
    t_wa[5] = u_ralpha; // rα + U_rα

    // s_{x-t}' = s_(x-t) + U_x
    t_wa[6] = u_x;

    /////t_wm[7][4] = u_x; //      α*(x-t) + α*U_x

    t_wm[7][6] = u_alpha; //          + (x-t)*U_α
    t_wa[7] = u_x * u_alpha; //       + U_x*U_α

    /////t_wm[8][5] = u_x; // rα*(x-t) + rα*U_x

    t_wm[8][6] = u_ralpha; //         + (x-t)*U_rα
    t_wa[8] = u_x * u_ralpha; // + U_x*U_α

    let v_coeff = |i: usize, j: usize, x: G::ScalarField| {
        field_pow(x, i - j) * binomials[i][j]
    };

    // r_i' = ∑ v_coeff(i,j,U_x) r_i + U_{r_i}
    for i in 0..d {
        for j in 0..i + 1 {
            t_wm[9 + i][9 + j] = v_coeff(i + 1, j + 1, u_x)
        }
        t_wa[9 + i] = u_rs[i]
    }

    // s_{r_{i}(x-t)}' = ...
    for i in 0..d - 1 {
        for j in 0..i + 1 {
            t_wm[9 + d + i][9 + j] = u_x * v_coeff(i + 1, j + 1, u_x);
            t_wm[9 + d + i][9 + d + j] = v_coeff(i + 1, j + 1, u_x);
        }
        t_wm[9 + d + i][6] = u_rs[i];
        t_wa[9 + d + i] = u_rs[i] * u_x;
    }

    t_aa[1] = g * u_x + hs[0] * u_rx; // Xcal * G^{U_x} * H0^{U_rx}

    t_am[2][2] = G::ScalarField::zero();
    t_aa[2] = g * u_alpha + hs[0] * u_ralpha; // Acal * G^{U_α} * H0^{U_rα}

    // A1
    t_aa[3] = g * u_rs[0];
    // D1
    t_aa[4] = g * u_x + hs[1] * u_rs[0] + hs[2] * (u_alpha);

    for i in 1..d {
        for j in 0..(i + 1) {
            t_am[3 + 2 * i][3 + 2 * j] = v_coeff(i + 1, j + 1, u_x);
            t_am[4 + 2 * i][4 + 2 * j] = v_coeff(i, j, u_x);
        }
        for j in 0..i {
            t_am[4 + 2 * i][n + 4 + 2 * j] =
                field_pow(u_x, i - j) * binomials[i][j + 1]
        }
        t_aa[3 + 2 * i] = g * u_rs[i];
        t_aa[4 + 2 * i] = g * (field_pow(u_x, i + 1)) + hs[1] * u_rs[i] + hs[2 + i] * u_alpha;
    }

    t_am[4 + 2 * d][4 + 2 * d] = G::ScalarField::zero();

    for i in 0..d - 1 {
        for j in 0..(i + 1) {
            t_am[5 + 2 * d + i][5 + 2 * d + j] = v_coeff(i + 1, j + 1, u_x);
            t_am[5 + 2 * d + i][n + 3 + 2 * j] = v_coeff(i + 1, j + 1, u_x) * u_x;
            t_am[5 + 2 * d + i][3 + 2 * j] = -v_coeff(i + 1, j + 1, u_x) * u_x;
        }
    }

    let mut t_xm: Vec<Vec<G::ScalarField>> = vec![vec![G::ScalarField::zero(); n]; n];
    let mut t_xa: Vec<G> = vec![G::zero(); n];

    for i in 0..n {
        for j in 0..n {
            t_xm[i][j] = t_am[i][j] + t_am[i][n + j];
        }
        t_xa[i] = t_aa[i];
    }

    CH20Trans {
        t_am,
        t_aa,
        t_xm,
        t_xa,
        t_wm,
        t_wa,
    }
}

pub fn consistency_trans_rand<G: Group, RNG: RngCore>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    rng: &mut RNG,
) -> CH20Trans<G> {
    let u_x: G::ScalarField = UniformRand::rand(rng);
    let u_rx: G::ScalarField = UniformRand::rand(rng);
    let u_rs: Vec<G::ScalarField> = (0..d).map(|_i| UniformRand::rand(rng)).collect();
    let u_alpha: G::ScalarField = From::from(0u64);
    let u_ralpha: G::ScalarField = From::from(0u64);
    consistency_trans(g, hs, d, binomials, u_x, u_rx, u_rs, u_alpha, u_ralpha)
}

pub fn consistency_core_trans<G: Group>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    u_x: G::ScalarField,
    u_rx: G::ScalarField,
    u_rs: Vec<G::ScalarField>,
) -> CH20Trans<G> {
    let n = 3 * d + 4;
    let m = 2 * d + 8;

    let u_alpha: G::ScalarField = From::from(0u64);
    let u_ralpha: G::ScalarField = From::from(0u64);
    let mut t = consistency_trans(g, hs, d, binomials, u_x, u_rx, u_rs, u_alpha, u_ralpha);

    for i in 0..m {
        t.t_wm[i].remove(8);
        t.t_wm[i].remove(7);
        t.t_wm[i].remove(5);
        t.t_wm[i].remove(4);
    }
    t.t_wm.remove(8);
    t.t_wm.remove(7);
    t.t_wm.remove(5);
    t.t_wm.remove(4);

    t.t_wa.remove(8);
    t.t_wa.remove(7);
    t.t_wa.remove(5);
    t.t_wa.remove(4);

    for i in 0..n {
        t.t_am[i].remove(n + 4 + 2 * d);
        t.t_am[i].remove(n + 2);
        t.t_am[i].remove(4 + 2 * d);
        t.t_am[i].remove(2);
    }

    t.t_am.remove(4 + 2 * d);
    t.t_am.remove(2);

    t.t_aa.remove(4 + 2 * d);
    t.t_aa.remove(2);

    for i in 0..n - 2 {
        t.t_xm[i].remove(4 + 2 * d);
        t.t_xm[i].remove(2);
    }

    t.t_xm.remove(4 + 2 * d);
    t.t_xm.remove(2);

    t.t_xa.remove(4 + 2 * d);
    t.t_xa.remove(2);

    t
}

pub fn consistency_core_trans_rand<G: Group, RNG: RngCore>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    rng: &mut RNG,
) -> CH20Trans<G> {
    let u_x: G::ScalarField = UniformRand::rand(rng);
    let u_rx: G::ScalarField = UniformRand::rand(rng);
    let u_rs: Vec<G::ScalarField> = (0..d).map(|_i| UniformRand::rand(rng)).collect();
    consistency_core_trans(g, hs, d, binomials, u_x, u_rx, u_rs)
}

pub fn consistency_blind_trans<G: Group>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    u_rs: Vec<G::ScalarField>,
    u_alpha: G::ScalarField,
    u_ralpha: G::ScalarField,
) -> CH20Trans<G> {
    let u_x: G::ScalarField = Zero::zero();
    let u_rx: G::ScalarField = Zero::zero();
    consistency_trans(g, hs, d, binomials, u_x, u_rx, u_rs, u_alpha, u_ralpha)
}

pub fn consistency_blind_trans_rand<G: Group, RNG: RngCore>(
    g: G,
    hs: &[G],
    d: usize,
    binomials: &Vec<Vec<G::ScalarField>>,
    rng: &mut RNG,
) -> CH20Trans<G> {
    let u_rs: Vec<G::ScalarField> = (0..d).map(|_i| UniformRand::rand(rng)).collect();
    let u_alpha: G::ScalarField = UniformRand::rand(rng);
    let u_ralpha: G::ScalarField = UniformRand::rand(rng);
    consistency_blind_trans(g, hs, d, binomials, u_rs, u_alpha, u_ralpha)
}

/// Generalises "core" proof to a "generic" one. To be used before blinding.
pub fn generalise_proof<P: Pairing>(d: usize, proof: CH20Proof<P>) -> CH20Proof<P> {
    assert!(proof.a.len() == 3 * d + 2);
    assert!(proof.d.len() == 2 * d + 4);

    let mut proof = proof.clone();

    proof.a.insert(2, P::G1::zero());
    proof.a.insert(4 + 2 * d, P::G1::zero());

    proof.d.insert(4, P::G2::zero());
    proof.d.insert(5, P::G2::zero());
    proof.d.insert(7, P::G2::zero());
    proof.d.insert(8, P::G2::zero());

    assert!(proof.a.len() == 3 * d + 4);
    assert!(proof.d.len() == 2 * d + 8);

    proof
}

/// Same as `generalise_proof` but for instance.
pub fn generalise_inst<G: Group>(lang: &AlgLang<G>, d: usize, inst: AlgInst<G>) -> AlgInst<G> {
    assert!(inst.instance.len() == 3 * d + 2);

    let mut inst = inst.clone();

    inst.instance.insert(2, G::zero());
    inst.instance.insert(4 + 2 * d, G::zero());

    // TODO this can be done more efficiently
    inst.matrix = lang.instantiate_matrix(&inst.instance);

    // TODO the code below does not work since not all fields should be 0. I ran out of time trying to fix it.

    // Number of witness elements
    // let m = 2 * d + 8;
    // let size = inst.matrix.len();
    // let to_append = m - d - 1;
    // inst.matrix.push(vec![G::zero(); m]);
    // inst.matrix.push(vec![G::zero(); m]);
    // for i in 0..size {
    //     inst.matrix[i].append(&mut vec![G::zero(); to_append]);
    // }

    inst
}

pub fn check_ublu_lang_consistency<P: Pairing>() {
    let mut rng = thread_rng();
    let g: P::G1 = UniformRand::rand(&mut rng);

    let d = 3;

    let hs: Vec<_> = (0..d + 2)
        .map(|_i| <P::G1 as UniformRand>::rand(&mut rng))
        .collect();

    let binomials: Vec<Vec<P::ScalarField>> = all_binomials(d);

    // "Base" language is consistent but only if we blind some randomness in s
    {
        let lang = consistency_lang(g, &hs, d);
        let (inst, wit) = consistency_gen_inst_wit(&lang, g, &hs, d, &mut rng);
        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");

        let trans: CH20Trans<P::G1> = consistency_trans_rand(g, &hs, d, &binomials, &mut rng);
        let mut s: Vec<P::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
            .collect();

        s[4] = P::ScalarField::zero();
        s[5] = P::ScalarField::zero();
        s[7] = P::ScalarField::zero();
        s[8] = P::ScalarField::zero();

        let blinding_compatible = trans.is_blinding_compatible_raw(&lang, &inst, s.clone());
        println!("Transformaion blinding compatible? {blinding_compatible:?}");
    }

    // Create an original proof

    let lang_core = consistency_core_lang(g, &hs, d);
    let (inst_core, wit_core) = consistency_core_gen_inst_wit(&lang_core, g, &hs, d, &mut rng);

    let lang_core_valid = lang_core.contains(&inst_core, &wit_core);
    println!("Language (core) valid? {lang_core_valid:?}");
    assert!(lang_core_valid);

    let crs: CH20CRS<P> = CH20CRS::setup(&mut thread_rng());
    let proof: CH20Proof<P> = CH20Proof::prove(&mut rng, &crs, &lang_core, &inst_core, &wit_core);
    let res = proof.verify(&crs, &lang_core, &inst_core);
    println!("Verification result: {:?}", res);
    assert!(res.is_ok());

    // Update it with some x values (but not α)

    let trans_core: CH20Trans<P::G1> = consistency_core_trans_rand(g, &hs, d, &binomials, &mut rng);
    let blinding_compatible = trans_core.is_blinding_compatible(&lang_core, &inst_core);
    println!("Transformaion (core) blinding compatible? {blinding_compatible:?}");
    assert!(blinding_compatible);
    let inst_core2 = trans_core.update_instance(&lang_core, &inst_core);
    let wit_core2 = trans_core.update_witness(&wit_core);
    let blinding_compatible2 = trans_core.is_blinding_compatible(&lang_core, &inst_core2);
    println!("Transformaion (core) blinding compatible wrt new inst? {blinding_compatible2:?}");
    assert!(blinding_compatible2);
    let lang_valid2 = lang_core.contains(&inst_core2, &wit_core2);
    println!("Transformed language valid? {lang_valid2:?}");
    assert!(lang_valid2);

    let proof2 = proof.update(&mut rng, &crs, &lang_core, &inst_core, &trans_core);
    let res2 = proof2.verify(&crs, &lang_core, &inst_core2);
    println!("Transformed proof valid?: {:?}", res2);
    assert!(res2.is_ok());

    // Blind with α, r_α, {r_i} (but not x!)

    let lang_gen = consistency_lang(g, &hs, d);
    let proof_gen = generalise_proof(d, proof2);
    let inst_gen = generalise_inst(&lang_gen, d, inst_core2);
    let res_gen = proof_gen.verify(&crs, &lang_gen, &inst_gen);
    println!("Transformed generalised proof valid?: {:?}", res_gen);
    assert!(res_gen.is_ok());

    let trans_blind: CH20Trans<P::G1> = consistency_blind_trans_rand(g, &hs, d, &binomials, &mut rng);
    let proof_blinded = proof_gen.update(&mut rng, &crs, &lang_gen, &inst_gen, &trans_blind);

    let inst_blinded = trans_blind.update_instance(&lang_gen, &inst_gen);
    let res_blinded = proof_blinded.verify(&crs, &lang_gen, &inst_blinded);
    println!(
        "Transformed generalised blinded proof valid?: {:?}",
        res_blinded
    );
    assert!(res_blinded.is_ok());

    let mut proof_blinded_broken = proof_blinded.clone();
    proof_blinded_broken.d[3] = P::G2::zero();
    let res_blinded_broken = proof_blinded_broken.verify(&crs, &lang_gen, &inst_blinded);

    println!(
        "Transformed malicious generalised blinded proof fails?: {:?}",
        res_blinded_broken.is_err()
    );
    assert!(res_blinded_broken.is_err());
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::CC;

    #[test]
    fn test_ublu_lang_consistency() {
        check_ublu_lang_consistency::<CC>();
    }
}
