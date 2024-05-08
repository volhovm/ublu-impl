use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::thread_rng;

use crate::{
    ch20::{AlgInst, AlgLang, AlgWit, CH20Proof, CH20Trans, LinearPoly, CH20CRS},
    utils::{binomial, field_pow},
};

pub fn test_ublu_lang_consistency<P: Pairing>() {
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
        let t: P::ScalarField = From::from(1u64);
        let r_t: P::ScalarField = From::from(2u64);
        let x: P::ScalarField = From::from(3u64);
        let r_x: P::ScalarField = From::from(1u64);
        let alpha: P::ScalarField = From::from(0u64);
        let r_alpha: P::ScalarField = From::from(0u64);
        //        let t: P::ScalarField = UniformRand::rand(&mut rng);
        //        let r_t: P::ScalarField = UniformRand::rand(&mut rng);
        //        let x: P::ScalarField = UniformRand::rand(&mut rng);
        //        let r_x: P::ScalarField = UniformRand::rand(&mut rng);
        //        let alpha: P::ScalarField = UniformRand::rand(&mut rng);
        //        let r_alpha: P::ScalarField = UniformRand::rand(&mut rng);
        let x_minus_t = x - t;
        let alpha_x_minus_t = alpha * (x_minus_t);
        let r_alpha_x_minus_t = r_alpha * (x_minus_t);

        //let rs: Vec<P::ScalarField> = (0..d).map(|_i| UniformRand::rand(&mut rng)).collect();
        let rs: Vec<P::ScalarField> = (0..d).map(|_i| From::from(1u64)).collect();
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

    let trans: CH20Trans<P> = {
        //let u_x: P::ScalarField = UniformRand::rand(&mut rng);
        //let u_rx: P::ScalarField = UniformRand::rand(&mut rng);
        //let u_alpha: P::ScalarField = UniformRand::rand(&mut rng);
        //let u_ralpha: P::ScalarField = UniformRand::rand(&mut rng);
        //let u_rs: Vec<P::ScalarField> = (0..d).map(|_i| UniformRand::rand(&mut rng)).collect();

        let u_x: P::ScalarField = From::from(2u64);
        let u_rx: P::ScalarField = From::from(3u64);
        let u_alpha: P::ScalarField = From::from(0u64);
        let u_ralpha: P::ScalarField = From::from(0u64);
        let u_rs: Vec<P::ScalarField> = (0..d).map(|_i| From::from(1u64)).collect();

        let mut t_am: Vec<Vec<P::ScalarField>> = vec![vec![P::ScalarField::zero(); 2 * n]; n];
        let mut t_aa: Vec<P::G1> = vec![P::G1::zero(); n];
        let mut t_wm: Vec<Vec<P::ScalarField>> = vec![vec![P::ScalarField::zero(); m]; m];
        let mut t_wa: Vec<P::ScalarField> = vec![P::ScalarField::zero(); m];

        for i in 0..n {
            t_am[i][i] = P::ScalarField::one();
        }
        for i in 0..m {
            t_wm[i][i] = P::ScalarField::one();
        }

        // x' = x + U_x
        t_wa[2] = u_x;

        // r_x' = r_x + U_rx
        t_wa[3] = u_rx;

        // α' = U_α
        t_wm[4][4] = P::ScalarField::zero();
        t_wa[4] = u_alpha;

        // α' = U_α
        t_wm[5][5] = P::ScalarField::zero();
        t_wa[5] = u_ralpha; // rα + U_rα

        // s_{x-t}' = s_(x-t) + U_x
        t_wa[6] = u_x;

        /////t_wm[7][4] = u_x; //      α*(x-t) + α*U_x

        t_wm[7][6] = u_alpha; //          + (x-t)*U_α
        t_wa[7] = u_x * u_alpha; //       + U_x*U_α

        /////t_wm[8][5] = u_x; // rα*(x-t) + rα*U_x

        t_wm[8][6] = u_ralpha; //         + (x-t)*U_rα
        t_wa[8] = u_x * u_ralpha; // + U_x*U_α

        let v_coeff = |i: usize, j: usize, x: P::ScalarField| {
            field_pow(x, i - j) * P::ScalarField::from(binomial(i, j) as u64)
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
                t_wm[9 + d + i][9 + d + j] = v_coeff(i + 1, j + 1, u_x);
                t_wm[9 + d + i][9 + j] = u_x * v_coeff(i + 1, j + 1, u_x);
            }
            t_wm[9 + d + i][6] = u_rs[i];
            t_wa[9 + d + i] = u_rs[i] * u_x;
        }

        t_aa[1] = g * u_x + hs[0] * u_rx; // Xcal * G^{U_x} * H0^{U_rx}

        t_am[2][2] = P::ScalarField::zero();
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
                    field_pow(u_x, i - j) * P::ScalarField::from(binomial(i, j + 1) as u64)
            }
            t_aa[3 + 2 * i] = g * u_rs[i];
            t_aa[4 + 2 * i] = g * (field_pow(u_x, i + 1)) + hs[1] * u_rs[i] + hs[2 + i] * u_alpha;
        }

        t_am[4 + 2 * d][4 + 2 * d] = P::ScalarField::zero();

        for i in 1..d - 1 {
            for j in 0..(i + 1) {
                t_am[5 + 2 * d + i][5 + 2 * d + j] = v_coeff(i + 1, j + 1, u_x);
                t_am[5 + 2 * d + i][n + 3 + j] = v_coeff(i + 1, j + 1, u_x) * u_x;
                t_am[5 + 2 * d + i][3 + j] = -v_coeff(i + 1, j + 1, u_x) * u_x;
            }
        }

        let mut t_xm: Vec<Vec<P::ScalarField>> = vec![vec![P::ScalarField::zero(); n]; n];
        let mut t_xa: Vec<P::G1> = vec![P::G1::zero(); n];

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
    };

    println!("Witness: {wit:?}");

    let mut s: Vec<P::ScalarField> = (0..(lang.wit_size()))
        .map(|_i| <P::ScalarField as UniformRand>::rand(&mut rng))
        .collect();
    s[4] = P::ScalarField::zero();
    s[5] = P::ScalarField::zero();
    let blinding_compatible = trans.is_blinding_compatible_raw(&lang, &inst, s.clone());
    println!("Transformaion blinding compatible? {blinding_compatible:?}");
    let inst2 = trans.update_instance(&inst);
    let wit2 = trans.update_witness(&wit);
    println!("Updated instance: {inst2:?}");
    println!("Updated witness: {wit2:?}");
    let blinding_compatible2 = trans.is_blinding_compatible_raw(&lang, &inst2, s);
    println!(":#? {:#?}", inst2);
    println!("Transformaion blinding compatible wrt new inst? {blinding_compatible2:?}");
    let lang_valid_2 = lang.contains(&inst2, &wit2);
    println!("Transformed language valid? {lang_valid_2:?}");

    let crs: CH20CRS<P> = CH20CRS::setup(&mut thread_rng());
    let proof: CH20Proof<P> = CH20Proof::prove(&crs, &lang, &inst, &wit);
    let res = proof.verify(&crs, &lang, &inst);
    println!("Verification result: {:?}", res);

    let proof2 = proof.update(&crs, &lang, &inst, &trans);
    let res2 = proof2.verify(&crs, &lang, &inst2);
    println!("Transformed proof valid?: {:?}", res2);
}
