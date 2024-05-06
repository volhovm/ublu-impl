use ark_ec::pairing::Pairing;
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::thread_rng;

use crate::{
    ch20::{AlgInst, AlgLang, AlgWit, CH20Trans, LinearPoly},
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
