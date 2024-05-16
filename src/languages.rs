use crate::ch20::{AlgInst, AlgLang, AlgWit, LinearPoly};
use ark_ec::Group;
use ark_ff::Zero;
use ark_std::UniformRand;
use rand::RngCore;

pub fn key_lang<G: Group>(g: G, h_com: G) -> AlgLang<G> {
    let il = 3;
    let matrix: Vec<Vec<LinearPoly<G>>> = vec![
        vec![
            LinearPoly::constant(il, g),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::zero(il),
            LinearPoly::constant(il, g),
            LinearPoly::single(il, 0),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::zero(il),
            LinearPoly::constant(il, -g),
            LinearPoly::zero(il),
            LinearPoly::constant(il, h_com),
        ],
    ];

    AlgLang { matrix }
}

pub fn escrow_lang<G: Group>(g: G, h_com: G) -> AlgLang<G> {
    let il = 8;
    let matrix: Vec<Vec<LinearPoly<G>>> = vec![
        vec![
            LinearPoly::constant(il, g),
            LinearPoly::constant(il, h_com),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::constant(il, g),
            LinearPoly::constant(il, h_com),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::single(il, 1),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::constant(il, -g),
            LinearPoly::constant(il, -h_com),
        ],
        vec![
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::single(il, 5),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::zero(il),
            LinearPoly::zero(il),
            LinearPoly::single(il, 6),
            LinearPoly::zero(il),
            LinearPoly::single(il, 7),
            LinearPoly::zero(il),
        ],
    ];

    AlgLang { matrix }
}

pub fn escrow_gen_wit<G: Group, RNG: RngCore>(rng: &mut RNG) -> AlgWit<G> {
    let a: G::ScalarField = UniformRand::rand(rng);
    let ra: G::ScalarField = UniformRand::rand(rng);
    let b: G::ScalarField = UniformRand::rand(rng);
    let rb: G::ScalarField = UniformRand::rand(rng);

    let ba = b * a;
    let rba = rb * a;
    AlgWit(vec![a, ra, b, rb, ba, rba])
}

pub fn escrow_gen_inst_from_wit<G: Group>(
    g: G,
    h_com: G,
    a_hint: &[G],
    d_hint: &[G],
    w_hint: &[G],
    wit: &AlgWit<G>,
) -> AlgInst<G> {
    let u: G = g * wit.0[0] + h_com * wit.0[1]; // g*alpha + h*ralpha
    let b: G = g * wit.0[2] + h_com * wit.0[3]; // g * b + h_com * rb
    let prod_a = a_hint.iter().sum();
    let prod_d = d_hint.iter().sum();
    let prod_w = w_hint.iter().sum();
    //todo!("raise elemnts to U and -U");
    let escrow1: G = prod_a * wit.0[2]; // PA * b
    let escrow2: G = prod_d * wit.0[2] + prod_w * wit.0[4]; // PD * b + PW * ba

    AlgInst(vec![
        u,
        b,
        g * G::ScalarField::zero(),
        escrow1,
        escrow2,
        prod_a,
        prod_d,
        prod_w,
    ])
}

pub fn trace_lang<G: Group>(g: G, h_com: G) -> AlgLang<G> {
    let il = 4;
    let matrix: Vec<Vec<LinearPoly<G>>> = vec![
        vec![
            LinearPoly::constant(il, g),
            LinearPoly::constant(il, h_com),
            LinearPoly::zero(il),
        ],
        vec![
            LinearPoly::constant(il, g),
            LinearPoly::zero(il),
            LinearPoly::constant(il, h_com),
        ],
    ];

    AlgLang { matrix }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::sigma::SigmaProof;
    use crate::{CF, CG1};
    use ark_std::UniformRand;
    use rand::thread_rng;

    #[allow(non_snake_case)]
    #[test]
    fn test_key_lang() {
        let mut rng = thread_rng();
        let G: CG1 = UniformRand::rand(&mut rng);
        let Hcom: CG1 = UniformRand::rand(&mut rng);

        let sk: CF = UniformRand::rand(&mut rng);
        let t: CF = UniformRand::rand(&mut rng);
        let r01: CF = UniformRand::rand(&mut rng);
        let rt: CF = UniformRand::rand(&mut rng);

        let H: CG1 = G * sk;
        let B01: CG1 = G * t + H * r01;
        let T: CG1 = G * t + Hcom * rt;

        let lang: AlgLang<CG1> = key_lang(G, Hcom);
        let inst: AlgInst<CG1> = AlgInst(vec![H, B01, T]); //
        let wit: AlgWit<CG1> = AlgWit(vec![sk, t, r01, rt]);

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);

        let proof = SigmaProof::prove(&lang, &inst, &wit);

        println!("proof {:?}", proof);

        let ver = proof.verify(&lang, &inst);
        println!("proof is {:?}", ver);
        assert!(ver.is_ok());
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_escrow_lang() {
        let mut rng = thread_rng();
        let G: CG1 = UniformRand::rand(&mut rng);
        let H: CG1 = UniformRand::rand(&mut rng);
        let PA: CG1 = UniformRand::rand(&mut rng);
        let PD: CG1 = UniformRand::rand(&mut rng);
        let PW: CG1 = UniformRand::rand(&mut rng);

        let lang: AlgLang<CG1> = escrow_lang(G, H);
        let wit: AlgWit<CG1> = escrow_gen_wit(&mut rng);
        let inst: AlgInst<CG1> =
            escrow_gen_inst_from_wit(G, H, &vec![PA], &vec![PD], &vec![PW], &wit);

        println!("inst {:?}", lang.instantiate_matrix(&inst.0));

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_trace_lang() {
        let mut rng = thread_rng();
        let G: CG1 = UniformRand::rand(&mut rng);
        let H: CG1 = UniformRand::rand(&mut rng);
        let Xi1: CG1 = UniformRand::rand(&mut rng);
        let xi: CF = UniformRand::rand(&mut rng);
        let rxi: CF = UniformRand::rand(&mut rng);
        let ri: CF = UniformRand::rand(&mut rng);
        let Xi: CG1 = G * xi + H * rxi + Xi1;
        let Ci: CG1 = G * xi + H * ri;

        let lang: AlgLang<CG1> = trace_lang(G, H);
        let inst: AlgInst<CG1> = AlgInst(vec![Xi - Xi1, Ci, H]); //
        let wit: AlgWit<CG1> = AlgWit(vec![xi, rxi, ri]);

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);

        let proof = SigmaProof::prove(&lang, &inst, &wit);

        println!("proof {:?}", proof);

        let ver = proof.verify(&lang, &inst);
        println!("proof is {:?}", ver);
        assert!(ver.is_ok());
    }
}
