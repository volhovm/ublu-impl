use ark_ec::{pairing::Pairing, Group};
use ark_ff::{One, Zero};
use ark_std::UniformRand;
use rand::{thread_rng, RngCore};
use crate::ch20::{AlgInst, AlgLang, AlgWit};

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct SigmaProof<G: Group> {
    a: Vec<G>,
    z: Vec<G::ScalarField>,
}

#[derive(Debug)]
pub enum SigmaVerifierError {
    SigmaGenericError(String),
}

impl<G: Group> SigmaProof<G> {
    pub fn prove(
        lang: &AlgLang<G>,
        inst: &AlgInst<G>,
        wit: &AlgWit<G>,
    ) -> SigmaProof<G>
        where
            G::ScalarField: UniformRand,
    {
        SigmaProof::default()
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{CF, CG1};
    use crate::ch20::LinearPoly;

    #[test]
    fn test_sigma_basics() {
        let mut rng = thread_rng();
        let a: CG1 = UniformRand::rand(&mut rng);
        let z: CF = UniformRand::rand(&mut rng);
        SigmaProof::<CG1>{a: vec![a], z: vec![z]};
    }

    #[allow(non_snake_case)]
    #[test]
    fn test_alglan() {
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
        assert!(lang_valid);

    }

    #[allow(non_snake_case)]
    #[test]
    fn test_tracelang() {
        let mut rng = thread_rng();
        let G: CG1 = UniformRand::rand(&mut rng);
        let H: CG1 = UniformRand::rand(&mut rng);
        let Xi1: CG1 = UniformRand::rand(&mut rng);
        let xi: CF = UniformRand::rand(&mut rng);
        let rxi: CF = UniformRand::rand(&mut rng);
        let ri: CF = UniformRand::rand(&mut rng);
        let Xi: CG1 = G * xi + H * rxi + Xi1;
        let Ci: CG1 = G * xi + H * ri;

        let il = 4;
        let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
            vec![LinearPoly::constant(il, G), LinearPoly::constant(il, H), LinearPoly::zero(il)],
            vec![LinearPoly::constant(il, G), LinearPoly::zero(il), LinearPoly::constant(il, H)],
        ];

        let lang: AlgLang<CG1> = AlgLang { matrix };
        let inst: AlgInst<CG1> = AlgInst(vec![Xi - Xi1, Ci, H]); //
        let wit: AlgWit<CG1> = AlgWit(vec![xi, rxi, ri]);

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);
    }

}