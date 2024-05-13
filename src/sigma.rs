use ark_ec::{Group};
use ark_std::UniformRand;
use ark_transcript::Transcript;
use rand::{thread_rng};
use ark_ff::{Zero};
use crate::ch20::{AlgInst, AlgLang, AlgWit, mul_mat_by_vec_g_f};

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
        let mut t = Transcript::new(b"sigma_proof");
        t.append(&inst.0);

        let mut rng = thread_rng();
        let r: Vec<G::ScalarField> = (0..(lang.wit_size()))
            .map(|_i| <G::ScalarField as UniformRand>::rand(&mut rng))
            .collect();
        let matrix = lang.instantiate_matrix(&inst.0);
        let a: Vec<G> = mul_mat_by_vec_g_f(&matrix, &r);
        t.append(&a);
        let chl: G::ScalarField = t.challenge(b"challenge").read_uniform();
        let z = wit.0.iter().zip(r).map(|(w,r)| r-chl*w ).collect();
        SigmaProof{a, z}
    }

    pub fn verify(
        &self,
        lang: &AlgLang<G>,
        inst: &AlgInst<G>,
    ) -> Result<(), SigmaVerifierError> {
        let mut t = Transcript::new(b"sigma_proof");
        t.append(&inst.0);
        t.append(&self.a);
        let chl: G::ScalarField = t.challenge(b"challenge").read_uniform();
        let matrix = lang.instantiate_matrix(&inst.0);
        let lhs: Vec<G> = mul_mat_by_vec_g_f(&matrix, &self.z);
        let rhs: Vec<G> = self.a.iter().zip(&inst.0).map(|(a,i)| a.clone() - i.clone()*chl ).collect();
        if lhs != rhs {
            return Err(SigmaVerifierError::SigmaGenericError(From::from(
                "Sides are not equal",
            )));
        }
        Ok(())
    }
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{CF, CG1};
    use crate::ch20::LinearPoly;
    use ark_transcript::Transcript;

    #[test]
    fn test_sigma_basics() {
        let mut rng = thread_rng();
        let a: CG1 = UniformRand::rand(&mut rng);
        let z: CF = UniformRand::rand(&mut rng);
        SigmaProof::<CG1>{a: vec![a], z: vec![z]};
    }

    #[test]
    fn transcript_v_witnesses() {

        let mut rng = thread_rng();

        let protocol_label = b"test collisions";
        let commitment1 = b"commitment data 1";
        let commitment2 = b"commitment data 2";

        let mut t1 = Transcript::new(protocol_label);
        let mut t2 = Transcript::new(protocol_label);
        let mut t3 = Transcript::new(protocol_label);
        let mut t4 = Transcript::new(protocol_label);

        t1.write_bytes(commitment1);
        t2.write_bytes(commitment2);
        t3.write_bytes(commitment2);
        t4.write_bytes(commitment2);

        let chl: CF = t1.witness(&mut rng).read_uniform();

        println!("challenge is {:?}", chl);
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
        let inst2: AlgInst<CG1> = AlgInst(vec![gx, gx, gz]);
        let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);

        let proof = SigmaProof::prove(&lang, &inst, &wit);

        println!("proof {:?}", proof);

        let ver = proof.verify(&lang, &inst).unwrap();
        println!("proof is {:?}", ver);

        let wrong = proof.verify(&lang, &inst2);
        assert!(wrong.is_err())
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

        let proof = SigmaProof::prove(&lang, &inst, &wit);

        println!("proof {:?}", proof);

        let ver = proof.verify(&lang, &inst).unwrap();
        println!("proof is {:?}", ver)
    }

    #[allow(unused_variables)]
    #[allow(non_snake_case)]
    #[test]
    fn test_escrowlang() {
        let mut rng = thread_rng();
        let G: CG1 = UniformRand::rand(&mut rng);
        let H: CG1 = UniformRand::rand(&mut rng);
        let PA: CG1 = UniformRand::rand(&mut rng);
        let PD: CG1 = UniformRand::rand(&mut rng);
        let PW: CG1 = UniformRand::rand(&mut rng);

        let a: CF = UniformRand::rand(&mut rng);
        let ra: CF = UniformRand::rand(&mut rng);
        let b: CF = UniformRand::rand(&mut rng);
        let rb: CF = UniformRand::rand(&mut rng);

        let ba: CF = b*a;
        let rba: CF = rb*a;

        let U: CG1 = G * a + H * ra;
        let B: CG1 = G * b + H * rb;
        let E1: CG1 = PA * b;
        let E2: CG1 = PD * b + PW * ba;

        let il = 8;
        let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
            vec![LinearPoly::constant(il, G), LinearPoly::constant(il, H), LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::zero(il)],
            vec![LinearPoly::zero(il), LinearPoly::zero(il),LinearPoly::constant(il, G), LinearPoly::constant(il, H), LinearPoly::zero(il), LinearPoly::zero(il)],
            vec![LinearPoly::single(il, 1), LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::constant(il, -G), LinearPoly::constant(il, -H),],

            vec![LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::single(il, 5), LinearPoly::zero(il),LinearPoly::zero(il),LinearPoly::zero(il)],
            vec![LinearPoly::zero(il), LinearPoly::zero(il), LinearPoly::single(il, 6), LinearPoly::zero(il),LinearPoly::single(il, 7),LinearPoly::zero(il)],
        ];

        let lang: AlgLang<CG1> = AlgLang { matrix };
        let inst: AlgInst<CG1> = AlgInst(vec![U,B,G*CF::zero(),E1,E2, PA, PD, PW]);
        let wit: AlgWit<CG1> = AlgWit(vec![a,ra,b,rb,ba,rba]);

        println!("inst {:?}", lang.instantiate_matrix(&inst.0));

        let lang_valid = lang.contains(&inst, &wit);
        println!("Language valid? {lang_valid:?}");
        assert!(lang_valid);
    }
}