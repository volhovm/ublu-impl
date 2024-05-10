use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;
use std::ops;

pub struct PedersenParams<G: Group> {
    pub g: G,
    pub h: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment<G: Group> {
    pub com: InnerCom<G>,
    pub rnd: G::ScalarField,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InnerCom<G: Group> {
    value: G,
}
impl<G: Group> ops::Add<InnerCom<G>> for InnerCom<G> {
    type Output = InnerCom<G>;

    fn add(self, rhs: InnerCom<G>) -> InnerCom<G> {
        let value = self.value + rhs.value;
        InnerCom { value }
    }
}

impl<G: Group> PedersenParams<G> {
    pub fn new<RNG: RngCore>(rng: &mut RNG) -> Self {
        PedersenParams {
            g: G::rand(rng),
            h: G::rand(rng),
        }
    }

    pub fn commit_raw(&self, msg: &G::ScalarField, rnd: &G::ScalarField) -> Commitment<G> {
        Commitment {
            com: InnerCom {
                value: self.g * msg + self.h * rnd,
            },
            rnd: rnd.to_owned(),
        }
    }

    pub fn commit<RNG: RngCore>(&self, msg: &G::ScalarField, rng: &mut RNG) -> Commitment<G> {
        self.commit_raw(msg, &<G::ScalarField as UniformRand>::rand(rng))
    }

    pub fn verify(&self, msg: &G::ScalarField, commitment: &Commitment<G>) -> bool {
        let reference = self.commit_raw(msg, &commitment.rnd);
        &reference == commitment
    }
}

impl<G: Group> ops::Add<Commitment<G>> for Commitment<G> {
    type Output = Commitment<G>;

    fn add(self, rhs: Commitment<G>) -> Commitment<G> {
        let inner_com = self.com + rhs.com;
        let rnd = self.rnd + rhs.rnd;
        Commitment {
            com: inner_com,
            rnd,
        }
    }
}

#[cfg(test)]
mod tests {
    use aes_prng::AesRng;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let pedersen: PedersenParams<<Bls12_381 as Pairing>::G1> = PedersenParams::new(&mut rng);
        let msg = <Bls12_381 as Pairing>::ScalarField::from(42);
        let commitment = pedersen.commit(&msg, &mut rng);
        assert!(pedersen.verify(&msg, &commitment));
    }
}
