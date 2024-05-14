use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;
use std::ops;

pub struct PedersenParams<G: Group> {
    pub g: G,
    pub h: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommWithRand<G: Group> {
    pub com: Comm<G>,
    pub rnd: G::ScalarField,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Comm<G: Group> {
    value: G,
}

impl<G: Group> ops::Add<Comm<G>> for Comm<G> {
    type Output = Comm<G>;

    fn add(self, rhs: Comm<G>) -> Comm<G> {
        let value = self.value + rhs.value;
        Comm { value }
    }
}

impl<G: Group> PedersenParams<G> {
    pub fn new<RNG: RngCore>(rng: &mut RNG) -> Self {
        PedersenParams {
            g: G::rand(rng),
            h: G::rand(rng),
        }
    }

    pub fn commit_raw(&self, msg: &G::ScalarField, rnd: &G::ScalarField) -> CommWithRand<G> {
        CommWithRand {
            com: Comm {
                value: self.g * msg + self.h * rnd,
            },
            rnd: rnd.to_owned(),
        }
    }

    pub fn commit<RNG: RngCore>(&self, msg: &G::ScalarField, rng: &mut RNG) -> CommWithRand<G> {
        self.commit_raw(msg, &<G::ScalarField as UniformRand>::rand(rng))
    }

    pub fn verify(&self, msg: &G::ScalarField, commitment: &CommWithRand<G>) -> bool {
        let reference = self.commit_raw(msg, &commitment.rnd);
        &reference == commitment
    }
}

impl<G: Group> ops::Add<CommWithRand<G>> for CommWithRand<G> {
    type Output = CommWithRand<G>;

    fn add(self, rhs: CommWithRand<G>) -> CommWithRand<G> {
        let inner_com = self.com + rhs.com;
        let rnd = self.rnd + rhs.rnd;
        CommWithRand {
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
