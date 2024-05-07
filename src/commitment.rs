use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;

pub struct PedersenParams<G: Group> {
    pub g: G,
    pub h: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment<G: Group> {
    pub com: G,
    pub rnd: G::ScalarField,
}

impl<G: Group> PedersenParams<G> {
    pub fn new<RNG: RngCore>(rng: &mut RNG) -> Self {
        PedersenParams {
            g: G::rand(rng),
            h: G::rand(rng),
        }
    }

    pub fn commit_raw(&self, msg: &G::ScalarField, rnd: G::ScalarField) -> Commitment<G> {
        Commitment {
            com: self.g * msg + self.h * rnd,
            rnd,
        }
    }

    pub fn commit<RNG: RngCore>(&self, msg: &G::ScalarField, rng: &mut RNG) -> Commitment<G> {
        self.commit_raw(msg, <G::ScalarField as UniformRand>::rand(rng))
    }

    pub fn verify(&self, msg: &G::ScalarField, commitment: &Commitment<G>) -> bool {
        let reference = self.commit_raw(msg, commitment.rnd);
        &reference == commitment
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
