use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;

pub struct Pedersen<G: Group> {
    pub G: G,
    pub H: G,
    pub rng: Box<dyn RngCore>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Commitment<G: Group> {
    pub com: G,
    pub rnd: G::ScalarField,
}

impl<G: Group> Pedersen<G> {
    pub fn new(mut rng: impl RngCore + 'static) -> Self {
        Pedersen {
            G: G::rand(&mut rng),
            H: G::rand(&mut rng),
            rng: Box::new(rng),
        }
    }

    pub fn commit(&mut self, msg: &G::ScalarField, rnd: Option<G::ScalarField>) -> Commitment<G> {
        match rnd {
            Some(rnd) => Commitment {
                com: self.G * msg + self.H * rnd,
                rnd,
            },
            None => {
                let sampled_rng = <G::ScalarField as UniformRand>::rand(&mut self.rng);
                Commitment {
                    com: self.G * msg + self.H * sampled_rng,
                    rnd: sampled_rng,
                }
            }
        }
    }

    pub fn verify(&mut self, msg: &G::ScalarField, commitment: &Commitment<G>) -> bool {
        let reference = self.commit(msg, Some(commitment.rnd));
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
        let mut pedersen: Pedersen<<Bls12_381 as Pairing>::G1> = Pedersen::new(rng);
        let msg = <Bls12_381 as Pairing>::ScalarField::from(42);
        let commitment = pedersen.commit(&msg, None);
        assert!(pedersen.verify(&msg, &commitment));
    }
}
