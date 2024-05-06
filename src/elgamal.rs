use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;

pub const MAX_TRIES: u32 = 10000;
pub struct Elgamal<G: Group> {
    pub G: G,
    pub rng: Box<dyn RngCore>,
}

#[derive(Clone, Debug)]
pub struct Cipher<G: Group> {
    pub A: G,
    pub B: G,
}

pub struct ElgamalPk<G: Group> {
    pub h: G,
}

pub struct ElgamalSk<G: Group> {
    pub sk: G::ScalarField,
}

impl<G: Group> Elgamal<G> {
    pub fn new(mut rng: impl RngCore + 'static) -> Self {
        Elgamal {
            G: G::rand(&mut rng),
            rng: Box::new(rng),
        }
    }

    pub fn key_gen(&mut self) -> (ElgamalSk<G>, ElgamalPk<G>) {
        let sk = G::ScalarField::rand(&mut self.rng);
        let pk = self.G * sk;
        (ElgamalSk { sk }, ElgamalPk { h: pk })
    }

    pub fn encrypt(
        &mut self,
        pk: &ElgamalPk<G>,
        msg: i32,
        rnd: Option<G::ScalarField>,
    ) -> Cipher<G> {
        let rnd_to_use = match rnd {
            Some(rnd_to_use) => rnd_to_use,
            None => <G::ScalarField as UniformRand>::rand(&mut self.rng),
        };
        let mut val = G::ScalarField::from(msg.unsigned_abs());
        if msg < 0 {
            val = -val;
        }
        // Observe we do exponent encryption
        Cipher {
            A: self.G * rnd_to_use,
            B: self.G * val + pk.h * rnd_to_use,
        }
    }

    pub fn decrypt(&self, cipher: &Cipher<G>, sk: &ElgamalSk<G>) -> anyhow::Result<i32> {
        let s = cipher.A * sk.sk;
        let M = s.neg() + cipher.B;
        for ctr in 0..=MAX_TRIES {
            if M == self.G * G::ScalarField::from(ctr) {
                return Ok(ctr as i32);
            }
            if M == self.G * (-G::ScalarField::from(ctr)) {
                return Ok(-(ctr as i32));
            }
        }
        println!("Failed to decrypt");
        Err(anyhow::anyhow!("Failed to decrypt"))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use aes_prng::AesRng;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use rand::SeedableRng;

    use super::Elgamal;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = Elgamal::<<Bls12_381 as Pairing>::G1>::new(rng);
        let (sk, pk) = elgamal.key_gen();
        let c = elgamal.encrypt(&pk, 42, None);
        let res = elgamal.decrypt(&c, &sk).unwrap();
        assert_eq!(res, 42);
    }

    #[test]
    fn sunshine_negative() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = Elgamal::<<Bls12_381 as Pairing>::G1>::new(rng);
        let (sk, pk) = elgamal.key_gen();
        let c = elgamal.encrypt(&pk, -42, None);
        let res = elgamal.decrypt(&c, &sk).unwrap();
        assert_eq!(res, -42);
    }
}
