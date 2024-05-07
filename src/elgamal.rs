use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;

pub const MAX_TRIES: u32 = 10000;
pub struct ElgamalParams<G: Group> {
    pub g: G,
}

#[derive(Clone, Debug)]
pub struct Cipher<G: Group> {
    pub a: G,
    pub b: G,
}

pub struct ElgamalPk<G: Group> {
    pub h: G,
}

pub struct ElgamalSk<G: Group> {
    pub sk: G::ScalarField,
}

impl<G: Group> ElgamalParams<G> {
    pub fn new<RNG: RngCore>(rng: &mut RNG) -> Self {
        ElgamalParams { g: G::rand(rng) }
    }

    pub fn key_gen<RNG: RngCore>(&self, rng: &mut RNG) -> (ElgamalSk<G>, ElgamalPk<G>) {
        let sk = G::ScalarField::rand(rng);
        let pk = self.g * sk;
        (ElgamalSk { sk }, ElgamalPk { h: pk })
    }

    pub fn encrypt_raw(&self, pk: &ElgamalPk<G>, msg: i32, rnd: G::ScalarField) -> Cipher<G> {
        let mut val = G::ScalarField::from(msg.unsigned_abs());
        if msg < 0 {
            val = -val;
        }
        // Observe we do exponent encryption
        Cipher {
            a: self.g * rnd,
            b: self.g * val + pk.h * rnd,
        }
    }

    pub fn encrypt<RNG: RngCore>(
        &mut self,
        pk: &ElgamalPk<G>,
        msg: i32,
        rng: &mut RNG,
    ) -> Cipher<G> {
        self.encrypt_raw(pk, msg, <G::ScalarField as UniformRand>::rand(rng))
    }

    pub fn decrypt(&self, cipher: &Cipher<G>, sk: &ElgamalSk<G>) -> anyhow::Result<i32> {
        let s = cipher.a * sk.sk;
        let m = s.neg() + cipher.b;
        for ctr in 0..=MAX_TRIES {
            if m == self.g * G::ScalarField::from(ctr) {
                return Ok(ctr as i32);
            }
            if m == self.g * (-G::ScalarField::from(ctr)) {
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

    use super::ElgamalParams;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = ElgamalParams::<<Bls12_381 as Pairing>::G1>::new(&mut rng);
        let (sk, pk) = elgamal.key_gen(&mut rng);
        let c = elgamal.encrypt(&pk, 42, &mut rng);
        let res = elgamal.decrypt(&c, &sk).unwrap();
        assert_eq!(res, 42);
    }

    #[test]
    fn sunshine_negative() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = ElgamalParams::<<Bls12_381 as Pairing>::G1>::new(&mut rng);
        let (sk, pk) = elgamal.key_gen(&mut rng);
        let c = elgamal.encrypt(&pk, -42, &mut rng);
        let res = elgamal.decrypt(&c, &sk).unwrap();
        assert_eq!(res, -42);
    }
}
