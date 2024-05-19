use ark_ec::Group;
use ark_ff::UniformRand;
use rand::RngCore;

pub const MAX_TRIES: u32 = 100;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElgamalParams<G: Group> {
    pub g: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Cipher<G: Group> {
    pub a: G,
    pub b: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElgamalPk<G: Group> {
    pub h: G,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

    pub fn encrypt_raw(
        &self,
        pk: &ElgamalPk<G>,
        msg: G::ScalarField,
        rnd: G::ScalarField,
    ) -> Cipher<G> {
        Cipher {
            a: self.g * rnd,
            b: self.g * msg + pk.h * rnd,
        }
    }

    pub fn encrypt<RNG: RngCore>(
        &mut self,
        pk: &ElgamalPk<G>,
        msg: G::ScalarField,
        rng: &mut RNG,
    ) -> Cipher<G> {
        self.encrypt_raw(pk, msg, <G::ScalarField as UniformRand>::rand(rng))
    }

    pub fn decrypt(&self, cipher: &Cipher<G>, sk: &ElgamalSk<G>) -> G {
        let s = cipher.a * sk.sk;
        s.neg() + cipher.b
    }

    pub fn decrypt_exponent(&self, cipher: &Cipher<G>, sk: &ElgamalSk<G>) -> anyhow::Result<i32> {
        let m = self.decrypt(cipher, sk);
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
    use crate::CF;
    use aes_prng::AesRng;
    use ark_bls12_381::Bls12_381;
    use ark_ec::pairing::Pairing;
    use ark_ff::Zero;
    use rand::SeedableRng;

    use super::ElgamalParams;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = ElgamalParams::<<Bls12_381 as Pairing>::G1>::new(&mut rng);
        let (sk, pk) = elgamal.key_gen(&mut rng);
        let c = elgamal.encrypt(&pk, From::from(42), &mut rng);
        let res = elgamal.decrypt_exponent(&c, &sk).unwrap();
        assert_eq!(res, 42);
    }

    #[test]
    fn sunshine_negative() {
        let mut rng = AesRng::seed_from_u64(1);
        let mut elgamal = ElgamalParams::<<Bls12_381 as Pairing>::G1>::new(&mut rng);
        let (sk, pk) = elgamal.key_gen(&mut rng);
        let c = elgamal.encrypt(&pk, CF::zero() - CF::from(42), &mut rng);
        let res = elgamal.decrypt_exponent(&c, &sk).unwrap();
        assert_eq!(res, -42);
    }
}
