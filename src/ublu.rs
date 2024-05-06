use aes_prng::AesRng;
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::Zero;
use rand::{RngCore, SeedableRng};

use crate::{
    ch20::{ch20_setup, CH20Proof, CH20CRS},
    commitment::Pedersen,
    elgamal::{Cipher, Elgamal, ElgamalSk},
};

pub struct Ublu<P: Pairing> {
    lambda: u32,
    d: u32,
    G: P::G1,
    com_H: P::G1,
    W: Vec<P::G1>,
    elgamal: Elgamal<P::G1>,
    pedersen: Pedersen<P::G1>,
    ch20: CH20CRS<P>,
    rng: Box<dyn RngCore>,
}

pub struct PkProof {}

pub struct PublicKey<P: Pairing> {
    H: P::G1,
    com_T: P::G1,
    proof_pk: PkProof,
}

pub struct SecretKey<P: Pairing> {
    elgamal_sk: ElgamalSk<P::G1>,
}

pub struct Hint<P: Pairing> {
    ciphers: Vec<Cipher<P::G1>>,
    com_X: P::G1,
    proof_c: CH20Proof<P>,
}

impl<P: Pairing> Ublu<P> {
    pub fn setup(lambda: u32, d: u32, mut rng: impl RngCore + 'static) -> Self {
        let G = <P::G1 as UniformRand>::rand(&mut rng);
        let com_H = <P::G1 as UniformRand>::rand(&mut rng);
        let mut W: Vec<P::G1> = Vec::with_capacity(d as usize);
        for _i in 0..d {
            W.push(<P::G1 as UniformRand>::rand(&mut rng));
        }
        let ch20: CH20CRS<P> = ch20_setup(&mut rng);
        let internal_rng = Box::new(AesRng::from_rng(&mut rng).unwrap());
        let elgamal_rng = Box::new(AesRng::from_rng(&mut rng).unwrap());
        let pedersen_rng = Box::new(AesRng::from_rng(&mut rng).unwrap());
        // let mut internal_rng = Box::new(AesRng::from_rng(pedersen_rng).unwrap());
        Ublu {
            lambda,
            d,
            G,
            W,
            elgamal: Elgamal {
                G,
                rng: elgamal_rng,
            },
            pedersen: Pedersen {
                G,
                H: com_H,
                rng: pedersen_rng,
            },
            ch20,
            rng: internal_rng,
            com_H,
        }
    }

    pub fn key_gen(&mut self, t: u32) -> (PublicKey<P>, SecretKey<P>, Hint<P>) {
        let (sk, pk) = self.elgamal.key_gen();
        let r_t = P::ScalarField::rand(&mut self.rng);
        let mut r_vec = Vec::with_capacity(t as usize);
        let mut cipher_vec = Vec::with_capacity(t as usize);
        for i in 1..=self.d {
            let base = -(t as i32);
            let cur_msg = base.pow(i);
            let cur_r = P::ScalarField::rand(&mut self.rng);
            r_vec.push(cur_r);
            cipher_vec.push(self.elgamal.encrypt(&pk, cur_msg, Some(cur_r)));
        }
        let com_t = self.pedersen.commit(&P::ScalarField::from(t), Some(r_t));
        let com_x0 = self
            .pedersen
            .commit(&P::ScalarField::from(0_u32), Some(P::ScalarField::zero()));
        let com_u0 = self
            .pedersen
            .commit(&P::ScalarField::from(0_u32), Some(P::ScalarField::zero()));
        // TODO do the proofs
        let proof_c = CH20Proof {
            a: Vec::new(),
            d: Vec::new(),
        };
        (
            PublicKey {
                H: pk.h,
                com_T: com_t.com,
                proof_pk: PkProof {},
            },
            SecretKey { elgamal_sk: sk },
            Hint {
                ciphers: cipher_vec,
                com_X: com_x0.com,
                proof_c,
            },
        )
    }
}
