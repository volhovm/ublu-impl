use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::Zero;
use rand::RngCore;

use crate::{
    ch20::{ch20_setup, CH20Proof, CH20CRS},
    commitment::PedersenParams,
    elgamal::{Cipher, ElgamalParams, ElgamalSk},
};

#[allow(dead_code)]
pub struct Ublu<P: Pairing> {
    lambda: u32,
    d: u32,
    g: P::G1,
    com_h: P::G1,
    w: Vec<P::G1>,
    elgamal: ElgamalParams<P::G1>,
    pedersen: PedersenParams<P::G1>,
    ch20: CH20CRS<P>,
}

pub struct PkProof {}

#[allow(dead_code)]
pub struct PublicKey<P: Pairing> {
    h: P::G1,
    com_t: P::G1,
    proof_pk: PkProof,
}

#[allow(dead_code)]
pub struct SecretKey<P: Pairing> {
    elgamal_sk: ElgamalSk<P::G1>,
}

#[allow(dead_code)]
pub struct Hint<P: Pairing> {
    ciphers: Vec<Cipher<P::G1>>,
    com_x: P::G1,
    proof_c: CH20Proof<P>,
}

impl<P: Pairing> Ublu<P> {
    pub fn setup<RNG: RngCore>(lambda: u32, d: u32, rng: &mut RNG) -> Self {
        let g = <P::G1 as UniformRand>::rand(rng);
        let com_h = <P::G1 as UniformRand>::rand(rng);
        let mut w: Vec<P::G1> = Vec::with_capacity(d as usize);
        for _i in 0..d {
            w.push(<P::G1 as UniformRand>::rand(rng));
        }
        let ch20: CH20CRS<P> = ch20_setup(rng);
        Ublu {
            lambda,
            d,
            g,
            w,
            elgamal: ElgamalParams { g },
            pedersen: PedersenParams { g, h: com_h },
            ch20,
            com_h,
        }
    }

    #[allow(unused_variables)]
    pub fn key_gen<RNG: RngCore>(
        &mut self,
        t: u32,
        rng: &mut RNG,
    ) -> (PublicKey<P>, SecretKey<P>, Hint<P>) {
        let (sk, pk) = self.elgamal.key_gen(rng);
        let r_t = P::ScalarField::rand(rng);
        let mut r_vec = Vec::with_capacity(t as usize);
        let mut cipher_vec = Vec::with_capacity(t as usize);
        for i in 1..=self.d {
            let base = -(t as i32);
            let cur_msg = base.pow(i);
            let cur_r = P::ScalarField::rand(rng);
            r_vec.push(cur_r);
            cipher_vec.push(self.elgamal.encrypt_raw(&pk, cur_msg, cur_r));
        }
        let com_t = self.pedersen.commit_raw(&P::ScalarField::from(t), r_t);
        let com_x0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), P::ScalarField::zero());
        let com_u0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), P::ScalarField::zero());
        // TODO do the proofs
        let proof_c = CH20Proof {
            a: Vec::new(),
            d: Vec::new(),
        };
        (
            PublicKey {
                h: pk.h,
                com_t: com_t.com,
                proof_pk: PkProof {},
            },
            SecretKey { elgamal_sk: sk },
            Hint {
                ciphers: cipher_vec,
                com_x: com_x0.com,
                proof_c,
            },
        )
    }
}
