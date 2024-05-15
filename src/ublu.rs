use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::Zero;
use rand::RngCore;

use crate::{
    ch20::{CH20Proof, CH20CRS},
    commitment::{InnerCom, PedersenParams},
    elgamal::{Cipher, ElgamalParams, ElgamalSk},
    utils::binomial,
};

#[allow(dead_code)]
pub struct Ublu<P: Pairing, RNG: RngCore> {
    rng: RNG,
    lambda: usize,
    d: usize,
    g: P::G1,
    com_h: P::G1,
    w: Vec<P::G1>,
    elgamal: ElgamalParams<P::G1>,
    pedersen: PedersenParams<P::G1>,
    ch20: CH20CRS<P>,
}

//TODO placeholder
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkProof<P: Pairing> {
    _phantom: std::marker::PhantomData<P>,
}

//TODO placeholder
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagProof<P: Pairing> {
    _phantom: std::marker::PhantomData<P>,
}
impl<P: Pairing> From<CH20Proof<P>> for TagProof<P> {
    fn from(_value: CH20Proof<P>) -> Self {
        todo!()
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey<P: Pairing> {
    h: P::G1,
    com_t: InnerCom<P::G1>,
    proof_pk: PkProof<P>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey<P: Pairing> {
    elgamal_sk: ElgamalSk<P::G1>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hint<P: Pairing> {
    ciphers: Vec<Cipher<P::G1>>,
    com_x: InnerCom<P::G1>,
    proof_c: CH20Proof<P>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag<P: Pairing> {
    proof: TagProof<P>,
    com: InnerCom<P::G1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XC<P: Pairing> {
    h: P::G1,
    comt_t: InnerCom<P::G1>,
    old_com_x: InnerCom<P::G1>,
    com_u: InnerCom<P::G1>,
    old_ciphers: Vec<Cipher<P::G1>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WC<P: Pairing> {
    x: usize,
    r_list: Vec<P::ScalarField>,
    r_x: P::ScalarField,
    alpha: P::ScalarField,
    r_alpha: P::ScalarField,
}

impl<P: Pairing, RNG: RngCore> Ublu<P, RNG> {
    pub fn setup(lambda: usize, d: usize, mut rng: RNG) -> Self {
        let g = P::G1::rand(&mut rng);
        let com_h = P::G1::rand(&mut rng);
        let mut w: Vec<P::G1> = Vec::with_capacity(d);
        for _i in 0..d {
            w.push(P::G1::rand(&mut rng));
        }
        let ch20: CH20CRS<P> = CH20CRS::setup(&mut rng);
        Ublu {
            lambda,
            d,
            g,
            w,
            elgamal: ElgamalParams { g },
            pedersen: PedersenParams { g, h: com_h },
            ch20,
            com_h,
            rng,
        }
    }

    #[allow(unused_variables)]
    pub fn key_gen(&mut self, t: u32) -> (PublicKey<P>, SecretKey<P>, Hint<P>) {
        let (sk, pk) = self.elgamal.key_gen(&mut self.rng);
        let r_t = P::ScalarField::rand(&mut self.rng);
        let mut r_vec = Vec::with_capacity(t as usize);
        let mut cipher_vec = Vec::with_capacity(t as usize);
        for i in 1..=self.d {
            let base = -(t as i32);
            let cur_msg = base.pow(i as u32);
            let cur_r = P::ScalarField::rand(&mut self.rng);
            r_vec.push(cur_r);
            cipher_vec.push(self.elgamal.encrypt_raw(&pk, cur_msg, cur_r));
        }
        let com_t = self.pedersen.commit_raw(&P::ScalarField::from(t), &r_t);
        let com_x0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::zero());
        let com_u0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::zero());
        // TODO do the proofs
        let proof_c = CH20Proof {
            a: Vec::new(),
            d: Vec::new(),
        };
        (
            PublicKey {
                h: pk.h,
                com_t: com_t.com,
                proof_pk: PkProof::<P> {
                    _phantom: std::marker::PhantomData,
                },
            },
            SecretKey { elgamal_sk: sk },
            Hint {
                ciphers: cipher_vec,
                com_x: com_x0.com,
                proof_c,
            },
        )
    }

    pub fn update(
        &mut self,
        pk: &PublicKey<P>,
        hint: &Hint<P>,
        _old_tag: Option<&Tag<P>>,
        x: usize,
        rnd: &P::ScalarField,
    ) -> (Hint<P>, Tag<P>) {
        let r_x = P::ScalarField::rand(&mut self.rng);
        let new_hint = self.update_hint(pk, hint, x, &r_x);
        let _cur_com = self
            .pedersen
            .commit_raw(&P::ScalarField::from(x as u64), rnd);
        // TODO do the proofs
        // @Misha: how does this work when there is no initial tag or tag proof? i.e. in the first update case.
        let proof_t = CH20Proof {
            a: Vec::new(),
            d: Vec::new(),
        };
        let new_tag = Tag {
            proof: proof_t.into(),
            com: new_hint.com_x.clone(),
        };
        (new_hint, new_tag)
    }

    fn update_hint(
        &mut self,
        pk: &PublicKey<P>,
        old_hint: &Hint<P>,
        x: usize,
        r_x: &P::ScalarField,
    ) -> Hint<P> {
        let mut r_i_list = Vec::with_capacity(self.d);
        for _i in 0..self.d {
            r_i_list.push(P::ScalarField::rand(&mut self.rng));
        }
        let mut new_com = self
            .pedersen
            .commit_raw(&P::ScalarField::from(x as u64), r_x)
            .com;
        new_com = new_com + old_hint.com_x.clone();
        // TODO can probably be optimized a bit by modifying cipherts in place
        let new_ciphers = self.update_powers(pk, old_hint.ciphers.clone(), r_i_list.clone(), x);
        let com_u = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::zero());
        let _xc: XC<P> = XC {
            h: pk.h,
            comt_t: pk.com_t.clone(),
            old_com_x: old_hint.com_x.clone(),
            com_u: com_u.com,
            old_ciphers: old_hint.ciphers.clone(),
        };
        let _wc: WC<P> = WC {
            x,
            r_list: r_i_list,
            r_x: *r_x,
            alpha: P::ScalarField::zero(),
            r_alpha: P::ScalarField::zero(),
        };
        // TODO do update proof
        let pi_c: CH20Proof<P> = CH20Proof {
            a: Vec::new(),
            d: Vec::new(),
        };

        Hint {
            ciphers: new_ciphers,
            com_x: new_com,
            proof_c: pi_c,
        }
    }

    fn update_powers(
        &mut self,
        pk: &PublicKey<P>,
        old_ciphers: Vec<Cipher<P::G1>>,
        r_i_list: Vec<P::ScalarField>,
        x: usize,
    ) -> Vec<Cipher<P::G1>> {
        let mut new_ciphers = Vec::with_capacity(self.d);
        for i in 1..=self.d {
            let mut cur_a_res = P::G1::zero();
            let mut cur_b_res = P::G1::zero();
            for j in 1..=i {
                let cur_v_val = P::ScalarField::from(v_func(x, i, j) as u64);
                cur_a_res += old_ciphers.get(j - 1).unwrap().a * cur_v_val;
                cur_b_res += old_ciphers.get(j - 1).unwrap().b * cur_v_val;
            }
            cur_a_res += self.g * r_i_list.get(i - 1).unwrap();
            cur_b_res += pk.h * r_i_list.get(i - 1).unwrap();
            new_ciphers.push(Cipher {
                a: cur_a_res,
                b: cur_b_res,
            });
        }
        new_ciphers
    }
}

fn v_func(x: usize, i: usize, j: usize) -> usize {
    let bin = binomial(i, j);
    bin * x.pow((i - j) as u32)
}
