#![allow(clippy::needless_range_loop)]
#![allow(unused_assignments)]
#![allow(unused_variables)]
#![allow(dead_code)]
use ark_ec::pairing::Pairing;
use ark_ff::UniformRand;
use ark_std::{One, Zero};
use rand::RngCore;

use crate::{
    ch20::{AlgInst, AlgWit, CH20Proof, CH20Trans, CH20CRS},
    commitment::{Comm, PedersenParams},
    consistency,
    elgamal::{Cipher, ElgamalParams, ElgamalSk},
    languages::{escrow_lang, key_lang, trace_lang},
    sigma::SigmaProof,
    utils::{binomial, field_pow},
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
    ch20crs: CH20CRS<P>,
    stirling: Vec<P::ScalarField>,
}

//TODO placeholder
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PkProof<P: Pairing> {
    proof: SigmaProof<P::G1>,
}

//TODO placeholder
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TagProof<P: Pairing> {
    proof: SigmaProof<P::G1>,
}
impl<P: Pairing> From<SigmaProof<P::G1>> for TagProof<P> {
    fn from(_value: SigmaProof<P::G1>) -> Self {
        TagProof { proof: _value }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKey<P: Pairing> {
    h: P::G1,
    com_t: Comm<P::G1>,
    proof_pk: PkProof<P>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey<P: Pairing> {
    elgamal_sk: ElgamalSk<P::G1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hint<P: Pairing> {
    ciphers: Vec<Cipher<P::G1>>,
    com_x: Comm<P::G1>,
    proof_c: CH20Proof<P>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Tag<P: Pairing> {
    proof: TagProof<P>,
    com: Comm<P::G1>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct XC<P: Pairing> {
    h: P::G1,
    comt_t: Comm<P::G1>,
    old_com_x: Comm<P::G1>,
    com_u: Comm<P::G1>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Escrow<P: Pairing> {
    /// (E1, E2)
    escrow_enc: Cipher<P::G1>,
    /// {A_i,D_i}
    blinded_ciphers: Vec<Cipher<P::G1>>,
    com_x: Comm<P::G1>,
    com_alpha: Comm<P::G1>,
    com_beta: Comm<P::G1>,
    proof_c: CH20Proof<P>,
    proof_e: SigmaProof<P::G1>,
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
        let stirling: Vec<P::ScalarField> = (0..d + 1)
            .map(|k| {
                let value: i64 = crate::utils::stirling_first_kind_rec(d, k);
                let sign = if value < 0 { -1 } else { 1 };
                let sign_f = if value < 0 {
                    -P::ScalarField::one()
                } else {
                    P::ScalarField::one()
                };
                P::ScalarField::from((value * sign) as u64) * sign_f
            })
            .collect();
        Ublu {
            lambda,
            d,
            g,
            w,
            elgamal: ElgamalParams { g },
            pedersen: PedersenParams { g, h: com_h },
            ch20crs: ch20,
            com_h,
            rng,
            stirling,
        }
    }

    pub fn key_gen(&mut self, t: u32) -> (PublicKey<P>, SecretKey<P>, Hint<P>) {
        let rng = &mut self.rng;
        let (sk, pk) = self.elgamal.key_gen(rng);
        let r_t = P::ScalarField::rand(rng);
        let mut r_vec = Vec::with_capacity(t as usize);
        let mut ciphers = Vec::with_capacity(t as usize);
        for i in 1..=self.d {
            let base = P::ScalarField::zero() - P::ScalarField::from(t);
            let cur_msg = field_pow(base, i);
            let cur_r = P::ScalarField::rand(rng);
            r_vec.push(cur_r);
            ciphers.push(self.elgamal.encrypt_raw(&pk, cur_msg, cur_r));
        }
        let com_t = self.pedersen.commit_raw(&P::ScalarField::from(t), &r_t);
        let com_x0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::from(0_u32));
        let com_u0 = self
            .pedersen
            .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::from(0_u32));

        let proof_pk = {
            let lang = key_lang(self.g, self.com_h);
            let inst = AlgInst(vec![pk.h, ciphers[0].b, com_t.com.value]); //B01
            let wit = AlgWit(vec![sk.sk, P::ScalarField::from(t), r_vec[0], r_t]);
            assert!(lang.contains(&inst, &wit));
            let proof = SigmaProof::prove(&lang, &inst, &wit);
            PkProof { proof }
        };

        let proof_c = {
            let x: P::ScalarField = From::from(0u64);
            let r_x: P::ScalarField = From::from(0u64);
            let alpha: P::ScalarField = From::from(0u64);
            let r_alpha: P::ScalarField = From::from(0u64);

            let hs: Vec<P::G1> = [self.com_h, pk.h]
                .into_iter()
                .chain(self.w.clone())
                .collect();

            let wit = consistency::consistency_form_wit(
                self.d,
                From::from(t),
                r_t,
                x,
                r_x,
                alpha,
                r_alpha,
                r_vec.clone(),
            );
            let inst = consistency::consistency_wit_to_inst(self.g, &hs, self.d, &wit);

            let lang_core = consistency::consistency_core_lang(self.g, &hs, self.d);

            let inst_core = consistency::consistency_inst_to_core(self.d, &inst);
            let wit_core = consistency::consistency_wit_to_core(&wit);

            CH20Proof::prove(&self.ch20crs, &lang_core, &inst_core, &wit_core)
        };

        (
            PublicKey {
                h: pk.h,
                com_t: com_t.com,
                proof_pk,
            },
            SecretKey { elgamal_sk: sk },
            Hint {
                ciphers,
                com_x: com_x0.com,
                proof_c,
            },
        )
    }

    pub fn update(
        &mut self,
        pk: &PublicKey<P>,
        hint: &Hint<P>,
        old_tag: &Option<Tag<P>>,
        x: usize,
        r_got: P::ScalarField,
    ) -> (Hint<P>, Tag<P>) {
        let r_x = P::ScalarField::rand(&mut self.rng);

        // @volhovm: we don't need to check any proofs in update according to our semantics
        // This proof is not supposed to pass w.r.t. hint_i, only w.r.t. hint_0.
        if old_tag.is_none() {
            let lang = key_lang(self.g, self.com_h);
            let inst = AlgInst(vec![pk.h, hint.ciphers[0].b, pk.com_t.value]);
            assert!(pk.proof_pk.proof.verify(&lang, &inst).is_ok());
        };

        let new_hint = self.update_hint(pk, hint, x, &r_x);
        // external commitment, gothic C
        let ext_com = self
            .pedersen
            .commit_raw(&P::ScalarField::from(x as u64), &r_got);
        // TODO do the proofs

        let proof_t = {
            // @Misha: how does this work when there is no initial tag or tag proof? i.e. in the first update case.
            //
            // volhovm:
            // - calX_0 is generated in KeyGen
            // - pi_{t,0} does not exist, however we can assume pi_{t,0} is some constant "dummy" value,
            //  e.g. SigmaProof { vec![], vec![] }. Remember that we "bind" the previous
            // trace proof by absorbing it into the Fiat Shamir hash, so it can be anything.
            let lang = trace_lang(self.g, self.com_h);

            assert_eq!(
                hint.com_x.value + self.g * P::ScalarField::from(x as u64) + self.com_h * r_x,
                new_hint.com_x.value
            );
            let inst = AlgInst(vec![
                new_hint.com_x.value - hint.com_x.value,
                ext_com.com.value,
                pk.h,
            ]);
            let wit = AlgWit(vec![P::ScalarField::from(x as u64), r_x, r_got]);
            assert!(lang.contains(&inst, &wit));

            match old_tag.is_none() {
                false => {
                    let prev_proof = &old_tag.to_owned().unwrap().proof.proof;
                    SigmaProof::sok(&lang, &inst, &wit, prev_proof)
                }
                true => {
                    let prev_proof = &pk.proof_pk.proof;
                    SigmaProof::sok(&lang, &inst, &wit, prev_proof)
                }
            }
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
        let x_field = P::ScalarField::from(x as u64);
        let mut new_com = self.pedersen.commit_raw(&x_field, r_x).com;
        new_com = new_com + old_hint.com_x.clone();
        // TODO can probably be optimized a bit by modifying cipherts in place
        let new_ciphers =
            self.update_powers2(old_hint.ciphers.clone(), r_i_list.clone(), x_field, pk.h);
        // let com_u = self
        //     .pedersen
        //     .commit_raw(&P::ScalarField::from(0_u32), &P::ScalarField::from(0_u32));
        // let _xc: XC<P> = XC {
        //     h: pk.h,
        //     comt_t: pk.com_t.clone(),
        //     old_com_x: old_hint.com_x.clone(),
        //     com_u: com_u.com,
        //     old_ciphers: old_hint.ciphers.clone(),
        // };
        // let _wc: WC<P> = WC {
        //     x,
        //     r_list: r_i_list.clone(),
        //     r_x: *r_x,
        //     alpha: P::ScalarField::zero(),
        //     r_alpha: P::ScalarField::zero(),
        // };

        let pi_c: CH20Proof<P> = {
            let hs: Vec<P::G1> = [self.com_h, pk.h]
                .into_iter()
                .chain(self.w.clone())
                .collect();

            let flat_old_ciphers: Vec<P::G1> = old_hint
                .ciphers
                .clone()
                .into_iter()
                .flat_map(|Cipher { a, b }| vec![a, b])
                .collect();

            let inst_core = AlgInst(
                vec![pk.com_t.value, old_hint.com_x.value]
                    .into_iter()
                    .chain(flat_old_ciphers)
                    .chain(vec![P::G1::zero(); self.d])
                    .collect(),
            );

            let lang_core = consistency::consistency_core_lang(self.g, &hs, self.d);
            let trans_core: CH20Trans<P::G1> = consistency::consistency_core_trans(
                self.g,
                &hs,
                self.d,
                From::from(x as u64),
                *r_x,
                r_i_list.clone(),
            );

            old_hint
                .proof_c
                .update(&self.ch20crs, &lang_core, &inst_core, &trans_core)
        };

        Hint {
            ciphers: new_ciphers,
            com_x: new_com,
            proof_c: pi_c,
        }
    }

    fn update_powers(
        &mut self,
        old_ciphers: Vec<Cipher<P::G1>>,
        r_i_list: Vec<P::ScalarField>,
        x: P::ScalarField,
        pk_h: P::G1,
    ) -> Vec<Cipher<P::G1>> {
        let v_coeff =
            |i: usize, j: usize| field_pow(x, i - j) * P::ScalarField::from(binomial(i, j) as u64);
        let mut new_ciphers: Vec<Cipher<P::G1>> = vec![];

        for i in 0..old_ciphers.len() {
            // TODO fails with negative subtraction because the j's should only iterate up to i, but goes all the way to d
            let a = old_ciphers
                .iter()
                .enumerate()
                .map(|(j, c_j)| c_j.a * v_coeff(i + 1, j + 1))
                .reduce(|x, y| x + y)
                .unwrap()
                + self.g * r_i_list[i];
            let b = old_ciphers
                .iter()
                .enumerate()
                .map(|(j, c_j)| c_j.b * v_coeff(i + 1, j + 1))
                .reduce(|x, y| x + y)
                .unwrap()
                + self.g * field_pow(x, i + 1)
                + pk_h * r_i_list[i];

            new_ciphers.push(Cipher { a, b });
        }

        new_ciphers
    }

    fn update_powers2(
        &self,
        old_ciphers: Vec<Cipher<P::G1>>,
        r_i_list: Vec<P::ScalarField>,
        x_field: P::ScalarField,
        pk_h: P::G1,
    ) -> Vec<Cipher<P::G1>> {
        let mut new_ciphers = Vec::with_capacity(self.d);
        for i in 1..=self.d {
            let mut cur_a_res = P::G1::zero();
            let mut cur_b_res = self.g * field_pow(x_field, i);
            for j in 1..=i {
                let cur_v_val = Self::v_func(x_field, i, j);
                cur_a_res += old_ciphers.get(j - 1).unwrap().a * cur_v_val;
                cur_b_res += old_ciphers.get(j - 1).unwrap().b * cur_v_val;
            }
            cur_a_res += self.g * r_i_list.get(i - 1).unwrap();
            cur_b_res += pk_h * r_i_list.get(i - 1).unwrap();
            new_ciphers.push(Cipher {
                a: cur_a_res,
                b: cur_b_res,
            });
        }
        new_ciphers
    }

    fn v_func(x: P::ScalarField, i: usize, j: usize) -> P::ScalarField {
        field_pow(x, i - j) * P::ScalarField::from(binomial(i, j) as u64)
    }

    fn randomize_ciphers(
        &self,
        old_ciphers: &[Cipher<P::G1>],
        r_i_list: &Vec<P::ScalarField>,
        pk_h: P::G1,
    ) -> Vec<Cipher<P::G1>> {
        let mut new_ciphers: Vec<_> = old_ciphers.to_vec();
        for i in 0..new_ciphers.len() {
            new_ciphers[i].a += self.g * r_i_list[i];
            new_ciphers[i].b += pk_h * r_i_list[i];
        }
        new_ciphers
    }

    fn blind_powers(
        &self,
        old_ciphers: &[Cipher<P::G1>],
        alpha: P::ScalarField,
    ) -> Vec<Cipher<P::G1>> {
        let mut new_ciphers: Vec<_> = old_ciphers.to_vec();
        for i in 0..new_ciphers.len() {
            new_ciphers[i].b += self.w[i] * alpha;
        }
        new_ciphers
    }

    pub fn escrow(&mut self, pk: &PublicKey<P>, hint: &Hint<P>) -> Escrow<P> {
        // TODO add rerandomizing of the hint
        let alpha = P::ScalarField::rand(&mut self.rng);
        let r_alpha = P::ScalarField::rand(&mut self.rng);
        let beta = P::ScalarField::rand(&mut self.rng);
        let r_beta = P::ScalarField::rand(&mut self.rng);

        let com_alpha = self.pedersen.commit_raw(&alpha, &r_alpha).com;
        let com_beta = self.pedersen.commit_raw(&beta, &r_beta).com;

        let r_i_list: Vec<_> = (0..self.d)
            .map(|_| P::ScalarField::rand(&mut self.rng))
            .collect();
        let rerand_ciphers = self.randomize_ciphers(&hint.ciphers, &r_i_list, pk.h);
        let blinded_ciphers = self.blind_powers(&rerand_ciphers, alpha);
        let escrow_enc = self.evaluate(&rerand_ciphers, beta);

        let proof_c: CH20Proof<P> = {
            let hs: Vec<P::G1> = [self.com_h, pk.h]
                .into_iter()
                .chain(self.w.clone())
                .collect();

            let flat_old_ciphers: Vec<P::G1> = hint
                .ciphers
                .clone()
                .into_iter()
                .flat_map(|Cipher { a, b }| vec![a, b])
                .collect();

            let inst_core = AlgInst(
                vec![pk.com_t.value, hint.com_x.value]
                    .into_iter()
                    .chain(flat_old_ciphers)
                    .chain(vec![P::G1::zero(); self.d])
                    .collect(),
            );
            let inst_gen = consistency::generalise_inst(self.d, inst_core);

            let proof_gen = consistency::generalise_proof(self.d, hint.proof_c.clone());
            let lang_full = consistency::consistency_lang(self.g, &hs, self.d);

            let trans_blind: CH20Trans<P::G1> =
                consistency::consistency_blind_trans(self.g, &hs, self.d, r_i_list, alpha, r_alpha);

            proof_gen.update(&self.ch20crs, &lang_full, &inst_gen, &trans_blind)
        };

        let proof_e = {
            let lang = escrow_lang(self.g, self.com_h);
            let betaalpha = beta * alpha;
            let r_betaalpha = r_beta * alpha;
            let wit = AlgWit(vec![alpha, r_alpha, beta, r_beta, betaalpha, r_betaalpha]);
            let mut prod_a = P::G1::zero();
            let mut prod_d = P::G1::zero();
            let mut prod_w = P::G1::zero();
            for i in 1..=self.d {
                prod_a += blinded_ciphers[i - 1].a * self.stirling[i - 1];
                prod_d += blinded_ciphers[i - 1].b * self.stirling[i - 1];
                prod_w += self.w[i - 1] * (-self.stirling[i - 1]);
            }
            assert_eq!(escrow_enc.a, prod_a * beta);
            assert_eq!(escrow_enc.b, prod_d * beta + prod_w * (beta * alpha));
            let inst = AlgInst(vec![
                com_alpha.value,
                com_beta.value,
                P::G1::zero(),
                escrow_enc.a,
                escrow_enc.b,
                prod_a,
                prod_d,
                prod_w,
            ]);
            assert!(lang.contains(&inst, &wit));
            SigmaProof::prove(&lang, &inst, &wit)
        };

        Escrow {
            escrow_enc,
            blinded_ciphers,
            com_x: hint.com_x.clone(),
            com_alpha,
            com_beta,
            proof_c,
            proof_e,
        }
    }

    pub fn decrypt(&self, sk: &SecretKey<P>, escrow: &Escrow<P>) -> bool {
        let e_1 = escrow.escrow_enc.a;
        let e_2 = escrow.escrow_enc.b;
        // Verify escrow proof
        let e_valid = {
            let lang = escrow_lang(self.g, self.com_h);
            let mut prod_a = P::G1::zero();
            let mut prod_d = P::G1::zero();
            let mut prod_w = P::G1::zero();
            for i in 1..=self.d {
                prod_a += escrow.blinded_ciphers[i - 1].a * self.stirling[i - 1];
                prod_d += escrow.blinded_ciphers[i - 1].b * self.stirling[i - 1];
                prod_w += self.w[i - 1] * (-self.stirling[i - 1]);
            }

            let inst = AlgInst(vec![
                escrow.com_alpha.value,
                escrow.com_beta.value,
                P::G1::zero(),
                escrow.escrow_enc.a,
                escrow.escrow_enc.b,
                prod_a,
                prod_d,
                prod_w,
            ]);
            escrow.proof_e.verify(&lang, &inst)
        };
        assert!(e_valid.is_ok());
        let rhs = e_1 * sk.elgamal_sk.sk;
        assert_ne!(rhs, P::G1::zero());
        assert_ne!(e_2, P::G1::zero());
        let m = e_2 - rhs;
        m == P::G1::zero()
    }

    pub fn verify_key_gen(&self, pk: &PublicKey<P>, hint0: &Hint<P>) -> bool {
        if hint0.com_x.value != P::G1::zero() {
            println!("Issue1");
            return false;
        };
        {
            let lang = key_lang(self.g, self.com_h);
            let inst = AlgInst(vec![pk.h, hint0.ciphers[0].b, pk.com_t.value]);
            if pk.proof_pk.proof.verify(&lang, &inst).is_err() {
                println!("Issue2");
                return false;
            }
        };
        {
            let hs: Vec<P::G1> = [self.com_h, pk.h]
                .into_iter()
                .chain(self.w.clone())
                .collect();

            let xcal = P::G1::zero();

            let ab_s: Vec<P::G1> = hint0
                .ciphers
                .clone()
                .into_iter()
                .flat_map(|Cipher { a, b }| vec![a, b])
                .collect();

            let inst_core = AlgInst(
                vec![pk.com_t.value, xcal]
                    .into_iter()
                    .chain(ab_s)
                    .chain(vec![P::G1::zero(); self.d])
                    .collect(),
            );

            let lang_core = consistency::consistency_core_lang(self.g, &hs, self.d);

            if hint0
                .proof_c
                .verify(&self.ch20crs, &lang_core, &inst_core)
                .is_err()
            {
                println!("Issue3");
                return false;
            }
        };

        true
    }

    pub fn verify_history(&self, pk: &PublicKey<P>, history: Vec<(Tag<P>, Comm<P::G1>)>) -> bool {
        let mut old_com_x = P::G1::zero();
        for (i, (tag_i, com_i)) in history.iter().enumerate() {
            let lang = trace_lang(self.g, self.com_h);
            let inst = AlgInst(vec![tag_i.com.value - old_com_x, com_i.value, pk.h]);
            let proof = &tag_i.proof.proof;

            if i == 0 {
                if proof.verify_sig(&lang, &inst, &pk.proof_pk.proof).is_err() {
                    println!("First proof failed");
                    return false;
                }
            } else if proof
                .verify_sig(&lang, &inst, &history[i - 1].0.proof.proof)
                .is_err()
            {
                println!("Proof #{i:?} failed");
                return false;
            }

            old_com_x = tag_i.com.value;
        }
        true
    }

    pub fn verify_hint(&self, pk: &PublicKey<P>, hint: &Hint<P>, tag: &Tag<P>) -> bool {
        let hs: Vec<P::G1> = [self.com_h, pk.h]
            .into_iter()
            .chain(self.w.clone())
            .collect();

        let acal = P::G1::zero();

        let ab_s: Vec<P::G1> = hint
            .ciphers
            .clone()
            .into_iter()
            .flat_map(|Cipher { a, b }| vec![a, b])
            .collect();

        let inst_core = AlgInst(
            vec![pk.com_t.value, tag.com.value]
                .into_iter()
                .chain(ab_s)
                .chain(vec![P::G1::zero(); self.d])
                .collect(),
        );

        let lang_core = consistency::consistency_core_lang(self.g, &hs, self.d);

        hint.proof_c
            .verify(&self.ch20crs, &lang_core, &inst_core)
            .is_ok()
    }

    pub fn verify_escrow(&self, pk: &PublicKey<P>, escrow: &Escrow<P>, tag: &Tag<P>) -> bool {
        if tag.com != escrow.com_x {
            return false;
        }

        {
            let hs: Vec<P::G1> = [self.com_h, pk.h]
                .into_iter()
                .chain(self.w.clone())
                .collect();

            let ab_s: Vec<P::G1> = escrow
                .blinded_ciphers
                .clone()
                .into_iter()
                .flat_map(|Cipher { a, b }| vec![a, b])
                .collect();

            let inst_full = AlgInst(
                vec![pk.com_t.value, tag.com.value, escrow.com_alpha.value]
                    .into_iter()
                    .chain(ab_s)
                    .chain(vec![P::G1::zero(); self.d + 1])
                    .collect(),
            );

            let lang_full = consistency::consistency_lang(self.g, &hs, self.d);

            if escrow
                .proof_c
                .verify(&self.ch20crs, &lang_full, &inst_full)
                .is_err()
            {
                println!("Consistency proof failed");
                return false;
            }
        }

        true
    }

    fn evaluate(&self, old_ciphers: &[Cipher<P::G1>], beta: P::ScalarField) -> Cipher<P::G1> {
        let mut e_1 = P::G1::zero();
        let mut e_2 = P::G1::zero();
        for i in 1..=self.d {
            e_1 += old_ciphers[i - 1].a * P::ScalarField::from(self.stirling[i - 1]);
            e_2 += old_ciphers[i - 1].b * P::ScalarField::from(self.stirling[i - 1]);
        }
        e_1 *= beta;
        e_2 *= beta;
        Cipher { a: e_1, b: e_2 }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{Tag, Ublu};
    use crate::{commitment::Comm, CC, CF, CG1};
    use aes_prng::AesRng;
    use ark_bls12_381::Bls12_381;
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn sunshine() {
        let mut rng = AesRng::seed_from_u64(1);
        let lambda = 40;
        let d = 10;
        let t = 3;
        let x_update: usize = 4;

        let mut ublu: Ublu<Bls12_381, AesRng> = Ublu::setup(lambda, d, rng.clone());
        let (pk, sk, mut hint_pre) = ublu.key_gen(t);
        let mut tag_pre = None;

        for i in 0..1 {
            let r_got = CF::rand(&mut rng);
            let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x_update, r_got);
            assert!(ublu.verify_hint(&pk, &hint_cur, &tag_cur));
            println!("Update step i={i:?}");
            let escrow = ublu.escrow(&pk, &hint_cur);
            assert!(ublu.verify_escrow(&pk, &escrow, &tag_cur));
            println!("Escrow decryption result: {:?}", ublu.decrypt(&sk, &escrow));
            hint_pre = hint_cur.clone();
            tag_pre = Some(tag_cur.clone());
        }

        panic!()
    }

    #[test]
    fn test_verify_key_gen() {
        let rng = AesRng::seed_from_u64(1);
        let lambda = 40;
        let d = 10;
        let t = 3;
        let x: usize = 5;

        let mut ublu: Ublu<Bls12_381, AesRng> = Ublu::setup(lambda, d, rng);
        let (pk, _sk, hint0) = ublu.key_gen(t);
        assert!(ublu.verify_key_gen(&pk, &hint0));
    }

    #[test]
    fn test_verify_hint() {
        let mut rng = AesRng::seed_from_u64(1);
        let lambda = 40;
        let d = 10;
        let t = 3;
        let x: usize = 2;
        let x_update: usize = 3;

        let mut ublu: Ublu<Bls12_381, AesRng> = Ublu::setup(lambda, d, rng.clone());
        let (pk, sk, hint_pre) = ublu.key_gen(t);
        let tag_pre = None;
        let r_got = CF::rand(&mut rng);
        let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);
        assert!(ublu.verify_hint(&pk, &hint_cur, &tag_cur));
    }

    #[test]
    fn test_verify_history() {
        let mut rng = AesRng::seed_from_u64(1);
        let lambda = 40;
        let d = 10;
        let t = 3;
        let x: usize = 2;
        let x_update: usize = 3;

        // Gothic rs for external commitments
        let mut r_got_vec: Vec<CF> = vec![];
        let mut hints: Vec<_> = vec![];
        let mut history: Vec<(Tag<CC>, Comm<CG1>)> = vec![];

        let mut ublu: Ublu<Bls12_381, AesRng> = Ublu::setup(lambda, d, rng.clone());
        let (pk, sk, hint0) = ublu.key_gen(t);
        hints.push(hint0);

        for i in 0..10 {
            let r_got = CF::rand(&mut rng);
            let prev_tag: &Option<Tag<CC>> = &history.last().map(|(tag, _)| tag.clone());
            let (hint, tag) = ublu.update(&pk, hints.last().unwrap(), prev_tag, x_update, r_got);
            let ext_com = ublu
                .pedersen
                .commit_raw(&CF::from(x_update as u64), &r_got)
                .com;

            r_got_vec.push(r_got);
            hints.push(hint);
            history.push((tag, ext_com));
        }

        assert!(ublu.verify_history(&pk, history));
    }

    #[test]
    fn test_verify_escrow() {
        let mut rng = AesRng::seed_from_u64(1);
        let lambda = 40;
        let d = 10;
        let t = 3;
        let x: usize = 2;
        let x_update: usize = 3;

        let mut ublu: Ublu<Bls12_381, AesRng> = Ublu::setup(lambda, d, rng.clone());
        let (pk, sk, hint_pre) = ublu.key_gen(t);
        let tag_pre = None;
        let r_got = CF::rand(&mut rng);
        let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);
        let escrow = ublu.escrow(&pk, &hint_cur);

        assert!(ublu.verify_escrow(&pk, &escrow, &tag_cur));
    }
}
