//#[macro_use]
extern crate criterion;

use rayon::prelude::*;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, Group, VariableBaseMSM};
use ark_ff::Zero;
use ark_std::iterable::Iterable;
use ark_std::UniformRand;
use criterion::*;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use ublu_impl::ch20::{
    mul_mat_by_vec_g_f, AlgInst, AlgLang, AlgWit, CH20VerifierError, LinearPoly,
};
use ublu_impl::commitment::Comm;
use ublu_impl::elgamal::Cipher;
use ublu_impl::ublu::{Tag, Ublu};
use ublu_impl::{CC, CF, CG1};

mod perf;

static D_VALUES: [usize; 1] = [32]; // [2, 4, 8, 16, 32, 64];
static T: u32 = 4;

fn bench_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("Setup");
    for d in D_VALUES {
        if d > 10 {
            group.sample_size(10);
        }
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let rng = thread_rng();
                    (lambda, rng)
                },
                |(lambda, rng)| Ublu::<Bls12_381, ThreadRng>::setup(lambda, *d, rng),
                BatchSize::LargeInput,
            )
        });
    }
    group.finish();
}

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");
    for d in D_VALUES {
        if d > 10 {
            group.sample_size(10);
        }
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let rng = thread_rng();
                    let ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng);
                    ublu
                },
                |mut ublu| ublu.key_gen(T),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_keyver(c: &mut Criterion) {
    let mut group = c.benchmark_group("VfKeyGen");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng);
                    let (pk, _sk, hint0) = ublu.key_gen(T);

                    (ublu, pk, hint0)
                },
                |(ublu, pk, hint0)| {
                    if hint0.com_x.value != CG1::zero() {
                        println!("Issue1");
                        return false;
                    };
                    {
                        let inst = AlgInst::new(
                            &ublu.pk_lang,
                            vec![pk.h, hint0.ciphers[0].b, pk.com_t.value],
                        );
                        if pk.proof_pk.proof.verify(&inst).is_err() {
                            println!("Issue2");
                            return false;
                        }
                    };
                    {
                        let xcal = CG1::zero();

                        let ab_s: Vec<CG1> = hint0
                            .ciphers
                            .clone()
                            .into_iter()
                            .flat_map(|Cipher { a, b }| vec![a, b])
                            .collect();

                        let inst_core = AlgInst::new(
                            &pk.consistency_core_lang,
                            vec![pk.com_t.value, xcal]
                                .into_iter()
                                .chain(ab_s)
                                .chain(vec![CG1::zero(); ublu.d])
                                .collect(),
                        );

                        let proofres = {
                            let lang = pk.consistency_core_lang;
                            let inst = inst_core;
                            let mut rng = thread_rng();
                            let mut lhs: Vec<CG1> = vec![CG1::zero(); lang.wit_size() + 2];
                            let mut rhs: Vec<<Bls12_381 as Pairing>::G2> = hint0.proof_c.d.clone();
                            rhs.push(-ublu.ch20crs.e);
                            rhs.push(-<Bls12_381 as Pairing>::G2::generator());

                            for i in 0..lang.inst_size() {
                                let alpha = CF::rand(&mut rng);
                                for j in 0..lang.wit_size() {
                                    lhs[j] += inst.matrix[i][j] * alpha;
                                }
                                lhs[lang.wit_size()] += inst.instance[i] * alpha;
                                lhs[lang.wit_size() + 1] += hint0.proof_c.a[i] * alpha;
                            }
                            let pairing_res = <Bls12_381 as Pairing>::multi_pairing(lhs, rhs);
                            if pairing_res != Zero::zero() {
                                panic!("combined")
                            }
                            // TODO: for efficiency, recombine equations first with a random
                            // element, this saves up quite some pairings
                            /*for (l, r) in lhs.iter().zip(rhs.iter()) {
                                let pairing_res = <Bls12_381 as Pairing>::multi_pairing(l, r);
                                if pairing_res != Zero::zero() {
                                    panic!();
                                }
                                break;
                            }*/
                            /*let mut rng = thread_rng();
                            let mut lhsc = lhs[0].clone();
                            for i in 1..lang.inst_size() {
                                let alpha = CF::rand(&mut rng);
                                for j in 0..lhs[i].len() {
                                    lhsc[j] += lhs[i][j]*alpha
                                }
                            }
                            let pairing_res = <Bls12_381 as Pairing>::multi_pairing(lhsc, &rhs[0]);
                            if pairing_res != Zero::zero() {
                                panic!("combined")
                            }*/
                            /*let mut rng = thread_rng();
                            let vercoeffs: Vec<CF> = lhs.iter().flatten().map(|_| CF::rand(&mut rng)).collect();
                            let lhsc: CG1 = lhs.iter().flatten().zip(&vercoeffs).map(|(l, vc)| *l*vc).sum();
                            let rhsc: <Bls12_381 as Pairing>::G2 = rhs.iter().flatten().zip(&vercoeffs).map(|(r, vc)| *r*vc).sum();
                            //let pairing_res = <Bls12_381 as Pairing>::pairing(lhsc, rhsc);
                            //if pairing_res != Zero::zero() {
                            //    panic!("combined")
                            //}
                            for (l, r) in lhs.iter().zip(rhs.iter()) {
                                let vercoeffs: Vec<CF> = l.iter().map(|_| CF::rand(&mut rng)).collect();
                                let lc: CG1 = l.iter().zip(&vercoeffs).map(|(l, vc)| *l*vc).sum();
                                let rc: <Bls12_381 as Pairing>::G2 = r.iter().zip(&vercoeffs).map(|(r, vc)| *r*vc).sum();
                                let pres = <Bls12_381 as Pairing>::pairing(lc, rc);
                                if pres != Zero::zero() {
                                    panic!("innercombined")
                                }
                                let pairing_res = <Bls12_381 as Pairing>::multi_pairing(l, r);
                                if pairing_res != Zero::zero() {
                                    panic!()
                                }
                            }*/
                            /*let lhs_flatten: Vec<CG1> = lhs.into_iter().flatten().collect();
                            let rhs_flatten: Vec<<Bls12_381 as Pairing>::G2> = rhs.into_iter().flatten().collect();
                            let pairing_res = <Bls12_381 as Pairing>::multi_pairing(lhs_flatten, rhs_flatten);
                            if pairing_res != Zero::zero() {
                                panic!()
                            }*/
                            false
                        };
                        if proofres {
                            println!("Issue3");
                            return false;
                        }
                    };

                    true
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_escrow(c: &mut Criterion) {
    let mut group = c.benchmark_group("Escrow");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let mut rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng.clone());
                    let (pk, _sk, hint_pre) = ublu.key_gen(T);
                    let x: usize = 2;
                    let tag_pre = None;
                    let r_got = CF::rand(&mut rng);
                    let (hint_cur, _tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);

                    (ublu, pk, hint_cur)
                },
                |(mut ublu, pk, hint_cur)| ublu.escrow(&pk, &hint_cur),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_update(c: &mut Criterion) {
    let mut group = c.benchmark_group("Update");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let mut rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng.clone());
                    let (pk, _sk, hint_pre) = ublu.key_gen(T);
                    let x: usize = 2;
                    let tag_pre = None;
                    let r_got = CF::rand(&mut rng);

                    (ublu, pk, hint_pre, tag_pre, x, r_got)
                },
                |(mut ublu, pk, hint_pre, tag_pre, x, r_got)| {
                    ublu.update(&pk, &hint_pre, &tag_pre, x, r_got)
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_vfhint(c: &mut Criterion) {
    let mut group = c.benchmark_group("VfHint");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let mut rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng.clone());

                    let (pk, _sk, hint_pre) = ublu.key_gen(T);
                    let x: usize = 2;
                    let tag_pre = None;
                    let r_got = CF::rand(&mut rng);

                    let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);

                    (ublu, pk, hint_cur, tag_cur)
                },
                |(ublu, pk, hint_cur, tag_cur)| ublu.verify_hint(&pk, &hint_cur, &tag_cur),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_vfhist(c: &mut Criterion) {
    let mut group = c.benchmark_group("VfHistory");
    group.sample_size(10);
    for d in D_VALUES {
        if d > 10 {
            group.sample_size(10);
        }
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let x_update: usize = 3;
                    let mut rng = thread_rng();

                    // Gothic rs for external commitments
                    let mut r_got_vec: Vec<CF> = vec![];
                    let mut hints: Vec<_> = vec![];
                    let mut history: Vec<(Tag<CC>, Comm<CG1>)> = vec![];

                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, 4, rng.clone());
                    let (pk, _sk, hint0) = ublu.key_gen(T);
                    hints.push(hint0);

                    for _ in 0..*d {
                        let r_got = CF::rand(&mut rng);
                        let prev_tag: &Option<Tag<CC>> =
                            &history.last().map(|(tag, _)| tag.clone());
                        let (hint, tag) =
                            ublu.update(&pk, hints.last().unwrap(), prev_tag, x_update, r_got);
                        let ext_com = ublu
                            .pedersen
                            .commit_raw(&CF::from(x_update as u64), &r_got)
                            .com;

                        r_got_vec.push(r_got);
                        hints.push(hint);
                        history.push((tag, ext_com));
                    }

                    (ublu, pk, history)
                },
                |(ublu, pk, history)| ublu.verify_history(&pk, history),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_escrow_ver(c: &mut Criterion) {
    let mut group = c.benchmark_group("VfEscrow");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let mut rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng.clone());
                    let (pk, _sk, hint_pre) = ublu.key_gen(T);
                    let x: usize = 2;
                    let tag_pre = None;
                    let r_got = CF::rand(&mut rng);
                    let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);

                    let escrow = ublu.escrow(&pk, &hint_cur);

                    (ublu, pk, escrow, tag_cur)
                },
                |(ublu, pk, escrow, tag_cur)| ublu.verify_escrow(&pk, &escrow, &tag_cur),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

fn bench_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("Decrypt");
    group.sample_size(10);
    for d in D_VALUES {
        group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, d| {
            b.iter_batched(
                || {
                    let lambda = 40;
                    let mut rng = thread_rng();
                    let mut ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, *d, rng.clone());
                    let (pk, sk, hint_pre) = ublu.key_gen(T);
                    let x: usize = 2;
                    let tag_pre = None;
                    let r_got = CF::rand(&mut rng);
                    let (hint_cur, _tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);

                    let escrow = ublu.escrow(&pk, &hint_cur);

                    (ublu, sk, escrow)
                },
                |(ublu, sk, escrow)| ublu.decrypt(&sk, &escrow),
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

pub fn msm_mat_by_vec_g_f<G: Group + VariableBaseMSM + CurveGroup>(
    mat: &[Vec<G>],
    vec: &[G::ScalarField],
) -> Vec<G> {
    let res = mat
        .iter()
        .map(|row| {
            let row_aff: Vec<G::Affine> = row.iter().map(|p| p.into_affine()).collect();
            let el = G::msm(&row_aff, &vec).unwrap();
            el
        })
        .collect();
    res
}

pub fn par_mat_by_vec_g_f<G: Group>(mat: &[Vec<G>], vec: &[G::ScalarField]) -> Vec<G> {
    let res: Vec<G> = mat
        .par_iter()
        .map(|row| {
            let el: G = row.iter().zip(vec).map(|(m, v)| *m * v).sum();
            el
        })
        .collect();
    res
}

fn bench_matrixmul(c: &mut Criterion) {
    let mut group = c.benchmark_group("Matrixmul");
    let d = 1;
    group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, _d| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();

                let g: CG1 = UniformRand::rand(&mut rng);
                let x: CF = UniformRand::rand(&mut rng);
                let y: CF = UniformRand::rand(&mut rng);
                let gx: CG1 = g * x;
                let gy: CG1 = g * y;
                let gz: CG1 = g * (x * y);

                // g 0
                // 0 g
                // 0 x1
                let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
                    vec![LinearPoly::constant(4, g), LinearPoly::zero(4)],
                    vec![LinearPoly::zero(4), LinearPoly::constant(4, g)],
                    vec![LinearPoly::zero(4), LinearPoly::single(4, 0)],
                ];

                let lang: AlgLang<CG1> = AlgLang { matrix };
                let inst: AlgInst<CG1> = AlgInst::new(&lang, vec![gx, gy, gz]);
                let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

                (inst, wit)
            },
            |(inst, wit)| mul_mat_by_vec_g_f(&inst.matrix, &wit.0),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_matrixmsm(c: &mut Criterion) {
    let mut group = c.benchmark_group("Matrixmsm");
    let d = 1;
    group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, _d| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();

                let g: CG1 = UniformRand::rand(&mut rng);
                let x: CF = UniformRand::rand(&mut rng);
                let y: CF = UniformRand::rand(&mut rng);
                let gx: CG1 = g * x;
                let gy: CG1 = g * y;
                let gz: CG1 = g * (x * y);

                // g 0
                // 0 g
                // 0 x1
                let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
                    vec![LinearPoly::constant(4, g), LinearPoly::zero(4)],
                    vec![LinearPoly::zero(4), LinearPoly::constant(4, g)],
                    vec![LinearPoly::zero(4), LinearPoly::single(4, 0)],
                ];

                let lang: AlgLang<CG1> = AlgLang { matrix };
                let inst: AlgInst<CG1> = AlgInst::new(&lang, vec![gx, gy, gz]);
                let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

                (inst, wit)
            },
            |(inst, wit)| msm_mat_by_vec_g_f(&inst.matrix, &wit.0),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn bench_matrixpar(c: &mut Criterion) {
    let mut group = c.benchmark_group("Matrixpar");
    let d = 1;
    group.bench_with_input(BenchmarkId::from_parameter(&d), &d, |b, _d| {
        b.iter_batched(
            || {
                let mut rng = thread_rng();

                let g: CG1 = UniformRand::rand(&mut rng);
                let x: CF = UniformRand::rand(&mut rng);
                let y: CF = UniformRand::rand(&mut rng);
                let gx: CG1 = g * x;
                let gy: CG1 = g * y;
                let gz: CG1 = g * (x * y);

                // g 0
                // 0 g
                // 0 x1
                let matrix: Vec<Vec<LinearPoly<CG1>>> = vec![
                    vec![LinearPoly::constant(4, g), LinearPoly::zero(4)],
                    vec![LinearPoly::zero(4), LinearPoly::constant(4, g)],
                    vec![LinearPoly::zero(4), LinearPoly::single(4, 0)],
                ];

                let lang: AlgLang<CG1> = AlgLang { matrix };
                let inst: AlgInst<CG1> = AlgInst::new(&lang, vec![gx, gy, gz]);
                let wit: AlgWit<CG1> = AlgWit(vec![x, y]);

                (inst, wit)
            },
            |(inst, wit)| par_mat_by_vec_g_f(&inst.matrix, &wit.0),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(perf::FlamegraphProfiler::new(100));
    targets = /*bench_vfhist,
    bench_setup,
    bench_keygen,*/
    bench_keyver,
    /*bench_update,
    bench_vfhint,
    bench_escrow,
    bench_escrow_ver,
    bench_decrypt,*/
    //bench_matrixmul,
    //bench_matrixpar
}
criterion_main!(benches);
