//#[macro_use]
extern crate criterion;

use aes_prng::AesRng;
use ark_bls12_381::Bls12_381;
use ark_std::UniformRand;
use criterion::*;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use ublu_impl::commitment::Comm;
use ublu_impl::ublu::{Tag, Ublu};
use ublu_impl::{CC, CF, CG1};

mod perf;

static D_VALUES: [usize; 6] = [2, 4, 8, 16, 32, 64];
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
                |(ublu, pk, hint0)| ublu.verify_key_gen(&pk, &hint0),
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
                |(mut ublu, pk, hint_cur, tag_cur)| ublu.verify_hint(&pk, &hint_cur, &tag_cur),
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
                    let (pk, sk, hint0) = ublu.key_gen(T);
                    hints.push(hint0);

                    for i in 0..*d {
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
                |(mut ublu, pk, history)| ublu.verify_history(&pk, history),
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
                    let (hint_cur, tag_cur) = ublu.update(&pk, &hint_pre, &tag_pre, x, r_got);

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

criterion_group! {
    name = benches;
    config = Criterion::default().with_profiler(perf::FlamegraphProfiler::new(100));
    targets = bench_vfhist,
    bench_setup,
    bench_keygen,
    bench_keyver,
    bench_update,
    bench_vfhint,
    bench_escrow,
    bench_escrow_ver,
    bench_decrypt,
}
criterion_main!(benches);
