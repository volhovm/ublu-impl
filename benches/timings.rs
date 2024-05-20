//#[macro_use]
extern crate criterion;

use ark_bls12_381::Bls12_381;
use ark_std::UniformRand;
use criterion::*;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use ublu_impl::ublu::Ublu;
use ublu_impl::CF;

static D_VALUES: [usize; 4] = [2, 4, 8, 20];
static T: u32 = 4;

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_generate");
    for d in D_VALUES {
        if d > 10 {
            group.sample_size(20);
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
    let mut group = c.benchmark_group("key_verify");
    group.sample_size(20);
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
    let mut group = c.benchmark_group("escrow_generate");
    group.sample_size(20);
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

fn bench_escrow_ver(c: &mut Criterion) {
    let mut group = c.benchmark_group("escrow_verify");
    group.sample_size(20);
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

criterion_group!(
    benches,
    bench_keygen,
    bench_keyver,
    bench_escrow,
    bench_escrow_ver
);
criterion_main!(benches);
