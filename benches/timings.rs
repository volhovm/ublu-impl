//#[macro_use]
extern crate criterion;

use std::fmt::{Display, Formatter};
use ark_bls12_381::Bls12_381;
use criterion::*;
use rand::rngs::ThreadRng;
use rand::thread_rng;
use ublu_impl::ublu::Ublu;

struct Benchparams {
    d: usize,
    t: u32
}
impl Display for Benchparams {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "d{}-t{}", self.d, self.t)
    }
}

fn bench_sign(c: &mut Criterion) {



    let mut group = c.benchmark_group("key_gen");
    for d in 2..3 {
        for t in [1,10].iter() {
            let bp = Benchparams{d, t: *t};
            group.bench_with_input(BenchmarkId::from_parameter(&bp), &bp, |b, bp| {
                b.iter_batched(|| {
                    let lambda = 40;
                    let rng = thread_rng();
                    let ublu: Ublu<Bls12_381, ThreadRng> = Ublu::setup(lambda, bp.d, rng);
                    ublu
                }, |mut ublu| ublu.key_gen(bp.t), BatchSize::SmallInput)
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_sign);
criterion_main!(benches);