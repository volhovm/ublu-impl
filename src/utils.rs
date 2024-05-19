use ark_ff::{PrimeField, Zero};

// Returns (n choose k) -- choosing k elements from n.
pub fn binomial(n: usize, k: usize) -> usize {
    if k == 0 {
        1
    } else {
        (n * binomial(n - 1, k - 1)) / k
    }
}

pub fn field_pow<F: PrimeField>(base: F, exp: usize) -> F {
    let mut res: F = F::one();
    let mut exp2 = exp;
    let mut bits: Vec<bool> = vec![];
    while !exp2.is_zero() {
        bits.push((exp2 & 0x1) == 0x1);
        exp2 >>= 1;
    }
    for b in bits.iter().rev() {
        res = res * res;
        if *b {
            res *= base;
        }
    }
    res
}

// TODO returns unsigned, should be signed.
// Fast dynamic programming implementation, does not work yet.
pub fn stirling_first_kind(n: usize, k: usize) -> u64 {
    let maxj: usize = n - k;

    let mut arr: Vec<u64> = vec![0; maxj + 1];

    for i in 0..maxj {
        arr[i] = 1;
    }

    for i in 2..k {
        for j in 1..maxj {
            arr[j] += (i as u64) * arr[j - 1];
        }
    }
    arr[maxj]
}

// Slow recursive PoC implementation
pub fn stirling_first_kind_rec(n: usize, k: usize) -> i64 {
    assert!(k <= n);

    // https://en.wikipedia.org/wiki/Stirling_numbers_of_the_first_kind#Recurrence_relation
    fn stirling_first_kind_rec_unsigned(n: usize, k: usize) -> u64 {
        if k == n {
            return 1;
        } else if k == 0 {
            return 0;
        }

        stirling_first_kind_rec_unsigned(n - 1, k - 1)
            + ((n - 1) as u64) * stirling_first_kind_rec_unsigned(n - 1, k)
    }

    let sign: i64 = if (n - k) % 2 == 0 { 1 } else { -1 };
    sign * (stirling_first_kind_rec_unsigned(n, k) as i64)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::CF;
    use ark_std::UniformRand;
    use rand::thread_rng;

    #[test]
    fn test_field_pow() {
        let mut rng = thread_rng();
        let x: CF = UniformRand::rand(&mut rng);
        assert!(field_pow(x, 1) == x);
        assert!(field_pow(x, 2) == x * x);
        assert!(field_pow(x, 3) == x * x * x);
        assert!(field_pow(x, 4) == x * x * x * x);
        assert!(field_pow(x, 5) == x * x * x * x * x);
    }

    #[test]
    fn test_binomial() {
        assert!(binomial(1, 1) == 1);
        assert!(binomial(2, 1) == 2);
        assert!(binomial(3, 1) == 3);
        assert!(binomial(3, 2) == 3);
        assert!(binomial(3, 3) == 1);
        assert!(binomial(9, 2) == 36);
        assert!(binomial(4, 3) == 4);
        assert!(binomial(5, 4) == 5);
        assert!(binomial(12, 5) == 792);
        println!("Binomial test passed")
    }

    #[test]
    fn test_stirling() {
        fn check_stirling(d: usize, x: i64) {
            let stirling: Vec<i64> = (0..d + 1).map(|k| stirling_first_kind_rec(d, k)).collect();

            //println!("Stirling numbers for d={d:?}: {stirling:?}");

            let eval1 = (0..d).map(|delta| x - (delta as i64)).reduce(|x, y| x * y);
            let eval2 = (0..d + 1).map(|i| stirling[i] * x).reduce(|x, y| x + y);

            assert!(eval1 == eval2, "Failed for d={d:?}, x={x:?}");
        }

        // Works
        check_stirling(1, 1);
        check_stirling(2, 1);
        check_stirling(3, 1);
        check_stirling(4, 1);
        check_stirling(5, 1);
        check_stirling(6, 1);
        check_stirling(7, 1);

        // Works
        check_stirling(1, 0);
        check_stirling(2, 1);
        check_stirling(3, 2);
        check_stirling(4, 3);
        check_stirling(5, 4);
        check_stirling(6, 5);
        check_stirling(7, 6);

        // Doesn't?
        //check_stirling(1, 0);
        //check_stirling(2, 1);
        //check_stirling(3, 2);
        //check_stirling(4, 3);
        //check_stirling(5, 4);
        //check_stirling(6, 5);
        //check_stirling(7, 6);
    }
}
