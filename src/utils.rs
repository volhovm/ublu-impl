use ark_ec::Group;
use ark_ff::{One, PrimeField, Zero};

pub fn all_binomials<F: PrimeField>(d: usize) -> Vec<Vec<F>> {
    let mut binom: Vec<Vec<F>> = (0..d + 1)
        .map(|i| (0..i + 1).map(|j| F::zero()).collect())
        .collect();

    for n in 0..=d {
        for k in 0..=n {
            if k == 0 || k == n {
                binom[n][k] = F::one();
            } else {
                binom[n][k] = binom[n - 1][k - 1] + binom[n - 1][k];
            }
        }
    }
    binom
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

pub fn stirling_first_kind_dp<G: Group>(n: usize, k: usize) -> G::ScalarField {
    // Create a 2D array to store the values of Stirling numbers
    let mut dp = vec![vec![G::ScalarField::zero(); k + 1]; n + 1];

    // Initialize the base cases
    for i in 0..=n {
        dp[i][0] = if i == 0 {
            G::ScalarField::one()
        } else {
            G::ScalarField::zero()
        };
        if i <= k {
            dp[i][i] = G::ScalarField::one();
        }
    }

    // Fill the dp table using the recursive formula
    for i in 1..=n {
        for j in 1..=k {
            dp[i][j] = dp[i - 1][j - 1]
                + (G::ScalarField::from(i as u64) - G::ScalarField::one()) * dp[i - 1][j];
        }
    }

    if (n - k) % 2 == 0 {
        dp[n][k]
    } else {
        -dp[n][k]
    }
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
    use crate::{CF, CG1};
    use ark_ff::BigInt;
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
    fn test_playground() {
        let d = 12;
        let stirling: Vec<i64> = (0..d + 1).map(|k| stirling_first_kind_rec(d, k)).collect();
        println!("stirlings rec {:?}", stirling);
        let stirling2: Vec<CF> = (0..d + 1)
            .map(|k| stirling_first_kind_dp::<CG1>(d, k))
            .collect();
        println!("stirlings dp {:?}", stirling2);
    }

    #[test]
    fn test_stirling_dp() {
        fn check_stirling(d: usize, x: i64) {
            let stirling: Vec<CF> = (0..d + 1)
                .map(|k| stirling_first_kind_dp::<CG1>(d, k))
                .collect();

            println!("Stirling numbers for d={d:?}: {stirling:?}");

            let eval1 = (0..d)
                .map(|delta| CF::from(x - (delta as i64)))
                .reduce(|x, y| x * y);
            let eval2 = (0..d + 1)
                .map(|i| stirling[i] * CF::from(x.pow(i as u32)))
                .reduce(|x, y| x + y);

            assert!(eval1 == eval2, "Failed for d={d:?}, x={x:?}");
        }

        check_stirling(1, 1);
        check_stirling(2, 1);
        check_stirling(3, 1);
        check_stirling(4, 1);
        check_stirling(5, 1);
        check_stirling(6, 1);
        check_stirling(7, 1);

        check_stirling(1, 0);
        check_stirling(2, 1);
        check_stirling(3, 2);
        check_stirling(4, 3);
        check_stirling(5, 4);
        check_stirling(6, 5);
        check_stirling(7, 6);

        check_stirling(1, 1);
        check_stirling(2, 2);
        check_stirling(3, 3);
        check_stirling(4, 4);
        check_stirling(5, 5);
        check_stirling(6, 6);
        check_stirling(7, 7);

        check_stirling(1, 100);
        check_stirling(2, 101);
        check_stirling(3, 102);
        check_stirling(4, 103);
        check_stirling(5, 104);
        check_stirling(6, 105);
        check_stirling(7, 106);
    }

    #[test]
    fn test_binomial() {
        let allbin = all_binomials::<CF>(128);
        assert_eq!(allbin[1][1], CF::from(1u64));
        assert_eq!(allbin[2][1], CF::from(2u64));
        assert_eq!(allbin[3][1], CF::from(3u64));
        assert_eq!(allbin[3][2], CF::from(3u64));
        assert_eq!(allbin[3][3], CF::from(1u64));
        assert_eq!(allbin[9][2], CF::from(36u64));
        assert_eq!(allbin[4][3], CF::from(4u64));
        assert_eq!(allbin[5][4], CF::from(5u64));
        assert_eq!(allbin[12][5], CF::from(792u64));
        let res = BigInt([13075353597415539270, 1298394228608800905, 0, 0]);
        assert_eq!(allbin[128][64], res.into());
        println!("Binomial test passed")
    }

    #[test]
    fn test_stirling() {
        fn check_stirling(d: usize, x: i64) {
            let stirling: Vec<i64> = (0..d + 1).map(|k| stirling_first_kind_rec(d, k)).collect();

            //println!("Stirling numbers for d={d:?}: {stirling:?}");

            let eval1 = (0..d).map(|delta| x - (delta as i64)).reduce(|x, y| x * y);
            let eval2 = (0..d + 1)
                .map(|i| stirling[i] * x.pow(i as u32))
                .reduce(|x, y| x + y);

            assert!(eval1 == eval2, "Failed for d={d:?}, x={x:?}");
        }

        check_stirling(1, 1);
        check_stirling(2, 1);
        check_stirling(3, 1);
        check_stirling(4, 1);
        check_stirling(5, 1);
        check_stirling(6, 1);
        check_stirling(7, 1);

        check_stirling(1, 0);
        check_stirling(2, 1);
        check_stirling(3, 2);
        check_stirling(4, 3);
        check_stirling(5, 4);
        check_stirling(6, 5);
        check_stirling(7, 6);

        check_stirling(1, 1);
        check_stirling(2, 2);
        check_stirling(3, 3);
        check_stirling(4, 4);
        check_stirling(5, 5);
        check_stirling(6, 6);
        check_stirling(7, 7);

        check_stirling(1, 100);
        check_stirling(2, 101);
        check_stirling(3, 102);
        check_stirling(4, 103);
        check_stirling(5, 104);
        check_stirling(6, 105);
        check_stirling(7, 106);
    }
}
