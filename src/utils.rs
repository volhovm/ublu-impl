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
}
