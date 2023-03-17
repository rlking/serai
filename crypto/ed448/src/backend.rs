use zeroize::Zeroize;

// Feature gated due to MSRV requirements
#[cfg(feature = "black_box")]
pub(crate) fn black_box<T>(val: T) -> T {
  core::hint::black_box(val)
}

#[cfg(not(feature = "black_box"))]
pub(crate) fn black_box<T>(val: T) -> T {
  val
}

pub(crate) fn u8_from_bool(bit_ref: &mut bool) -> u8 {
  let bit_ref = black_box(bit_ref);

  let mut bit = black_box(*bit_ref);
  let res = black_box(bit as u8);
  bit.zeroize();
  debug_assert!((res | 1) == 1);

  bit_ref.zeroize();
  res
}

#[doc(hidden)]
#[macro_export]
macro_rules! field {
  ($FieldName: ident, $MODULUS: ident, $WIDE_MODULUS: ident, $NUM_BITS: literal) => {
    use core::ops::{DerefMut, Add, AddAssign, Neg, Sub, SubAssign, Mul, MulAssign};

    use subtle::{Choice, CtOption, ConstantTimeEq, ConstantTimeLess, ConditionallySelectable};
    use rand_core::RngCore;

    use generic_array::{typenum::U57, GenericArray};
    use crypto_bigint::{Integer, NonZero, Encoding};

    use group::ff::{Field, PrimeField, FieldBits, PrimeFieldBits};

    // Needed to publish for some reason? Yet not actually needed
    #[allow(unused_imports)]
    use dalek_ff_group::{from_wrapper, math_op};
    use dalek_ff_group::{constant_time, from_uint, math};

    use $crate::backend::u8_from_bool;

    fn reduce(x: U1024) -> U512 {
      U512::from_le_slice(&x.rem(&NonZero::new($WIDE_MODULUS).unwrap()).to_le_bytes()[.. 64])
    }

    constant_time!($FieldName, U512);
    math!(
      $FieldName,
      $FieldName,
      |x, y| U512::add_mod(&x, &y, &$MODULUS.0),
      |x, y| U512::sub_mod(&x, &y, &$MODULUS.0),
      |x, y| reduce(U1024::from(U512::mul_wide(&x, &y)))
    );
    from_uint!($FieldName, U512);

    impl Neg for $FieldName {
      type Output = $FieldName;
      fn neg(self) -> $FieldName {
        Self(self.0.neg_mod(&$MODULUS.0))
      }
    }

    impl<'a> Neg for &'a $FieldName {
      type Output = $FieldName;
      fn neg(self) -> Self::Output {
        (*self).neg()
      }
    }

    impl $FieldName {
      pub fn pow(&self, other: $FieldName) -> $FieldName {
        let mut table = [Self(U512::ONE); 16];
        table[1] = *self;
        for i in 2 .. 16 {
          table[i] = table[i - 1] * self;
        }

        let mut res = Self(U512::ONE);
        let mut bits = 0;
        for (i, mut bit) in other.to_le_bits().iter_mut().rev().enumerate() {
          bits <<= 1;
          let mut bit = u8_from_bool(bit.deref_mut());
          bits |= bit;
          bit.zeroize();

          if ((i + 1) % 4) == 0 {
            if i != 3 {
              for _ in 0 .. 4 {
                res *= res;
              }
            }
            res *= table[usize::from(bits)];
            bits = 0;
          }
        }
        res
      }
    }

    impl Field for $FieldName {
      fn random(mut rng: impl RngCore) -> Self {
        let mut bytes = [0; 128];
        rng.fill_bytes(&mut bytes);
        $FieldName(reduce(U1024::from_le_slice(bytes.as_ref())))
      }

      fn zero() -> Self {
        Self(U512::ZERO)
      }
      fn one() -> Self {
        Self(U512::ONE)
      }
      fn square(&self) -> Self {
        *self * self
      }
      fn double(&self) -> Self {
        $FieldName((self.0 << 1).rem(&NonZero::new($MODULUS.0).unwrap()))
      }

      fn invert(&self) -> CtOption<Self> {
        const NEG_2: $FieldName = Self($MODULUS.0.saturating_sub(&U512::from_u8(2)));
        CtOption::new(self.pow(NEG_2), !self.is_zero())
      }

      fn sqrt(&self) -> CtOption<Self> {
        const MOD_1_4: $FieldName =
          Self($MODULUS.0.saturating_add(&U512::from_u8(1)).wrapping_div(&U512::from_u8(4)));
        let res = self.pow(MOD_1_4);
        CtOption::new(res, res.square().ct_eq(self))
      }
    }

    impl PrimeField for $FieldName {
      type Repr = GenericArray<u8, U57>;
      const NUM_BITS: u32 = $NUM_BITS;
      const CAPACITY: u32 = $NUM_BITS - 1;
      fn from_repr(bytes: Self::Repr) -> CtOption<Self> {
        let res = $FieldName(U512::from_le_slice(&[bytes.as_ref(), [0; 7].as_ref()].concat()));
        CtOption::new(res, res.0.ct_lt(&$MODULUS.0))
      }
      fn to_repr(&self) -> Self::Repr {
        let mut repr = GenericArray::<u8, U57>::default();
        repr.copy_from_slice(&self.0.to_le_bytes()[.. 57]);
        repr
      }

      // True for both the Ed448 Scalar field and FieldElement field
      const S: u32 = 1;
      fn is_odd(&self) -> Choice {
        self.0.is_odd()
      }
      fn multiplicative_generator() -> Self {
        unimplemented!()
      }
      fn root_of_unity() -> Self {
        unimplemented!()
      }
    }

    impl PrimeFieldBits for $FieldName {
      type ReprBits = [u8; 56];

      fn to_le_bits(&self) -> FieldBits<Self::ReprBits> {
        let mut repr = [0; 56];
        repr.copy_from_slice(&self.to_repr()[.. 56]);
        repr.into()
      }

      fn char_le_bits() -> FieldBits<Self::ReprBits> {
        MODULUS.to_le_bits()
      }
    }
  };
}
