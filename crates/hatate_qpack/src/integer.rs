//! Prefixed integers (RFC 9204 §4.1.1 and RFC 7541 §5.1).
//!
//! A [`PrefixedField`] keeps the value together with the number of zero
//! 7-bit groups its encoding carries beyond the shortest one, so that a field
//! read with [`read()`] writes back with [`write()`] to the octets it was read from.

use crate::InsufficientCapacityError;
use bytes::{Buf, BufMut};
use core::fmt;
use snafu::Snafu;

/// A value a QPACK prefixed integer can carry: at present every `u64`, more
/// than the 62 bits RFC 9204 §4.1.1 requires. Supporting another range only
/// changes this type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PrefixedInt(u64);

impl PrefixedInt {
    /// The value zero.
    pub const ZERO: Self = Self(0);

    /// The largest supported value.
    pub const MAX: Self = Self(u64::MAX);

    /// The value as a `u64`.
    pub const fn get(self) -> u64 {
        self.0
    }
}

impl fmt::Display for PrefixedInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl From<u8> for PrefixedInt {
    fn from(value: u8) -> Self {
        Self(value.into())
    }
}

impl From<u16> for PrefixedInt {
    fn from(value: u16) -> Self {
        Self(value.into())
    }
}

impl From<u32> for PrefixedInt {
    fn from(value: u32) -> Self {
        Self(value.into())
    }
}

impl From<u64> for PrefixedInt {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<PrefixedInt> for u64 {
    fn from(value: PrefixedInt) -> Self {
        value.0
    }
}

/// A prefixed integer field: the value `T` and the number of continuation
/// octets its encoding uses beyond the shortest one.
///
/// A longer encoding can only append 7-bit groups of value zero after the
/// shortest one: a value below 2<sup>N</sup> − 1 fits in the prefix and has no
/// continuation octets, and a larger value's groups run from least to most
/// significant. The value and `padding` therefore determine the octets for
/// a given prefix width `N`. A value below 2<sup>N</sup> − 1 takes no padding at
/// that width.
///
/// `T` is [`PrefixedInt`] or a domain type such as
/// [`static_table::Index`](crate::static_table::Index). Its conversions must
/// agree: `T::try_from(PrefixedInt::from(x))` is `Ok(x)`. Equality covers
/// both the value and the padding.
///
/// ```
/// use hatate_qpack::integer::{PrefixedField, PrefixedInt};
///
/// let shortest = PrefixedField::shortest(PrefixedInt::from(31u8));
/// assert_eq!(shortest.encoded_len::<5>(), 2);
/// let padded = PrefixedField::new::<5>(PrefixedInt::from(31u8), 2)?;
/// assert_eq!(padded.encoded_len::<5>(), 4);
/// assert_ne!(padded, shortest);
/// // 30 fits in a five-bit prefix, which leaves nothing to pad.
/// assert!(PrefixedField::new::<5>(PrefixedInt::from(30u8), 1).is_err());
/// # Ok::<(), hatate_qpack::integer::PaddingError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PrefixedField<T = PrefixedInt> {
    value: T,
    padding: u8,
}

impl<T: Copy + Into<PrefixedInt>> PrefixedField<T> {
    /// The field holding `value` in its shortest encoding.
    pub const fn shortest(value: T) -> Self {
        Self { value, padding: 0 }
    }

    /// The field holding `value` with `padding` additional zero groups in a
    /// prefix of `N` bits (`1..=8`, checked at compile time).
    ///
    /// # Errors
    ///
    /// [`PaddingError`] if `padding` is nonzero while the value fits in the
    /// prefix, or if the encoding would exceed eleven octets, the longest
    /// encoding [`read()`] accepts.
    pub fn new<const N: u8>(value: T, padding: u8) -> Result<Self, PaddingError> {
        let field = Self { value, padding };
        field.check::<N>()?;
        Ok(field)
    }

    /// The value.
    pub const fn value(&self) -> T {
        self.value
    }

    /// The continuation octets beyond the shortest encoding.
    pub const fn padding(&self) -> u8 {
        self.padding
    }

    /// The octets of the encoding in a prefix of `N` bits, including the
    /// first octet that it shares with the enclosing format. Exact for a
    /// field that is valid at `N`, as one constructed or read at `N` is.
    pub fn encoded_len<const N: u8>(&self) -> usize {
        1 + usize::from(shortest_continuations::<N>(self.value.into().0))
            + usize::from(self.padding)
    }

    /// Whether this field has an encoding in a prefix of `N` bits. A field
    /// moved to a format with a different prefix width can lose it.
    pub(crate) fn check<const N: u8>(&self) -> Result<(), PaddingError> {
        let value = self.value.into();
        let continuations = shortest_continuations::<N>(value.0);
        if self.padding == 0
            || (continuations > 0
                && u16::from(continuations) + u16::from(self.padding)
                    <= u16::from(MAX_CONTINUATIONS))
        {
            Ok(())
        } else {
            Err(PaddingError {
                value,
                padding: self.padding,
                prefix_bits: N,
            })
        }
    }
}

impl<T> PrefixedField<T> {
    /// Convert the value, keeping the padding. `U` represents the same
    /// prefixed integer, so the encoding stays the same.
    pub(crate) fn try_map<U, E>(
        self,
        convert: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<PrefixedField<U>, E> {
        Ok(PrefixedField {
            value: convert(self.value)?,
            padding: self.padding,
        })
    }
}

/// A padding that a prefixed integer cannot carry at its prefix width.
///
/// Either the value fits in the prefix, leaving no continuation octet to
/// pad, or the encoding would exceed eleven octets.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Snafu)]
#[snafu(display(
    "prefixed integer {value} cannot take {padding} padding octets with a {prefix_bits}-bit prefix"
))]
pub struct PaddingError {
    value: PrefixedInt,
    padding: u8,
    prefix_bits: u8,
}

impl PaddingError {
    /// The value of the rejected field.
    pub const fn value(&self) -> PrefixedInt {
        self.value
    }

    /// The rejected padding, never zero.
    pub const fn padding(&self) -> u8 {
        self.padding
    }

    /// The prefix width in bits.
    pub const fn prefix_bits(&self) -> u8 {
        self.prefix_bits
    }
}

/// Failure to read a QPACK prefixed integer after its first octet.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum ReadError {
    /// The encoding ends before its terminating octet.
    #[snafu(display("missing continuation octet of prefixed integer"))]
    Incomplete,
    /// The numeric value exceeds u64::MAX.
    #[snafu(display("prefixed integer exceeds 64 bits"))]
    Overflow,
    /// The encoding needs more than ten continuation octets.
    #[snafu(display("prefixed integer exceeds ten continuation octets"))]
    TooLong,
}

/// A prefixed integer could not be written.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum WriteError {
    /// The encoding does not fit in the destination.
    #[snafu(transparent)]
    InsufficientCapacity {
        /// Exact required and available capacities in octets.
        source: InsufficientCapacityError,
    },
    /// The field's padding has no encoding at this prefix width.
    #[snafu(transparent)]
    Padding {
        /// The field and the prefix width.
        source: PaddingError,
    },
}

const fn prefix_mask<const N: u8>() -> u8 {
    const { assert!(N >= 1 && N <= 8) };
    u8::MAX >> (8 - N)
}

/// Continuation octets of the shortest encoding: none below the prefix
/// maximum, and at least one at or above it.
fn shortest_continuations<const N: u8>(value: u64) -> u8 {
    let mask = u64::from(prefix_mask::<N>());
    if value < mask {
        return 0;
    }
    let rest = value - mask;
    (u64::BITS - rest.leading_zeros()).max(1).div_ceil(7) as u8
}

/// Read a prefixed integer given the already-consumed first octet. Its low
/// `N` bits belong to the integer (`1..=8`, checked at compile time).
/// The implementation accepts values through `u64::MAX` and at most ten
/// continuation octets in addition to `first`. Non-minimal encodings within
/// both limits are accepted, and the field keeps their padding. A digit that
/// would exceed the numeric range is [`ReadError::Overflow`]. If the tenth
/// continuation octet still requests a further octet, the encoding is
/// [`ReadError::TooLong`] unless that digit already overflowed the value.
/// Only continuation octets are consumed from `src`, including on error; an
/// eleventh continuation octet is never read.
pub fn read<const N: u8>(first: u8, src: &mut impl Buf) -> Result<PrefixedField, ReadError> {
    use core::ops::ControlFlow;
    let mut continuation = match Continuation::start::<N>(first) {
        ControlFlow::Break(value) => return Ok(PrefixedField::shortest(PrefixedInt(value))),
        ControlFlow::Continue(state) => state,
    };
    loop {
        let byte = src.try_get_u8().map_err(|_| ReadError::Incomplete)?;
        if let Some(value) = continuation.push(byte)? {
            return Ok(continuation.field::<N>(value));
        }
    }
}

/// The digits of one prefixed integer, shared with instruction streams where
/// a read may suspend between any two octets.
pub(crate) struct Continuation {
    value: u64,
    shift: u32,
}

impl Continuation {
    pub(crate) fn start<const N: u8>(first: u8) -> core::ops::ControlFlow<u64, Self> {
        use core::ops::ControlFlow;
        let mask = prefix_mask::<N>();
        let value = u64::from(first & mask);
        if value < u64::from(mask) {
            ControlFlow::Break(value)
        } else {
            ControlFlow::Continue(Self { value, shift: 0 })
        }
    }

    /// Least value the unfinished integer can have (all further digits zero).
    pub(crate) fn minimum(&self) -> u64 {
        self.value
    }

    /// Stop feeding octets at either a result or an error.
    pub(crate) fn push(&mut self, byte: u8) -> Result<Option<u64>, ReadError> {
        let digit = u64::from(byte & 0x7f);
        if digit > (u64::MAX - self.value) >> self.shift {
            return Err(ReadError::Overflow);
        }
        self.value += digit << self.shift;
        if byte & 0x80 == 0 {
            return Ok(Some(self.value));
        }
        if self.shift == 63 {
            return Err(ReadError::TooLong);
        }
        self.shift += 7;
        Ok(None)
    }

    /// The field after [`Self::push`] returned `value`, with the padding of
    /// the octets consumed.
    pub(crate) fn field<const N: u8>(&self, value: u64) -> PrefixedField {
        let continuations = (self.shift / 7 + 1) as u8;
        PrefixedField {
            value: PrefixedInt(value),
            padding: continuations - shortest_continuations::<N>(value),
        }
    }
}

/// One prefix octet and at most ten base-128 digits.
pub(crate) const MAX_ENCODED_LEN: usize = 11;
const MAX_CONTINUATIONS: u8 = MAX_ENCODED_LEN as u8 - 1;

/// The octets of one prefixed integer, the first one carrying the flags of
/// the enclosing format.
#[derive(Clone, Copy)]
pub(crate) struct Encoded {
    bytes: [u8; MAX_ENCODED_LEN],
    len: u8,
}

impl Encoded {
    pub(crate) const EMPTY: Self = Self {
        bytes: [0; MAX_ENCODED_LEN],
        len: 0,
    };

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

/// Encode `field`, keeping the high `8 - N` bits of `first` and replacing its
/// low `N` bits.
pub(crate) fn encode<const N: u8, T: Copy + Into<PrefixedInt>>(
    first: u8,
    field: PrefixedField<T>,
) -> Result<Encoded, PaddingError> {
    field.check::<N>()?;
    let mask = prefix_mask::<N>();
    let flags = first & !mask;
    let value = field.value.into().0;
    let mut encoded = Encoded::EMPTY;
    if value < u64::from(mask) {
        encoded.bytes[0] = flags | value as u8;
        encoded.len = 1;
        return Ok(encoded);
    }
    encoded.bytes[0] = flags | mask;
    let mut remaining = value - u64::from(mask);
    let digits = shortest_continuations::<N>(value) + field.padding;
    for at in 1..=digits {
        let more = if at < digits { 0x80 } else { 0 };
        encoded.bytes[usize::from(at)] = (remaining as u8 & 0x7f) | more;
        remaining >>= 7;
    }
    encoded.len = 1 + digits;
    Ok(encoded)
}

/// Write `field` in a prefix of `N` bits (`1..=8`, checked at compile time),
/// keeping the high `8 - N` bits of `first`. The encoding carries the field's
/// padding. If the field has no encoding at `N` or the complete integer
/// cannot fit, leave `dst` unchanged.
pub fn write<const N: u8, T: Copy + Into<PrefixedInt>>(
    dst: &mut impl BufMut,
    first: u8,
    field: PrefixedField<T>,
) -> Result<(), WriteError> {
    let encoded = encode::<N, T>(first, field)?;
    InsufficientCapacityError::check(u128::from(encoded.len), dst.remaining_mut())?;
    dst.put_slice(encoded.as_slice());
    Ok(())
}

#[cfg(test)]
mod tests;
