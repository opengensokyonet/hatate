//! QPACK's entries in the HTTP/3 registries ([RFC 9204 §8]).
//!
//! QPACK registers two settings, two unidirectional stream types and three
//! error codes in the registries of HTTP/3. Every HTTP/3 connection uses
//! QPACK, so these entries are not a separate part of a composition: the
//! RFC 9114 part of `hatate_wire` takes them in. This package holds the
//! values and what each of them means, and nothing of the composition.
//!
//! [RFC 9204 §8]: https://www.rfc-editor.org/rfc/rfc9204.html#section-8
#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

use sakuya_var_int::{VarInt, VarIntField};

/// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): the largest dynamic table
/// capacity the encoder may set ([RFC 9204 §5]). Every value is valid.
///
/// It defaults to 0: without it the peer has no dynamic table.
///
/// [RFC 9204 §5]: https://www.rfc-editor.org/rfc/rfc9204.html#section-5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QpackMaxTableCapacity {
    value: VarIntField<VarInt>,
}

impl QpackMaxTableCapacity {
    /// The setting identifier on the wire.
    pub const IDENTIFIER: VarInt = VarInt::from_u32(0x01);

    /// The setting with `value`.
    pub const fn new(value: VarIntField<VarInt>) -> Self {
        Self { value }
    }

    /// The value.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// The value that applies until the peer's SETTINGS frame states one: 0,
/// in its shortest encoding.
impl Default for QpackMaxTableCapacity {
    fn default() -> Self {
        Self::new(VarIntField::shortest(VarInt::ZERO))
    }
}

/// SETTINGS_QPACK_BLOCKED_STREAMS (0x07): how many streams may be blocked
/// waiting for encoder instructions ([RFC 9204 §5]). Every value is valid.
///
/// It defaults to 0: without it no stream may be blocked.
///
/// [RFC 9204 §5]: https://www.rfc-editor.org/rfc/rfc9204.html#section-5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct QpackBlockedStreams {
    value: VarIntField<VarInt>,
}

impl QpackBlockedStreams {
    /// The setting identifier on the wire.
    pub const IDENTIFIER: VarInt = VarInt::from_u32(0x07);

    /// The setting with `value`.
    pub const fn new(value: VarIntField<VarInt>) -> Self {
        Self { value }
    }

    /// The value.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// The value that applies until the peer's SETTINGS frame states one: 0,
/// in its shortest encoding.
impl Default for QpackBlockedStreams {
    fn default() -> Self {
        Self::new(VarIntField::shortest(VarInt::ZERO))
    }
}

/// A unidirectional stream type that QPACK defines ([RFC 9204 §4.2]).
///
/// Each endpoint opens at most one stream of each type, and closing either
/// is a connection error of type H3_CLOSED_CRITICAL_STREAM. An endpoint must
/// accept them even when its settings rule out a dynamic table.
///
/// [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QpackStreamType {
    /// The encoder stream (0x02), carrying encoder instructions.
    Encoder,
    /// The decoder stream (0x03), carrying decoder instructions.
    Decoder,
}

impl QpackStreamType {
    /// Both stream types.
    pub const ALL: [Self; 2] = [Self::Encoder, Self::Decoder];

    /// The stream type on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::Encoder => 0x02,
            Self::Decoder => 0x03,
        })
    }

    /// The stream type `value`, if QPACK defines it.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x02 => Some(Self::Encoder),
            0x03 => Some(Self::Decoder),
            _ => None,
        }
    }
}

/// An error code that QPACK defines ([RFC 9204 §6]).
///
/// [RFC 9204 §6]: https://www.rfc-editor.org/rfc/rfc9204.html#section-6
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QpackErrorCode {
    /// QPACK_DECOMPRESSION_FAILED (0x0200): a field section could not be
    /// interpreted.
    DecompressionFailed,
    /// QPACK_ENCODER_STREAM_ERROR (0x0201): an encoder instruction could not
    /// be interpreted.
    EncoderStreamError,
    /// QPACK_DECODER_STREAM_ERROR (0x0202): a decoder instruction could not
    /// be interpreted.
    DecoderStreamError,
}

impl QpackErrorCode {
    /// The three error codes.
    pub const ALL: [Self; 3] = [
        Self::DecompressionFailed,
        Self::EncoderStreamError,
        Self::DecoderStreamError,
    ];

    /// The error code on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::DecompressionFailed => 0x0200,
            Self::EncoderStreamError => 0x0201,
            Self::DecoderStreamError => 0x0202,
        })
    }

    /// The error code `value`, if QPACK defines it.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x0200 => Some(Self::DecompressionFailed),
            0x0201 => Some(Self::EncoderStreamError),
            0x0202 => Some(Self::DecoderStreamError),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_map_back() {
        assert_eq!(QpackMaxTableCapacity::IDENTIFIER.get(), 0x01);
        assert_eq!(QpackBlockedStreams::IDENTIFIER.get(), 0x07);
        assert_eq!(QpackMaxTableCapacity::default().value().get(), VarInt::ZERO);
        assert_eq!(QpackBlockedStreams::default().value().get(), VarInt::ZERO);
        for kind in QpackStreamType::ALL {
            assert_eq!(QpackStreamType::of(kind.value()), Some(kind));
        }
        for code in QpackErrorCode::ALL {
            assert_eq!(QpackErrorCode::of(code.value()), Some(code));
        }
        assert_eq!(QpackStreamType::of(VarInt::from_u32(0x00)), None);
        assert_eq!(QpackErrorCode::of(VarInt::from_u32(0x0203)), None);
    }
}
