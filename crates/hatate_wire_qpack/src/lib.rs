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

use sakuya_var_int::VarInt;

/// A setting that QPACK defines ([RFC 9204 §5]).
///
/// Both default to 0: without them the peer has no dynamic table and no
/// stream may be blocked.
///
/// [RFC 9204 §5]: https://www.rfc-editor.org/rfc/rfc9204.html#section-5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QpackSettingIdentifier {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (0x01): the largest dynamic table
    /// capacity the encoder may set.
    MaxTableCapacity,
    /// SETTINGS_QPACK_BLOCKED_STREAMS (0x07): how many streams may be
    /// blocked waiting for encoder instructions.
    BlockedStreams,
}

impl QpackSettingIdentifier {
    /// Both identifiers.
    pub const ALL: [Self; 2] = [Self::MaxTableCapacity, Self::BlockedStreams];

    /// The setting identifier on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::MaxTableCapacity => 0x01,
            Self::BlockedStreams => 0x07,
        })
    }

    /// The setting with the identifier `value`, if QPACK defines it.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x01 => Some(Self::MaxTableCapacity),
            0x07 => Some(Self::BlockedStreams),
            _ => None,
        }
    }

    /// The value that applies until the peer's SETTINGS frame states one.
    pub const fn default_value(self) -> VarInt {
        VarInt::ZERO
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
        for id in QpackSettingIdentifier::ALL {
            assert_eq!(QpackSettingIdentifier::of(id.value()), Some(id));
            assert_eq!(id.default_value(), VarInt::ZERO);
        }
        for kind in QpackStreamType::ALL {
            assert_eq!(QpackStreamType::of(kind.value()), Some(kind));
        }
        for code in QpackErrorCode::ALL {
            assert_eq!(QpackErrorCode::of(code.value()), Some(code));
        }
        assert_eq!(QpackSettingIdentifier::of(VarInt::from_u32(0x06)), None);
        assert_eq!(QpackStreamType::of(VarInt::from_u32(0x00)), None);
        assert_eq!(QpackErrorCode::of(VarInt::from_u32(0x0203)), None);
    }
}
