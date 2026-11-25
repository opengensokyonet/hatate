//! Unidirectional stream types ([RFC 9114 §6.2]).
//!
//! A unidirectional stream starts with its type, a variable-length integer.
//! The types of a connection are those of a list of parts, as for frames:
//! each part claims its types ([`StreamTypePart`]), checked at compile time
//! to be disjoint and not reserved, and says what it reads from a stream of
//! each ([`StreamPart`](crate::stream::part::StreamPart)). A type no part
//! claims gives an [`UnknownStream`](crate::stream::UnknownStream), which the
//! receiver discards or stops reading ([RFC 9114 §9]). Read the start of a
//! stream with
//! [`read_unidirectional_stream`](crate::stream::codec::read_unidirectional_stream);
//! write the type with `io.encode(field)` of `nitori_codec`.
//!
//! [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::registry::{ClaimedValue, ClaimedValues, UnclaimedValueError};
use frunk_core::hlist::{HCons, HNil};
use hatate_wire_qpack::QpackStreamType;
use sakuya_var_int::VarInt;

/// One part of the unidirectional stream types of a connection.
pub trait StreamTypePart {
    /// The stream type values this part claims.
    const STREAM_TYPES: &'static ClaimedValues;
}

/// The unidirectional stream types of a list of parts, `HNil` or
/// `HCons<P, Ps>`.
pub trait StreamTypeSet {
    /// The stream type values the parts of this list claim.
    const STREAM_TYPES: &'static ClaimedValues;
    /// Whether the parts claim disjoint stream types, none of them reserved
    /// ([`is_reserved`](crate::registry::is_reserved)).
    const CLAIMS_VALID: bool;
}

impl StreamTypeSet for HNil {
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
    const CLAIMS_VALID: bool = true;
}

impl<P: StreamTypePart, Ps: StreamTypeSet> StreamTypeSet for HCons<P, Ps> {
    const STREAM_TYPES: &'static ClaimedValues =
        &ClaimedValues::join(P::STREAM_TYPES, Ps::STREAM_TYPES);
    const CLAIMS_VALID: bool = Ps::CLAIMS_VALID
        && P::STREAM_TYPES.is_disjoint(Ps::STREAM_TYPES)
        && P::STREAM_TYPES.avoids_reserved();
}

/// A unidirectional stream type that the HTTP/3 part takes: RFC 9114's own
/// and QPACK's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http3StreamType {
    /// A control stream (0x00, [RFC 9114 §6.2.1]).
    ///
    /// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
    Control,
    /// A push stream (0x01, [RFC 9114 §6.2.2]), which a server opens; its
    /// Push ID follows the type.
    ///
    /// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
    Push,
    /// A stream of QPACK.
    Qpack(QpackStreamType),
}

impl Http3StreamType {
    /// The four types.
    pub const ALL: [Self; 4] = [
        Self::Control,
        Self::Push,
        Self::Qpack(QpackStreamType::Encoder),
        Self::Qpack(QpackStreamType::Decoder),
    ];

    /// The stream type on the wire.
    pub const fn value(self) -> VarInt {
        match self {
            Self::Control => VarInt::from_u32(0x00),
            Self::Push => VarInt::from_u32(0x01),
            Self::Qpack(stream_type) => stream_type.value(),
        }
    }

    /// The stream type `value`, if the HTTP/3 part takes it.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x00 => Some(Self::Control),
            0x01 => Some(Self::Push),
            _ => match QpackStreamType::of(value) {
                Some(stream_type) => Some(Self::Qpack(stream_type)),
                None => None,
            },
        }
    }
}

impl ClaimedValue for Http3StreamType {
    fn value(self) -> VarInt {
        Self::value(self)
    }

    fn of(value: VarInt) -> Option<Self> {
        Self::of(value)
    }
}

impl From<Http3StreamType> for VarInt {
    fn from(stream_type: Http3StreamType) -> Self {
        stream_type.value()
    }
}

impl TryFrom<VarInt> for Http3StreamType {
    type Error = UnclaimedValueError;

    fn try_from(value: VarInt) -> Result<Self, UnclaimedValueError> {
        Self::of(value).ok_or(UnclaimedValueError::new(value))
    }
}
