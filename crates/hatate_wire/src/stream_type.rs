//! Unidirectional stream types ([RFC 9114 §6.2]).
//!
//! A unidirectional stream starts with its type, a variable-length integer.
//! The types of a connection are those of a list of parts, as for frames; a
//! type no part claims is [`StreamType::Unknown`], and the receiver
//! discards the stream or stops reading it ([RFC 9114 §9]). Write a type
//! with [`sakuya_var_int::call::write_var_int_field`].
//!
//! [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::{Role, registry::ClaimedValues};
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
};
use hatate_wire_qpack::QpackStreamType;
use sakuya_var_int::{VarInt, VarIntField};

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;

/// The properties of a stream type that the rules on opening and closing
/// unidirectional streams ask about. They hold without connection state.
pub trait StreamTypeKind: Copy + Eq {
    /// Whether an endpoint of role `role` may accept a stream of this type
    /// that its peer opened; otherwise it is a connection error of type
    /// H3_STREAM_CREATION_ERROR.
    fn acceptable_by(self, role: Role) -> bool;

    /// Whether closing a stream of this type is a connection error of type
    /// H3_CLOSED_CRITICAL_STREAM.
    fn is_critical(self) -> bool;

    /// Whether each endpoint opens at most one stream of this type; a second
    /// is a connection error of type H3_STREAM_CREATION_ERROR.
    fn at_most_one(self) -> bool;
}

/// One part of the unidirectional stream types of a connection.
pub trait StreamTypePart {
    /// The kinds of the stream types of this part.
    type Kind: StreamTypeKind;
    /// A stream type value this part claims, in the form of this part.
    type TypeValue: Copy;
    /// The stream type values this part claims.
    const STREAM_TYPES: &'static ClaimedValues;
    /// The stream type `value` in the form of this part.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;
    /// The value on the wire of `type_value`.
    fn value_of(type_value: Self::TypeValue) -> VarInt;
    /// The kind that `type_value` announces.
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;
}

/// The unidirectional stream types of a list of parts, `HNil` or
/// `HCons<P, Ps>`, as a `Coproduct` in the order of the list.
pub trait StreamTypeSet {
    /// The kinds of the stream types of this list.
    type Kind: StreamTypeKind;
    /// A stream type value a part of this list claims.
    type TypeValue: Copy;
    /// The stream type values the parts of this list claim.
    const STREAM_TYPES: &'static ClaimedValues;
    /// Whether the parts claim disjoint stream types, none of them reserved
    /// ([`is_reserved`](crate::registry::is_reserved)).
    const CLAIMS_VALID: bool;
    /// The stream type `value` in the form of the part that claims it.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;
    /// The value on the wire of `type_value`.
    fn value_of(type_value: Self::TypeValue) -> VarInt;
    /// The kind that `type_value` announces.
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;
}

impl StreamTypeSet for HNil {
    type Kind = CNil;
    type TypeValue = CNil;
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
    const CLAIMS_VALID: bool = true;

    fn type_value_of(_value: VarInt) -> Option<CNil> {
        None
    }

    fn value_of(type_value: CNil) -> VarInt {
        match type_value {}
    }

    fn kind_of(type_value: CNil) -> CNil {
        match type_value {}
    }
}

impl<P: StreamTypePart, Ps: StreamTypeSet> StreamTypeSet for HCons<P, Ps> {
    type Kind = Coproduct<P::Kind, Ps::Kind>;
    type TypeValue = Coproduct<P::TypeValue, Ps::TypeValue>;
    const STREAM_TYPES: &'static ClaimedValues =
        &ClaimedValues::join(P::STREAM_TYPES, Ps::STREAM_TYPES);
    const CLAIMS_VALID: bool = Ps::CLAIMS_VALID
        && P::STREAM_TYPES.is_disjoint(Ps::STREAM_TYPES)
        && P::STREAM_TYPES.avoids_reserved();

    fn type_value_of(value: VarInt) -> Option<Self::TypeValue> {
        const {
            assert!(
                Self::CLAIMS_VALID,
                "the parts claim overlapping or reserved stream types"
            );
        }
        P::type_value_of(value)
            .map(Coproduct::Inl)
            .or_else(|| Ps::type_value_of(value).map(Coproduct::Inr))
    }

    fn value_of(type_value: Self::TypeValue) -> VarInt {
        match type_value {
            Coproduct::Inl(type_value) => P::value_of(type_value),
            Coproduct::Inr(type_value) => Ps::value_of(type_value),
        }
    }

    fn kind_of(type_value: Self::TypeValue) -> Self::Kind {
        match type_value {
            Coproduct::Inl(type_value) => Coproduct::Inl(P::kind_of(type_value)),
            Coproduct::Inr(type_value) => Coproduct::Inr(Ps::kind_of(type_value)),
        }
    }
}

impl StreamTypeKind for CNil {
    fn acceptable_by(self, _role: Role) -> bool {
        match self {}
    }

    fn is_critical(self) -> bool {
        match self {}
    }

    fn at_most_one(self) -> bool {
        match self {}
    }
}

impl<H: StreamTypeKind, T: StreamTypeKind> StreamTypeKind for Coproduct<H, T> {
    fn acceptable_by(self, role: Role) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.acceptable_by(role),
            Coproduct::Inr(kind) => kind.acceptable_by(role),
        }
    }

    fn is_critical(self) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.is_critical(),
            Coproduct::Inr(kind) => kind.is_critical(),
        }
    }

    fn at_most_one(self) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.at_most_one(),
            Coproduct::Inr(kind) => kind.at_most_one(),
        }
    }
}

/// The type of a unidirectional stream as a list of parts reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamType<T> {
    /// A type a part of the list claims, in the form of that part.
    Known(T),
    /// A type no part of the list claims.
    Unknown(VarInt),
}

/// The type at the start of a unidirectional stream, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamTypeHead<T> {
    stream_type: StreamType<T>,
    field: VarIntField<VarInt>,
}

impl<T: Copy> StreamTypeHead<T> {
    /// The type, as the list of parts reads it.
    pub const fn stream_type(&self) -> StreamType<T> {
        self.stream_type
    }

    /// The Stream Type field as it was on the wire.
    pub const fn field(&self) -> VarIntField<VarInt> {
        self.field
    }
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

/// The rules of [RFC 9114 §6.2.1, §6.2.2] and [RFC 9204 §4.2].
///
/// [RFC 9114 §6.2.1, §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
/// [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
impl StreamTypeKind for Http3StreamType {
    fn acceptable_by(self, role: Role) -> bool {
        match self {
            // Only servers push.
            Self::Push => role == Role::Client,
            Self::Control | Self::Qpack(_) => true,
        }
    }

    fn is_critical(self) -> bool {
        !matches!(self, Self::Push)
    }

    fn at_most_one(self) -> bool {
        !matches!(self, Self::Push)
    }
}
