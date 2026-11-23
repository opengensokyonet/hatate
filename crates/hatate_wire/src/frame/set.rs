//! The frame types of a list of parts.
use crate::Role;
use crate::registry::ClaimedValues;
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
};
use sakuya_var_int::VarInt;

/// The kind of stream a frame is on, for the placement rules of
/// [RFC 9114 §7.2]: each frame type may appear on some of them.
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamKind {
    /// A control stream ([RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)).
    Control,
    /// A request stream: a client-initiated bidirectional stream
    /// ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)).
    Request,
    /// A push stream ([RFC 9114 §6.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2)).
    Push,
}

/// The properties of a frame type that the placement and role rules of
/// HTTP/3 ask about. They hold without any connection state.
///
/// The kinds of each part implement it, and so do the sums of kinds of a
/// list of parts.
pub trait FrameKind: Copy + Eq {
    /// Whether a frame of this kind may appear on a stream of kind
    /// `stream`; elsewhere it is a connection error of type
    /// H3_FRAME_UNEXPECTED.
    fn allowed_on(self, stream: StreamKind) -> bool;

    /// Whether an endpoint of role `role` may receive a frame of this kind.
    fn receivable_by(self, role: Role) -> bool;
}

/// One part of the frame types of a connection: the frame types defined by
/// RFC 9114, or those of one extension.
///
/// It is implemented by the marker type of each part. A list of parts
/// implements [`FrameSet`], which [`read_frame_head`](super::codec::read_frame_head)
/// reads with.
pub trait FramePart {
    /// The kinds of the frames of this part.
    type Kind: FrameKind;

    /// A frame type value this part claims, in the form of this part:
    /// obtained only from [`type_value_of`](Self::type_value_of), so it is
    /// always a value of this part.
    type TypeValue: Copy;

    /// The frame type values this part claims.
    const FRAME_TYPES: &'static ClaimedValues;

    /// The frame type `value` in the form of this part, or `None` for a
    /// value this part does not claim.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;

    /// The value on the wire of `type_value`.
    fn value_of(type_value: Self::TypeValue) -> VarInt;

    /// The kind that `type_value` announces.
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;
}

/// The frame types of a list of parts, `HNil` or `HCons<P, Ps>` of a part
/// `P` and the list `Ps`. A frame type value or kind of the list is a
/// `Coproduct` of those of the parts, in the order of the list, ending in
/// `CNil`.
pub trait FrameSet {
    /// The kinds of the frames of this list.
    type Kind: FrameKind;

    /// A frame type value a part of this list claims, in the form of that
    /// part ([`FramePart::TypeValue`]).
    type TypeValue: Copy;

    /// The frame type values the parts of this list claim.
    const FRAME_TYPES: &'static ClaimedValues;

    /// Whether the parts claim disjoint frame type values, none of them
    /// reserved ([`is_reserved`](crate::registry::is_reserved)) or left
    /// by HTTP/2 ([`Http2FrameType`](super::Http2FrameType)).
    const CLAIMS_VALID: bool;

    /// The frame type `value` in the form of the part that claims it, or
    /// `None` for a value no part claims.
    fn type_value_of(value: VarInt) -> Option<Self::TypeValue>;

    /// The value on the wire of `type_value`.
    fn value_of(type_value: Self::TypeValue) -> VarInt;

    /// The kind that `type_value` announces, as its part gives it.
    fn kind_of(type_value: Self::TypeValue) -> Self::Kind;
}

impl FrameSet for HNil {
    type Kind = CNil;
    type TypeValue = CNil;
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
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

impl<P: FramePart, Ps: FrameSet> FrameSet for HCons<P, Ps> {
    type Kind = Coproduct<P::Kind, Ps::Kind>;
    type TypeValue = Coproduct<P::TypeValue, Ps::TypeValue>;
    const FRAME_TYPES: &'static ClaimedValues =
        &ClaimedValues::join(P::FRAME_TYPES, Ps::FRAME_TYPES);
    const CLAIMS_VALID: bool = Ps::CLAIMS_VALID
        && P::FRAME_TYPES.is_disjoint(Ps::FRAME_TYPES)
        && P::FRAME_TYPES.is_disjoint(&super::HTTP2_FRAME_TYPES)
        && P::FRAME_TYPES.avoids_reserved();

    fn type_value_of(value: VarInt) -> Option<Self::TypeValue> {
        // Evaluated when the function is generated for a concrete list, so a
        // list whose claims conflict does not build.
        const {
            assert!(
                Self::CLAIMS_VALID,
                "the parts claim overlapping, reserved or HTTP/2 frame types"
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

impl FrameKind for CNil {
    fn allowed_on(self, _stream: StreamKind) -> bool {
        match self {}
    }

    fn receivable_by(self, _role: Role) -> bool {
        match self {}
    }
}

impl<H: FrameKind, T: FrameKind> FrameKind for Coproduct<H, T> {
    fn allowed_on(self, stream: StreamKind) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.allowed_on(stream),
            Coproduct::Inr(kind) => kind.allowed_on(stream),
        }
    }

    fn receivable_by(self, role: Role) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.receivable_by(role),
            Coproduct::Inr(kind) => kind.receivable_by(role),
        }
    }
}
