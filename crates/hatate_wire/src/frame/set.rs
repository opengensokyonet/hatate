//! The frame types of a list of parts, and of the kinds of stream they are on.
//!
//! Each part claims frame types ([`FramePart`]) and, for each kind of stream
//! that carries frames, says which of them appear there ([`FramePartOn`]): a
//! request, control or push stream, or the stream of an extension. A list of
//! parts sums both ([`FrameSet`], [`FrameSetOn`]). A frame on a stream of
//! kind `K` has a type of the sum on `K`, or is reserved or unknown
//! ([`FrameType`](super::FrameType)); a type a part claims for other kinds of
//! stream is a connection error there.
use crate::{Role, registry::ClaimedValue, registry::ClaimedValues, stream::kind::StreamKind};
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
};

/// The properties of a frame type that the role rules of HTTP/3 ask about.
/// They hold without any connection state.
///
/// The frame types of each part on each kind of stream implement it, and so
/// do their sums.
pub trait FrameKind: Copy {
    /// Whether an endpoint of role `role` may receive a frame of this type;
    /// otherwise it is a connection error of type H3_FRAME_UNEXPECTED.
    fn receivable_by(self, role: Role) -> bool;
}

impl FrameKind for CNil {
    fn receivable_by(self, _role: Role) -> bool {
        match self {}
    }
}

impl<H: FrameKind, T: FrameKind> FrameKind for Coproduct<H, T> {
    fn receivable_by(self, role: Role) -> bool {
        match self {
            Coproduct::Inl(kind) => kind.receivable_by(role),
            Coproduct::Inr(kind) => kind.receivable_by(role),
        }
    }
}

/// One part of the frame types of a connection: the frame types defined by
/// RFC 9114, or those of one extension.
///
/// It is implemented by the marker type of each part. A list of parts
/// implements [`FrameSet`].
pub trait FramePart {
    /// The frame type values this part claims, on every kind of stream.
    const FRAME_TYPES: &'static ClaimedValues;
}

/// The frame types a part has on streams of kind `K`.
///
/// Every part of a list implements it for each kind of stream that carries
/// frames, with [`CNil`] where it has none, so that the list can sum them.
#[diagnostic::on_unimplemented(
    message = "the part `{Self}` does not say which of its frame types appear on streams of kind `{K}`",
    label = "implement `FramePartOn<{K}>` for it, with `FrameType = CNil` if it has none there"
)]
pub trait FramePartOn<K: StreamKind>: FramePart {
    /// The frame types of this part that may appear on a stream of kind `K`,
    /// a subset of [`FRAME_TYPES`](FramePart::FRAME_TYPES).
    type FrameType: ClaimedValue + FrameKind;
}

/// The frame types of a list of parts, `HNil` or `HCons<P, Ps>` of a part
/// `P` and the list `Ps`.
pub trait FrameSet {
    /// The frame type values the parts of this list claim.
    const FRAME_TYPES: &'static ClaimedValues;

    /// Whether the parts claim disjoint frame type values, none of them
    /// reserved ([`is_reserved`](crate::registry::is_reserved)) or left
    /// by HTTP/2 ([`Http2FrameType`](super::Http2FrameType)).
    const CLAIMS_VALID: bool;
}

impl FrameSet for HNil {
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
    const CLAIMS_VALID: bool = true;
}

impl<P: FramePart, Ps: FrameSet> FrameSet for HCons<P, Ps> {
    const FRAME_TYPES: &'static ClaimedValues =
        &ClaimedValues::join(P::FRAME_TYPES, Ps::FRAME_TYPES);
    const CLAIMS_VALID: bool = Ps::CLAIMS_VALID
        && P::FRAME_TYPES.is_disjoint(Ps::FRAME_TYPES)
        && P::FRAME_TYPES.is_disjoint(&super::HTTP2_FRAME_TYPES)
        && P::FRAME_TYPES.avoids_reserved();
}

/// The frame types a list of parts has on streams of kind `K`: a
/// `Coproduct` of those of the parts ([`FramePartOn::FrameType`]), in the
/// order of the list, ending in `CNil`.
pub trait FrameSetOn<K: StreamKind>: FrameSet {
    /// A frame type a part of the list has on a stream of kind `K`.
    type FrameType: ClaimedValue + FrameKind;
}

impl<K: StreamKind> FrameSetOn<K> for HNil {
    type FrameType = CNil;
}

impl<K: StreamKind, P: FramePartOn<K>, Ps: FrameSetOn<K>> FrameSetOn<K> for HCons<P, Ps> {
    type FrameType = Coproduct<P::FrameType, Ps::FrameType>;
}
