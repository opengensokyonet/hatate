//! What each part makes of the start of a stream the peer opened.
//!
//! A stream of each class of QUIC stream ([`class`](super::class)) starts
//! with a variable-length integer: the type of a unidirectional stream, or
//! the type of the first frame of a bidirectional one, after any reserved
//! frames. Each part gives its verdict on the value ([`StreamPart::judge`]);
//! the part that claims it then reads what follows the value and gives its
//! own stream ([`StreamPart::read`]). A part never touches a stream that is
//! not its own.
use super::class::StreamClass;
use crate::error_code::ErrorCode;
use core::future::Future;
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
};
use nitori_call::ReceiverAccess;
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField};

/// A part's verdict on the value at the start of a stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StreamVerdict<T> {
    /// The value opens a stream of this part, in the form of this part.
    Claimed(T),
    /// The value is none of this part's.
    NotClaimed,
    /// The value belongs to this part, and a stream of this class that
    /// starts with it is a connection error with this code.
    Error(ErrorCode),
    /// A connection error with this code, unless another part claims the
    /// value; HTTP/3 gives it on server-initiated bidirectional streams,
    /// which extensions may use, and on a client-initiated one that starts
    /// with a frame type another part has for other streams.
    ErrorUnlessClaimed(ErrorCode),
}

/// What a part makes of the start of a stream of class `C`, in a
/// connection whose list of parts is `L`.
///
/// It is implemented by the marker type of each part, for each of the four
/// classes; a part that opens no stream of a class gives
/// [`StreamVerdict::NotClaimed`] there, with `CNil` for its types.
#[diagnostic::on_unimplemented(
    message = "the part `{Self}` does not say what it makes of streams of class `{C}`",
    label = "implement `StreamPart<{C}, L>` for it, claiming nothing if it opens no stream of this class"
)]
pub trait StreamPart<C: StreamClass, L> {
    /// A value this part claims, in the form of this part: obtained only
    /// from [`judge`](Self::judge).
    type Claimed: Copy;
    /// A stream of this part, on the access `I`.
    type Stream<I>;
    /// The failures of reading what follows the value, from a source whose
    /// failures are `E`.
    type ReadError<E>;

    /// The verdict on `value` at the start of a stream of class `C`.
    /// `skipped` tells whether reserved frames preceded it, on a
    /// bidirectional stream.
    ///
    /// A part gives [`StreamVerdict::Claimed`] or [`StreamVerdict::Error`]
    /// only for values of its own: on a unidirectional stream the stream
    /// types it declares ([`StreamTypePart::STREAM_TYPES`]), on a
    /// bidirectional one frame types it declares or values no other part
    /// declares. The list does not check this.
    ///
    /// [`StreamTypePart::STREAM_TYPES`]: crate::stream_type::StreamTypePart::STREAM_TYPES
    fn judge(value: VarInt, skipped: bool) -> StreamVerdict<Self::Claimed>;

    /// Reads what follows the value `claimed`, read as `field`, from `io`,
    /// and gives the stream of this part.
    #[allow(clippy::type_complexity)] // The part's stream and failure on `I`.
    fn read<I: ReceiverAccess<Family: Read>>(
        claimed: Self::Claimed,
        field: VarIntField<VarInt>,
        io: I,
    ) -> impl Future<Output = Result<Self::Stream<I>, Self::ReadError<<I::Family as Read>::Error>>>;
}

/// What a list of parts, `HNil` or `HCons<P, Ps>`, makes of the start of a
/// stream of class `C`: the parts' claims, streams and failures as a
/// `Coproduct` in the order of the list.
///
/// The verdicts combine thus: values are claimed by at most one part, so at
/// most one part gives [`StreamVerdict::Claimed`] or [`StreamVerdict::Error`]
/// for a value, and that is the verdict of the list. If every other part
/// gives [`StreamVerdict::NotClaimed`], a [`StreamVerdict::ErrorUnlessClaimed`]
/// is the verdict; otherwise no part claims the value.
pub trait StreamSet<C: StreamClass, L> {
    /// A value a part of this list claims.
    type Claimed: Copy;
    /// A stream of a part of this list.
    type Stream<I>;
    /// A failure of a part of this list.
    type ReadError<E>;

    /// The verdict of the list on `value`.
    fn judge(value: VarInt, skipped: bool) -> StreamVerdict<Self::Claimed>;

    /// Reads what follows `claimed`, as the part that claims it does.
    #[allow(clippy::type_complexity)] // The part's stream and failure on `I`.
    fn read<I: ReceiverAccess<Family: Read>>(
        claimed: Self::Claimed,
        field: VarIntField<VarInt>,
        io: I,
    ) -> impl Future<Output = Result<Self::Stream<I>, Self::ReadError<<I::Family as Read>::Error>>>;
}

impl<C: StreamClass, L> StreamSet<C, L> for HNil {
    type Claimed = CNil;
    type Stream<I> = CNil;
    type ReadError<E> = CNil;

    fn judge(_value: VarInt, _skipped: bool) -> StreamVerdict<CNil> {
        StreamVerdict::NotClaimed
    }

    async fn read<I: ReceiverAccess<Family: Read>>(
        claimed: CNil,
        _field: VarIntField<VarInt>,
        _io: I,
    ) -> Result<CNil, CNil> {
        match claimed {}
    }
}

impl<C: StreamClass, L, P: StreamPart<C, L>, Ps: StreamSet<C, L>> StreamSet<C, L> for HCons<P, Ps> {
    type Claimed = Coproduct<P::Claimed, Ps::Claimed>;
    type Stream<I> = Coproduct<P::Stream<I>, Ps::Stream<I>>;
    type ReadError<E> = Coproduct<P::ReadError<E>, Ps::ReadError<E>>;

    fn judge(value: VarInt, skipped: bool) -> StreamVerdict<Self::Claimed> {
        use StreamVerdict::{Claimed, Error, ErrorUnlessClaimed, NotClaimed};
        match (P::judge(value, skipped), Ps::judge(value, skipped)) {
            (Claimed(claimed), _) => Claimed(Coproduct::Inl(claimed)),
            (_, Claimed(claimed)) => Claimed(Coproduct::Inr(claimed)),
            (Error(code), _) | (_, Error(code)) => Error(code),
            (ErrorUnlessClaimed(code), _) | (_, ErrorUnlessClaimed(code)) => {
                ErrorUnlessClaimed(code)
            }
            (NotClaimed, NotClaimed) => NotClaimed,
        }
    }

    async fn read<I: ReceiverAccess<Family: Read>>(
        claimed: Self::Claimed,
        field: VarIntField<VarInt>,
        io: I,
    ) -> Result<Self::Stream<I>, Self::ReadError<<I::Family as Read>::Error>> {
        match claimed {
            Coproduct::Inl(claimed) => P::read(claimed, field, io)
                .await
                .map(Coproduct::Inl)
                .map_err(Coproduct::Inl),
            Coproduct::Inr(claimed) => Ps::read(claimed, field, io)
                .await
                .map(Coproduct::Inr)
                .map_err(Coproduct::Inr),
        }
    }
}
