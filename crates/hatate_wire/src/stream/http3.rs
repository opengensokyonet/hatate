//! The streams of RFC 9114 and QPACK: what the HTTP/3 part reads at the
//! start of a stream, and the streams it gives.
use super::{
    FrameStream, NextFrameError, TypedStream, UnidirectionalStream,
    class::{
        ClientInitiatedBidirectional, ClientInitiatedUnidirectional, ServerInitiatedBidirectional,
        ServerInitiatedUnidirectional, StreamClass,
    },
    kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
    part::{StreamPart, StreamVerdict},
};
use crate::{
    Part, Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        Frame, FrameType, Http2FrameType, PushId,
        codec::ReadFrameHeadError,
        payload::FramePayload,
        set::{FrameKind, FrameSetOn},
    },
    registry::ClaimedValue,
    stream_type::Http3StreamType,
};
use frunk_core::coproduct::CNil;
use hatate_wire_qpack::{
    QpackStreamType,
    stream::{QpackDecoderStream, QpackEncoderStream, QpackStreamError},
};
use nitori_call::{Composed, ReceiverAccess};
use nitori_io::{Infinite, Min, Read, Skip};
use sakuya_var_int::{
    VarInt, VarIntField,
    call::{ReadVarIntError, ReadVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// A unidirectional stream of the HTTP/3 part, one of its four types. The
/// type of each kind of stream is a parameter, so that the `transpose` of a
/// [`UnidirectionalStream`] of it can give each its Stream Type field; [`Http3UnidirectionalStreamOf`] is
/// the one read from the wire.
#[derive(Debug)]
pub enum Http3UnidirectionalStream<C, P, E, D> {
    /// A control stream (0x00).
    Control(C),
    /// A push stream (0x01).
    Push(P),
    /// The QPACK encoder stream (0x02).
    QpackEncoder(E),
    /// The QPACK decoder stream (0x03).
    QpackDecoder(D),
}

/// The unidirectional stream of the HTTP/3 part on the access `I`, in a
/// connection whose list of parts is `L`.
pub type Http3UnidirectionalStreamOf<L, I> = Http3UnidirectionalStream<
    ControlStream<L, I>,
    PushStream<L, I>,
    QpackEncoderStream<I>,
    QpackDecoderStream<I>,
>;

impl<C: TypedStream, P: TypedStream, E: TypedStream, D: TypedStream> TypedStream
    for Http3UnidirectionalStream<C, P, E, D>
{
    fn stream_type(&self) -> VarInt {
        match self {
            Self::Control(stream) => stream.stream_type(),
            Self::Push(stream) => stream.stream_type(),
            Self::QpackEncoder(stream) => stream.stream_type(),
            Self::QpackDecoder(stream) => stream.stream_type(),
        }
    }
}

impl<C, P, E, D> UnidirectionalStream<Http3UnidirectionalStream<C, P, E, D>> {
    /// The stream, with the width of its type, as the kind of stream it is.
    #[allow(clippy::type_complexity)] // The four kinds, each with its width.
    pub fn transpose(
        self,
    ) -> Http3UnidirectionalStream<
        UnidirectionalStream<C>,
        UnidirectionalStream<P>,
        UnidirectionalStream<E>,
        UnidirectionalStream<D>,
    > {
        let width = self.width();
        match self.into_stream() {
            Http3UnidirectionalStream::Control(stream) => {
                Http3UnidirectionalStream::Control(UnidirectionalStream::read(stream, width))
            }
            Http3UnidirectionalStream::Push(stream) => {
                Http3UnidirectionalStream::Push(UnidirectionalStream::read(stream, width))
            }
            Http3UnidirectionalStream::QpackEncoder(stream) => {
                Http3UnidirectionalStream::QpackEncoder(UnidirectionalStream::read(stream, width))
            }
            Http3UnidirectionalStream::QpackDecoder(stream) => {
                Http3UnidirectionalStream::QpackDecoder(UnidirectionalStream::read(stream, width))
            }
        }
    }
}

impl<I> TypedStream for QpackEncoderStream<I> {
    fn stream_type(&self) -> VarInt {
        QpackStreamType::Encoder.value()
    }
}

impl<I> TypedStream for QpackDecoderStream<I> {
    fn stream_type(&self) -> VarInt {
        QpackStreamType::Decoder.value()
    }
}

/// H3_CLOSED_CRITICAL_STREAM for a QPACK stream that ended
/// ([RFC 9204 §4.2]).
///
/// [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
impl<E> ErrorCodeOf<ErrorCode> for QpackStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Closed => Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
            Self::Instruction { .. } => None,
        }
    }
}

/// A control stream of the peer ([RFC 9114 §6.2.1]), which is critical: it
/// never ends, and a control stream that ends is a connection error of type
/// H3_CLOSED_CRITICAL_STREAM ([`ControlStreamError::Closed`]).
///
/// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
pub struct ControlStream<L: FrameSetOn<ControlStreamKind>, I> {
    frames: FrameStream<L, ControlStreamKind, I>,
}

impl<L: FrameSetOn<ControlStreamKind>, I> core::fmt::Debug for ControlStream<L, I>
where
    L::FrameType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlStream")
            .field("frames", &self.frames)
            .finish()
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I: ReceiverAccess<Family: Read>> ControlStream<L, I> {
    /// The current frame, as [`FrameStream::frame`] gives it. The first one
    /// is required to be SETTINGS ([RFC 9114 §6.2.1]), which the connection
    /// checks.
    ///
    /// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
    pub fn frame(&mut self) -> Frame<FrameType<L::FrameType>, Composed<&mut I, &mut FramePayload>> {
        self.frames.frame()
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I> ControlStream<L, I>
where
    I: ReceiverAccess<Family: Skip<Count: Clone + Min<u64, Output = u64>>>,
    u64: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    /// Moves to the next frame, as [`FrameStream::next_frame`] does.
    ///
    /// # Errors
    ///
    /// [`ControlStreamError`]: the stream ended, or the frame could not be
    /// read.
    pub async fn next_frame(
        &mut self,
    ) -> Result<
        Frame<FrameType<L::FrameType>, Composed<&mut I, &mut FramePayload>>,
        ControlStreamError<<I::Family as Read>::Error>,
    > {
        match self.frames.next_frame().await {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) => Err(ControlStreamError::Closed),
            Err(source) => Err(ControlStreamError::Frame { source }),
        }
    }

    /// Moves to the next frame of a known type, as
    /// [`FrameStream::next_known_frame`] does.
    ///
    /// # Errors
    ///
    /// [`ControlStreamError`], as for [`next_frame`](Self::next_frame).
    pub async fn next_known_frame(
        &mut self,
    ) -> Result<
        Frame<FrameType<L::FrameType>, Composed<&mut I, &mut FramePayload>>,
        ControlStreamError<<I::Family as Read>::Error>,
    > {
        match self.frames.next_known_frame().await {
            Ok(Some(frame)) => Ok(frame),
            Ok(None) => Err(ControlStreamError::Closed),
            Err(source) => Err(ControlStreamError::Frame { source }),
        }
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I> ControlStream<L, I> {
    /// The stream of frames, giving up that it is critical.
    pub fn into_frames(self) -> FrameStream<L, ControlStreamKind, I> {
        self.frames
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I> TypedStream for ControlStream<L, I> {
    fn stream_type(&self) -> VarInt {
        Http3StreamType::Control.value()
    }
}

/// Failures of reading a control stream.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ControlStreamError<E> {
    /// The stream ended, which a control stream may not
    /// ([RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)).
    #[snafu(display("the control stream was closed"))]
    Closed,
    /// The next frame could not be read.
    #[snafu(display("could not read a frame of the control stream"))]
    Frame {
        /// The failure of reading it.
        source: NextFrameError<E>,
    },
}

/// H3_CLOSED_CRITICAL_STREAM for a control stream that ended; otherwise the
/// code of the failure of reading the frame.
impl<E> ErrorCodeOf<ErrorCode> for ControlStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Closed => Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
            Self::Frame { source } => source.error_code(),
        }
    }
}

/// A push stream ([RFC 9114 §6.2.2]): its Push ID, and its frames.
///
/// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
pub struct PushStream<L: FrameSetOn<PushStreamKind>, I> {
    push_id: VarIntField<PushId>,
    frames: FrameStream<L, PushStreamKind, I>,
}

impl<L: FrameSetOn<PushStreamKind>, I> core::fmt::Debug for PushStream<L, I>
where
    L::FrameType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PushStream")
            .field("push_id", &self.push_id)
            .field("frames", &self.frames)
            .finish()
    }
}

impl<L: FrameSetOn<PushStreamKind>, I> PushStream<L, I> {
    /// The Push ID, at the width it had on the wire. Whether it is within
    /// the permitted range is a question for the connection.
    pub const fn push_id(&self) -> VarIntField<PushId> {
        self.push_id
    }

    /// The frames of the stream.
    pub fn frames(&mut self) -> &mut FrameStream<L, PushStreamKind, I> {
        &mut self.frames
    }

    /// The Push ID and the frames of the stream.
    pub fn into_parts(self) -> (VarIntField<PushId>, FrameStream<L, PushStreamKind, I>) {
        (self.push_id, self.frames)
    }
}

impl<L: FrameSetOn<PushStreamKind>, I> TypedStream for PushStream<L, I> {
    fn stream_type(&self) -> VarInt {
        Http3StreamType::Push.value()
    }
}

/// Failures of reading the start of a unidirectional stream of the HTTP/3
/// part, after its type.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Http3UnidirectionalStreamError<E> {
    /// The first frame of a control stream could not be read.
    #[snafu(display("could not read the first frame of a control stream"))]
    Control {
        /// The failure of reading its head.
        source: ReadFrameHeadError<E>,
    },
    /// A control stream ended before its first frame.
    #[snafu(display("the control stream was closed before its first frame"))]
    ControlClosed,
    /// The Push ID of a push stream could not be read.
    #[snafu(display("could not read the push ID of a push stream"))]
    PushId {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The first frame of a push stream could not be read.
    #[snafu(display("could not read the first frame of a push stream"))]
    Push {
        /// The failure of reading its head.
        source: ReadFrameHeadError<E>,
    },
    /// A push stream ended after its Push ID, before any frame.
    #[snafu(display("the push stream ended before its first frame"))]
    PushEnded,
}

/// H3_CLOSED_CRITICAL_STREAM for a control stream that ended; the code of a
/// frame head that was rejected or cut short. `None` when the stream fails,
/// or a push stream ends before its frames, which a receiver tolerates.
impl<E> ErrorCodeOf<ErrorCode> for Http3UnidirectionalStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Control { source } | Self::Push { source } => source.error_code(),
            Self::ControlClosed => Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
            Self::PushId { .. } | Self::PushEnded => None,
        }
    }
}

/// Reads what follows the type `stream_type` of a unidirectional stream
/// received by an endpoint of role `role`.
async fn read_unidirectional<L, I>(
    stream_type: Http3StreamType,
    role: Role,
    mut io: I,
) -> Result<
    Http3UnidirectionalStreamOf<L, I>,
    Http3UnidirectionalStreamError<<I::Family as Read>::Error>,
>
where
    L: FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
    I: ReceiverAccess<Family: Read>,
{
    use http3_unidirectional_stream_error::{ControlSnafu, PushIdSnafu, PushSnafu};
    Ok(match stream_type {
        Http3StreamType::Control => Http3UnidirectionalStream::Control(ControlStream {
            frames: FrameStream::read(io, role)
                .await
                .context(ControlSnafu)?
                .ok_or(Http3UnidirectionalStreamError::ControlClosed)?,
        }),
        Http3StreamType::Push => {
            let push_id = io
                .read_var_int_field::<PushId>()
                .await
                .context(PushIdSnafu)?;
            Http3UnidirectionalStream::Push(PushStream {
                push_id,
                frames: FrameStream::read(io, role)
                    .await
                    .context(PushSnafu)?
                    .ok_or(Http3UnidirectionalStreamError::PushEnded)?,
            })
        }
        Http3StreamType::Qpack(QpackStreamType::Encoder) => {
            Http3UnidirectionalStream::QpackEncoder(QpackEncoderStream::new(io))
        }
        Http3StreamType::Qpack(QpackStreamType::Decoder) => {
            Http3UnidirectionalStream::QpackDecoder(QpackDecoderStream::new(io))
        }
    })
}

macro_rules! unidirectional_part {
    ($class:ty, $judge:expr) => {
        impl<L> StreamPart<$class, L> for Part
        where
            L: FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
        {
            type Claimed = Http3StreamType;
            type Stream<I> = Http3UnidirectionalStreamOf<L, I>;
            type ReadError<E> = Http3UnidirectionalStreamError<E>;

            fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<Http3StreamType> {
                let judge: fn(Http3StreamType) -> StreamVerdict<Http3StreamType> = $judge;
                Http3StreamType::of(value).map_or(StreamVerdict::NotClaimed, judge)
            }

            async fn read<I: ReceiverAccess<Family: Read>>(
                claimed: Http3StreamType,
                _field: VarIntField<VarInt>,
                io: I,
            ) -> Result<Self::Stream<I>, Http3UnidirectionalStreamError<<I::Family as Read>::Error>>
            {
                read_unidirectional(claimed, <$class as StreamClass>::RECEIVER, io).await
            }
        }
    };
}

// A server receives client-initiated streams, and only servers push
// (RFC 9114 §6.2.2).
unidirectional_part!(
    ClientInitiatedUnidirectional,
    |stream_type| match stream_type {
        Http3StreamType::Push => StreamVerdict::Error(ErrorCode::H3_STREAM_CREATION_ERROR),
        stream_type => StreamVerdict::Claimed(stream_type),
    }
);
unidirectional_part!(ServerInitiatedUnidirectional, StreamVerdict::Claimed);

/// A client-initiated bidirectional stream is a request stream when its
/// first frame that is not reserved has a type the list has on request
/// streams ([RFC 9114 §6.1]); HTTP/3 does not take a stream that starts with
/// any other frame, so an application that reads such frames adds the part
/// that has them on request streams. A type of HTTP/2, or one a part claims
/// for other streams, is a connection error of type H3_FRAME_UNEXPECTED, as
/// is a frame type the server does not receive.
///
/// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
impl<L: FrameSetOn<RequestStreamKind>> StreamPart<ClientInitiatedBidirectional, L> for Part {
    type Claimed = ();
    type Stream<I> = FrameStream<L, RequestStreamKind, I>;
    type ReadError<E> = ReadFrameHeadError<E>;

    fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<()> {
        let receiver = <ClientInitiatedBidirectional as StreamClass>::RECEIVER;
        if Http2FrameType::of(value).is_some() {
            return StreamVerdict::Error(ErrorCode::H3_FRAME_UNEXPECTED);
        }
        match <L as FrameSetOn<RequestStreamKind>>::FrameType::of(value) {
            Some(frame_type) if frame_type.receivable_by(receiver) => StreamVerdict::Claimed(()),
            Some(_) => StreamVerdict::Error(ErrorCode::H3_FRAME_UNEXPECTED),
            None if L::FRAME_TYPES.contains(value) => {
                StreamVerdict::Error(ErrorCode::H3_FRAME_UNEXPECTED)
            }
            None => StreamVerdict::NotClaimed,
        }
    }

    async fn read<I: ReceiverAccess<Family: Read>>(
        (): (),
        field: VarIntField<VarInt>,
        io: I,
    ) -> Result<FrameStream<L, RequestStreamKind, I>, ReadFrameHeadError<<I::Family as Read>::Error>>
    {
        let receiver = <ClientInitiatedBidirectional as StreamClass>::RECEIVER;
        FrameStream::with_type(io, receiver, field).await
    }
}

/// HTTP/3 does not use server-initiated bidirectional streams: one that no
/// extension claims is a connection error of type H3_STREAM_CREATION_ERROR
/// ([RFC 9114 §6.1]).
///
/// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
impl<L> StreamPart<ServerInitiatedBidirectional, L> for Part {
    type Claimed = CNil;
    type Stream<I> = CNil;
    type ReadError<E> = CNil;

    fn judge(_value: VarInt, _skipped: bool) -> StreamVerdict<CNil> {
        StreamVerdict::ErrorUnlessClaimed(ErrorCode::H3_STREAM_CREATION_ERROR)
    }

    async fn read<I: ReceiverAccess<Family: Read>>(
        claimed: CNil,
        _field: VarIntField<VarInt>,
        _io: I,
    ) -> Result<CNil, CNil> {
        match claimed {}
    }
}
