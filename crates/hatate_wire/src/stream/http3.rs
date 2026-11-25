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
        Frame, FrameType, Http3FrameType, PushId,
        codec::{ReadFrameHeadError, UnexpectedFrameTypeError, check_frame_type},
        payload::FramePayload,
        set::FrameSetOn,
    },
    registry::ClaimedValue,
    stream_type::Http3StreamType,
};
use frunk_core::coproduct::CNil;
use hatate_qpack::{
    decoder_instruction::codec::ReadError as DecoderInstructionError,
    encoder_instruction::{
        codec::{LiteralHeaderError, StartError, ValueError},
        literal::{FinishError, HuffmanReadError, InputError},
    },
    huffman::DecodeError,
    instruction::{NumberError, OctetError},
};
use hatate_wire_qpack::{
    QpackErrorCode, QpackStreamType,
    stream::{CriticalStream, CriticalStreamError, QpackDecoderStream, QpackEncoderStream},
};
use nitori_call::{Composed, ReceiverAccess};
use nitori_codec::prelude::*;
use nitori_io::{Combine, Infinite, Min, Read, Skip, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField, stream::ReadVarIntError};
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

/// The unidirectional stream of the HTTP/3 part on the access `I`, whose
/// bytes carry the metadata `M`, in a connection whose list of parts is `L`.
pub type Http3UnidirectionalStreamOf<L, I, M = ()> = Http3UnidirectionalStream<
    ControlStream<L, I, M>,
    PushStream<L, I, M>,
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

impl<C, P, E, D, M> UnidirectionalStream<Http3UnidirectionalStream<C, P, E, D>, M> {
    /// The stream, with the width of its type and the metadata of its bytes,
    /// as the kind of stream it is.
    #[allow(clippy::type_complexity)] // The four kinds, each with its width.
    pub fn transpose(
        self,
    ) -> Http3UnidirectionalStream<
        UnidirectionalStream<C, M>,
        UnidirectionalStream<P, M>,
        UnidirectionalStream<E, M>,
        UnidirectionalStream<D, M>,
    > {
        let width = self.width();
        let (stream, type_metadata) = self.into_parts();
        match stream {
            Http3UnidirectionalStream::Control(stream) => Http3UnidirectionalStream::Control(
                UnidirectionalStream::read(stream, width, type_metadata),
            ),
            Http3UnidirectionalStream::Push(stream) => Http3UnidirectionalStream::Push(
                UnidirectionalStream::read(stream, width, type_metadata),
            ),
            Http3UnidirectionalStream::QpackEncoder(stream) => {
                Http3UnidirectionalStream::QpackEncoder(UnidirectionalStream::read(
                    stream,
                    width,
                    type_metadata,
                ))
            }
            Http3UnidirectionalStream::QpackDecoder(stream) => {
                Http3UnidirectionalStream::QpackDecoder(UnidirectionalStream::read(
                    stream,
                    width,
                    type_metadata,
                ))
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

/// H3_CLOSED_CRITICAL_STREAM for a critical stream that ended
/// ([RFC 9114 §6.2.1], [RFC 9204 §4.2]); otherwise the code of the stream's
/// own failure.
///
/// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
/// [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for CriticalStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Closed => Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
            Self::Host { source } => source.error_code(),
        }
    }
}

/// Where a failure to read a QPACK instruction came from.
enum QpackFailure<'e, E> {
    /// The stream failed.
    Host(&'e E),
    /// The instruction cannot be interpreted.
    Malformed,
    /// The stream ended inside the instruction, a limit of this endpoint was
    /// exceeded, or the stream was already abandoned: no code of its own.
    Other,
}

/// The origin of a failure to read a QPACK instruction.
trait QpackFailureOf<E> {
    fn failure(&self) -> QpackFailure<'_, E>;
}

impl<E> QpackFailureOf<E> for OctetError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            // The other failure of the read is the end of the stream.
            Self::Read { source } => source
                .host_error()
                .map_or(QpackFailure::Other, QpackFailure::Host),
            Self::WireLimit { .. } => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for NumberError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Continuation { source } => source.failure(),
            Self::Integer { .. } => QpackFailure::Malformed,
        }
    }
}

impl<E> QpackFailureOf<E> for LiteralHeaderError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Length { source } => source.failure(),
            Self::WireLimit { .. } | Self::DecodedLength { .. } => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for StartError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Prefix { source } => source.failure(),
            Self::Capacity { source } | Self::Duplicate { source } | Self::NameIndex { source } => {
                source.failure()
            }
            Self::Name { source } => source.failure(),
            Self::StaticName { .. } => QpackFailure::Malformed,
            Self::WireLimit { .. } | Self::Interrupted => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for ValueError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Prefix { source } => source.failure(),
            Self::Value { source } => source.failure(),
        }
    }
}

impl<E> QpackFailureOf<E> for InputError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Host { source } => QpackFailure::Host(source),
            Self::Truncated { .. } | Self::Failed => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for HuffmanReadError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Input { source } => source.failure(),
            Self::Coding {
                source:
                    DecodeError::EndOfString | DecodeError::ExcessPadding | DecodeError::InvalidPadding,
            } => QpackFailure::Malformed,
            Self::Coding {
                source: DecodeError::ReserveOutput { .. } | DecodeError::OutputTooLong { .. },
            }
            | Self::Failed => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for DecoderInstructionError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Prefix { source } => source.failure(),
            Self::AcknowledgmentNumber { source }
            | Self::CancellationNumber { source }
            | Self::IncrementNumber { source } => source.failure(),
            Self::AcknowledgmentStream { .. }
            | Self::CancellationStream { .. }
            | Self::ZeroIncrement => QpackFailure::Malformed,
            Self::Interrupted => QpackFailure::Other,
        }
    }
}

macro_rules! qpack_error_code {
    ($code:ident, $stream:literal: $($error:ident),+) => {
        $(
            #[doc = concat!(
                "The code of the stream's own failure, such as\n",
                "H3_CLOSED_CRITICAL_STREAM on a QPACK stream that ended inside\n",
                "an instruction; ", $stream, " for an instruction that cannot be\n",
                "interpreted ([RFC 9204 §6]); `None` for the end of a stream that\n",
                "is not critical, a limit of this endpoint, and a stream already\n",
                "abandoned.\n\n",
                "[RFC 9204 §6]: https://www.rfc-editor.org/rfc/rfc9204.html#section-6",
            )]
            impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for $error<E> {
                fn error_code(&self) -> Option<ErrorCode> {
                    match self.failure() {
                        QpackFailure::Host(source) => source.error_code(),
                        QpackFailure::Malformed => Some(QpackErrorCode::$code.into()),
                        QpackFailure::Other => None,
                    }
                }
            }
        )+
    };
}

qpack_error_code!(
    EncoderStreamError,
    "QPACK_ENCODER_STREAM_ERROR":
    StartError,
    ValueError,
    InputError,
    HuffmanReadError
);
qpack_error_code!(DecoderStreamError, "QPACK_DECODER_STREAM_ERROR": DecoderInstructionError);

/// QPACK_ENCODER_STREAM_ERROR for a Huffman literal whose ending cannot be
/// interpreted ([RFC 9204 §6]); `None` for a literal left unread or already
/// failed, and a limit of this endpoint.
///
/// [RFC 9204 §6]: https://www.rfc-editor.org/rfc/rfc9204.html#section-6
impl ErrorCodeOf<ErrorCode> for FinishError {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Coding {
                source:
                    DecodeError::EndOfString | DecodeError::ExcessPadding | DecodeError::InvalidPadding,
            } => Some(QpackErrorCode::EncoderStreamError.into()),
            Self::Coding {
                source: DecodeError::ReserveOutput { .. } | DecodeError::OutputTooLong { .. },
            }
            | Self::Unread
            | Self::Failed => None,
        }
    }
}

/// A control stream of the peer ([RFC 9114 §6.2.1]), which is critical: it
/// is read through [`CriticalStream`], so its end, at a frame boundary or
/// inside a frame, is a failure of the stream with the code
/// H3_CLOSED_CRITICAL_STREAM, and it has no last frame.
///
/// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
pub struct ControlStream<L: FrameSetOn<ControlStreamKind>, I, M = ()> {
    frames: FrameStream<L, ControlStreamKind, Composed<I, CriticalStream>, M>,
}

impl<L: FrameSetOn<ControlStreamKind>, I, M: core::fmt::Debug> core::fmt::Debug
    for ControlStream<L, I, M>
where
    L::FrameType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ControlStream")
            .field("frames", &self.frames)
            .finish()
    }
}

/// The frame a [`ControlStream`] on `I`, whose bytes carry the metadata `M`,
/// gives.
pub type ControlFrame<'s, L, I, M = ()> = Frame<
    FrameType<<L as FrameSetOn<ControlStreamKind>>::FrameType>,
    &'s mut FramePayload<Composed<I, CriticalStream>>,
    M,
>;

/// The failure of reading a [`ControlStream`] on `I`.
pub type ControlStreamErrorOf<I> =
    ControlStreamError<<<Composed<I, CriticalStream> as ReceiverAccess>::Family as Read>::Error>;

/// Failures of reading the frames of a [`ControlStream`] after the first,
/// from a stream whose failures are `E`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ControlStreamError<E> {
    /// The next frame could not be read.
    #[snafu(display("could not read the next frame of the control stream"))]
    Next {
        /// The failure of reading it.
        source: NextFrameError<E>,
    },
    /// A second SETTINGS frame ([RFC 9114 §7.2.4]).
    ///
    /// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
    #[snafu(display("received a second SETTINGS frame on the control stream"))]
    SecondSettings,
}

/// The code of the failure of reading the next frame; H3_FRAME_UNEXPECTED
/// for a second SETTINGS frame.
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ControlStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Next { source } => source.error_code(),
            Self::SecondSettings => Some(ErrorCode::H3_FRAME_UNEXPECTED),
        }
    }
}

/// Whether the frame type is SETTINGS.
fn is_settings<C: ClaimedValue>(frame_type: FrameType<C>) -> bool {
    matches!(frame_type, FrameType::Known(known) if known.value() == Http3FrameType::Settings.value())
}

impl<L: FrameSetOn<ControlStreamKind>, I: ReceiverAccess, M> ControlStream<L, I, M>
where
    Composed<I, CriticalStream>: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin + Clone,
{
    /// The current frame, as [`FrameStream::frame`] gives it. The first one
    /// is SETTINGS ([RFC 9114 §6.2.1]): the stream is read only if it is.
    ///
    /// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
    pub fn frame(&mut self) -> ControlFrame<'_, L, I, M> {
        self.frames.frame()
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I: ReceiverAccess, M> ControlStream<L, I, M>
where
    Composed<I, CriticalStream>:
        ReceiverAccess<Family: Skip<Count: Clone + Min<u64, Output = u64>, Metadata = M>>,
    M: Combine + Unpin + Clone,
    u64: Min<
            <<Composed<I, CriticalStream> as ReceiverAccess>::Family as Skip>::Count,
            Output = <<Composed<I, CriticalStream> as ReceiverAccess>::Family as Skip>::Count,
        >,
    Infinite: Min<
            <<Composed<I, CriticalStream> as ReceiverAccess>::Family as Skip>::Count,
            Output = <<Composed<I, CriticalStream> as ReceiverAccess>::Family as Skip>::Count,
        >,
{
    /// Moves to the next frame, as [`FrameStream::next_frame`] does. The
    /// stream never ends: its end is a failure. The first frame was SETTINGS,
    /// and no later frame may be.
    ///
    /// # Errors
    ///
    /// [`ControlStreamError`], whose failures of the stream are
    /// [`CriticalStreamError`].
    pub async fn next_frame(
        &mut self,
    ) -> Result<ControlFrame<'_, L, I, M>, ControlStreamErrorOf<I>> {
        let frame = self
            .frames
            .next_frame()
            .await
            .context(control_stream_error::NextSnafu)?
            // invariant: a critical stream reports its end as a failure.
            .expect("a critical stream does not end");
        if is_settings(frame.frame_type()) {
            return Err(ControlStreamError::SecondSettings);
        }
        Ok(frame)
    }

    /// Moves to the next frame of a known type, as
    /// [`FrameStream::next_known_frame`] does.
    ///
    /// # Errors
    ///
    /// [`ControlStreamError`], as for [`next_frame`](Self::next_frame).
    pub async fn next_known_frame(
        &mut self,
    ) -> Result<ControlFrame<'_, L, I, M>, ControlStreamErrorOf<I>> {
        let frame = self
            .frames
            .next_known_frame()
            .await
            .context(control_stream_error::NextSnafu)?
            // invariant: as for next_frame.
            .expect("a critical stream does not end");
        if is_settings(frame.frame_type()) {
            return Err(ControlStreamError::SecondSettings);
        }
        Ok(frame)
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I: ReceiverAccess, M> ControlStream<L, I, M> {
    /// The access, giving up the stream.
    pub fn into_io(self) -> I {
        self.frames.into_io().into_parts().0
    }
}

impl<L: FrameSetOn<ControlStreamKind>, I, M> TypedStream for ControlStream<L, I, M> {
    fn stream_type(&self) -> VarInt {
        Http3StreamType::Control.value()
    }
}

/// A push stream ([RFC 9114 §6.2.2]): its Push ID, and its frames.
///
/// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
pub struct PushStream<L: FrameSetOn<PushStreamKind>, I, M = ()> {
    push_id: ReadValue<VarIntField<PushId>, M>,
    frames: FrameStream<L, PushStreamKind, I, M>,
}

impl<L: FrameSetOn<PushStreamKind>, I, M: core::fmt::Debug> core::fmt::Debug for PushStream<L, I, M>
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

impl<L: FrameSetOn<PushStreamKind>, I, M> PushStream<L, I, M> {
    /// The Push ID, at the width it had on the wire. Whether it is within
    /// the permitted range is a question for the connection.
    pub const fn push_id(&self) -> VarIntField<PushId> {
        self.push_id.value
    }

    /// The metadata of the bytes of the Push ID.
    pub const fn push_id_metadata(&self) -> &M {
        &self.push_id.metadata
    }

    /// The frames of the stream.
    pub fn frames(&mut self) -> &mut FrameStream<L, PushStreamKind, I, M> {
        &mut self.frames
    }

    /// The Push ID, with the metadata of its bytes, and the frames of the
    /// stream.
    #[allow(clippy::type_complexity)] // The Push ID with its metadata, and the frames.
    pub fn into_parts(
        self,
    ) -> (
        ReadValue<VarIntField<PushId>, M>,
        FrameStream<L, PushStreamKind, I, M>,
    ) {
        (self.push_id, self.frames)
    }
}

impl<L: FrameSetOn<PushStreamKind>, I, M> TypedStream for PushStream<L, I, M> {
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
        /// The failure of reading its head; the end of the stream is a
        /// failure of the stream, [`CriticalStreamError::Closed`].
        source: ReadFrameHeadError<CriticalStreamError<E>>,
    },
    /// The first frame of a control stream is not SETTINGS ([RFC 9114
    /// §6.2.1]).
    ///
    /// [RFC 9114 §6.2.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1
    #[snafu(display(
        "the first frame of a control stream has the type {frame_type:?}, not SETTINGS"
    ))]
    MissingSettings {
        /// The type of the first frame.
        frame_type: VarInt,
    },
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

/// H3_CLOSED_CRITICAL_STREAM for a control stream that ended, and
/// H3_MISSING_SETTINGS for one whose first frame is not SETTINGS; the code of
/// a frame head that was rejected or cut short. `None` when the stream fails,
/// or a push stream ends before its frames, which a receiver tolerates.
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for Http3UnidirectionalStreamError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Control { source } => source.error_code(),
            Self::MissingSettings { .. } => Some(ErrorCode::H3_MISSING_SETTINGS),
            Self::Push { source } => source.error_code(),
            Self::PushId { source } => source.host_error().and_then(ErrorCodeOf::error_code),
            Self::PushEnded => None,
        }
    }
}

/// Reads what follows the type `stream_type` of a unidirectional stream
/// received by an endpoint of role `role`.
async fn read_unidirectional<L, I, M>(
    stream_type: Http3StreamType,
    role: Role,
    mut io: I,
) -> Result<
    Http3UnidirectionalStreamOf<L, I, M>,
    Http3UnidirectionalStreamError<<I::Family as Read>::Error>,
>
where
    L: FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
    I: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    use http3_unidirectional_stream_error::{
        ControlSnafu, MissingSettingsSnafu, PushIdSnafu, PushSnafu,
    };
    Ok(match stream_type {
        Http3StreamType::Control => {
            // invariant: a critical stream reports its end as a failure.
            let frames: FrameStream<L, ControlStreamKind, _, M> =
                FrameStream::read(Composed::new(io, CriticalStream), role)
                    .await
                    .context(ControlSnafu)?
                    .expect("a critical stream does not end");
            // The first frame is SETTINGS; a reserved or unknown one is not.
            let settings = Http3FrameType::Settings.value();
            if !matches!(frames.r#type.value.get(), FrameType::Known(known) if known.value() == settings)
            {
                return MissingSettingsSnafu {
                    frame_type: frames.r#type.value.to_var_int(),
                }
                .fail();
            }
            Http3UnidirectionalStream::Control(ControlStream { frames })
        }
        Http3StreamType::Push => {
            let push_id = ReadValue::<VarIntField<PushId>, M>::decode_from(&mut io)
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

/// A push stream that a client opened: only servers push ([RFC 9114
/// §6.2.2]), so it is a connection error of type H3_STREAM_CREATION_ERROR.
///
/// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientPushStreamError;

impl core::fmt::Display for ClientPushStreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a client opened a push stream")
    }
}

impl core::error::Error for ClientPushStreamError {}

/// H3_STREAM_CREATION_ERROR.
impl ErrorCodeOf<ErrorCode> for ClientPushStreamError {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(ErrorCode::H3_STREAM_CREATION_ERROR)
    }
}

/// A bidirectional stream that a server opened, which HTTP/3 does not use
/// ([RFC 9114 §6.1]): a connection error of type H3_STREAM_CREATION_ERROR
/// unless an extension claims it.
///
/// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ServerBidirectionalStreamError;

impl core::fmt::Display for ServerBidirectionalStreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("a server opened a bidirectional stream")
    }
}

impl core::error::Error for ServerBidirectionalStreamError {}

/// H3_STREAM_CREATION_ERROR.
impl ErrorCodeOf<ErrorCode> for ServerBidirectionalStreamError {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(ErrorCode::H3_STREAM_CREATION_ERROR)
    }
}

macro_rules! unidirectional_part {
    ($class:ty, $rejection:ty, $judge:expr) => {
        impl<L> StreamPart<$class, L> for Part
        where
            L: FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
        {
            type Claimed = Http3StreamType;
            type Rejection = $rejection;
            type Stream<I, M> = Http3UnidirectionalStreamOf<L, I, M>;
            type ReadError<E> = Http3UnidirectionalStreamError<E>;

            fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<Http3StreamType, $rejection> {
                let judge: fn(Http3StreamType) -> StreamVerdict<Http3StreamType, $rejection> =
                    $judge;
                Http3StreamType::of(value).map_or(StreamVerdict::NotClaimed, judge)
            }

            async fn read<
                I: ReceiverAccess<Family: Read<Metadata = M>>,
                M: Combine + Unpin + Clone,
            >(
                claimed: Http3StreamType,
                _field: ReadValue<VarIntField<VarInt>, M>,
                io: I,
            ) -> Result<
                Self::Stream<I, M>,
                Http3UnidirectionalStreamError<<I::Family as Read>::Error>,
            > {
                read_unidirectional(claimed, <$class as StreamClass>::RECEIVER, io).await
            }
        }
    };
}

// A server receives client-initiated streams, and only servers push
// (RFC 9114 §6.2.2).
unidirectional_part!(
    ClientInitiatedUnidirectional,
    ClientPushStreamError,
    |stream_type| match stream_type {
        Http3StreamType::Push => StreamVerdict::Error(ClientPushStreamError),
        stream_type => StreamVerdict::Claimed(stream_type),
    }
);
unidirectional_part!(ServerInitiatedUnidirectional, CNil, StreamVerdict::Claimed);

/// A client-initiated bidirectional stream is a request stream when its
/// first frame that is not reserved has a type the list has on request
/// streams ([RFC 9114 §6.1]); HTTP/3 does not take a stream that starts with
/// any other frame, so an application that reads such frames adds the part
/// that has them on request streams. A type of HTTP/2, a frame type of
/// HTTP/3 for other streams, or one the server does not receive, is a
/// connection error of type H3_FRAME_UNEXPECTED; so is a frame type another
/// part has for other streams, unless a part claims the stream.
///
/// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
impl<L: FrameSetOn<RequestStreamKind>> StreamPart<ClientInitiatedBidirectional, L> for Part {
    type Claimed = ();
    type Rejection = UnexpectedFrameTypeError;
    type Stream<I, M> = FrameStream<L, RequestStreamKind, I, M>;
    type ReadError<E> = ReadFrameHeadError<E>;

    fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<(), UnexpectedFrameTypeError> {
        let receiver = <ClientInitiatedBidirectional as StreamClass>::RECEIVER;
        match check_frame_type::<L, RequestStreamKind>(value, receiver) {
            Ok(FrameType::Known(_)) => StreamVerdict::Claimed(()),
            Ok(FrameType::Reserved(_) | FrameType::Unknown(_)) => StreamVerdict::NotClaimed,
            // Another part may take a stream that starts with a frame of its
            // own for other streams, as WebTransport does with 0x41.
            Err(rejection @ UnexpectedFrameTypeError::NotAllowedOnStream { .. })
                if Http3FrameType::of(value).is_none() =>
            {
                StreamVerdict::ErrorUnlessClaimed(rejection)
            }
            Err(rejection) => StreamVerdict::Error(rejection),
        }
    }

    async fn read<I: ReceiverAccess<Family: Read<Metadata = M>>, M: Combine + Unpin + Clone>(
        (): (),
        field: ReadValue<VarIntField<VarInt>, M>,
        io: I,
    ) -> Result<
        FrameStream<L, RequestStreamKind, I, M>,
        ReadFrameHeadError<<I::Family as Read>::Error>,
    > {
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
    type Rejection = ServerBidirectionalStreamError;
    type Stream<I, M> = CNil;
    type ReadError<E> = CNil;

    fn judge(
        _value: VarInt,
        _skipped: bool,
    ) -> StreamVerdict<CNil, ServerBidirectionalStreamError> {
        StreamVerdict::ErrorUnlessClaimed(ServerBidirectionalStreamError)
    }

    async fn read<I: ReceiverAccess<Family: Read<Metadata = M>>, M: Combine + Unpin + Clone>(
        claimed: CNil,
        _field: ReadValue<VarIntField<VarInt>, M>,
        _io: I,
    ) -> Result<CNil, CNil> {
        match claimed {}
    }
}
