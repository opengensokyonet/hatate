//! Reading and checking frame heads, and decoding and encoding frames.
use super::{
    Frame, FrameType, Http2FrameType, Http2FrameTypeError,
    payload::{FramePayload, PayloadError},
    set::{FrameKind, FrameSetOn},
};
use crate::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    stream::kind::StreamKind,
};
use core::num::NonZeroU64;
use length_check::PayloadWriteLimit;
use nitori_call::{AsAccess, Composed};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{Combine, Read, Write, calls::ReadValue};
use sakuya_var_int::{
    VarInt, VarIntField,
    stream::{ReadVarIntError, WriteVarIntError},
};
use snafu::{ResultExt, Snafu};

pub mod length_check;

/// The Type of the next frame, with the metadata of its bytes, or `None` at
/// the end of the stream.
pub(crate) async fn read_type<S: AsAccess<Family: Read<Metadata = M>>, M: Combine + Unpin>(
    io: S,
) -> Result<Option<ReadValue<VarIntField<VarInt>, M>>, ReadFrameError<<S::Family as Read>::Error>> {
    match ReadValue::<VarIntField<VarInt>, M>::decode_from(io).await {
        Ok(field) => Ok(Some(field)),
        Err(error) if error.is_incomplete() && error.completed() == 0 => Ok(None),
        Err(source) => Err(ReadFrameError::Type { source }),
    }
}

/// The Length of a frame, with the metadata of its bytes.
pub(crate) async fn read_length<S: AsAccess<Family: Read<Metadata = M>>, M: Combine + Unpin>(
    io: S,
) -> Result<ReadValue<VarIntField<VarInt>, M>, ReadFrameError<<S::Family as Read>::Error>> {
    ReadValue::<VarIntField<VarInt>, M>::decode_from(io)
        .await
        .context(read_frame_error::LengthSnafu)
}

/// Failures of reading the Type and Length of a frame.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadFrameError<E> {
    /// The Type could not be read: the stream failed, or ended before the
    /// Type was whole. Ended before its first byte, the stream ended at a
    /// frame boundary, which [`FrameStream`](crate::stream::FrameStream)
    /// reports as the end of the frames.
    #[snafu(display("could not read frame type"))]
    Type {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The Length could not be read.
    #[snafu(display("could not read frame length"))]
    Length {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
}

/// H3_FRAME_ERROR when the stream ends inside the head of a frame
/// ([RFC 9114 §7.1]), on a stream that ended cleanly; none when it ends
/// before the first byte of the Type, at a frame boundary, which is not a
/// frame error; otherwise the code of the stream's own failure, such as
/// H3_CLOSED_CRITICAL_STREAM on a critical stream.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadFrameError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Type { source } if source.is_incomplete() && source.completed() == 0 => None,
            Self::Type { source } | Self::Length { source } => {
                if source.is_incomplete() {
                    return Some(ErrorCode::H3_FRAME_ERROR);
                }
                source.host_error().and_then(ErrorCodeOf::error_code)
            }
        }
    }
}

/// Checks the type `value` of a frame received on a stream of kind `K`
/// whose list of parts is `L`, at an endpoint of role `role`: a type of
/// HTTP/2, or one the list claims for other kinds of stream, is not
/// allowed there, and some types only one role receives.
pub(crate) fn check_frame_type<L: FrameSetOn<K>, K: StreamKind>(
    value: VarInt,
    role: Role,
) -> Result<FrameType<L::FrameType>, UnexpectedFrameTypeError> {
    // Evaluated when the function is generated for a concrete list, so a
    // list whose claims conflict does not build.
    const {
        assert!(
            L::CLAIMS_VALID,
            "the parts claim overlapping, reserved or HTTP/2 frame types"
        );
    }
    if let Some(frame_type) = Http2FrameType::of(value) {
        return Err(UnexpectedFrameTypeError::Http2Type {
            source: Http2FrameTypeError::new(frame_type),
        });
    }
    let frame_type = FrameType::<L::FrameType>::from(value);
    match frame_type {
        FrameType::Known(known) if !known.receivable_by(role) => {
            Err(UnexpectedFrameTypeError::NotReceivableByRole {
                frame_type: value,
                role,
            })
        }
        FrameType::Unknown(_) if L::FRAME_TYPES.contains(value) => {
            Err(UnexpectedFrameTypeError::NotAllowedOnStream { frame_type: value })
        }
        _ => Ok(frame_type),
    }
}

/// A frame type that may not arrive where it arrived ([RFC 9114 §7.2]): at
/// the start of a stream or later on it.
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(module)]
pub enum UnexpectedFrameTypeError {
    /// The type is one HTTP/2 defines and HTTP/3 does not.
    #[snafu(display("received a frame type of HTTP/2"))]
    Http2Type {
        /// The type received.
        source: Http2FrameTypeError,
    },
    /// A part of the list claims the type, but not on this kind of stream.
    #[snafu(display("frame type {frame_type} is not allowed on this kind of stream"))]
    NotAllowedOnStream {
        /// The type received.
        frame_type: VarInt,
    },
    /// An endpoint of this role may not receive a frame of this type
    /// ([`FrameKind::receivable_by`]).
    #[snafu(display("frame type {frame_type} may not be received by a {role:?}"))]
    NotReceivableByRole {
        /// The type received.
        frame_type: VarInt,
        /// The role of this endpoint.
        role: Role,
    },
}

/// H3_FRAME_UNEXPECTED, for an HTTP/2 type ([RFC 9114 §7.2.8]) and for a
/// frame where it may not arrive ([RFC 9114 §7.2]).
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
impl ErrorCodeOf<ErrorCode> for UnexpectedFrameTypeError {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(ErrorCode::H3_FRAME_UNEXPECTED)
    }
}

/// Failures of reading the head of a frame on a stream that carries frames
/// ([`FrameStream`](crate::stream::FrameStream)).
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadFrameHeadError<E> {
    /// The Type or Length could not be read.
    #[snafu(display("could not read frame head"))]
    Frame {
        /// The failure of reading it.
        source: ReadFrameError<E>,
    },
    /// The type may not arrive on this stream.
    #[snafu(display("received an unexpected frame type"))]
    Unexpected {
        /// Why it may not.
        source: UnexpectedFrameTypeError,
    },
}

/// The code of [`ReadFrameError`] for a head that could not be read, and of
/// [`UnexpectedFrameTypeError`].
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadFrameHeadError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Frame { source } => source.error_code(),
            Self::Unexpected { source } => source.error_code(),
        }
    }
}

/// Decodes a frame in stages: the Type and the Length now, and the payload,
/// a [`FramePayload`] that holds the source, for the caller to read
/// ([RFC 9114 §7.1]). The Type is read as a `VarInt` and converted to `T`.
///
/// Only frame types of HTTP/2 are rejected here: whether the type may appear
/// on the kind of stream it was read from, and whether this endpoint's role
/// receives it, are not checked. To read frame after frame, with those
/// checks and the skipping of what a frame leaves, read them on a
/// [`FrameStream`](crate::stream::FrameStream).
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<S, T, M> DecodeFrom<S> for Frame<T, FramePayload<S>, M>
where
    S: AsAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    type Error = DecodeFrameError<<S::Family as Read>::Error, T::Error>;

    async fn decode_from(mut source: S) -> Result<Self, Self::Error> {
        let r#type = ReadValue::<VarIntField<VarInt>, M>::decode_from(source.access())
            .await
            .map_err(|source| DecodeFrameError::Head {
                source: ReadFrameError::Type { source },
            })?;
        let value = r#type.value.get();
        if let Some(frame_type) = Http2FrameType::of(value) {
            return Err(DecodeFrameError::Http2Type {
                source: Http2FrameTypeError::new(frame_type),
            });
        }
        let frame_type = T::try_from(value).map_err(|source| DecodeFrameError::Type { source })?;
        let length = read_length(source.access())
            .await
            .map_err(|source| DecodeFrameError::Head { source })?;
        // invariant: the frame type is the value that was read at this width.
        let type_field =
            VarIntField::new(frame_type, r#type.value.width()).expect("the width held the value");
        let payload = FramePayload::new(source, length.value.get().get());
        Ok(Frame::from_parts(
            ReadValue {
                value: type_field,
                metadata: r#type.metadata,
            },
            length,
            payload,
        ))
    }
}

/// Decodes a whole frame: the Type and the Length, then the payload as a
/// `P` read from it ([`FramePayload::decode_to_end`]), which must take all of
/// it, such as `ReadValue<VarIntField<GoawayId>, M>` for a GOAWAY frame.
impl<S, T, P, M, E> DecodeFrom<S> for Frame<T, P, M>
where
    S: AsAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
    P: for<'a> DecodeFrom<&'a mut FramePayload<S>, Error = E>,
{
    type Error = DecodeWholeFrameError<<S::Family as Read>::Error, T::Error, E>;

    async fn decode_from(source: S) -> Result<Self, Self::Error> {
        let Frame {
            r#type,
            length,
            payload: mut staged,
        } = Frame::<T, FramePayload<S>, M>::decode_from(source)
            .await
            .map_err(|source| DecodeWholeFrameError::Frame { source })?;
        let payload = staged
            .decode_to_end::<P, E>()
            .await
            .map_err(|source| DecodeWholeFrameError::Payload { source })?;
        Ok(Frame::from_parts(r#type, length, payload))
    }
}

/// Failures of decoding a frame in stages, from a source whose failures are
/// `E`, into a frame whose Type converts from a `VarInt` failing with `T`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeFrameError<E, T> {
    /// The Type or Length could not be read.
    #[snafu(display("could not read frame head"))]
    Head {
        /// The failure of reading it.
        source: ReadFrameError<E>,
    },
    /// The type is one HTTP/2 defines and HTTP/3 does not.
    #[snafu(display("received a frame type of HTTP/2"))]
    Http2Type {
        /// The type received.
        source: Http2FrameTypeError,
    },
    /// The type is not one the Type field holds, such as a frame of another
    /// type for a field of one frame type ([`FrameTypeMismatchError`](super::FrameTypeMismatchError)).
    ///
    /// The source is then inside the head of the frame, after the Type and
    /// before the Length, and cannot be read on as frames: give it up. To
    /// pick frames by their type, read them on a
    /// [`FrameStream`](crate::stream::FrameStream).
    #[snafu(display("frame type does not convert to the type of the field"))]
    Type {
        /// The failure of converting it.
        source: T,
    },
}

/// The code of [`ReadFrameError`] for a head that could not be read;
/// H3_FRAME_UNEXPECTED for a type of HTTP/2 ([RFC 9114 §7.2.8]); `None`
/// for a type of another frame, which is not an error of the connection.
///
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
impl<E: ErrorCodeOf<ErrorCode>, T> ErrorCodeOf<ErrorCode> for DecodeFrameError<E, T> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Head { source } => source.error_code(),
            Self::Http2Type { .. } => Some(ErrorCode::H3_FRAME_UNEXPECTED),
            Self::Type { .. } => None,
        }
    }
}

/// Failures of decoding a whole frame: as [`DecodeFrameError`], and of
/// reading its payload, failing with `P`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeWholeFrameError<E, T, P> {
    /// The frame could not be decoded up to its payload.
    #[snafu(display("could not decode frame"))]
    Frame {
        /// The failure of decoding it.
        source: DecodeFrameError<E, T>,
    },
    /// The payload could not be read whole.
    #[snafu(display("could not decode frame payload"))]
    Payload {
        /// The failure of reading it.
        source: DecodeToEndError<P>,
    },
}

/// The code of the failure of decoding the frame or its payload.
impl<E: ErrorCodeOf<ErrorCode>, T, P: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode>
    for DecodeWholeFrameError<E, T, P>
{
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Frame { source } => source.error_code(),
            Self::Payload { source } => source.error_code(),
        }
    }
}

/// Failures of [`FramePayload::decode_to_end`]: of reading the value,
/// failing with `E`, or of the payload going on after it.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeToEndError<E> {
    /// The value could not be read.
    #[snafu(display("could not read the value of the frame payload"))]
    Value {
        /// The value's failure.
        source: E,
    },
    /// Bytes follow the value within the payload.
    #[snafu(display("frame payload continues for {left} bytes after its value"))]
    Unread {
        /// How many.
        left: NonZeroU64,
    },
}

/// H3_FRAME_ERROR when the payload goes on after its value ([RFC 9114
/// §7.1]); otherwise the code of the value's failure.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodeToEndError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Value { source } => source.error_code(),
            Self::Unread { .. } => Some(ErrorCode::H3_FRAME_ERROR),
        }
    }
}

/// H3_FRAME_ERROR when the payload of a frame ends inside the integer
/// ([RFC 9114 §7.1]); otherwise the code of the payload's failure, such as
/// H3_FRAME_ERROR when the stream ended inside the frame. `None` when the
/// stream failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadVarIntError<PayloadError<E>> {
    fn error_code(&self) -> Option<ErrorCode> {
        payload_integer_error_code(self)
    }
}

/// Encodes a frame: its Type and Length, each at its width, and then its
/// payload, which encodes itself into the sink held to the Length
/// ([`PayloadWriteLimit`]). The output is the merged report of the head and
/// the payload's output.
///
/// # Panics
///
/// When the payload writes more or fewer bytes than the Length, which it
/// does only if it, or the source it writes out, does not keep the length it
/// reported: such as a source whose exact length ([`ExactLen`](nitori_io::ExactLen))
/// is wrong, or a payload swapped for one of another length
/// ([`Frame::map_payload`]). A frame with such a payload would be written
/// with a head that does not match it. A frame that was read keeps the
/// Length of the wire, so to write it back its payload must write as many
/// bytes as it read: a payload that writes a value at another width than
/// the one it read, such as at its shortest, panics on a peer's longer
/// encoding.
impl<S, T, P, M, O, E> EncodeInto<S> for Frame<T, P, M>
where
    S: AsAccess<Family: Write<Report: Combine>>,
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
    P: for<'a> EncodeInto<
            Composed<&'a mut S::Access, &'a mut PayloadWriteLimit>,
            Output = O,
            Error = E,
        >,
{
    type Output = FrameOutput<<S::Family as Write>::Report, O>;
    type Error = EncodeFrameError<<S::Family as Write>::Error, E>;

    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        let r#type = self
            .r#type
            .value
            .encode_into(sink.access())
            .await
            .context(encode_frame_error::TypeSnafu)?;
        let length = self
            .length
            .value
            .encode_into(sink.access())
            .await
            .context(encode_frame_error::LengthSnafu)?;
        let mut limit = PayloadWriteLimit::new(self.length.value.get().get());
        let payload = self
            .payload
            .encode_into(Composed::new(sink.access(), &mut limit))
            .await
            .context(encode_frame_error::PayloadSnafu)?;
        limit.finish();
        Ok(FrameOutput {
            head: r#type.combine(length),
            payload,
        })
    }
}

/// What encoding a frame produced: the merged report `R` of writing its Type
/// and Length, and the output `O` of its payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameOutput<R, O> {
    /// The merged report of writing the Type and Length.
    pub head: R,
    /// What encoding the payload produced.
    pub payload: O,
}

/// Failures of encoding a frame into a sink whose failures are `W`, with a
/// payload whose failures are `P`. A failure leaves the stream inside the
/// frame.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeFrameError<W, P> {
    /// The Type could not be written.
    #[snafu(display("could not write frame type"))]
    Type {
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
    /// The Length could not be written.
    #[snafu(display("could not write frame length"))]
    Length {
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
    /// The payload could not be written.
    #[snafu(display("could not write frame payload"))]
    Payload {
        /// The payload's failure.
        source: P,
    },
}

/// The connection error for a failure reading an integer from a frame
/// payload: H3_FRAME_ERROR when the payload ended inside it, otherwise the
/// code of the source's failure.
pub(crate) fn payload_integer_error_code<E: ErrorCodeOf<ErrorCode>>(
    error: &ReadVarIntError<E>,
) -> Option<ErrorCode> {
    if error.is_incomplete() {
        return Some(ErrorCode::H3_FRAME_ERROR);
    }
    error.host_error().and_then(ErrorCodeOf::error_code)
}
