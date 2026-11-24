//! Reading and checking frame heads, writing frames and frame heads, and
//! reading the Push ID of a PUSH_PROMISE.
use super::{
    Frame, FrameType, FrameWidths, Http2FrameType, Http2FrameTypeError, Http3FrameType, PushId,
    set::{FrameKind, FrameSetOn},
};
use crate::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    stream::kind::StreamKind,
};
use core::{future::poll_fn, num::NonZeroU64, task::Poll};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, calls::WriteAllError, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField, VarIntWidth, VarIntWidthError,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// The Type of the next frame, or `None` at the end of the stream.
pub(crate) async fn read_type<I: ReceiverAccess<Family: Read>>(
    io: &mut I,
) -> Result<Option<VarIntField<VarInt>>, ReadFrameError<<I::Family as Read>::Error>> {
    match io.read_var_int_field::<VarInt>().await {
        Ok(field) => Ok(Some(field)),
        Err(error) if error.is_incomplete() && error.completed() == 0 => Ok(None),
        Err(source) => Err(ReadFrameError::Type { source }),
    }
}

pub(crate) async fn read_length<I: ReceiverAccess<Family: Read>>(
    io: &mut I,
) -> Result<VarIntField<VarInt>, ReadFrameError<<I::Family as Read>::Error>> {
    io.read_var_int_field::<VarInt>()
        .await
        .context(read_frame_error::LengthSnafu)
}

/// Failures of reading the Type and Length of a frame.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadFrameError<E> {
    /// The Type could not be read: the stream failed, or ended after the
    /// first byte of the Type.
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
/// ([RFC 9114 §7.1]), on a stream that ended cleanly; otherwise the code of
/// the stream's own failure, such as H3_CLOSED_CRITICAL_STREAM on a critical
/// stream.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadFrameError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
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

/// Writes the Type and Length of a frame, each at its width: the step every
/// writer of a frame takes before its payload, which must follow, of exactly
/// `length` bytes. A type of HTTP/2 is reported before anything is written.
pub(crate) async fn write_head<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    type_field: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
) -> Result<(), WriteFrameHeadError<F::Error>> {
    if let Some(frame_type) = Http2FrameType::of(type_field.get()) {
        return Err(WriteFrameHeadError::Http2Type {
            source: Http2FrameTypeError::new(frame_type),
        });
    }
    io.write_var_int_field(type_field)
        .await
        .context(write_frame_head_error::TypeSnafu)?;
    io.write_var_int_field(length)
        .await
        .context(write_frame_head_error::LengthSnafu)
}

/// Failures of writing the Type and Length of a frame.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteFrameHeadError<E> {
    /// The type is one HTTP/2 defines and HTTP/3 does not, which must not
    /// be sent.
    #[snafu(display("cannot send a frame type of HTTP/2"))]
    Http2Type {
        /// The type given.
        source: Http2FrameTypeError,
    },
    /// The Type could not be written.
    #[snafu(display("could not write frame type"))]
    Type {
        /// The failure of writing the integer.
        source: WriteVarIntError<E>,
    },
    /// The Length could not be written.
    #[snafu(display("could not write frame length"))]
    Length {
        /// The failure of writing the integer.
        source: WriteVarIntError<E>,
    },
}

/// Writes `frame`: its Type and Length, each at its width, and then its
/// payload, a source of exactly Length bytes, such as the bytes of a DATA
/// or HEADERS frame, or of a frame of a type this crate does not read.
///
/// The Type is any type that gives its value on the wire: a frame read from
/// a [`FrameStream`](crate::stream::FrameStream), whose type is a
/// [`FrameType`], is written back as it was read; write the types of RFC 9114
/// as [`Http3FrameType`], and others as a raw `VarInt`. A type of HTTP/2 is
/// rejected. Pass the payload as a `&mut` borrow to keep it.
///
/// # Errors
///
/// [`WriteFrameError`]. A payload whose exact length is not the Length and
/// a type of HTTP/2 are reported before anything is written; a failure
/// after that leaves the stream inside the frame.
#[call(sync)]
pub async fn write_frame<
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
    R: Read + ExactLen,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    frame: Frame<T, P>,
) -> Result<(), WriteFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let length = frame.length;
    // invariant: the field held the value at its width when it was made.
    let r#type = VarIntField::new(frame.r#type.to_var_int(), frame.r#type.width())
        .expect("a field's width holds its value");
    let mut payload = frame.payload;
    let remaining =
        poll_fn(|cx| payload.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len())))
            .await;
    // A length that does not fit a u64 is not the Length either.
    let payload_length = remaining.try_into().ok();
    let declared = length.get().get();
    if payload_length != Some(declared) {
        return Err(WriteFrameError::Length {
            source: FrameLengthMismatchError {
                length: length.get(),
                payload: payload_length,
            },
        });
    }
    write_head(io, r#type, length)
        .await
        .context(write_frame_error::HeadSnafu)?;
    copy_payload(io, &mut payload, declared)
        .await
        .context(write_frame_error::PayloadSnafu)
}

/// Failures of [`write_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteFrameError<R, W> {
    /// The exact length of the payload is not the Length.
    #[snafu(transparent)]
    Length {
        /// The Length and the length of the payload.
        source: FrameLengthMismatchError,
    },
    /// The head could not be written.
    #[snafu(display("could not write frame head"))]
    Head {
        /// The failure of writing the head.
        source: WriteFrameHeadError<W>,
    },
    /// The payload could not be copied from its source.
    #[snafu(display("could not write frame payload"))]
    Payload {
        /// The failure of copying it.
        source: CopyPayloadError<R, W>,
    },
}

/// The exact length of the payload of a frame to write is not its Length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("frame payload length is not the Length {}", length.get()))]
pub struct FrameLengthMismatchError {
    length: VarInt,
    payload: Option<u64>,
}

impl FrameLengthMismatchError {
    /// The value of the Length.
    pub const fn length(&self) -> VarInt {
        self.length
    }

    /// The exact length the payload reports, if it fits a `u64`; it is not
    /// the Length.
    pub const fn payload(&self) -> Option<u64> {
        self.payload
    }
}

/// Writes a PUSH_PROMISE frame: `push_id`, then the encoded field section
/// that `section` holds. The Length is the length of both, at the width in
/// `widths`.
///
/// # Errors
///
/// [`WritePushPromiseFrameError`]. A Length that cannot be written is
/// reported before anything is written; a failure after that leaves the
/// stream inside the frame.
#[call(sync)]
pub async fn write_push_promise_frame<
    R: Read + ExactLen,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    section: &mut P,
    widths: FrameWidths,
    push_id: VarIntField<PushId>,
) -> Result<(), WritePushPromiseFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let section_length = exact_length(section)
        .await
        .context(write_push_promise_frame_error::LengthSnafu)?;
    let length_field = length_field(
        section_length,
        push_id.encoded_len() as u64,
        widths.length_width(),
    )
    .context(write_push_promise_frame_error::LengthSnafu)?;
    let type_field = VarIntField::new(Http3FrameType::PushPromise.value(), widths.type_width())
        .expect("every width holds the frame type 0x05");
    write_head(io, type_field, length_field)
        .await
        .context(write_push_promise_frame_error::HeadSnafu)?;
    io.write_var_int_field(push_id)
        .await
        .context(write_push_promise_frame_error::PushIdSnafu)?;
    copy_payload(io, section, section_length)
        .await
        .context(write_push_promise_frame_error::SectionSnafu)
}

/// Failures of [`write_push_promise_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WritePushPromiseFrameError<R, W> {
    /// The Length cannot state the push ID and the field section.
    #[snafu(display("could not encode PUSH_PROMISE length"))]
    Length {
        /// Why the Length cannot be written.
        source: FrameLengthError,
    },
    /// The head could not be written.
    #[snafu(display("could not write PUSH_PROMISE head"))]
    Head {
        /// The failure of writing the head.
        source: WriteFrameHeadError<W>,
    },
    /// The push ID could not be written.
    #[snafu(display("could not write push ID"))]
    PushId {
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
    /// The field section could not be copied from its source.
    #[snafu(display("could not write PUSH_PROMISE field section"))]
    Section {
        /// The failure of copying it.
        source: CopyPayloadError<R, W>,
    },
}

/// The Length of a frame cannot be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(module)]
pub enum FrameLengthError {
    /// The payload is longer than a variable-length integer can state.
    #[snafu(display("frame payload length exceeds 2^62 - 1"))]
    OutOfRange,
    /// The Length does not fit the requested width.
    #[snafu(display("frame length does not fit its width"))]
    Width {
        /// The length and the width.
        source: VarIntWidthError,
    },
}

/// Copying the bytes of a payload from its source to the stream failed.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum CopyPayloadError<R, W> {
    /// The source ended before the length it reported.
    #[snafu(display("frame payload source ended with {missing} bytes missing"))]
    ShortSource {
        /// Bytes of the reported length that the source did not supply.
        missing: NonZeroU64,
    },
    /// The source failed.
    #[snafu(display("could not read frame payload source"))]
    Read {
        /// The source's error.
        source: R,
    },
    /// The bytes could not be written.
    #[snafu(display("could not write frame payload"))]
    Send {
        /// The failure and the bytes accepted in this write.
        source: WriteAllError<W>,
    },
}

/// The exact remaining length of `source`.
async fn exact_length<R: Read + ExactLen, P: ReceiverAccess<Family = R>>(
    source: &mut P,
) -> Result<u64, FrameLengthError>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let length =
        poll_fn(|cx| source.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len()))).await;
    // A length that does not fit a u64 exceeds 2^62 - 1 too.
    length.try_into().map_err(|_| FrameLengthError::OutOfRange)
}

/// The Length field for `length` bytes from the source after `prefix`
/// bytes of fields.
pub(crate) fn length_field(
    length: u64,
    prefix: u64,
    width: VarIntWidth,
) -> Result<VarIntField<VarInt>, FrameLengthError> {
    let total = length
        .checked_add(prefix)
        .and_then(|total| VarInt::new(total).ok())
        .ok_or(FrameLengthError::OutOfRange)?;
    VarIntField::new(total, width).context(frame_length_error::WidthSnafu)
}

/// Copies exactly `length` bytes from `source` to `io`.
async fn copy_payload<
    R: Read,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    source: &mut P,
    length: u64,
) -> Result<(), CopyPayloadError<R::Error, F::Error>> {
    let mut remaining = length;
    let mut buffer = [0; 1024];
    while let Some(missing) = NonZeroU64::new(remaining) {
        let request = Ord::min(remaining, buffer.len() as u64) as usize;
        let count = source
            .read(&mut &mut buffer[..request])
            .await
            .context(copy_payload_error::ReadSnafu)?;
        if count == 0 {
            return Err(CopyPayloadError::ShortSource { missing });
        }
        // invariant: a read into a slice of `request` bytes fills at most
        // `request`, which is at most `remaining`.
        remaining = u64::try_from(count)
            .ok()
            .and_then(|count| remaining.checked_sub(count))
            .expect("a read fills at most its destination");
        io.write_all(&buffer[..count])
            .await
            .context(copy_payload_error::SendSnafu)?;
    }
    Ok(())
}

/// Reads the Push ID at the start of the payload of a PUSH_PROMISE frame
/// ([RFC 9114 §7.2.5]). The encoded field section follows it, to the end of
/// the payload.
///
/// `io` is the payload of the frame, a [`FramePayload`](crate::frame::payload::FramePayload) composed onto
/// the request stream.
///
/// A read dropped before it completes may have taken bytes of the Push ID,
/// and a later read would give a wrong one without failing: after such a
/// drop, do not read this frame again, and skip it with
/// [`FrameStream::next_frame`](crate::stream::FrameStream::next_frame).
///
/// # Errors
///
/// [`ReadPushPromisePushIdError`]; its [`ErrorCodeOf::error_code`] gives
/// the connection error it calls for.
///
/// [RFC 9114 §7.2.5]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.5
#[call(sync)]
pub async fn read_push_promise_push_id<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<VarIntField<PushId>, ReadPushPromisePushIdError<F::Error>> {
    io.read_var_int_field::<PushId>()
        .await
        .context(ReadPushPromisePushIdSnafu)
}

/// The Push ID of a PUSH_PROMISE could not be read: the payload ended
/// before it, or the stream failed.
#[derive(Debug, Snafu)]
#[snafu(display("could not read the push ID of PUSH_PROMISE"))]
pub struct ReadPushPromisePushIdError<E> {
    source: ReadVarIntError<E>,
}

impl<E> ReadPushPromisePushIdError<E> {
    /// The failure of reading the integer.
    pub const fn read_error(&self) -> &ReadVarIntError<E> {
        &self.source
    }
}

/// H3_FRAME_ERROR when the payload is shorter than the Push ID
/// ([RFC 9114 §7.1]); otherwise the code of the source's failure, such as
/// H3_FRAME_ERROR when the stream ended inside the frame. `None` when the
/// stream failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadPushPromisePushIdError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        payload_integer_error_code(&self.source)
    }
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
