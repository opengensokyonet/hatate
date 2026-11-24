//! Reading and writing frame heads, writing frames whose payload comes
//! from a source, reading the Push ID of a PUSH_PROMISE, and discarding a
//! payload.
use super::{
    FrameHead, FrameType, FrameWidths, Http2FrameType, Http2FrameTypeError, Http3FrameType, PushId,
    set::FrameSet,
};
use crate::error_code::{ErrorCode, ErrorCodeOf};
use core::{future::poll_fn, marker::PhantomData, num::NonZeroU64, task::Poll};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, calls::WriteAllError, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField, VarIntWidth, VarIntWidthError,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// Reads the Type and Length of the next frame, and looks the type up in
/// the list of parts `S`, which `parts` names.
///
/// Returns `None` if the stream ends before the first byte: at a frame
/// boundary. The payload follows; compose [`FrameHead::payload`] onto the
/// stream to consume it.
///
/// # Errors
///
/// [`ReadFrameHeadError`]; its [`ErrorCodeOf::error_code`] gives the
/// connection error the failure calls for, if any.
#[call(sync)]
pub async fn read_frame_head<S: FrameSet, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    parts: PhantomData<S>,
) -> Result<Option<FrameHead<S::TypeValue>>, ReadFrameHeadError<F::Error>> {
    let type_field = match io.read_var_int_field::<VarInt>().await {
        Ok(field) => field,
        Err(error) if error.is_incomplete() && error.completed() == 0 => return Ok(None),
        Err(source) => return Err(ReadFrameHeadError::Type { source }),
    };
    let value = type_field.get();
    if let Some(frame_type) = Http2FrameType::of(value) {
        return Err(ReadFrameHeadError::Http2Type {
            source: Http2FrameTypeError::new(frame_type),
        });
    }
    let length = io
        .read_var_int_field::<VarInt>()
        .await
        .context(read_frame_head_error::LengthSnafu)?;
    let _ = parts;
    let frame_type = S::type_value_of(value).map_or(FrameType::Unknown(value), FrameType::Known);
    Ok(Some(FrameHead {
        frame_type,
        type_field,
        length,
    }))
}

/// Failures of [`read_frame_head`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadFrameHeadError<E> {
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
    /// The type is one HTTP/2 defines and HTTP/3 does not.
    #[snafu(display("received a frame type of HTTP/2"))]
    Http2Type {
        /// The type received.
        source: Http2FrameTypeError,
    },
}

/// H3_FRAME_ERROR when the stream ends inside the head of a frame
/// ([RFC 9114 §7.1]), on a stream that ended cleanly; H3_FRAME_UNEXPECTED
/// for an HTTP/2 type ([RFC 9114 §7.2.8]). `None` when the stream itself
/// failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
impl<E> ErrorCodeOf<ErrorCode> for ReadFrameHeadError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Type { source } | Self::Length { source } => {
                source.is_incomplete().then_some(ErrorCode::H3_FRAME_ERROR)
            }
            Self::Http2Type { .. } => Some(ErrorCode::H3_FRAME_UNEXPECTED),
        }
    }
}

/// Writes the Type and Length of a frame, each at its width.
///
/// For the frames of a part's own; the frames of RFC 9114 have writers
/// that compute the Length from the payload. The payload must follow, of
/// exactly `length` bytes.
///
/// # Errors
///
/// [`WriteFrameHeadError`]. A type of HTTP/2 is reported before anything
/// is written; bytes accepted before a later failure stay written.
#[call(sync)]
pub async fn write_frame_head<F: Write, A: ReceiverAccess<Family = F>>(
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

/// Failures of [`write_frame_head`].
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

/// Writes a frame whose payload is the whole of `payload`: DATA, HEADERS,
/// or the frame of a type this crate does not read. The Length is the
/// exact length `payload` reports, at `length_width`.
///
/// Returns the length of the payload. Write the types of RFC 9114 with
/// [`Http3FrameType::value`]; a type of HTTP/2 is rejected.
///
/// # Errors
///
/// [`WritePayloadFrameError`]. A Length that cannot be written and a type
/// of HTTP/2 are reported before anything is written; a failure after that
/// leaves the stream inside the frame.
#[call(sync)]
pub async fn write_payload_frame<
    R: Read + ExactLen,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    payload: &mut P,
    type_field: VarIntField<VarInt>,
    length_width: VarIntWidth,
) -> Result<u64, WritePayloadFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let length = exact_length(payload)
        .await
        .context(write_payload_frame_error::LengthSnafu)?;
    let length_field =
        length_field(length, 0, length_width).context(write_payload_frame_error::LengthSnafu)?;
    io.write_frame_head(type_field, length_field)
        .await
        .context(write_payload_frame_error::HeadSnafu)?;
    copy_payload(io, payload, length)
        .await
        .context(write_payload_frame_error::PayloadSnafu)?;
    Ok(length)
}

/// Failures of [`write_payload_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WritePayloadFrameError<R, W> {
    /// The Length cannot state the payload.
    #[snafu(display("could not encode frame length"))]
    Length {
        /// Why the Length cannot be written.
        source: FrameLengthError,
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
    io.write_frame_head(type_field, length_field)
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
        let request = remaining.min(buffer.len() as u64) as usize;
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
/// `io` is the payload, a [`FramePayload`](super::payload::FramePayload)
/// composed onto the request stream.
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

/// Reads and discards the rest of a source, such as the payload of a frame
/// of an unknown type, and returns how many bytes it discarded.
///
/// # Errors
///
/// The source's error; the bytes read before it stay consumed.
#[call(sync)]
pub async fn discard<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> Result<u64, F::Error> {
    let mut buffer = [0; 256];
    let mut discarded = 0u64;
    loop {
        let count = io.read(&mut &mut buffer[..]).await?;
        if count == 0 {
            return Ok(discarded);
        }
        discarded += count as u64;
    }
}
