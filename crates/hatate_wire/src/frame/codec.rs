//! Reading and writing frame heads, and writing frames whose payload comes
//! from a source.
use super::{
    FrameHead, FrameType, FrameWidths, Http2FrameType, Http3FrameType, PushId, set::FrameSet,
};
use crate::error_code::ErrorCode;
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
/// [`ReadFrameHeadError`]; [`ReadFrameHeadError::error_code`] gives the
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
        return Err(ReadFrameHeadError::Http2Type { frame_type });
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
    /// The Type could not be read after its first byte.
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
    #[snafu(display("received HTTP/2 frame type {frame_type:?}"))]
    Http2Type {
        /// The type received.
        frame_type: Http2FrameType,
    },
}

impl<E> ReadFrameHeadError<E> {
    /// The connection error this failure calls for: H3_FRAME_ERROR when the
    /// stream ends inside the head of a frame ([RFC 9114 §7.1]), on a stream
    /// that ended cleanly; H3_FRAME_UNEXPECTED for an HTTP/2 type
    /// ([RFC 9114 §7.2.8]). `None` when the stream itself failed.
    ///
    /// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
    /// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
    pub fn error_code(&self) -> Option<ErrorCode> {
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
/// [`WriteFrameHeadError`]; bytes accepted before the failure stay written.
#[call(sync)]
pub async fn write_frame_head<F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    type_field: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
) -> Result<(), WriteFrameHeadError<F::Error>> {
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
/// Returns the length of the payload. The frame type is not checked: write
/// the types of RFC 9114 with [`Http3FrameType::value`].
///
/// # Errors
///
/// [`WritePayloadFrameError`]. A Length that cannot be written is reported
/// before anything is written; a failure after that leaves the stream
/// inside the frame.
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
    let length = exact_length(payload).await?;
    let length_field = length_field(length, 0, length_width)?;
    io.write_frame_head(type_field, length_field)
        .await
        .context(write_payload_frame_error::HeadSnafu)?;
    transfer(io, payload, length).await?;
    Ok(length)
}

/// Writes a PUSH_PROMISE frame: `push_id`, then the encoded field section
/// that `section` holds. The Length is the length of both, at the width in
/// `widths`.
///
/// # Errors
///
/// As [`write_payload_frame`]; [`WritePayloadFrameError::PushId`] if the
/// push ID cannot be written.
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
) -> Result<(), WritePayloadFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let section_length = exact_length(section).await?;
    let length_field = length_field(
        section_length,
        push_id.encoded_len() as u64,
        widths.length_width(),
    )?;
    let type_field = VarIntField::new(Http3FrameType::PushPromise.value(), widths.type_width())
        .expect("every width holds the frame type 0x05");
    io.write_frame_head(type_field, length_field)
        .await
        .context(write_payload_frame_error::HeadSnafu)?;
    io.write_var_int_field(push_id)
        .await
        .context(write_payload_frame_error::PushIdSnafu)?;
    transfer(io, section, section_length).await
}

/// The exact remaining length of `source`.
async fn exact_length<R: Read + ExactLen, P: ReceiverAccess<Family = R>, W>(
    source: &mut P,
) -> Result<u64, WritePayloadFrameError<R::Error, W>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let length =
        poll_fn(|cx| source.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len()))).await;
    length
        .try_into()
        .map_err(|_| WritePayloadFrameError::LengthOutOfRange)
}

/// The Length field for `length` bytes from the source after `prefix`
/// bytes of fields.
fn length_field<R, W>(
    length: u64,
    prefix: u64,
    width: VarIntWidth,
) -> Result<VarIntField<VarInt>, WritePayloadFrameError<R, W>> {
    let total = length
        .checked_add(prefix)
        .and_then(|total| VarInt::new(total).ok())
        .ok_or(WritePayloadFrameError::LengthOutOfRange)?;
    VarIntField::new(total, width).context(write_payload_frame_error::LengthWidthSnafu)
}

/// Copies exactly `length` bytes from `source` to `io`.
async fn transfer<
    R: Read,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    source: &mut P,
    length: u64,
) -> Result<(), WritePayloadFrameError<R::Error, F::Error>> {
    let mut remaining = length;
    let mut buffer = [0; 1024];
    while let Some(missing) = NonZeroU64::new(remaining) {
        let request = remaining.min(buffer.len() as u64) as usize;
        let count = source
            .read(&mut &mut buffer[..request])
            .await
            .context(write_payload_frame_error::ReadSnafu)?;
        if count == 0 {
            return Err(WritePayloadFrameError::ShortSource { missing });
        }
        remaining -= count as u64;
        io.write_all(&buffer[..count])
            .await
            .context(write_payload_frame_error::SendSnafu)?;
    }
    Ok(())
}

/// Failures of [`write_payload_frame`] and [`write_push_promise_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WritePayloadFrameError<R, W> {
    /// The payload is longer than a variable-length integer can state.
    #[snafu(display("frame payload length exceeds 2^62 - 1"))]
    LengthOutOfRange,
    /// The Length does not fit the requested width.
    #[snafu(display("frame length does not fit its width"))]
    LengthWidth {
        /// The length and the width.
        source: VarIntWidthError,
    },
    /// The head could not be written.
    #[snafu(display("could not write frame head"))]
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
    /// The payload could not be written.
    #[snafu(display("could not write frame payload"))]
    Send {
        /// The failure and the bytes accepted in this write.
        source: WriteAllError<W>,
    },
}
