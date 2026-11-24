//! Reading frames, finishing them and moving on to the next one, writing
//! frames and frame heads, and reading the Push ID of a PUSH_PROMISE.
use super::{
    Frame, FrameType, FrameWidths, Http2FrameType, Http2FrameTypeError, Http3FrameType, PushId,
    ReceivedFrame,
    payload::{FramePayload, PayloadError},
    set::{FrameKind, FrameSet, FrameStreamKind},
};
use crate::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    stream::{FrameStreamInfo, FrameStreamInfoViewExt as _},
};
use core::{future::poll_fn, num::NonZeroU64, task::Poll};
use nitori_call::{Composed, ReceiverAccess, call};
use nitori_io::{ExactLen, Infinite, Min, calls::WriteAllError, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField, VarIntWidth, VarIntWidthError,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// Reads the Type and Length of the next frame from `io`, any source, and
/// returns the frame, whose payload is `io` composed with a
/// [`FramePayload`] of the Length.
///
/// `io` is passed through, by value; it can be a `&mut` borrow of an
/// access. The type is not looked up and nothing is checked about it; on a
/// stream that carries frames, [`read_received_frame`] does that.
///
/// Returns `None` if the stream ends before the first byte: at a frame
/// boundary. The stream stays inside the frame until the frame is finished
/// ([`Frame::finish`]).
///
/// # Errors
///
/// [`ReadFrameError`]; its [`ErrorCodeOf::error_code`] gives the
/// connection error the failure calls for, if any.
pub async fn read_frame<I: ReceiverAccess<Family: Read>>(
    mut io: I,
) -> Result<Option<Frame<Composed<I, FramePayload>>>, ReadFrameError<<I::Family as Read>::Error>> {
    let Some(r#type) = read_type(&mut io).await? else {
        return Ok(None);
    };
    let length = read_length(&mut io).await?;
    Ok(Some(payload_frame(io, r#type, length)))
}

/// The Type of the next frame, or `None` at the end of the stream.
async fn read_type<I: ReceiverAccess<Family: Read>>(
    io: &mut I,
) -> Result<Option<VarIntField<VarInt>>, ReadFrameError<<I::Family as Read>::Error>> {
    match io.read_var_int_field::<VarInt>().await {
        Ok(field) => Ok(Some(field)),
        Err(error) if error.is_incomplete() && error.completed() == 0 => Ok(None),
        Err(source) => Err(ReadFrameError::Type { source }),
    }
}

async fn read_length<I: ReceiverAccess<Family: Read>>(
    io: &mut I,
) -> Result<VarIntField<VarInt>, ReadFrameError<<I::Family as Read>::Error>> {
    io.read_var_int_field::<VarInt>()
        .await
        .context(read_frame_error::LengthSnafu)
}

/// The frame whose payload follows on `io`.
fn payload_frame<I: ReceiverAccess>(
    io: I,
    r#type: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
) -> Frame<Composed<I, FramePayload>> {
    let payload = Composed::new(io, FramePayload::new(length.get().get()));
    Frame::new(r#type, length, payload)
}

/// Failures of [`read_frame`].
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
/// ([RFC 9114 §7.1]), on a stream that ended cleanly. `None` when the
/// stream itself failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E> ErrorCodeOf<ErrorCode> for ReadFrameError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Type { source } | Self::Length { source } => {
                source.is_incomplete().then_some(ErrorCode::H3_FRAME_ERROR)
            }
        }
    }
}

/// The frame type value of the parts of the stream `I` reads.
type StreamTypeValue<I> =
    <<<I as ReceiverAccess>::Family as FrameStreamInfo>::Parts as FrameSet>::TypeValue;

/// The frame `read_received_frame` reads from `I`.
type ReceivedPayloadFrame<I> = ReceivedFrame<StreamTypeValue<I>, Composed<I, FramePayload>>;

/// The failure of `read_received_frame` on `I`.
type ReceivedFrameError<I> =
    ReadReceivedFrameError<<<I as ReceiverAccess>::Family as Read>::Error, StreamTypeValue<I>>;

/// Reads the next frame from `io`, a stream that carries frames: the
/// Type, which it looks up in the list of parts of the stream and checks
/// against the kind of the stream and the role of this endpoint, and the
/// Length. The payload is `io` composed with a [`FramePayload`] of the
/// Length.
///
/// `io` is passed through, by value; its family tells which stream it is
/// ([`FrameStreamInfo`]), as a stream composed with a
/// [`FrameStream`](crate::stream::FrameStream) does. A type that no part
/// claims is not checked; the caller normally skips its payload
/// ([RFC 9114 §9]).
///
/// Returns `None` if the stream ends before the first byte: at a frame
/// boundary. The stream stays inside the frame until the frame is finished
/// ([`ReceivedFrame::finish`]).
///
/// # Errors
///
/// [`ReadReceivedFrameError`]; its [`ErrorCodeOf::error_code`] gives the
/// connection error the failure calls for, if any. A type is rejected before
/// the Length is read.
///
/// [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
pub async fn read_received_frame<I>(
    mut io: I,
) -> Result<Option<ReceivedPayloadFrame<I>>, ReceivedFrameError<I>>
where
    I: ReceiverAccess<Family: Read + FrameStreamInfo<Parts: FrameSet>>,
{
    let stream =
        poll_fn(|cx| io.poll_access(cx, |mut view, _| Poll::Ready(view.frame_stream()))).await;
    let Some(r#type) = read_type(&mut io)
        .await
        .context(read_received_frame_error::FrameSnafu)?
    else {
        return Ok(None);
    };
    let value = r#type.get();
    if let Some(frame_type) = Http2FrameType::of(value) {
        return Err(ReadReceivedFrameError::Http2Type {
            source: Http2FrameTypeError::new(frame_type),
        });
    }
    type Parts<I> = <<I as ReceiverAccess>::Family as FrameStreamInfo>::Parts;
    let frame_type = match <Parts<I> as FrameSet>::type_value_of(value) {
        Some(frame_type) => {
            let kind = <Parts<I> as FrameSet>::kind_of(frame_type);
            if !kind.allowed_on(stream.kind()) {
                return Err(ReadReceivedFrameError::NotAllowedOnStream {
                    frame_type,
                    stream: stream.kind(),
                });
            }
            if !kind.receivable_by(stream.role()) {
                return Err(ReadReceivedFrameError::NotReceivableByRole {
                    frame_type,
                    role: stream.role(),
                });
            }
            FrameType::Known(frame_type)
        }
        None => FrameType::Unknown(value),
    };
    let length = read_length(&mut io)
        .await
        .context(read_received_frame_error::FrameSnafu)?;
    Ok(Some(ReceivedFrame::new(
        frame_type,
        payload_frame(io, r#type, length),
    )))
}

/// Failures of [`read_received_frame`]. `T` is the frame type value of
/// the list of parts of the stream.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadReceivedFrameError<E, T> {
    /// The Type or Length could not be read.
    #[snafu(display("could not read frame head"))]
    Frame {
        /// The failure of reading it.
        source: ReadFrameError<E>,
    },
    /// The type is one HTTP/2 defines and HTTP/3 does not.
    #[snafu(display("received a frame type of HTTP/2"))]
    Http2Type {
        /// The type received.
        source: Http2FrameTypeError,
    },
    /// A frame of this type may not appear on this kind of stream
    /// ([`FrameKind::allowed_on`]).
    #[snafu(display("frame type is not allowed on a stream of kind {stream:?}"))]
    NotAllowedOnStream {
        /// The type received.
        frame_type: T,
        /// The kind of the stream.
        stream: FrameStreamKind,
    },
    /// An endpoint of this role may not receive a frame of this type
    /// ([`FrameKind::receivable_by`]).
    #[snafu(display("frame type may not be received by a {role:?}"))]
    NotReceivableByRole {
        /// The type received.
        frame_type: T,
        /// The role of this endpoint.
        role: Role,
    },
}

/// The code of [`ReadFrameError`] for a head that could not be read;
/// H3_FRAME_UNEXPECTED for an HTTP/2 type ([RFC 9114 §7.2.8]) and for a
/// frame where it may not arrive ([RFC 9114 §7.2]).
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
impl<E, T> ErrorCodeOf<ErrorCode> for ReadReceivedFrameError<E, T> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Frame { source } => source.error_code(),
            Self::Http2Type { .. }
            | Self::NotAllowedOnStream { .. }
            | Self::NotReceivableByRole { .. } => Some(ErrorCode::H3_FRAME_UNEXPECTED),
        }
    }
}

/// The failure of reading the payload of a frame read from `I`.
type PayloadReadError<I> = PayloadError<<<I as ReceiverAccess>::Family as Read>::Error>;

/// Finishing a frame read from a stream `I`, whose payload is `I`
/// composed with a [`FramePayload`], and moving on to the next one.
///
/// The payload skips what is left of it on the stream, which therefore
/// skips ([`Skip`]); compose [`ReadSkip`](nitori_io::adapters::ReadSkip)
/// or [`ReadChunkSkip`](nitori_io::adapters::ReadChunkSkip) onto a stream
/// that only reads.
impl<I> Frame<Composed<I, FramePayload>>
where
    I: ReceiverAccess<Family: Skip<Count: Clone + Min<u64, Output = u64>>>,
    u64: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    /// Skips what is left of the payload and gives the stream back, at the
    /// next frame.
    ///
    /// # Errors
    ///
    /// The failure of skipping the payload, such as a stream that ends
    /// inside it; the stream is then inside the frame.
    pub async fn finish(self) -> Result<I, PayloadReadError<I>> {
        let mut payload = self.payload;
        payload.skip_to_end().await?;
        Ok(payload.into_parts().0)
    }

    /// Finishes this frame and reads the next one with [`read_frame`].
    ///
    /// # Errors
    ///
    /// [`NextFrameError`]: the failure of finishing this frame or of
    /// reading the next.
    pub async fn next(
        self,
    ) -> Result<
        Option<Self>,
        NextFrameError<<I::Family as Read>::Error, ReadFrameError<<I::Family as Read>::Error>>,
    > {
        let io = self.finish().await.context(next_frame_error::FinishSnafu)?;
        read_frame(io).await.context(next_frame_error::ReadSnafu)
    }
}

/// Finishing a frame read from a stream that carries frames, and moving on
/// to the next one; as for [`Frame`], the stream skips.
impl<I> ReceivedPayloadFrame<I>
where
    I: ReceiverAccess<
        Family: Skip<Count: Clone + Min<u64, Output = u64>> + FrameStreamInfo<Parts: FrameSet>,
    >,
    u64: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    /// Skips what is left of the payload and gives the stream back, at the
    /// next frame.
    ///
    /// # Errors
    ///
    /// The failure of skipping the payload, such as a stream that ends
    /// inside it; the stream is then inside the frame.
    pub async fn finish(self) -> Result<I, PayloadReadError<I>> {
        self.frame.finish().await
    }

    /// Finishes this frame and reads the next one with
    /// [`read_received_frame`].
    ///
    /// # Errors
    ///
    /// [`NextFrameError`]: the failure of finishing this frame or of
    /// reading the next.
    pub async fn next(
        self,
    ) -> Result<Option<Self>, NextFrameError<<I::Family as Read>::Error, ReceivedFrameError<I>>>
    {
        let io = self.finish().await.context(next_frame_error::FinishSnafu)?;
        read_received_frame(io)
            .await
            .context(next_frame_error::ReadSnafu)
    }
}

/// Failures of moving on to the next frame: of [`Frame::next`], where `R`
/// is [`ReadFrameError`], and of [`ReceivedFrame::next`], where it is
/// [`ReadReceivedFrameError`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum NextFrameError<E, R> {
    /// What was left of the payload could not be skipped.
    #[snafu(display("could not finish frame"))]
    Finish {
        /// The failure of skipping it.
        source: PayloadError<E>,
    },
    /// The next frame could not be read.
    #[snafu(display("could not read next frame"))]
    Read {
        /// The failure of reading it.
        source: R,
    },
}

/// The code of the failure of finishing or reading.
impl<E, R: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for NextFrameError<E, R> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Finish { source } => source.error_code(),
            Self::Read { source } => source.error_code(),
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

/// Writes `frame`: its Type and Length, each at its width, and then its
/// payload, a source of exactly Length bytes, such as the bytes of a DATA
/// or HEADERS frame, or of a frame of a type this crate does not read.
///
/// Write the types of RFC 9114 with [`Http3FrameType::value`]; a type of
/// HTTP/2 is rejected. Pass the payload as a `&mut` borrow to keep it.
///
/// # Errors
///
/// [`WriteFrameError`]. A payload whose exact length is not the Length and
/// a type of HTTP/2 are reported before anything is written; a failure
/// after that leaves the stream inside the frame.
#[call(sync)]
pub async fn write_frame<
    R: Read + ExactLen,
    P: ReceiverAccess<Family = R>,
    F: Write,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    frame: Frame<P>,
) -> Result<(), WriteFrameError<R::Error, F::Error>>
where
    <R as ExactLen>::Length: TryInto<u64>,
{
    let (r#type, length) = (frame.r#type, frame.length);
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
    io.write_frame_head(r#type, length)
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
/// `io` is the payload of the frame, a [`FramePayload`] composed onto
/// the request stream.
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
