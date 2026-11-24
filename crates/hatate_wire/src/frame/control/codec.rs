//! Reading and writing CANCEL_PUSH, GOAWAY and MAX_PUSH_ID.
use super::{CancelPushFrame, GoawayFrame, MaxPushIdFrame};
use crate::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        FrameWidths, Http3FrameType,
        codec::{WriteFrameHeadError, WriteFrameHeadExt as _, payload_integer_error_code},
    },
};
use core::{future::poll_fn, num::NonZeroU64, task::Poll};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

macro_rules! integer_frame_codec {
    ($name:ident, $kind:ident, $field:ident, $read:ident, $write:ident) => {
        #[doc = concat!("Reads the payload of a [`", stringify!($name), "`] whose head had `widths`.")]
        ///
        /// `io` is the payload, such as a [`FramePayload`](crate::frame::payload::FramePayload)
        /// composed onto the stream; the frame ends where it reports EOF.
        ///
        /// # Errors
        ///
        /// [`ReadIntegerFrameError`].
        #[call(sync)]
        pub async fn $read<F: Read + ExactLen, A: ReceiverAccess<Family = F>>(
            io: &mut A,
            widths: FrameWidths,
        ) -> Result<$name, ReadIntegerFrameError<F::Error>>
        where
            <F as ExactLen>::Length: TryInto<u64>,
        {
            let $field = read_integer(io).await?;
            Ok($name::with_widths($field, widths))
        }

        #[doc = concat!("Writes a whole [`", stringify!($name), "`].")]
        ///
        /// # Errors
        ///
        /// [`WriteIntegerFrameError`]; bytes accepted before the failure
        /// stay written.
        #[call(sync)]
        pub async fn $write<F: Write, A: ReceiverAccess<Family = F>>(
            io: &mut A,
            frame: $name,
        ) -> Result<(), WriteIntegerFrameError<F::Error>> {
            write_integer(io, Http3FrameType::$kind, frame.widths(), frame.$field()).await
        }
    };
}

integer_frame_codec!(
    CancelPushFrame,
    CancelPush,
    push_id,
    read_cancel_push_frame,
    write_cancel_push_frame
);
integer_frame_codec!(
    GoawayFrame,
    Goaway,
    id,
    read_goaway_frame,
    write_goaway_frame
);
integer_frame_codec!(
    MaxPushIdFrame,
    MaxPushId,
    push_id,
    read_max_push_id_frame,
    write_max_push_id_frame
);

/// Reads the one integer of a payload and checks that nothing follows it.
async fn read_integer<T, F: Read + ExactLen, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Result<VarIntField<T>, ReadIntegerFrameError<F::Error>>
where
    T: Copy + Into<VarInt> + From<VarInt>,
    <F as ExactLen>::Length: TryInto<u64>,
{
    let field = io
        .read_var_int_field::<T>()
        .await
        .context(read_integer_frame_error::FieldSnafu)?;
    let remaining =
        poll_fn(|cx| io.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len()))).await;
    // A remaining length that does not fit a u64 is not zero either.
    match remaining.try_into().map(NonZeroU64::new) {
        Ok(None) => Ok(field),
        Ok(Some(remaining)) => Err(ReadIntegerFrameError::Trailing {
            remaining: Some(remaining),
        }),
        Err(_) => Err(ReadIntegerFrameError::Trailing { remaining: None }),
    }
}

async fn write_integer<T, F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    kind: Http3FrameType,
    widths: FrameWidths,
    field: VarIntField<T>,
) -> Result<(), WriteIntegerFrameError<F::Error>>
where
    T: Copy + Into<VarInt> + TryFrom<VarInt>,
{
    // invariant: frame types of RFC 9114 and lengths of at most 8 fit
    // every width.
    let type_field = VarIntField::new(kind.value(), widths.type_width())
        .expect("every width holds a frame type of RFC 9114");
    let length = VarIntField::new(
        VarInt::from_u32(field.encoded_len() as u32),
        widths.length_width(),
    )
    .expect("every width holds a length of at most 8");
    io.write_frame_head(type_field, length)
        .await
        .context(write_integer_frame_error::HeadSnafu)?;
    io.write_var_int_field(field)
        .await
        .context(write_integer_frame_error::FieldSnafu)
}

/// Failures reading the payload of a CANCEL_PUSH, GOAWAY or MAX_PUSH_ID.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadIntegerFrameError<E> {
    /// The integer could not be read: the payload ended before it, or the
    /// stream failed.
    #[snafu(display("could not read the integer of the frame"))]
    Field {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// Bytes follow the integer within the payload.
    #[snafu(display("frame payload continues after its integer"))]
    Trailing {
        /// How many, if the payload reports a count that fits a `u64`.
        remaining: Option<NonZeroU64>,
    },
}

/// H3_FRAME_ERROR when the payload is shorter or longer than its integer
/// ([RFC 9114 §7.1]); otherwise the code of the source's failure, such as
/// H3_FRAME_ERROR when the stream ended inside a frame read through a
/// [`FramePayload`](crate::frame::payload::FramePayload). `None` when the
/// stream failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for ReadIntegerFrameError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Field { source } => payload_integer_error_code(source),
            Self::Trailing { .. } => Some(ErrorCode::H3_FRAME_ERROR),
        }
    }
}

/// Failures writing a CANCEL_PUSH, GOAWAY or MAX_PUSH_ID.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteIntegerFrameError<E> {
    /// The head could not be written.
    #[snafu(display("could not write frame head"))]
    Head {
        /// The failure of writing the head.
        source: WriteFrameHeadError<E>,
    },
    /// The integer could not be written.
    #[snafu(display("could not write the integer of the frame"))]
    Field {
        /// The failure of writing the integer.
        source: WriteVarIntError<E>,
    },
}
