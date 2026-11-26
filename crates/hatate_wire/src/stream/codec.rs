//! Reading the start of a stream the peer opened.
use super::{
    ReceivedStream, UnidirectionalStream, UnknownStream,
    class::{BidirectionalClass, UnidirectionalClass},
    part::{StreamSet, StreamVerdict},
};
use crate::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        codec::{ReadFrameError, read_length, read_type},
        payload::{FramePayload, PayloadError},
    },
    parts::PartsError,
    registry::is_reserved,
    stream_type::StreamTypeSet,
};
use nitori_call::ReceiverAccess;
use nitori_codec::prelude::*;
use nitori_io::{Combine, Infinite, Min, Read, Skip, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField, stream::ReadVarIntError};
use snafu::{ResultExt, Snafu};

/// The stream that [`read_unidirectional_stream`] gives, from a source whose
/// bytes carry the metadata `M`.
pub type ReceivedUnidirectionalStream<L, C, I, M = ()> =
    UnidirectionalStream<ReceivedStream<<L as StreamSet<C, L>>::Stream<I, M>, UnknownStream<I>>, M>;

/// The streams that [`read_bidirectional_stream`] gives, from a source whose
/// bytes carry the metadata `M`.
pub type ReceivedBidirectionalStream<L, C, I, M = ()> =
    ReceivedStream<<L as StreamSet<C, L>>::Stream<I, M>, UnknownStream<I>>;

/// Reads the type at the start of a unidirectional stream of class `C`
/// that the peer opened, and gives the stream of the part of `L` that
/// claims the type, read up to where it can be used, or an
/// [`UnknownStream`] if no part claims it.
///
/// `io` is the stream and is passed through. The type keeps the width it
/// was read with. Name the parts and the class with a turbofish:
/// `read_unidirectional_stream::<Parts, ClientInitiatedUnidirectional, _, ()>(io)`.
/// Streams are read concurrently: one whose start has not arrived does not
/// hold up the others. The metadata of the bytes of the type is kept
/// ([`UnidirectionalStream::type_metadata`]).
///
/// Returns `None` if the stream ends before the first byte; a receiver
/// tolerates a stream closed before its type ([RFC 9114 §6.2]).
///
/// # Errors
///
/// [`ReadUnidirectionalStreamError`]; its [`ErrorCodeOf::error_code`]
/// gives the connection error the failure calls for, if any.
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
pub async fn read_unidirectional_stream<L, C, I, M>(
    mut io: I,
) -> Result<
    Option<ReceivedUnidirectionalStream<L, C, I, M>>,
    ReadUnidirectionalStreamError<
        <I::Family as Read>::Error,
        <L as StreamSet<C, L>>::ReadError<<I::Family as Read>::Error>,
        <L as StreamSet<C, L>>::Rejection,
    >,
>
where
    C: UnidirectionalClass,
    L: StreamSet<C, L> + StreamTypeSet,
    I: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin + Clone,
{
    const {
        assert!(
            L::CLAIMS_VALID,
            "the parts claim overlapping or reserved stream types"
        );
    }
    let field = match ReadValue::<VarIntField<VarInt>, M>::decode_from(&mut io).await {
        Ok(field) => field,
        Err(error) if error.is_incomplete() && error.completed() == 0 => return Ok(None),
        Err(source) => return Err(ReadUnidirectionalStreamError::Type { source }),
    };
    let value = field.value.get();
    let stream = match L::judge(value, false) {
        StreamVerdict::Claimed(claimed) => ReceivedStream::Known(
            L::read(claimed, field.clone(), io)
                .await
                .map_err(PartsError::new)
                .context(read_unidirectional_stream_error::PartSnafu)?,
        ),
        StreamVerdict::NotClaimed => ReceivedStream::Unknown(UnknownStream::new(value, io)),
        StreamVerdict::Error(rejection) | StreamVerdict::ErrorUnlessClaimed(rejection) => {
            return Err(ReadUnidirectionalStreamError::Rejected {
                stream_type: value,
                source: PartsError::new(rejection),
            });
        }
    };
    Ok(Some(UnidirectionalStream::read(
        stream,
        field.value.width(),
        field.metadata,
    )))
}

/// Failures of [`read_unidirectional_stream`]. `P` is the sum of the
/// failures of the parts, `R` the sum of their rejections.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadUnidirectionalStreamError<E, P, R> {
    /// The type could not be read: the stream failed, or ended after the
    /// first byte of the type.
    #[snafu(display("could not read stream type"))]
    Type {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The part the type belongs to rejects a stream of this class with it,
    /// such as a push stream that a client opened ([RFC 9114 §6.2.2]).
    ///
    /// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
    #[snafu(display("stream type {stream_type} is not allowed on this stream"))]
    Rejected {
        /// The type of the stream.
        stream_type: VarInt,
        /// Why the part rejects it.
        source: PartsError<R>,
    },
    /// The part that claims the type could not read what follows it.
    #[snafu(display("could not read the start of the stream"))]
    Part {
        /// The failure of that part.
        source: PartsError<P>,
    },
}

/// The code of the rejection, or of the part's failure, or of the stream's
/// own failure. `None` when the stream ends inside its type, which a
/// receiver tolerates ([RFC 9114 §6.2]).
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
impl<E: ErrorCodeOf<ErrorCode>, P: ErrorCodeOf<ErrorCode>, R: ErrorCodeOf<ErrorCode>>
    ErrorCodeOf<ErrorCode> for ReadUnidirectionalStreamError<E, P, R>
{
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Type { source } => source.host_error().and_then(ErrorCodeOf::error_code),
            Self::Rejected { source, .. } => source.error_code(),
            Self::Part { source } => source.error_code(),
        }
    }
}

/// Reads the start of a bidirectional stream of class `C` that the peer
/// opened, and gives the stream of the part of `L` that claims it, read up
/// to where it can be used, or an [`UnknownStream`] if no part claims it.
///
/// Reserved frames at the start are skipped; the first value that is not
/// the type of a reserved frame is judged by the parts, which are told
/// whether anything was skipped. A request stream comes back at its first
/// frame. Name the parts and the class with a turbofish:
/// `read_bidirectional_stream::<Parts, ClientInitiatedBidirectional, _, ()>(io)`.
///
/// Returns `None` if the stream ends before such a value. The parts do not
/// judge such a stream, so on a class that HTTP/3 does not use, the
/// server-initiated bidirectional streams, the caller treats `None` as a
/// connection error of type H3_STREAM_CREATION_ERROR unless an extension it
/// negotiated uses the class ([RFC 9114 §6.1]).
///
/// # Errors
///
/// [`ReadBidirectionalStreamError`]; its [`ErrorCodeOf::error_code`]
/// gives the connection error the failure calls for, if any.
///
/// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
pub async fn read_bidirectional_stream<L, C, I, M>(
    mut io: I,
) -> Result<
    Option<ReceivedBidirectionalStream<L, C, I, M>>,
    ReadBidirectionalStreamError<
        <I::Family as Read>::Error,
        <L as StreamSet<C, L>>::ReadError<<I::Family as Read>::Error>,
        <L as StreamSet<C, L>>::Rejection,
    >,
>
where
    C: BidirectionalClass,
    L: StreamSet<C, L>,
    I: ReceiverAccess<Family: Skip<Count: Clone + Min<u64, Output = u64>, Metadata = M>>,
    M: Combine + Unpin + Clone,
    u64: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    let mut skipped = false;
    let field = loop {
        let Some(field) = read_type(&mut io)
            .await
            .context(read_bidirectional_stream_error::HeadSnafu)?
        else {
            return Ok(None);
        };
        if !is_reserved(field.value.get()) {
            break field;
        }
        let length = read_length(&mut io)
            .await
            .context(read_bidirectional_stream_error::HeadSnafu)?;
        FramePayload::new(&mut io, length.value.get().get())
            .finish()
            .await
            .context(read_bidirectional_stream_error::ReservedPayloadSnafu)?;
        skipped = true;
    };
    let value = field.value.get();
    Ok(Some(match L::judge(value, skipped) {
        StreamVerdict::Claimed(claimed) => ReceivedStream::Known(
            L::read(claimed, field, io)
                .await
                .map_err(PartsError::new)
                .context(read_bidirectional_stream_error::PartSnafu)?,
        ),
        StreamVerdict::NotClaimed => ReceivedStream::Unknown(UnknownStream::new(value, io)),
        StreamVerdict::Error(rejection) | StreamVerdict::ErrorUnlessClaimed(rejection) => {
            return Err(ReadBidirectionalStreamError::Rejected {
                value,
                source: PartsError::new(rejection),
            });
        }
    }))
}

/// Failures of [`read_bidirectional_stream`]. `P` is the sum of the
/// failures of the parts, `R` the sum of their rejections.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadBidirectionalStreamError<E, P, R> {
    /// The head of a frame at the start could not be read.
    #[snafu(display("could not read the start of the stream"))]
    Head {
        /// The failure of reading it.
        source: ReadFrameError<E>,
    },
    /// The payload of a reserved frame at the start could not be skipped.
    #[snafu(display("could not skip a reserved frame"))]
    ReservedPayload {
        /// The failure of skipping it.
        source: PayloadError<E>,
    },
    /// The part the value belongs to rejects a stream of this class that
    /// starts with it, or no part claims a stream of this class that HTTP/3
    /// does not use ([RFC 9114 §6.1]).
    ///
    /// [RFC 9114 §6.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1
    #[snafu(display("value {value} is not allowed at the start of this stream"))]
    Rejected {
        /// The value.
        value: VarInt,
        /// Why the part rejects it.
        source: PartsError<R>,
    },
    /// The part that claims the value could not read the stream.
    #[snafu(display("could not read the start of the stream"))]
    Part {
        /// The failure of that part.
        source: PartsError<P>,
    },
}

/// The code of the failure, the rejection, or the part's failure.
impl<E: ErrorCodeOf<ErrorCode>, P: ErrorCodeOf<ErrorCode>, R: ErrorCodeOf<ErrorCode>>
    ErrorCodeOf<ErrorCode> for ReadBidirectionalStreamError<E, P, R>
{
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Head { source } => source.error_code(),
            Self::ReservedPayload { source } => source.error_code(),
            Self::Rejected { source, .. } => source.error_code(),
            Self::Part { source } => source.error_code(),
        }
    }
}
