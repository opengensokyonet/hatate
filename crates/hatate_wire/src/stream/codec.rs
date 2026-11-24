//! Reading the start of a unidirectional stream.
use super::{FrameStream, ReceivedStream, UnidirectionalStream};
use crate::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{PushId, set::FrameStreamKind},
    stream_type::{Http3StreamType, StreamType, StreamTypeHead, StreamTypeKind, StreamTypeSet},
};
use nitori_call::{Composed, ReceiverAccess};
use nitori_io::Read;
use sakuya_var_int::{
    VarInt,
    call::{ReadVarIntError, ReadVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// Reads the type at the start of a unidirectional stream that the peer
/// opened, looks it up in the list of parts `L`, and, on a push stream,
/// reads the Push ID that follows.
///
/// `io` is the stream and is passed through: a control or push stream
/// comes back composed with its [`FrameStream`], at its first frame, and
/// any other stream comes back as it is, after its type. Each comes with
/// the head it was read from, which keeps the width of the Stream Type
/// field. `role` is the
/// role of this endpoint. Name the parts with a turbofish:
/// `read_unidirectional_stream::<Parts, _>(io, role)`.
///
/// Returns `None` if the stream ends before the first byte; a receiver
/// tolerates a stream closed before its type ([RFC 9114 §6.2]).
///
/// Dropping the returned future, or the stream, before it completes leaves
/// the stream inside its type or Push ID: it cannot be read from the start
/// any more, and is abandoned, as with an unfinished frame
/// ([`Frame`](crate::frame::Frame)).
///
/// # Errors
///
/// [`ReadUnidirectionalStreamError`]; its [`ErrorCodeOf::error_code`]
/// gives the connection error the failure calls for, if any.
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
pub async fn read_unidirectional_stream<L: StreamTypeSet, I: ReceiverAccess<Family: Read>>(
    mut io: I,
    role: Role,
) -> Result<
    Option<UnidirectionalStream<I, L>>,
    ReadUnidirectionalStreamError<<I::Family as Read>::Error, L::TypeValue>,
> {
    let field = match io.read_var_int_field::<VarInt>().await {
        Ok(field) => field,
        Err(error) if error.is_incomplete() && error.completed() == 0 => return Ok(None),
        Err(source) => return Err(ReadUnidirectionalStreamError::Type { source }),
    };
    let value = field.get();
    let stream_type = L::type_value_of(value).map_or(StreamType::Unknown(value), StreamType::Known);
    if let StreamType::Known(stream_type) = stream_type
        && !L::kind_of(stream_type).acceptable_by(role)
    {
        return Err(ReadUnidirectionalStreamError::NotAcceptableByRole { stream_type, role });
    }
    let head = StreamTypeHead::new(stream_type, field);
    let frames = FrameStream::new(FrameStreamKind::Unidirectional(value), role);
    let framed = match stream_type {
        StreamType::Known(_) => Http3StreamType::of(value),
        StreamType::Unknown(_) => None,
    };
    Ok(Some(match framed {
        Some(Http3StreamType::Control) => UnidirectionalStream::Control {
            head,
            stream: Composed::new(io, frames),
        },
        Some(Http3StreamType::Push) => {
            let push_id = io
                .read_var_int_field::<PushId>()
                .await
                .context(read_unidirectional_stream_error::PushIdSnafu)?;
            UnidirectionalStream::Push {
                head,
                push_id,
                stream: Composed::new(io, frames),
            }
        }
        Some(Http3StreamType::Qpack(_)) | None => {
            UnidirectionalStream::Other(ReceivedStream { head, io })
        }
    }))
}

/// Failures of [`read_unidirectional_stream`]. `T` is the stream type
/// value of the list of parts.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadUnidirectionalStreamError<E, T> {
    /// The type could not be read: the stream failed, or ended after the
    /// first byte of the type.
    #[snafu(display("could not read stream type"))]
    Type {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The Push ID of a push stream could not be read.
    #[snafu(display("could not read the push ID of a push stream"))]
    PushId {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// An endpoint of this role may not accept a stream of this type, such
    /// as a push stream at a server ([RFC 9114 §6.2.2]).
    ///
    /// [RFC 9114 §6.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2
    #[snafu(display("an endpoint of role {role:?} may not accept this stream type"))]
    NotAcceptableByRole {
        /// The type of the stream.
        stream_type: T,
        /// The role of this endpoint.
        role: Role,
    },
}

/// H3_STREAM_CREATION_ERROR for a type this endpoint may not accept
/// ([RFC 9114 §6.2]). `None` when the stream fails or ends inside its type
/// or Push ID, which a receiver tolerates ([RFC 9114 §6.2]), and when the
/// stream itself failed.
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
impl<E, T> ErrorCodeOf<ErrorCode> for ReadUnidirectionalStreamError<E, T> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Type { .. } | Self::PushId { .. } => None,
            Self::NotAcceptableByRole { .. } => Some(ErrorCode::H3_STREAM_CREATION_ERROR),
        }
    }
}
