//! The codes of the failures to read a QPACK instruction.
use crate::error_code::{ErrorCode, ErrorCodeOf};
use hatate_qpack::{
    decoder_instruction::codec::ReadError as DecoderInstructionError,
    encoder_instruction::{
        codec::{LiteralHeaderError, StartError, ValueError},
        literal::{FinishError, HuffmanReadError, InputError},
    },
    huffman::DecodeError,
    instruction::{NumberError, OctetError},
};
use hatate_wire_qpack::QpackErrorCode;

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
