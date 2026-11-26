//! The codes of the failures to read a QPACK instruction.
use crate::error_code::{ErrorCode, ErrorCodeOf};
use hatate_qpack::{
    decoder_instruction::DecodeDecoderInstructionError,
    encoder_instruction::{DecodeEncoderInstructionError, DecodeLiteralError},
    huffman::DecodeError,
    instruction::{NumberError, OctetError},
};
use hatate_wire_qpack::{QpackErrorCode, stream::DecodeQpackEncoderInstructionError};

/// Where a failure to read a QPACK instruction came from.
enum QpackFailure<'e, E> {
    /// The stream failed.
    Host(&'e E),
    /// The instruction cannot be interpreted.
    Malformed,
    /// The instruction exceeds the limits it was read within.
    Limit,
    /// The stream ended inside the instruction, or the stream was already
    /// abandoned: no code of its own.
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
            Self::WireLimit { .. } => QpackFailure::Limit,
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

impl<E> QpackFailureOf<E> for DecodeLiteralError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Length { source } => source.failure(),
            Self::Read { source } => QpackFailure::Host(source),
            Self::Huffman {
                source:
                    DecodeError::EndOfString | DecodeError::ExcessPadding | DecodeError::InvalidPadding,
            } => QpackFailure::Malformed,
            Self::WireLimit { .. }
            | Self::DecodedLength { .. }
            | Self::Huffman {
                source: DecodeError::OutputTooLong { .. },
            } => QpackFailure::Limit,
            Self::Truncated { .. } => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for DecodeEncoderInstructionError<E> {
    fn failure(&self) -> QpackFailure<'_, E> {
        match self {
            Self::Prefix { source } | Self::ValuePrefix { source } => source.failure(),
            Self::Capacity { source } | Self::Duplicate { source } | Self::NameIndex { source } => {
                source.failure()
            }
            Self::Name { source } | Self::Value { source } => source.failure(),
            Self::StaticName { .. } => QpackFailure::Malformed,
            Self::WireLimit { .. } => QpackFailure::Limit,
            Self::Interrupted => QpackFailure::Other,
        }
    }
}

impl<E> QpackFailureOf<E> for DecodeDecoderInstructionError<E> {
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

/// The code of `failure` on a stream whose failures that cannot be
/// interpreted have `code`, and whose limits are the peer's to keep if
/// `limits_bind_the_peer`.
fn code_of<E: ErrorCodeOf<ErrorCode>>(
    failure: QpackFailure<'_, E>,
    code: QpackErrorCode,
    limits_bind_the_peer: bool,
) -> Option<ErrorCode> {
    match failure {
        QpackFailure::Host(source) => source.error_code(),
        QpackFailure::Malformed => Some(code.into()),
        QpackFailure::Limit if limits_bind_the_peer => Some(code.into()),
        QpackFailure::Limit | QpackFailure::Other => None,
    }
}

/// The code of the stream's own failure, such as H3_CLOSED_CRITICAL_STREAM
/// on a QPACK stream that ended inside an instruction;
/// QPACK_ENCODER_STREAM_ERROR for an instruction that cannot be interpreted
/// ([RFC 9204 §6]); `None` for the end of a stream that is not critical, a
/// limit of the caller's choice, and a stream already abandoned.
///
/// [RFC 9204 §6]: https://www.rfc-editor.org/rfc/rfc9204.html#section-6
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodeEncoderInstructionError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        code_of(self.failure(), QpackErrorCode::EncoderStreamError, false)
    }
}

/// As for [`DecodeEncoderInstructionError`], except that an instruction
/// beyond the limits of the dynamic table capacity this endpoint allows is
/// also QPACK_ENCODER_STREAM_ERROR: an insertion that cannot fit in the
/// table ([RFC 9204 §3.2.2]).
///
/// [RFC 9204 §3.2.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.2
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodeQpackEncoderInstructionError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        code_of(
            self.instruction_error().failure(),
            QpackErrorCode::EncoderStreamError,
            true,
        )
    }
}

/// The code of the stream's own failure, such as H3_CLOSED_CRITICAL_STREAM
/// on a QPACK stream that ended inside an instruction;
/// QPACK_DECODER_STREAM_ERROR for an instruction that cannot be interpreted
/// ([RFC 9204 §6]); `None` for the end of a stream that is not critical, a
/// limit of this endpoint, and a stream already abandoned.
///
/// [RFC 9204 §6]: https://www.rfc-editor.org/rfc/rfc9204.html#section-6
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodeDecoderInstructionError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        code_of(self.failure(), QpackErrorCode::DecoderStreamError, false)
    }
}
