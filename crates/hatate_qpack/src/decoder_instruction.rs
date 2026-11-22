//! Instructions on the QPACK decoder stream (RFC 9204 §4.4).
use core::num::NonZeroU64;
use snafu::Snafu;

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;

/// A QUIC stream ID (RFC 9000 §2.1), carried as a QPACK prefixed integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct StreamId(u64);

impl StreamId {
    /// Numeric stream identifier, at most 2^62 − 1.
    pub const fn get(self) -> u64 {
        self.0
    }
}
impl TryFrom<u64> for StreamId {
    type Error = StreamIdError;
    fn try_from(value: u64) -> Result<Self, Self::Error> {
        if value < 1 << 62 {
            Ok(Self(value))
        } else {
            Err(StreamIdError { value })
        }
    }
}

/// A QPACK integer that exceeds the QUIC stream ID range.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("stream ID {value} exceeds 62 bits"))]
pub struct StreamIdError {
    value: u64,
}
impl StreamIdError {
    /// The value received on the wire or passed to the constructor.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// One complete decoder-stream instruction. Connection state determines
/// whether a stream reference or the resulting known insert count is valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecoderInstruction {
    /// A field section on this stream has been processed.
    SectionAcknowledgment(StreamId),
    /// The decoder abandoned processing of this stream.
    StreamCancellation(StreamId),
    /// Additional dynamic table insertions received by the decoder.
    InsertCountIncrement(NonZeroU64),
}
