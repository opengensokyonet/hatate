//! Instructions on the QPACK decoder stream (RFC 9204 §4.4).
use crate::encoder_instruction::StreamState;
use core::num::NonZeroU64;
use nitori_call::ReceiverAccess;
use nitori_io::Read;
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

/// One decoder stream, read instruction by instruction from within a call.
///
/// It is made at an instruction boundary and reads nothing until asked for
/// the next instruction. Each instruction is read whole and handed over by
/// value. An instruction that fails, or whose read is dropped after it
/// began, leaves the stream interrupted: it reports an error on every later
/// instruction and is abandoned; [`into_io`](Self::into_io) gives the access
/// back.
#[derive(Debug)]
pub struct DecoderStream<A> {
    io: A,
    state: StreamState,
}

impl<A: ReceiverAccess> DecoderStream<A>
where
    A::Family: Read,
{
    /// The stream on `io`, an access or an exclusive borrow of one, at an
    /// instruction boundary. Nothing is read.
    pub fn new(io: A) -> Self {
        Self {
            io,
            state: StreamState::Boundary,
        }
    }

    /// Reads the next instruction. The limit counts the first octet and all
    /// continuations.
    ///
    /// Returns `None` if the stream ends at the instruction boundary. Whether
    /// that is an error is a question for the stream's place in the connection.
    ///
    /// # Errors
    ///
    /// [`ReadError`](codec::ReadError); after any of them the stream is
    /// interrupted. EOF inside a number is attributed to that instruction's
    /// field.
    pub async fn next_instruction(
        &mut self,
        max_wire_len: usize,
    ) -> Result<Option<DecoderInstruction>, codec::ReadError<<A::Family as Read>::Error>> {
        if self.state == StreamState::Interrupted {
            return Err(codec::ReadError::Interrupted);
        }
        self.state = StreamState::Interrupted;
        match codec::read_decoder_instruction(&mut self.io, max_wire_len).await {
            Ok(instruction) => {
                self.state = StreamState::Boundary;
                Ok(Some(instruction))
            }
            Err(codec::ReadError::Prefix { source }) if source.ended_before_first_octet() => {
                self.state = StreamState::Boundary;
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
}

impl<A> DecoderStream<A> {
    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.io
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
