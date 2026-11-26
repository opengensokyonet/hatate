//! Instructions on the QPACK decoder stream (RFC 9204 §4.4).
use crate::{
    encoder_instruction::StreamState,
    instruction::{self, WireBudget},
    integer,
};
use core::num::NonZeroU64;
use nitori_call::{AsAccess, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{
    Combine, Read,
    adapters::{MergedMetadata, MergingSource},
    calls::ReadValue,
};
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

/// The limit on the instructions of one decoder stream.
///
/// It is checked as each instruction is read and applies to the instructions
/// read after it is set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderStreamLimits {
    /// The most wire octets one instruction may take: its first octet and all
    /// continuations.
    pub max_wire_len: usize,
}

/// The longest an instruction can be: one prefixed integer, of at most 11
/// octets, the longest encoding of a `u64`.
impl Default for DecoderStreamLimits {
    fn default() -> Self {
        Self {
            max_wire_len: integer::MAX_ENCODED_LEN,
        }
    }
}

/// One decoder stream, read instruction by instruction from within a call.
///
/// It is made at an instruction boundary and reads nothing until asked for
/// the next instruction, which is decoded from the stream as an
/// `Option<ReadValue<DecoderInstruction, M>>`, `M` being the metadata of the
/// stream's bytes. Each instruction is read whole and handed over by
/// value. A read dropped before the first octet of an instruction has read
/// nothing and leaves the stream at the boundary. An instruction that fails,
/// or whose read is dropped after it began, leaves the stream interrupted: it reports an error on every later
/// instruction and is abandoned; [`into_io`](Self::into_io) gives the access
/// back.
#[derive(Debug)]
pub struct DecoderStream<A> {
    io: A,
    state: StreamState,
    limits: DecoderStreamLimits,
}

/// Reads the next instruction. The stream's [`DecoderStreamLimits`] count the
/// first octet and all continuations.
///
/// The value is `None` if the stream ends at the instruction boundary.
/// Whether that is an error is a question for the stream's place in the
/// connection. Otherwise the metadata is the merged metadata of the octets of
/// the instruction. A failure does not return the metadata of the octets read
/// before it.
///
/// # Errors
///
/// [`ReadError`](codec::ReadError); after any of them the stream is
/// interrupted. EOF inside a number is attributed to that instruction's
/// field.
impl<'s, A, M> DecodeFrom<&'s mut DecoderStream<A>> for Option<ReadValue<DecoderInstruction, M>>
where
    A: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    type Error = codec::ReadError<<A::Family as Read>::Error>;

    async fn decode_from(stream: &'s mut DecoderStream<A>) -> Result<Self, Self::Error> {
        if stream.state == StreamState::Interrupted {
            return Err(codec::ReadError::Interrupted);
        }
        // A call dropped before the first octet has read nothing: the stream
        // stays at the boundary.
        let mut budget = WireBudget::new(stream.limits.max_wire_len);
        let mut merged = MergedMetadata(M::default());
        let mut source = MergingSource::new(&mut stream.io, &mut merged);
        let first = match instruction::octet(&mut source.access(), &mut budget).await {
            Ok(first) => first,
            Err(error) if error.ended_before_first_octet() => return Ok(None),
            Err(source) => {
                stream.state = StreamState::Interrupted;
                return Err(codec::ReadError::Prefix { source });
            }
        };
        stream.state = StreamState::Interrupted;
        let instruction =
            codec::read_decoder_instruction(&mut source.access(), budget, first).await?;
        stream.state = StreamState::Boundary;
        Ok(Some(ReadValue {
            value: instruction,
            metadata: merged.0,
        }))
    }
}

impl<A> DecoderStream<A> {
    /// The stream on `io`, an access or an exclusive borrow of one, at an
    /// instruction boundary, reading instructions within `limits`. Nothing
    /// is read.
    pub fn new(io: A, limits: DecoderStreamLimits) -> Self {
        Self {
            io,
            state: StreamState::Boundary,
            limits,
        }
    }

    /// The limit the next instruction is read within.
    pub const fn limits(&self) -> DecoderStreamLimits {
        self.limits
    }

    /// Reads the instructions after this call within `limits`.
    pub fn set_limits(&mut self, limits: DecoderStreamLimits) {
        self.limits = limits;
    }

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
