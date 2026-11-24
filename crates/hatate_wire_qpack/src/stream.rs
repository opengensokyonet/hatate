//! The QPACK encoder and decoder streams as HTTP/3 has them
//! ([RFC 9204 §4.2]): unidirectional streams of type 0x02 and 0x03, each
//! critical, read instruction by instruction.
//!
//! [`QpackEncoderStream`] and [`QpackDecoderStream`] hold the instruction
//! streams of `hatate_qpack`, which read any source and end at an
//! instruction boundary. These know that they are critical: they never end,
//! and a stream that ends is [`QpackStreamError::Closed`], which is a
//! connection error of type H3_CLOSED_CRITICAL_STREAM.
//!
//! [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
use hatate_qpack::{
    decoder_instruction::{DecoderInstruction, DecoderStream, codec::ReadError},
    encoder_instruction::{EncoderStream, Started, codec::StartError},
};
use nitori_call::ReceiverAccess;
use nitori_io::Read;
use snafu::Snafu;

/// The QPACK encoder stream of the peer (stream type 0x02).
#[derive(Debug)]
pub struct QpackEncoderStream<A> {
    stream: EncoderStream<A>,
}

impl<A: ReceiverAccess> QpackEncoderStream<A>
where
    A::Family: Read,
{
    /// The stream on `io`, right after its type. Nothing is read.
    pub fn new(io: A) -> Self {
        Self {
            stream: EncoderStream::new(io),
        }
    }

    /// Reads the start of the next instruction, as
    /// [`EncoderStream::next_instruction`] does.
    ///
    /// # Errors
    ///
    /// [`QpackStreamError`]: the stream ended, or the instruction could not
    /// be read.
    pub async fn next_instruction(
        &mut self,
        max_wire_len: usize,
        max_decoded_len: usize,
    ) -> Result<Started<'_, A>, QpackStreamError<StartError<<A::Family as Read>::Error>>> {
        match self
            .stream
            .next_instruction(max_wire_len, max_decoded_len)
            .await
        {
            Ok(Some(started)) => Ok(started),
            Ok(None) => Err(QpackStreamError::Closed),
            Err(source) => Err(QpackStreamError::Instruction { source }),
        }
    }
}

impl<A> QpackEncoderStream<A> {
    /// The instruction stream, giving up that it is critical.
    pub fn into_inner(self) -> EncoderStream<A> {
        self.stream
    }
}

/// The QPACK decoder stream of the peer (stream type 0x03).
#[derive(Debug)]
pub struct QpackDecoderStream<A> {
    stream: DecoderStream<A>,
}

impl<A: ReceiverAccess> QpackDecoderStream<A>
where
    A::Family: Read,
{
    /// The stream on `io`, right after its type. Nothing is read.
    pub fn new(io: A) -> Self {
        Self {
            stream: DecoderStream::new(io),
        }
    }

    /// Reads the next instruction, as [`DecoderStream::next_instruction`]
    /// does.
    ///
    /// # Errors
    ///
    /// [`QpackStreamError`]: the stream ended, or the instruction could not
    /// be read.
    pub async fn next_instruction(
        &mut self,
        max_wire_len: usize,
    ) -> Result<DecoderInstruction, QpackStreamError<ReadError<<A::Family as Read>::Error>>> {
        match self.stream.next_instruction(max_wire_len).await {
            Ok(Some(instruction)) => Ok(instruction),
            Ok(None) => Err(QpackStreamError::Closed),
            Err(source) => Err(QpackStreamError::Instruction { source }),
        }
    }
}

impl<A> QpackDecoderStream<A> {
    /// The instruction stream, giving up that it is critical.
    pub fn into_inner(self) -> DecoderStream<A> {
        self.stream
    }
}

/// Failures of reading a QPACK stream. `E` is the failure of reading an
/// instruction.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum QpackStreamError<E> {
    /// The stream ended, which a critical stream may not
    /// ([RFC 9204 §4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2)).
    #[snafu(display("a QPACK stream was closed"))]
    Closed,
    /// The instruction could not be read.
    #[snafu(display("could not read a QPACK instruction"))]
    Instruction {
        /// The failure of reading it.
        source: E,
    },
}
