//! Write a single encoder instruction in wire order. An insertion borrows
//! the writer until its value has been transferred. Keep one writer for
//! the stream. Abandon the stream on a partial write or cancelled insertion.
use super::{NameReference, codec::DecodedLengthError};
use crate::huffman::{DecodeError, SymbolDecoder};
use crate::instruction::{EncodedInteger, WireBudget, WireLimitError};
use core::{future::poll_fn, num::NonZeroU64, task::Poll};
use nitori_call::ReceiverAccess;
use nitori_io::{calls::WriteAllError, prelude::*};
use snafu::{ResultExt, Snafu};

/// A source of the exact bytes to put on the wire for one literal.
/// In both cases the advertised length is the encoded payload length.
pub enum Payload<S> {
    /// Uncompressed bytes.
    Raw(S),
    /// Bytes already encoded and padded with the RFC 7541 Huffman code.
    /// The writer validates them and counts decoded symbols while streaming.
    Huffman(S),
}

/// Sequential output access to a QPACK encoder stream.
pub struct Writer<A> {
    io: A,
    at_boundary: bool,
}

/// A header could not be written at the current instruction boundary.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum HeaderError<W> {
    /// An earlier instruction was abandoned or failed after output began.
    #[snafu(display("encoder output is inside an unfinished instruction"))]
    NotAtBoundary,
    /// The instruction cannot fit the supplied wire limit.
    #[snafu(transparent)]
    WireLimit {
        /// Required wire size and caller limit.
        source: WireLimitError,
    },
    /// The host failed to accept the header bytes.
    #[snafu(display("could not write the instruction header"))]
    Send {
        /// Write failure and progress within this write.
        source: WriteAllError<W>,
    },
}

/// A literal's header or payload could not be transferred.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LiteralError<R, W> {
    /// The reported payload length cannot be represented by a QPACK integer.
    #[snafu(display("literal length cannot be encoded as a u64"))]
    LengthOutOfRange,
    /// The uncompressed payload exceeds the remaining decoded limit.
    #[snafu(transparent)]
    DecodedLength {
        /// Advertised raw length and remaining decoded budget.
        source: DecodedLengthError,
    },
    /// Encoded bytes violate the Huffman rules or exceed the decoded budget.
    #[snafu(display("invalid Huffman payload for encoder instruction"))]
    Huffman {
        /// The coding or decoded-size failure.
        source: DecodeError,
    },
    /// Starting or writing this literal's header failed.
    #[snafu(transparent)]
    Header {
        /// The header failure.
        source: HeaderError<W>,
    },
    /// The source ended before its advertised length.
    #[snafu(display("literal source ended with {missing} octets missing"))]
    ShortSource {
        /// Advertised octets still missing.
        missing: NonZeroU64,
    },
    /// The source failed to supply a payload block.
    #[snafu(display("could not read literal payload"))]
    Read {
        /// The original input error.
        source: R,
    },
    /// The host failed to accept a payload block.
    #[snafu(display("could not write literal payload"))]
    Send {
        /// Write failure and progress within this write.
        source: WriteAllError<W>,
    },
}

impl<A: ReceiverAccess> Writer<A>
where
    A::Family: Write,
{
    /// Start at an instruction boundary using an owned or borrowed access.
    pub fn new(io: A) -> Self {
        Self {
            io,
            at_boundary: true,
        }
    }

    fn boundary(&self) -> Result<(), HeaderError<<A::Family as Write>::Error>> {
        if self.at_boundary {
            Ok(())
        } else {
            Err(HeaderError::NotAtBoundary)
        }
    }

    async fn header(
        &mut self,
        encoded: &EncodedInteger,
    ) -> Result<(), HeaderError<<A::Family as Write>::Error>> {
        self.at_boundary = false;
        self.io
            .write_all(encoded.as_slice())
            .await
            .context(header_error::SendSnafu)
    }

    async fn number(
        &mut self,
        encoded: EncodedInteger,
        max_wire_len: usize,
    ) -> Result<(), HeaderError<<A::Family as Write>::Error>> {
        self.boundary()?;
        WireBudget::new(max_wire_len).check(encoded.as_slice().len() as u64)?;
        self.header(&encoded).await?;
        self.at_boundary = true;
        Ok(())
    }

    /// Emit one Set Dynamic Table Capacity instruction.
    pub async fn set_dynamic_table_capacity(
        &mut self,
        capacity: u64,
        max_wire_len: usize,
    ) -> Result<(), HeaderError<<A::Family as Write>::Error>> {
        self.number(EncodedInteger::new::<5>(0x20, capacity), max_wire_len)
            .await
    }

    /// Emit one Duplicate instruction carrying a relative index.
    pub async fn duplicate(
        &mut self,
        index: u64,
        max_wire_len: usize,
    ) -> Result<(), HeaderError<<A::Family as Write>::Error>> {
        self.number(EncodedInteger::new::<5>(0, index), max_wire_len)
            .await
    }

    /// Emit an insert's name reference and return the state awaiting its value.
    pub async fn name_reference(
        &mut self,
        name: NameReference,
        max_wire_len: usize,
        max_decoded_len: usize,
    ) -> Result<PendingValue<'_, A>, HeaderError<<A::Family as Write>::Error>> {
        self.boundary()?;
        let header = match name {
            NameReference::Static(i) => EncodedInteger::new::<6>(0xc0, i.get().into()),
            NameReference::Relative(i) => EncodedInteger::new::<6>(0x80, i),
        };
        let mut wire = WireBudget::new(max_wire_len);
        wire.take(header.as_slice().len() as u64)?;
        wire.check(1)?; // Even an empty value needs its length prefix.
        self.header(&header).await?;
        Ok(PendingValue {
            writer: self,
            wire,
            decoded_left: max_decoded_len,
        })
    }

    /// Transfer a literal name before asking the caller for its value.
    pub async fn literal_name<F: Read + ExactLen>(
        &mut self,
        name: Payload<&mut impl ReceiverAccess<Family = F>>,
        max_wire_len: usize,
        max_decoded_len: usize,
    ) -> Result<PendingValue<'_, A>, LiteralError<F::Error, <A::Family as Write>::Error>>
    where
        F::Length: TryInto<u64>,
    {
        self.boundary()?;
        let mut pending = PendingValue {
            writer: self,
            wire: WireBudget::new(max_wire_len),
            decoded_left: max_decoded_len,
        };
        pending.transfer::<5, F>(name, 0x40, 1).await?;
        Ok(pending)
    }
}

/// A name has been fully emitted. Supply the value to complete this insertion.
#[must_use]
pub struct PendingValue<'a, A> {
    writer: &'a mut Writer<A>,
    wire: WireBudget,
    decoded_left: usize,
}

impl<A: ReceiverAccess> PendingValue<'_, A>
where
    A::Family: Write,
{
    async fn transfer<const N: u8, F: Read + ExactLen>(
        &mut self,
        payload: Payload<&mut impl ReceiverAccess<Family = F>>,
        prefix: u8,
        minimum_tail: u64,
    ) -> Result<(), LiteralError<F::Error, <A::Family as Write>::Error>>
    where
        F::Length: TryInto<u64>,
    {
        let (src, prefix, mut decoder) = match payload {
            Payload::Raw(src) => (src, prefix, None),
            Payload::Huffman(src) => (
                src,
                prefix | (1 << N),
                Some(SymbolDecoder::new(self.decoded_left)),
            ),
        };
        let declared =
            poll_fn(|cx| src.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len())))
                .await;
        let length = declared
            .try_into()
            .map_err(|_| LiteralError::LengthOutOfRange)?;
        let header = EncodedInteger::new::<N>(prefix, length);
        self.wire
            .take(header.as_slice().len() as u64)
            .map_err(HeaderError::from)?;
        self.wire.take(length).map_err(HeaderError::from)?;
        self.wire.check(minimum_tail).map_err(HeaderError::from)?;
        if decoder.is_none() {
            DecodedLengthError::check(length, self.decoded_left)?;
            self.decoded_left -= length as usize;
        }
        self.writer.header(&header).await?;
        let mut remaining = length;
        let mut buf = [0; 1024];
        while let Some(missing) = NonZeroU64::new(remaining) {
            let request = remaining.min(buf.len() as u64) as usize;
            let count = src
                .read(&mut &mut buf[..request])
                .await
                .context(literal_error::ReadSnafu)?;
            if count == 0 {
                return Err(LiteralError::ShortSource { missing });
            }
            remaining -= count as u64;
            if let Some(decoder) = &mut decoder {
                for &octet in &buf[..count] {
                    for shift in (0..8).rev() {
                        decoder
                            .bit((octet >> shift) & 1)
                            .context(literal_error::HuffmanSnafu)?;
                    }
                }
                if remaining == 0 {
                    self.decoded_left -= decoder.finish().context(literal_error::HuffmanSnafu)?;
                }
            }
            self.writer
                .io
                .write_all(&buf[..count])
                .await
                .context(literal_error::SendSnafu)?;
        }
        Ok(())
    }

    /// Transfer a literal value, consuming this state. Success restores the
    /// instruction boundary. A failure leaves the writer inside the insertion.
    pub async fn value<F: Read + ExactLen>(
        mut self,
        value: Payload<&mut impl ReceiverAccess<Family = F>>,
    ) -> Result<(), LiteralError<F::Error, <A::Family as Write>::Error>>
    where
        F::Length: TryInto<u64>,
    {
        self.transfer::<7, F>(value, 0, 0).await?;
        self.writer.at_boundary = true;
        Ok(())
    }
}
