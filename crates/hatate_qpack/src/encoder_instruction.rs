//! Instructions sent on the QPACK encoder stream (RFC 9204 §4.3).
//!
//! Inside a `nitori_call` operation, create an [`EncoderStream`] over the
//! current access, at an instruction boundary, with its [`EncoderStreamLimits`].
//! Decode the next instruction as an `Option<ReadValue<Started<'_, A>, M>>`
//! and match its state; the `ReadValue` carries the merged metadata of the
//! bytes that began the instruction. For a literal name,
//! borrow [`Name::source`] and read it to its boundary. [`Name::finish`]
//! validates the ending and releases a [`ValueStart`]. Open and consume the
//! value in the same way. Commit an insertion only after [`Value::finish`]
//! succeeds. An error may follow previously delivered decoded bytes.
//!
//! The source of a raw literal preserves the host's chunks. The Huffman
//! source implements `nitori_io::Read` and writes into the supplied buffer.
//! A consumer choosing owned chunks provides its own collection adapter.
pub mod literal;
pub mod write;

use crate::{instruction::WireBudget, integer, static_table};
use literal::{FinishError, Literal, LiteralSource};
use nitori_call::{AsAccess, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{
    Combine, Read,
    adapters::{MergedMetadata, MergingSource},
    calls::ReadValue,
};

#[allow(missing_docs)] // #[call] also generates operation and extension trait items.
pub mod codec;

/// An encoder-stream name reference. Relative index zero refers to the most
/// recent insertion when the instruction is applied (RFC 9204 §3.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameReference {
    /// A known static table entry.
    Static(static_table::Index),
    /// A dynamic entry in encoder-stream coordinates.
    Relative(u64),
}

/// The limits on the instructions of one encoder stream.
///
/// They are checked as each instruction is read and apply to the instructions
/// read after they are set. The defaults are those of a peer that has not been
/// given a dynamic table: see [`for_table_capacity`](Self::for_table_capacity).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderStreamLimits {
    /// The most wire octets one instruction may take, counting every prefix,
    /// integer and literal payload of it.
    pub max_wire_len: usize,
    /// The most octets the name and the value of an insertion may have
    /// together once decoded; the Huffman literals count their decoded
    /// octets.
    pub max_decoded_len: usize,
}

impl EncoderStreamLimits {
    /// The size that RFC 9204 §3.2.1 adds to the lengths of the name and the
    /// value of an entry.
    const ENTRY_OVERHEAD: u64 = 32;
    /// The most bits of a Huffman code of RFC 7541 Appendix B.
    const HUFFMAN_CODE_BITS: usize = 30;

    /// The limits that suit a dynamic table of at most `capacity` octets
    /// (SETTINGS_QPACK_MAX_TABLE_CAPACITY, RFC 9204 §5).
    ///
    /// An entry takes the lengths of its name and value and 32 octets (RFC
    /// 9204 §3.2.1), so the name and the value of an insertion together have
    /// at most `capacity` less 32 octets (none if the capacity is less than
    /// 32), saturating at `usize::MAX`: that is `max_decoded_len`.
    ///
    /// `max_wire_len` is what an insertion of that size can take on the wire
    /// at most: two prefixed integers, each of at most 11 octets (the
    /// longest encoding of a `u64`), and the name and the value as Huffman
    /// literals, where each decoded octet takes at most 30 bits (RFC 7541
    /// Appendix B) and each literal fills its last octet. It saturates at
    /// `usize::MAX`. The other instructions take one integer.
    pub const fn for_table_capacity(capacity: u64) -> Self {
        let room = capacity.saturating_sub(Self::ENTRY_OVERHEAD);
        let max_decoded_len = if room > usize::MAX as u64 {
            usize::MAX
        } else {
            room as usize
        };
        let literals = if max_decoded_len == 0 {
            0
        } else {
            // ceil(max_decoded_len * 30 / 8), saturating, without the overflow
            // of the product, and one octet more: the name and the value
            // each round up to whole octets, so together they can take one
            // more than their decoded octets would as one literal.
            (max_decoded_len / 8)
                .saturating_mul(Self::HUFFMAN_CODE_BITS)
                .saturating_add((max_decoded_len % 8 * Self::HUFFMAN_CODE_BITS).div_ceil(8))
                .saturating_add(1)
        };
        Self {
            max_wire_len: (2 * integer::MAX_ENCODED_LEN).saturating_add(literals),
            max_decoded_len,
        }
    }
}

/// The limits of a peer that has not been given a dynamic table: those of a
/// capacity of 0, the value of SETTINGS_QPACK_MAX_TABLE_CAPACITY until a
/// SETTINGS frame states another (RFC 9204 §5). No insertion is within them.
impl Default for EncoderStreamLimits {
    fn default() -> Self {
        Self::for_table_capacity(0)
    }
}

/// One encoder stream, read instruction by instruction from within a call.
///
/// It is made at an instruction boundary and reads nothing until asked for
/// the next instruction: a peer that does not use the dynamic table may never
/// send one. The next instruction is decoded from the stream as an
/// `Option<ReadValue<Started<'_, A>, M>>`, `M` being the metadata of the
/// stream's bytes; it is `None` where the stream ends at an instruction
/// boundary. An insertion borrows the stream until its value is finished, so
/// the next instruction cannot be read before. An instruction that is not
/// finished, because it failed or because it or the call reading it was
/// dropped, leaves the stream interrupted: what is left of the instruction is
/// never skipped, since the dynamic table would no longer match the peer's.
/// A call dropped before the first octet of an instruction has read nothing
/// and leaves the stream at the boundary.
/// An interrupted stream reports an error on every later instruction and is
/// abandoned; [`into_io`](Self::into_io) gives the access back.
#[derive(Debug)]
pub struct EncoderStream<A> {
    io: A,
    state: StreamState,
    limits: EncoderStreamLimits,
}

/// Where an instruction stream is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StreamState {
    /// At an instruction boundary.
    Boundary,
    /// Inside an instruction that was not finished, or one that failed.
    Interrupted,
}

/// Reads the start of the next instruction. Numeric instructions finish
/// here. Insertions lend this stream to their first state. The stream's
/// [`EncoderStreamLimits`] apply to all wire octets and to the sum of the
/// decoded literal octets, respectively.
///
/// The value is `None` if the stream ends at the instruction boundary.
/// Whether that is an error is a question for the stream's place in the
/// connection. Otherwise the metadata is the merged metadata of the octets
/// read: the first octet and the integers of the instruction's start. A
/// failure does not return the metadata of the octets read before it.
///
/// # Errors
///
/// [`StartError`](codec::StartError); after any of them, and after
/// [`StartError::Interrupted`](codec::StartError::Interrupted) itself, the
/// stream is interrupted.
impl<'s, A, M> DecodeFrom<&'s mut EncoderStream<A>> for Option<ReadValue<Started<'s, A>, M>>
where
    A: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    type Error = codec::StartError<<A::Family as Read>::Error>;

    async fn decode_from(stream: &'s mut EncoderStream<A>) -> Result<Self, Self::Error> {
        if stream.state == StreamState::Interrupted {
            return Err(codec::StartError::Interrupted);
        }
        let limits = stream.limits;
        // A call dropped before the first octet has read nothing: the stream
        // stays at the boundary.
        let mut wire = WireBudget::new(limits.max_wire_len);
        let mut merged = MergedMetadata(M::default());
        let mut source = MergingSource::new(&mut stream.io, &mut merged);
        let first = match crate::instruction::octet(&mut source.access(), &mut wire).await {
            Ok(first) => first,
            Err(error) if error.ended_before_first_octet() => return Ok(None),
            Err(source) => {
                stream.state = StreamState::Interrupted;
                return Err(codec::StartError::Prefix { source });
            }
        };
        // Until the instruction is complete, dropping this call or the state
        // it returns leaves the stream interrupted.
        stream.state = StreamState::Interrupted;
        let head = codec::read_head(
            &mut source.access(),
            &mut wire,
            limits.max_decoded_len,
            first,
        )
        .await?;
        let metadata = merged.0;
        let started = match head {
            codec::Head::Capacity(n) => {
                stream.state = StreamState::Boundary;
                Started::SetDynamicTableCapacity(n)
            }
            codec::Head::Duplicate(n) => {
                stream.state = StreamState::Boundary;
                Started::Duplicate(n)
            }
            codec::Head::Reference(name) => Started::InsertWithNameReference {
                name,
                value: ValueStart {
                    ctx: Context {
                        reader: stream,
                        wire,
                        decoded_left: limits.max_decoded_len,
                    },
                },
            },
            codec::Head::Literal(name) => Started::InsertWithLiteralName(Name {
                ctx: Context {
                    reader: stream,
                    wire,
                    decoded_left: limits.max_decoded_len,
                },
                literal: name,
            }),
        };
        Ok(Some(ReadValue {
            value: started,
            metadata,
        }))
    }
}

impl<A> EncoderStream<A> {
    /// The stream on `io`, an access or an exclusive borrow of one, at an
    /// instruction boundary, reading instructions within `limits`. Nothing
    /// is read.
    pub fn new(io: A, limits: EncoderStreamLimits) -> Self {
        Self {
            io,
            state: StreamState::Boundary,
            limits,
        }
    }

    /// The limits the next instruction is read within.
    pub const fn limits(&self) -> EncoderStreamLimits {
        self.limits
    }

    /// Reads the instructions after this call within `limits`. An
    /// instruction begun before is read within the limits it began with.
    pub fn set_limits(&mut self, limits: EncoderStreamLimits) {
        self.limits = limits;
    }

    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.io
    }
}

/// A completed integer instruction or the first readable state of an insertion.
#[must_use]
pub enum Started<'s, A: ReceiverAccess> {
    /// The new dynamic table capacity in bytes.
    SetDynamicTableCapacity(u64),
    /// Relative index of the entry to duplicate.
    Duplicate(u64),
    /// The name is supplied by a reference. Open the value to continue.
    InsertWithNameReference {
        /// Entry supplying the name.
        name: NameReference,
        /// The next field in the stream.
        value: ValueStart<'s, A>,
    },
    /// The literal name precedes the value header on the wire.
    InsertWithLiteralName(Name<'s, A>),
}

struct Context<'s, A> {
    reader: &'s mut EncoderStream<A>,
    wire: WireBudget,
    decoded_left: usize,
}

/// Read the name before attempting to read its value header.
#[must_use]
pub struct Name<'s, A> {
    ctx: Context<'s, A>,
    literal: Literal,
}

impl<'s, A: ReceiverAccess> Name<'s, A> {
    /// Borrow the name's source. Further composition preserves backpressure.
    pub fn source(&mut self) -> LiteralSource<'_, A> {
        self.literal.source(&mut self.ctx.reader.io)
    }
    /// Validate the ending of the consumed name and release its value state.
    /// Does not read from the stream. Unread data is an error.
    pub fn finish(self) -> Result<ValueStart<'s, A>, FinishError> {
        let mut ctx = self.ctx;
        ctx.decoded_left -= self.literal.finish()?;
        Ok(ValueStart { ctx })
    }
}

/// The stream is positioned immediately before the value length and H bit.
#[must_use]
pub struct ValueStart<'s, A> {
    ctx: Context<'s, A>,
}

impl<'s, A: ReceiverAccess> ValueStart<'s, A> {
    /// Consume the value header and lend out its bounded payload source. The
    /// metadata is the merged metadata of the octets of the header.
    pub async fn open<M>(
        mut self,
    ) -> Result<ReadValue<Value<'s, A>, M>, codec::ValueError<<A::Family as Read>::Error>>
    where
        A::Family: Read<Metadata = M>,
        M: Combine + Unpin,
    {
        let mut merged = MergedMetadata(M::default());
        let mut source = MergingSource::new(&mut self.ctx.reader.io, &mut merged);
        let literal = codec::read_value_header(
            &mut source.access(),
            &mut self.ctx.wire,
            self.ctx.decoded_left,
        )
        .await?;
        Ok(ReadValue {
            value: Value {
                ctx: self.ctx,
                literal,
            },
            metadata: merged.0,
        })
    }
}

/// An insertion's value. Only a successful finish completes the instruction.
#[must_use]
pub struct Value<'s, A> {
    ctx: Context<'s, A>,
    literal: Literal,
}

impl<A: ReceiverAccess> Value<'_, A> {
    /// Borrow the value's source.
    pub fn source(&mut self) -> LiteralSource<'_, A> {
        self.literal.source(&mut self.ctx.reader.io)
    }
    /// Validate the consumed value's ending and enable the next instruction.
    pub fn finish(self) -> Result<(), FinishError> {
        self.literal.finish()?;
        self.ctx.reader.state = StreamState::Boundary;
        Ok(())
    }
}
