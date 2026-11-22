//! Instructions sent on the QPACK encoder stream (RFC 9204 §4.3).
//!
//! Inside a `nitori_call` operation, create a [`Reader`] over the current
//! access. Start an instruction and match its state. For a literal name,
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

use crate::{instruction::WireBudget, static_table};
use literal::{FinishError, Literal, LiteralSource};
use nitori_call::ReceiverAccess;
use nitori_io::Read;

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

/// Sequential access to one encoder stream from within a call. Create this
/// reader at an instruction boundary and retain it for the parsing loop.
/// On error or cancellation after the opcode has been consumed, abandon the stream: dropping an
/// unfinished state never consumes, skips, or reinterprets its remaining data.
pub struct Reader<A> {
    io: A,
    at_boundary: bool,
}

impl<A: ReceiverAccess> Reader<A>
where
    A::Family: Read,
{
    /// Take ownership of an access or an exclusive borrow of it.
    pub fn new(io: A) -> Self {
        Self {
            io,
            at_boundary: true,
        }
    }

    /// Start exactly one instruction. Numeric instructions finish here.
    /// Insertions lend this reader to their first state. Limits apply to all
    /// wire octets and to the sum of the decoded literal octets, respectively.
    pub async fn start(
        &mut self,
        max_wire_len: usize,
        max_decoded_len: usize,
    ) -> Result<Started<'_, A>, codec::StartError<<A::Family as Read>::Error>> {
        if !self.at_boundary {
            return Err(codec::StartError::NotAtBoundary);
        }
        let mut wire = WireBudget::new(max_wire_len);
        let first = crate::instruction::octet(&mut self.io, &mut wire)
            .await
            .map_err(|source| codec::StartError::Prefix { source })?;
        self.at_boundary = false;
        let head = codec::read_head(&mut self.io, &mut wire, max_decoded_len, first).await?;
        Ok(match head {
            codec::Head::Capacity(n) => {
                self.at_boundary = true;
                Started::SetDynamicTableCapacity(n)
            }
            codec::Head::Duplicate(n) => {
                self.at_boundary = true;
                Started::Duplicate(n)
            }
            codec::Head::Reference(name) => Started::InsertWithNameReference {
                name,
                value: ValueStart {
                    ctx: Context {
                        reader: self,
                        wire,
                        decoded_left: max_decoded_len,
                    },
                },
            },
            codec::Head::Literal(name) => Started::InsertWithLiteralName(Name {
                ctx: Context {
                    reader: self,
                    wire,
                    decoded_left: max_decoded_len,
                },
                literal: name,
            }),
        })
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
    reader: &'s mut Reader<A>,
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

impl<'s, A: ReceiverAccess> ValueStart<'s, A>
where
    A::Family: Read,
{
    /// Consume the value header and lend out its bounded payload source.
    pub async fn open(
        mut self,
    ) -> Result<Value<'s, A>, codec::ValueError<<A::Family as Read>::Error>> {
        let literal = codec::read_value_header(
            &mut self.ctx.reader.io,
            &mut self.ctx.wire,
            self.ctx.decoded_left,
        )
        .await?;
        Ok(Value {
            ctx: self.ctx,
            literal,
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
        self.ctx.reader.at_boundary = true;
        Ok(())
    }
}
