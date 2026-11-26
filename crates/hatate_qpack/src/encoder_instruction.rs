//! Instructions sent on the QPACK encoder stream (RFC 9204 §4.3).
//!
//! An [`EncoderInstruction`] is the same type whether it was read or is to be
//! written. Inside a `nitori_call` operation, keep an [`EncoderStream`] over
//! the current access, made at an instruction boundary with its
//! [`EncoderStreamLimits`]. Decode the next instruction from it as an
//! `Option<ReadValue<EncoderInstruction<S, H>, M>>`: the instruction is read
//! whole before it is handed over, with the merged metadata `M` of all of its
//! octets. Encode an instruction into it to write it: the stream checks the
//! instruction against its limits before it writes the first octet.
//!
//! Every integer and literal keeps the details of its encoding: an
//! instruction read and written back yields the octets it was read from.
//! A raw literal collects the source's chunks in `S` (`Default + Extend` of
//! the chunk type), so with [`JoinedBytes`](crate::string_literal::JoinedBytes)
//! and a source of `Bytes` chunks, a literal that arrives in one chunk shares
//! its storage. A Huffman literal collects its decoded octets in `H`
//! (`Default + Extend<u8>`). To write an instruction back, `S` must also
//! encode itself into the stream and `H` must be a `Buf`.
//!
//! ```
//! # #![feature(impl_trait_in_assoc_type)]
//! use bytes::{Bytes, BytesMut};
//! use core::fmt::Debug;
//! use hatate_qpack::encoder_instruction::{
//!     EncoderInstruction, EncoderStream, EncoderStreamLimits,
//! };
//! use hatate_qpack::string_literal::JoinedBytes;
//! use nitori_call::{ReceiverAccess, call};
//! use nitori_codec::{DecodeFrom, EncodeInto};
//! use nitori_io::{calls::ReadValue, prelude::*};
//!
//! /// Reads each instruction of `input` and writes it to `output`.
//! #[call(sync)]
//! async fn relay<F: ReadChunk<Chunk = Bytes, Metadata = ()>, G: Write<Report = ()>>(
//!     input: &mut impl ReceiverAccess<Family = F>,
//!     output: &mut impl ReceiverAccess<Family = G>,
//! ) where
//!     F::Error: Debug,
//!     G::Error: Debug,
//! {
//!     let limits = EncoderStreamLimits::for_table_capacity(220);
//!     let mut reader = EncoderStream::new(input, limits);
//!     let mut writer = EncoderStream::new(output, limits);
//!     type Next = Option<ReadValue<EncoderInstruction<JoinedBytes, BytesMut>, ()>>;
//!     while let Some(read) = Next::decode_from(&mut reader).await.unwrap() {
//!         read.value.encode_into(&mut writer).await.unwrap();
//!     }
//! }
//!
//! // Set Dynamic Table Capacity 220 with one octet more than it needs, and
//! // an insertion of the value "www" with the static name :authority.
//! let wire = Bytes::from_static(b"\x3f\xbd\x81\x00\xc0\x03www");
//! let mut hosts = (wire.clone(), Vec::new());
//! hosts.sync_relay_unpin();
//! assert_eq!(hosts.1, wire);
//! ```
mod read;
mod write;

pub use read::{DecodeEncoderInstructionError, DecodeLiteralError, DecodedLengthError};
pub use write::EncodeEncoderInstructionError;

use crate::{
    instruction::Position,
    integer::{self, PrefixedField},
    static_table,
    string_literal::StringLiteral,
};
use bytes::Bytes;

/// An encoder-stream name reference. Relative index zero refers to the most
/// recent insertion when the instruction is applied (RFC 9204 §3.2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameReference {
    /// A known static table entry.
    Static {
        /// The entry, with the padding of its encoding.
        index: PrefixedField<static_table::Index>,
    },
    /// A dynamic entry in encoder-stream coordinates.
    Relative {
        /// The relative index, with the padding of its encoding.
        index: PrefixedField,
    },
}

/// One encoder instruction (RFC 9204 §4.3): what is read from an encoder
/// stream and what is written to one.
///
/// A raw literal holds its octets in `S`, a Huffman literal its decoded
/// octets in `H` ([`StringLiteral`]). The literals' lengths were fixed when
/// they were constructed, so the instruction knows its size on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncoderInstruction<S = Bytes, H = Bytes> {
    /// Set Dynamic Table Capacity (RFC 9204 §4.3.1).
    SetDynamicTableCapacity {
        /// The new capacity in octets.
        capacity: PrefixedField,
    },
    /// Insert with Name Reference (RFC 9204 §4.3.2).
    InsertWithNameReference {
        /// The entry supplying the name.
        name: NameReference,
        /// The value.
        value: StringLiteral<S, H>,
    },
    /// Insert with Literal Name (RFC 9204 §4.3.3).
    InsertWithLiteralName {
        /// The name.
        name: StringLiteral<S, H>,
        /// The value.
        value: StringLiteral<S, H>,
    },
    /// Duplicate (RFC 9204 §4.3.4).
    Duplicate {
        /// The relative index of the entry to duplicate.
        index: PrefixedField,
    },
}

/// The prefix widths of the instruction's integers and literal lengths.
const CAPACITY_BITS: u8 = 5;
const DUPLICATE_BITS: u8 = 5;
const NAME_INDEX_BITS: u8 = 6;
const NAME_LENGTH_BITS: u8 = 5;
const VALUE_LENGTH_BITS: u8 = 7;

impl<S, H> EncoderInstruction<S, H> {
    /// The octets of the whole instruction on the wire: its integers and its
    /// literals with their length prefixes. Saturates at `u64::MAX`. Exact
    /// for an instruction whose integers and lengths have an encoding in
    /// their positions, as one read or constructed for them has.
    pub fn wire_len(&self) -> u64 {
        match self {
            Self::SetDynamicTableCapacity { capacity } => {
                capacity.encoded_len::<CAPACITY_BITS>() as u64
            }
            Self::Duplicate { index } => index.encoded_len::<DUPLICATE_BITS>() as u64,
            Self::InsertWithNameReference { name, value } => {
                let name = match name {
                    NameReference::Static { index } => index.encoded_len::<NAME_INDEX_BITS>(),
                    NameReference::Relative { index } => index.encoded_len::<NAME_INDEX_BITS>(),
                };
                (name as u64).saturating_add(value.wire_len::<VALUE_LENGTH_BITS>())
            }
            Self::InsertWithLiteralName { name, value } => name
                .wire_len::<NAME_LENGTH_BITS>()
                .saturating_add(value.wire_len::<VALUE_LENGTH_BITS>()),
        }
    }

    /// The decoded octets of the instruction's literals together: the value
    /// of an insertion, and its name if that is a literal. A name taken from
    /// a table entry does not count. Saturates at `u64::MAX`.
    pub fn decoded_len(&self) -> u64 {
        match self {
            Self::SetDynamicTableCapacity { .. } | Self::Duplicate { .. } => 0,
            Self::InsertWithNameReference { value, .. } => value.decoded_len(),
            Self::InsertWithLiteralName { name, value } => {
                name.decoded_len().saturating_add(value.decoded_len())
            }
        }
    }
}

/// The limits on the instructions of one encoder stream.
///
/// A stream that reads checks them as each instruction is read; they are
/// this endpoint's, following from the dynamic table capacity it allows. A
/// stream that writes checks them before it writes an instruction; they are
/// the peer's. They apply to the instructions after they are set. The
/// defaults are those of a peer that has not been given a dynamic table:
/// see [`for_table_capacity`](Self::for_table_capacity).
///
/// They bound the size of an instruction, not what the dynamic table
/// holds: the name of an insertion that references an entry does not count
/// toward `max_decoded_len`, nor do the 32 octets an entry adds to its name
/// and value (RFC 9204 §3.2.1). Whether an inserted entry fits the table's
/// current capacity (RFC 9204 §3.2.2) is for the decoder that keeps the
/// table to check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncoderStreamLimits {
    /// The most wire octets one instruction may take, counting every prefix,
    /// integer and literal payload of it.
    pub max_wire_len: usize,
    /// The most octets the literals of an insertion, its name if it has one
    /// and its value, may have together once decoded; the Huffman literals
    /// count their decoded octets. A name taken from a table entry does not
    /// count.
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
    /// 9204 §3.2.1), so the name and the value of an entry that fits together
    /// have at most `capacity` less 32 octets (none if the capacity is less
    /// than 32), saturating at `usize::MAX`: that is `max_decoded_len`. It
    /// bounds the literals only; an insertion within these limits can still
    /// make an entry larger than `capacity`, such as an empty name and value,
    /// or a long name referenced from a table.
    ///
    /// `max_wire_len` is what an insertion of that size can take on the wire
    /// at most: two prefixed integers, each of at most 11 octets (the
    /// longest encoding a stream reads), and the name and the value as
    /// Huffman literals, where each decoded octet takes at most 30 bits (RFC
    /// 7541 Appendix B) and each literal fills its last octet. It saturates
    /// at `usize::MAX`. The other instructions take one integer.
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
/// SETTINGS frame states another (RFC 9204 §5). No literal octet is within
/// them; an insertion whose name is referenced and whose value is empty, or
/// whose name and value are both empty, is.
impl Default for EncoderStreamLimits {
    fn default() -> Self {
        Self::for_table_capacity(0)
    }
}

/// One encoder stream, read or written instruction by instruction from
/// within a call.
///
/// The same type serves both directions: decode instructions from the
/// stream of the peer's encoder, within this endpoint's limits, or encode
/// them into this endpoint's encoder stream, within the peer's.
///
/// It is made at an instruction boundary and does nothing until asked for
/// the next instruction: a peer that does not use the dynamic table may never
/// send one. The next instruction is decoded from it as an
/// `Option<ReadValue<EncoderInstruction<S, H>, M>>`, `M` being the metadata
/// of the stream's octets; it is `None` where the stream ends at an
/// instruction boundary.
///
/// An instruction that was begun and not finished, because it failed or
/// because the call reading or writing it was dropped, leaves the stream
/// interrupted: what is left of the instruction is never skipped or written
/// later, since the dynamic table would no longer match the peer's. A read
/// has begun once it has read the first octet; a write once the stream has
/// accepted one. A read or write dropped before that, or a write refused
/// before it wrote anything, leaves the stream at the boundary. An
/// interrupted stream reports an error on every later instruction and is
/// abandoned; [`into_io`](Self::into_io) gives the access back.
#[derive(Debug)]
pub struct EncoderStream<A> {
    io: A,
    position: Position,
    limits: EncoderStreamLimits,
}

impl<A> EncoderStream<A> {
    /// The stream on `io`, an access or an exclusive borrow of one, at an
    /// instruction boundary, with the instructions within `limits`. Nothing
    /// is read or written.
    pub fn new(io: A, limits: EncoderStreamLimits) -> Self {
        Self {
            io,
            position: Position::new(),
            limits,
        }
    }

    /// The limits of the next instruction.
    pub const fn limits(&self) -> EncoderStreamLimits {
        self.limits
    }

    /// Reads or writes the instructions after this call within `limits`.
    /// An instruction begun before keeps the limits it began with.
    pub fn set_limits(&mut self, limits: EncoderStreamLimits) {
        self.limits = limits;
    }

    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.io
    }
}
