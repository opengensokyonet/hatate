//! Read and write one QPACK field line representation.

use bytes::{Buf, Bytes};
use nitori_io::SplitTo;
use snafu::{ResultExt, Snafu};

use crate::static_table::Index;
use crate::string_literal::StringLiteral;
use crate::{integer, static_table, string_literal};

mod write;
pub use write::{WriteError, write_field_line};

/// A field line's reference, relative to its field section where applicable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TableIndex {
    /// An entry from the fixed QPACK table.
    Static(Index),
    /// Dynamic entry at absolute index Base − 1 − this value.
    Relative(u64),
    /// Dynamic entry at absolute index Base + this value.
    PostBase(u64),
}

/// The five wire formats group by whether they index an entire field, its
/// name, or neither. The index's kind determines the wire prefix. A set
/// `never_index` requires a literal representation when forwarding the field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FieldLine<S = Bytes, H = Bytes> {
    /// Both name and value come from this entry.
    Indexed(TableIndex),
    /// A name from a table and a literal value.
    LiteralWithNameReference {
        /// The N bit.
        never_index: bool,
        /// The table entry supplying the name.
        name: TableIndex,
        /// Literal field value.
        value: StringLiteral<S, H>,
    },
    /// Both name and value are literal.
    LiteralWithLiteralName {
        /// The N bit.
        never_index: bool,
        /// Literal field name, preserving the peer's octets.
        name: StringLiteral<S, H>,
        /// Literal field value.
        value: StringLiteral<S, H>,
    },
}

/// A field line could not be read. The source identifies which wire rule failed.
#[derive(Debug, Snafu)]
pub enum ReadError {
    /// No first octet of the representation.
    #[snafu(display("missing field line prefix"))]
    MissingPrefix,
    /// The indexed field's index could not be read.
    #[snafu(display("invalid field index"))]
    FieldIndex {
        /// Prefixed integer failure.
        source: integer::ReadError,
    },
    /// The referenced name's index could not be read.
    #[snafu(display("invalid name index"))]
    NameIndex {
        /// Prefixed integer failure.
        source: integer::ReadError,
    },
    /// An indexed field references a nonexistent static entry.
    #[snafu(display("invalid static field reference"))]
    StaticField {
        /// Out-of-range static index.
        source: static_table::IndexError,
    },
    /// A literal references a nonexistent static name.
    #[snafu(display("invalid static name reference"))]
    StaticName {
        /// Out-of-range static index.
        source: static_table::IndexError,
    },
    /// The field name is an invalid string literal.
    #[snafu(display("invalid literal field name"))]
    Name {
        /// String literal failure.
        source: string_literal::ReadError,
    },
    /// A literal field has no initial length octet for its value.
    #[snafu(display("missing literal value length"))]
    MissingValueLength,
    /// The field value is an invalid string literal.
    #[snafu(display("invalid literal field value"))]
    Value {
        /// String literal failure.
        source: string_literal::ReadError,
    },
}

/// Read a single field line. The limit applies separately to the decoded
/// length of each literal name and value, in octets. Bytes already read on
/// failure stay consumed. Dynamic references are returned in wire coordinates.
pub fn read_field_line<S: Buf + SplitTo>(
    src: &mut S,
    max_literal_len: usize,
) -> Result<FieldLine<S>, ReadError> {
    let first = src.try_get_u8().map_err(|_| ReadError::MissingPrefix)?;
    let value = |src: &mut S| {
        let prefix = src
            .try_get_u8()
            .map_err(|_| ReadError::MissingValueLength)?;
        string_literal::read::<7, _>(prefix, src, max_literal_len).context(ValueSnafu)
    };
    match first {
        0x80..=0xff => {
            let index = integer::read::<6>(first, src).context(FieldIndexSnafu)?;
            let index = if first & 0x40 != 0 {
                TableIndex::Static(Index::try_from(index).context(StaticFieldSnafu)?)
            } else {
                TableIndex::Relative(index)
            };
            Ok(FieldLine::Indexed(index))
        }
        0x40..=0x7f => {
            let index = integer::read::<4>(first, src).context(NameIndexSnafu)?;
            let name = if first & 0x10 != 0 {
                TableIndex::Static(Index::try_from(index).context(StaticNameSnafu)?)
            } else {
                TableIndex::Relative(index)
            };
            Ok(FieldLine::LiteralWithNameReference {
                never_index: first & 0x20 != 0,
                name,
                value: value(src)?,
            })
        }
        0x20..=0x3f => Ok(FieldLine::LiteralWithLiteralName {
            never_index: first & 0x10 != 0,
            name: string_literal::read::<3, _>(first, src, max_literal_len).context(NameSnafu)?,
            value: value(src)?,
        }),
        0x10..=0x1f => {
            let index = integer::read::<4>(first, src).context(FieldIndexSnafu)?;
            Ok(FieldLine::Indexed(TableIndex::PostBase(index)))
        }
        0x00..=0x0f => {
            let index = integer::read::<3>(first, src).context(NameIndexSnafu)?;
            Ok(FieldLine::LiteralWithNameReference {
                never_index: first & 0x08 != 0,
                name: TableIndex::PostBase(index),
                value: value(src)?,
            })
        }
    }
}

#[cfg(test)]
mod tests;
