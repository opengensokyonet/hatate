//! Complete QPACK field sections when the negotiated maximum table capacity
//! is zero (RFC 9204 §4.5). HTTP field syntax is checked by the caller.
//!
//! ```
//! use hatate_qpack::static_section::read_static_section;
//!
//! let payload = &[0, 0, 0xd1, 0xd7][..];
//! let fields = read_static_section(payload, 0, 86)?.collect::<Result<Vec<_>, _>>()?;
//! assert_eq!(fields[0].value.as_ref(), b"GET");
//! assert_eq!(fields[1].value.as_ref(), b"https");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod budget;
mod prefix;
mod write;

use crate::field_line::{self, Head, TableIndex};
use crate::string_literal::StringLiteral;
use budget::Budget;
use bytes::{Buf, Bytes};
use core::iter::FusedIterator;
use nitori_io::SplitTo;
use snafu::{ResultExt, Snafu};

pub use prefix::PrefixError;
pub use write::{WriteError, write_static_section};

/// Decoded name or value octets and their backing storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldBytes<S> {
    /// Bytes from a static table entry.
    Static(&'static [u8]),
    /// A literal split directly from the original input.
    Input(S),
    /// Bytes produced by the Huffman decoder.
    Huffman(Bytes),
}

impl<S: AsRef<[u8]>> AsRef<[u8]> for FieldBytes<S> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Static(bytes) => bytes,
            Self::Input(bytes) => bytes.as_ref(),
            Self::Huffman(bytes) => bytes.as_ref(),
        }
    }
}

impl<S> From<StringLiteral<S>> for FieldBytes<S> {
    fn from(literal: StringLiteral<S>) -> Self {
        match literal {
            StringLiteral::Raw(data) => Self::Input(data),
            StringLiteral::Huffman(data) => Self::Huffman(data),
        }
    }
}

/// One resolved field. Duplicate names and wire order are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field<S> {
    /// Decoded field name, including any leading colon.
    pub name: FieldBytes<S>,
    /// Decoded field value.
    pub value: FieldBytes<S>,
    /// The N bit from a literal representation; false for indexed fields.
    pub never_index: bool,
}

/// A dynamic reference in a section with zero maximum table capacity.
#[derive(Debug, PartialEq, Eq, Snafu)]
pub enum DynamicReferenceError {
    /// A whole field referenced a dynamic entry.
    #[snafu(display("indexed field refers to the dynamic table"))]
    Field,
    /// A literal field's name referenced a dynamic entry.
    #[snafu(display("field name refers to the dynamic table"))]
    Name,
}

/// Failure while iterating over a section with a valid prefix.
#[derive(Debug, Snafu)]
pub enum ReadError {
    /// Invalid encoding or a literal exceeding its own decoded size limit.
    #[snafu(display("could not decode field line"))]
    Line {
        /// Error while reading the field representation.
        source: field_line::ReadError,
    },
    /// The resolved section would exceed the decoded section size limit.
    #[snafu(display("decoded field section exceeds its size limit"))]
    SectionTooLarge,
    /// Static mode does not allow the field's reference.
    #[snafu(display("dynamic reference in static field section"))]
    DynamicReference {
        /// Where the reference occurred.
        source: DynamicReferenceError,
    },
}

/// Parse the prefix of an entire field section payload, then decode one field
/// per iteration. A literal's decoded size is bounded by `max_literal_len`;
/// `max_section_size` includes the resolved names, values and 32 bytes per
/// field (RFC 9114 §4.2.2). When the two bounds tie, a literal overrun is
/// reported as a literal error. Accept the section only after successful
/// exhaustion: dropping the iterator skips validation of the unread suffix.
pub fn read_static_section<S: Buf + SplitTo>(
    mut src: S,
    max_literal_len: usize,
    max_section_size: usize,
) -> Result<Fields<S>, PrefixError> {
    prefix::read(&mut src)?;
    Ok(Fields {
        src: Some(src),
        budget: Budget::new(max_literal_len, max_section_size),
    })
}

/// An ordered sequence of decoded fields. The first error ends iteration.
pub struct Fields<S> {
    src: Option<S>,
    budget: Budget,
}

impl<S: Buf + SplitTo> Iterator for Fields<S> {
    type Item = Result<Field<S>, ReadError>;

    fn next(&mut self) -> Option<Self::Item> {
        let src = self.src.as_mut()?;
        if !src.has_remaining() {
            self.src = None;
            return None;
        }
        let field = read_one(src, &mut self.budget);
        if field.is_err() {
            self.src = None;
        }
        Some(field)
    }
}

impl<S: Buf + SplitTo> FusedIterator for Fields<S> {}

fn read_one<S: Buf + SplitTo>(src: &mut S, budget: &mut Budget) -> Result<Field<S>, ReadError> {
    budget.start_line()?;
    let head = field_line::read_head(src).context(LineSnafu)?;
    let (name, never_index) = match head {
        Head::Indexed(TableIndex::Static(index)) => {
            let (name, value) = index.entry();
            budget.charge(name.len())?;
            budget.charge(value.len())?;
            return Ok(Field {
                name: FieldBytes::Static(name),
                value: FieldBytes::Static(value),
                never_index: false,
            });
        }
        Head::Indexed(_) => {
            return Err(ReadError::DynamicReference {
                source: DynamicReferenceError::Field,
            });
        }
        Head::NameReference {
            name: TableIndex::Static(index),
            never_index,
        } => {
            let (name, _) = index.entry();
            budget.charge(name.len())?;
            (FieldBytes::Static(name), never_index)
        }
        Head::NameReference { .. } => {
            return Err(ReadError::DynamicReference {
                source: DynamicReferenceError::Name,
            });
        }
        Head::LiteralName { first, never_index } => (
            budget
                .literal(|limit| field_line::read_name(first, src, limit))?
                .into(),
            never_index,
        ),
    };
    let value = budget
        .literal(|limit| field_line::read_value(src, limit))?
        .into();
    Ok(Field {
        name,
        value,
        never_index,
    })
}
