//! Complete QPACK field sections when the negotiated maximum table capacity
//! is zero (RFC 9204 §4.5). HTTP field syntax is checked by the caller.
//!
//! Reading a section yields its prefix and each line's representation along
//! with the resolved name and value; writing the prefix and the lines back
//! yields the octets that were read.
//!
//! ```
//! use bytes::BytesMut;
//! use hatate_qpack::{
//!     field_line::FieldLine,
//!     static_section::{read_static_section, write_static_section},
//! };
//!
//! let payload = &[0, 0, 0xd1, 0xd7][..];
//! let section = read_static_section::<_, BytesMut>(payload, 0, 86)?;
//! let fields = section.fields.collect::<Result<Vec<_>, _>>()?;
//! assert_eq!(fields[0].value.as_ref(), b"GET");
//! assert_eq!(fields[1].value.as_ref(), b"https");
//! let mut output = Vec::new();
//! let lines = fields.iter().map(|field| FieldLine::from(&field.line));
//! write_static_section(&mut output, &section.prefix, lines)?;
//! assert_eq!(output, payload);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod budget;
mod prefix;
mod write;

use crate::field_line::{self, FieldLine, Head, TableIndex};
use crate::string_literal::{LiteralBytes, StringLiteral};
use budget::Budget;
use bytes::Buf;
use core::iter::FusedIterator;
use core::marker::PhantomData;
use nitori_io::SplitTo;
use snafu::{ResultExt, Snafu};

pub use prefix::{PrefixError, SectionPrefix};
pub use write::{WriteError, write_static_section};

/// Decoded name or value octets and their backing storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldBytes<S, H> {
    /// Bytes from a static table entry.
    Static(&'static [u8]),
    /// A literal split directly from the original input.
    Input(S),
    /// Bytes produced by the Huffman decoder.
    Huffman(H),
}

impl<S: AsRef<[u8]>, H: AsRef<[u8]>> AsRef<[u8]> for FieldBytes<S, H> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Static(bytes) => bytes,
            Self::Input(bytes) => bytes.as_ref(),
            Self::Huffman(bytes) => bytes.as_ref(),
        }
    }
}

impl<S: Clone, H: Clone> From<&StringLiteral<S, H>> for FieldBytes<S, H> {
    fn from(literal: &StringLiteral<S, H>) -> Self {
        match literal.bytes() {
            LiteralBytes::Raw(bytes) => Self::Input(bytes.clone()),
            LiteralBytes::Huffman(decoded) => Self::Huffman(decoded.clone()),
        }
    }
}

/// One field: its representation on the wire and its resolved name and
/// value. Duplicate names and wire order are preserved. The N bit is in
/// `line`; an indexed field has none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field<S, H> {
    /// The representation as read, which writes back to the same octets.
    pub line: FieldLine<S, H>,
    /// Decoded field name, including any leading colon.
    pub name: FieldBytes<S, H>,
    /// Decoded field value.
    pub value: FieldBytes<S, H>,
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
///
/// Raw literals are split from `src`, Huffman literals decoded into `H`. A
/// [`Field`] holds each literal both in its line and as its name or value,
/// so the iterator clones them: cheaply for `Bytes` or a slice, by copying
/// for a `Vec<u8>` or `BytesMut`.
pub fn read_static_section<S: Buf + SplitTo, H>(
    mut src: S,
    max_literal_len: usize,
    max_section_size: usize,
) -> Result<StaticSection<S, H>, PrefixError> {
    let prefix = prefix::read(&mut src)?;
    Ok(StaticSection {
        prefix,
        fields: Fields {
            src: Some(src),
            budget: Budget::new(max_literal_len, max_section_size),
            huffman: PhantomData,
        },
    })
}

/// A field section being read in static mode: its prefix, read whole, and
/// its fields, read one per iteration ([`read_static_section`]).
pub struct StaticSection<S, H> {
    /// The section's prefix.
    pub prefix: SectionPrefix,
    /// The fields after the prefix.
    pub fields: Fields<S, H>,
}

/// An ordered sequence of decoded fields. The first error ends iteration.
pub struct Fields<S, H> {
    src: Option<S>,
    budget: Budget,
    huffman: PhantomData<fn() -> H>,
}

impl<S, H> Iterator for Fields<S, H>
where
    S: Buf + SplitTo + Clone,
    H: Default + Extend<u8> + Clone,
{
    type Item = Result<Field<S, H>, ReadError>;

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

impl<S, H> FusedIterator for Fields<S, H>
where
    S: Buf + SplitTo + Clone,
    H: Default + Extend<u8> + Clone,
{
}

fn read_one<S, H>(src: &mut S, budget: &mut Budget) -> Result<Field<S, H>, ReadError>
where
    S: Buf + SplitTo + Clone,
    H: Default + Extend<u8> + Clone,
{
    budget.start_line()?;
    let head = field_line::read_head(src).context(LineSnafu)?;
    match head {
        Head::Indexed(index @ TableIndex::Static { index: entry }) => {
            let (name, value) = entry.value().entry();
            budget.charge(name.len())?;
            budget.charge(value.len())?;
            Ok(Field {
                line: FieldLine::Indexed { index },
                name: FieldBytes::Static(name),
                value: FieldBytes::Static(value),
            })
        }
        Head::Indexed(_) => Err(ReadError::DynamicReference {
            source: DynamicReferenceError::Field,
        }),
        Head::NameReference {
            name: name @ TableIndex::Static { index },
            never_index,
        } => {
            let (resolved, _) = index.value().entry();
            budget.charge(resolved.len())?;
            let value = budget.literal(|limit| field_line::read_value(src, limit))?;
            Ok(Field {
                name: FieldBytes::Static(resolved),
                value: FieldBytes::from(&value),
                line: FieldLine::LiteralWithNameReference {
                    never_index,
                    name,
                    value,
                },
            })
        }
        Head::NameReference { .. } => Err(ReadError::DynamicReference {
            source: DynamicReferenceError::Name,
        }),
        Head::LiteralName { first, never_index } => {
            let name = budget.literal(|limit| field_line::read_name(first, src, limit))?;
            let value = budget.literal(|limit| field_line::read_value(src, limit))?;
            Ok(Field {
                name: FieldBytes::from(&name),
                value: FieldBytes::from(&value),
                line: FieldLine::LiteralWithLiteralName {
                    never_index,
                    name,
                    value,
                },
            })
        }
    }
}
