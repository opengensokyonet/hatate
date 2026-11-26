use super::{DynamicReferenceError, SectionPrefix};
use crate::InsufficientCapacityError;
use crate::field_line::{self, FieldLine, Part, Prepared, TableIndex};
use alloc::{collections::TryReserveError, vec::Vec};
use bytes::{Buf, BufMut};
use snafu::{ResultExt, Snafu};

/// A static-mode field section could not be encoded.
#[derive(Debug, Snafu)]
pub enum WriteError {
    /// The prefix needs a dynamic table: a nonzero Encoded Insert Count or
    /// a set sign bit.
    #[snafu(display("field section prefix refers to the dynamic table"))]
    DynamicPrefix,
    /// A field uses a relative or post-Base index.
    #[snafu(display("dynamic reference in field {index}"))]
    DynamicReference {
        /// Zero-based position in the input.
        index: usize,
        /// Where the reference occurred.
        source: DynamicReferenceError,
    },
    /// Could not prepare the selected representation of a field.
    #[snafu(display("could not encode field {index}"))]
    Line {
        /// Zero-based position in the input.
        index: usize,
        /// The field encoding failure.
        source: field_line::WriteError,
    },
    /// Could not reserve storage for the measured representations.
    #[snafu(display("could not reserve field section metadata"))]
    ReserveFields {
        /// The host reservation error.
        source: TryReserveError,
    },
    /// The complete representation would not fit.
    #[snafu(transparent)]
    InsufficientCapacity {
        /// Required wire length and available destination space.
        source: InsufficientCapacityError,
    },
}

/// Write `prefix` followed by the caller's selected representations in
/// order, each with the encoding details it carries. Validation and sizing
/// of the prefix and all fields take place before the first write. On error
/// the destination is unchanged.
pub fn write_static_section<S: Buf, H: Buf>(
    dst: &mut impl BufMut,
    prefix: &SectionPrefix,
    lines: impl IntoIterator<Item = FieldLine<S, H>>,
) -> Result<(), WriteError> {
    if prefix.encoded_insert_count().value().get() != 0 || prefix.is_negative() {
        return Err(WriteError::DynamicPrefix);
    }
    // The sign bit is clear here.
    let head = Prepared::from_parts(
        Part::integer::<8, _>(0, prefix.encoded_insert_count())
            .expect("the prefix checked its encoded insert count"),
        Part::integer::<7, _>(0, prefix.delta_base()).expect("the prefix checked its delta base"),
    );
    let mut required = head.len;
    let mut prepared = Vec::new();
    prepared.try_reserve(1).context(ReserveFieldsSnafu)?;
    prepared.push(head.buf);
    for (index, line) in lines.into_iter().enumerate() {
        match &line {
            FieldLine::Indexed {
                index: TableIndex::Relative { .. } | TableIndex::PostBase { .. },
            } => {
                return Err(WriteError::DynamicReference {
                    index,
                    source: DynamicReferenceError::Field,
                });
            }
            FieldLine::LiteralWithNameReference {
                name: TableIndex::Relative { .. } | TableIndex::PostBase { .. },
                ..
            } => {
                return Err(WriteError::DynamicReference {
                    index,
                    source: DynamicReferenceError::Name,
                });
            }
            _ => {}
        }
        let field = Prepared::new(line).context(LineSnafu { index })?;
        // Each line's length is below 2^66 octets, and there can be fewer
        // than 2^64 lines, so the total fits a u128.
        required += field.len;
        prepared.try_reserve(1).context(ReserveFieldsSnafu)?;
        prepared.push(field.buf);
    }
    field_line::transfer(dst, required, prepared.into_iter())?;
    Ok(())
}
