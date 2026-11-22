use super::{DynamicReferenceError, prefix};
use crate::InsufficientCapacityError;
use crate::field_line::{self, FieldLine, Prepared, TableIndex};
use alloc::{collections::TryReserveError, vec::Vec};
use bytes::BufMut;
use snafu::{ResultExt, Snafu};

/// A static-mode field section could not be encoded.
#[derive(Debug, Snafu)]
pub enum WriteError {
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

/// Write a canonical zero prefix followed by the caller's selected
/// representations in order. Validation and sizing of all fields takes place
/// before the first write. On error the destination is unchanged.
pub fn write_static_section<S: AsRef<[u8]>, H: AsRef<[u8]>>(
    dst: &mut impl BufMut,
    lines: &[FieldLine<S, H>],
) -> Result<(), WriteError> {
    let mut prepared = Vec::new();
    prepared
        .try_reserve_exact(lines.len())
        .context(ReserveFieldsSnafu)?;
    let mut required = prefix::ENCODED.len() as u128;
    for (index, line) in lines.iter().enumerate() {
        match line {
            FieldLine::Indexed(TableIndex::Relative(_) | TableIndex::PostBase(_)) => {
                return Err(WriteError::DynamicReference {
                    index,
                    source: DynamicReferenceError::Field,
                });
            }
            FieldLine::LiteralWithNameReference {
                name: TableIndex::Relative(_) | TableIndex::PostBase(_),
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
        // Each descriptor occupies more than two bytes; even a maximal slice
        // of descriptors with two u64-sized payloads each fits a u128 total.
        required += field.len();
        prepared.push(field);
    }
    let octets = prefix::ENCODED
        .into_iter()
        .chain(prepared.into_iter().flat_map(Prepared::octets));
    field_line::transfer(dst, required, octets)?;
    Ok(())
}
