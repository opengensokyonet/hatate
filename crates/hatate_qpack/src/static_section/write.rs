use super::{DynamicReferenceError, SectionPrefix};
use crate::InsufficientCapacityError;
use crate::field_line::{self, FieldLine, LineBuf, Part, Prepared, TableIndex};
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
    /// Walked a second time to be written, `lines` gave at `index` a line
    /// that no longer passes the checks or the length measured, or ended
    /// there before the length measured: a clone of the iterator did not
    /// give the same lines, or a literal's octets changed. The destination
    /// holds the prefix and the lines before `index`.
    #[snafu(display("field {index} changed between checking and writing"))]
    LineChanged {
        /// Zero-based position in the input.
        index: usize,
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
/// of the prefix and all fields take place before the first write: a clone
/// of `lines` is walked to check and measure the lines, and then `lines`
/// itself to write them, with the octets of their literals borrowed. On
/// error the destination is unchanged, except after
/// [`WriteError::LineChanged`].
pub fn write_static_section<'l, S, H, I>(
    dst: &mut impl BufMut,
    prefix: &SectionPrefix,
    lines: I,
) -> Result<(), WriteError>
where
    S: AsRef<[u8]> + 'l,
    H: AsRef<[u8]> + 'l,
    I: IntoIterator<Item = &'l FieldLine<S, H>>,
    I::IntoIter: Clone,
{
    if prefix.encoded_insert_count().value().get() != 0 || prefix.is_negative() {
        return Err(WriteError::DynamicPrefix);
    }
    // The sign bit is clear here.
    let head = Prepared::<&[u8], &[u8]>::from_parts(
        Part::integer::<8, _>(0, prefix.encoded_insert_count())
            .expect("the prefix checked its encoded insert count"),
        Part::integer::<7, _>(0, prefix.delta_base()).expect("the prefix checked its delta base"),
    );
    let lines = lines.into_iter();
    let mut required = head.len;
    for (index, line) in lines.clone().enumerate() {
        if let Some(source) = dynamic_reference(line) {
            return Err(WriteError::DynamicReference { index, source });
        }
        let field = Prepared::new(line.as_slices()).context(LineSnafu { index })?;
        // Each line's length is below 2^66 octets, and there can be fewer
        // than 2^64 lines, so the total fits a u128.
        required += field.len;
    }
    InsufficientCapacityError::check(required, dst.remaining_mut())?;
    // The check bounds the total by the destination's usize capacity. The
    // section goes in one `put`: a segmented destination may report a more
    // conservative capacity after its cursor moves.
    let mut section = Rewalk::new(head.buf, lines, required as usize);
    dst.put(&mut section);
    let more = section.lines.next().is_some();
    match section.changed {
        Some(index) => Err(WriteError::LineChanged { index }),
        None if more => Err(WriteError::LineChanged {
            index: section.index,
        }),
        None => Ok(()),
    }
}

/// The prefix and the lines of a section walked a second time, as one buffer
/// of the length the first walk measured. A line that no longer passes the
/// checks or fits what is left of that length, or an end of the lines before
/// it, ends the buffer there and is recorded in `changed`.
struct Rewalk<'l, I> {
    lines: I,
    /// The position of the next line.
    index: usize,
    current: Option<LineBuf<&'l [u8], &'l [u8]>>,
    remaining: usize,
    changed: Option<usize>,
}

impl<'l, I, S, H> Rewalk<'l, I>
where
    I: Iterator<Item = &'l FieldLine<S, H>>,
    S: AsRef<[u8]> + 'l,
    H: AsRef<[u8]> + 'l,
{
    fn new(head: LineBuf<&'l [u8], &'l [u8]>, lines: I, remaining: usize) -> Self {
        let mut section = Self {
            lines,
            index: 0,
            current: Some(head),
            remaining,
            changed: None,
        };
        section.settle();
        section
    }

    // Keep a current buffer with octets left while octets remain.
    fn settle(&mut self) {
        while self.remaining > 0 && !self.current.as_ref().is_some_and(Buf::has_remaining) {
            let next = self.lines.next();
            let field = next.and_then(|line| {
                Prepared::new(line.as_slices()).ok().filter(|field| {
                    field.len <= self.remaining as u128 && dynamic_reference(line).is_none()
                })
            });
            match field {
                Some(field) => {
                    self.current = Some(field.buf);
                    self.index += 1;
                }
                None => {
                    self.changed = Some(self.index);
                    self.current = None;
                    self.remaining = 0;
                }
            }
        }
    }
}

impl<'l, I, S, H> Buf for Rewalk<'l, I>
where
    I: Iterator<Item = &'l FieldLine<S, H>>,
    S: AsRef<[u8]> + 'l,
    H: AsRef<[u8]> + 'l,
{
    fn remaining(&self) -> usize {
        self.remaining
    }

    fn chunk(&self) -> &[u8] {
        match &self.current {
            Some(current) => current.chunk(),
            None => &[],
        }
    }

    fn advance(&mut self, mut count: usize) {
        // invariant: only this module's `put` advances it, by at most a
        // chunk it gave.
        assert!(
            count <= self.remaining,
            "advance past the end of the section"
        );
        while count > 0 {
            let Some(current) = self.current.as_mut() else {
                break;
            };
            let step = count.min(current.remaining());
            current.advance(step);
            count -= step;
            self.remaining -= step;
            self.settle();
        }
    }
}

/// Where `line` refers to the dynamic table, if it does.
fn dynamic_reference<S, H>(line: &FieldLine<S, H>) -> Option<DynamicReferenceError> {
    match line {
        FieldLine::Indexed {
            index: TableIndex::Relative { .. } | TableIndex::PostBase { .. },
        } => Some(DynamicReferenceError::Field),
        FieldLine::LiteralWithNameReference {
            name: TableIndex::Relative { .. } | TableIndex::PostBase { .. },
            ..
        } => Some(DynamicReferenceError::Name),
        _ => None,
    }
}
