//! Decoded section size accounting (RFC 9114 §4.2.2).
use crate::string_literal::StringLiteral;
use crate::{field_line, huffman, string_literal};

pub(super) struct Budget {
    remaining: usize,
    max_literal_len: usize,
}

use super::ReadError as Error;

impl Budget {
    pub(super) fn new(max_literal_len: usize, max_section_size: usize) -> Self {
        Self {
            remaining: max_section_size,
            max_literal_len,
        }
    }

    pub(super) fn charge(&mut self, octets: usize) -> Result<(), Error> {
        self.remaining = self
            .remaining
            .checked_sub(octets)
            .ok_or(Error::SectionTooLarge)?;
        Ok(())
    }

    pub(super) fn start_line(&mut self) -> Result<(), Error> {
        self.charge(32)
    }

    pub(super) fn literal<S, H>(
        &mut self,
        read: impl FnOnce(usize) -> Result<StringLiteral<S, H>, field_line::ReadError>,
    ) -> Result<StringLiteral<S, H>, Error> {
        let limit = self.max_literal_len.min(self.remaining);
        let value = read(limit).map_err(|err| {
            if self.remaining < self.max_literal_len && literal_limit_exceeded(&err) {
                Error::SectionTooLarge
            } else {
                Error::Line { source: err }
            }
        })?;
        // The read limit bounds the decoded length by a usize.
        self.charge(value.decoded_len() as usize)?;
        Ok(value)
    }
}

fn literal_limit_exceeded(error: &field_line::ReadError) -> bool {
    match error {
        field_line::ReadError::Name { source } | field_line::ReadError::Value { source } => {
            matches!(
                source,
                string_literal::ReadError::RawTooLong { .. }
                    | string_literal::ReadError::Huffman {
                        source: huffman::DecodeError::OutputTooLong { .. }
                    }
            )
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    type Literal<'a> = StringLiteral<&'a [u8], Vec<u8>>;

    #[test]
    fn name_consumes_value_allowance_before_value_decoding() {
        let mut budget = Budget::new(8, 39);
        assert!(budget.start_line().is_ok());
        let mut name = &b"abc"[..];
        assert!(
            budget
                .literal(|limit| field_line::read_name::<_, Vec<u8>>(0x23, &mut name, limit))
                .is_ok()
        );
        let mut value = &b"\x05value"[..];
        assert!(matches!(
            budget.literal(|limit| -> Result<Literal<'static>, _> {
                field_line::read_value(&mut value, limit)
            }),
            Err(Error::SectionTooLarge)
        ));
        assert_eq!(value, b"value");
    }

    #[test]
    fn malformed_huffman_preserves_its_wire_error_with_a_tight_section_budget() {
        let mut budget = Budget::new(32, 33);
        assert!(budget.start_line().is_ok());
        let mut value = &b"\x81\xff"[..];
        assert!(matches!(
            budget.literal(|limit| -> Result<Literal<'static>, _> {
                field_line::read_value(&mut value, limit)
            }),
            Err(Error::Line {
                source: field_line::ReadError::Value {
                    source: string_literal::ReadError::Huffman {
                        source: huffman::DecodeError::ExcessPadding
                    }
                }
            })
        ));
    }

    #[test]
    fn huffman_observes_the_otherwise_smaller_literal_limit() {
        let mut budget = Budget::new(7, 128);
        assert!(budget.start_line().is_ok());
        let mut value = &[0x85, 0, 0, 0, 0, 0][..];
        assert!(matches!(
            budget.literal(|limit| -> Result<Literal<'static>, _> {
                field_line::read_value(&mut value, limit)
            }),
            Err(Error::Line {
                source: field_line::ReadError::Value {
                    source: string_literal::ReadError::Huffman {
                        source: huffman::DecodeError::OutputTooLong { limit: 7 }
                    }
                }
            })
        ));
    }
}
