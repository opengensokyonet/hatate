//! QPACK field line representations (RFC 9204 §4.5.2–§4.5.6).
//!
//! Decode from a complete field section payload after its prefix. Each call
//! consumes one representation and leaves dynamic references relative to its
//! Base. Literal names and values retain their exact decoded octets.
//!
//! ```
//! use hatate_qpack::field_line::{read_field_line, write_field_line, FieldLine, TableIndex};
//!
//! let mut input = &[0xd1, 0x10][..];
//! let line = read_field_line(&mut input, 4096)?;
//! assert_eq!(input, &[0x10]);
//! if let FieldLine::Indexed(TableIndex::Static(index)) = &line {
//!     assert_eq!(index.entry(), (&b":method"[..], &b"GET"[..]));
//! }
//! let mut output = Vec::new();
//! write_field_line(&mut output, &line)?;
//! assert_eq!(output, [0xd1]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod field_line;
pub mod huffman;
pub mod integer;
pub mod static_table;
pub mod string_literal;
