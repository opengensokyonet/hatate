//! Compare whole-instruction encoder-stream reading with in-memory decoding
//! from the bounded wire region, from sources that hand out chunks of
//! different sizes; write each instruction read back and compare it with the
//! octets it was read from. Write instructions made of the input and compare
//! them with an independent encoding, and instructions whose integers and
//! length prefixes carry padding, read back. The limits come from the input
//! or from a table capacity (`EncoderStreamLimits::for_table_capacity`);
//! a failed read has the kind its first octet allows.
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use bytes::{Buf, BufMut, BytesMut};
use core::{
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use hatate_qpack::{
    encoder_instruction::{
        DecodeEncoderInstructionError, EncoderInstruction, EncoderStream, EncoderStreamLimits,
        NameReference,
    },
    huffman,
    integer::{self, PrefixedField, PrefixedInt},
    static_table::Index,
    string_literal::{CopiedBytes, StringLiteral},
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{calls::ReadValue, prelude::*};

/// A source that hands out at most `block` octets per read or chunk.
struct Blocks<'a> {
    rest: &'a [u8],
    block: usize,
}
nitori_call::family_receiver!(impl ['a] for Blocks<'a>);

impl nitori_io::Read for Blocks<'_> {
    type Error = !;
    type Metadata = ();
    fn poll_read<'v, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let count = this.block.min(this.rest.len()).min(dst.remaining_mut());
        let (head, tail) = this.rest.split_at(count);
        dst.put_slice(head);
        this.rest = tail;
        Poll::Ready(Ok(NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

impl<'a> ReadChunk for Blocks<'a> {
    type Chunk = &'a [u8];
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<&'a [u8], ()>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if this.rest.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = this.block.min(this.rest.len()).min(maximum.get());
        let (chunk, tail) = this.rest.split_at(count);
        this.rest = tail;
        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
            chunk,
            metadata: (),
        })))
    }
}

/// An instruction as the stream reads it.
type Read = EncoderInstruction<CopiedBytes, BytesMut>;
/// An instruction made of the input.
type Made<'a> = EncoderInstruction<&'a [u8], &'a [u8]>;

#[derive(Debug, PartialEq, Eq)]
enum Name {
    Static(u64),
    Relative(u64),
}

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Capacity(u64),
    Duplicate(u64),
    Reference(Name, Vec<u8>),
    Literal(Vec<u8>, Vec<u8>),
}

fn string<const N: u8>(first: u8, src: &mut &[u8], remaining: &mut usize) -> Option<Vec<u8>> {
    let n = usize::try_from(integer::read::<N>(first, src).ok()?.value().get()).ok()?;
    let (body, tail) = src.split_at_checked(n)?;
    *src = tail;
    let bytes = if first & (1 << N) != 0 {
        huffman::decode::<Vec<u8>>(body, *remaining).ok()?
    } else {
        if body.len() > *remaining {
            return None;
        }
        body.to_vec()
    };
    *remaining -= bytes.len();
    Some(bytes)
}

fn reference(src: &mut &[u8], mut decoded: usize) -> Option<Parsed> {
    let first = src.try_get_u8().ok()?;
    Some(match first {
        0..=0x1f => Parsed::Duplicate(integer::read::<5>(first, src).ok()?.value().get()),
        0x20..=0x3f => Parsed::Capacity(integer::read::<5>(first, src).ok()?.value().get()),
        0x40..=0x7f => {
            let name = string::<5>(first, src, &mut decoded)?;
            let head = src.try_get_u8().ok()?;
            Parsed::Literal(name, string::<7>(head, src, &mut decoded)?)
        }
        _ => {
            let n = integer::read::<6>(first, src).ok()?.value().get();
            let name = if first & 0x40 != 0 {
                Index::try_from(n).ok()?;
                Name::Static(n)
            } else {
                Name::Relative(n)
            };
            let head = src.try_get_u8().ok()?;
            Parsed::Reference(name, string::<7>(head, src, &mut decoded)?)
        }
    })
}

fn parsed(instruction: &Read) -> Parsed {
    match instruction {
        EncoderInstruction::SetDynamicTableCapacity { capacity } => {
            Parsed::Capacity(capacity.value().get())
        }
        EncoderInstruction::Duplicate { index } => Parsed::Duplicate(index.value().get()),
        EncoderInstruction::InsertWithNameReference { name, value } => Parsed::Reference(
            match name {
                NameReference::Static { index } => Name::Static(index.value().get().into()),
                NameReference::Relative { index } => Name::Relative(index.value().get()),
            },
            value.as_ref().to_vec(),
        ),
        EncoderInstruction::InsertWithLiteralName { name, value } => {
            Parsed::Literal(name.as_ref().to_vec(), value.as_ref().to_vec())
        }
    }
}

/// The kind of a failed read.
#[derive(Debug, PartialEq, Eq)]
enum Failure {
    /// The first octet could not be read.
    Prefix,
    /// The octets read so far already exceed the wire limit.
    Wire,
    Capacity,
    Duplicate,
    NameIndex,
    StaticName,
    Name,
    ValuePrefix,
    Value,
}

impl Failure {
    fn of<E>(error: &DecodeEncoderInstructionError<E>) -> Self {
        use DecodeEncoderInstructionError as D;
        match error {
            D::Interrupted => unreachable!("the first read of a stream"),
            D::WireLimit { .. } => Self::Wire,
            D::Prefix { .. } => Self::Prefix,
            D::Capacity { .. } => Self::Capacity,
            D::Duplicate { .. } => Self::Duplicate,
            D::NameIndex { .. } => Self::NameIndex,
            D::StaticName { .. } => Self::StaticName,
            D::Name { .. } => Self::Name,
            D::ValuePrefix { .. } => Self::ValuePrefix,
            D::Value { .. } => Self::Value,
        }
    }

    /// Whether an instruction that begins with `first`, read from a
    /// nonempty source within `wire` octets, can fail this way.
    fn possible(&self, first: u8, wire: usize) -> bool {
        match self {
            // The source has no host failure and is not empty: only an
            // empty budget stops the first octet.
            Self::Prefix => wire == 0,
            _ if wire == 0 => false,
            Self::Wire => first >= 0x80,
            Self::Duplicate => first <= 0x1f,
            Self::Capacity => (0x20..=0x3f).contains(&first),
            Self::NameIndex | Self::ValuePrefix | Self::Value => first >= 0x40,
            Self::StaticName => first >= 0xc0,
            Self::Name => (0x40..=0x7f).contains(&first),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The stream ended at the instruction boundary.
    End,
    Item(Read),
    Failed(Failure),
}

#[call(sync)]
async fn parse<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    wire: usize,
    decoded: usize,
) -> Outcome
where
    CopiedBytes: Extend<<F as ReadChunk>::Chunk>,
{
    let mut stream = EncoderStream::new(io, limits(wire, decoded));
    match Option::<ReadValue<Read, ()>>::decode_from(&mut stream).await {
        Ok(Some(read)) => Outcome::Item(read.value),
        Ok(None) => Outcome::End,
        Err(error) => {
            // A failed instruction leaves the stream interrupted, unless
            // nothing of it was read: a failure before the first octet leaves
            // the stream at the boundary, to fail the same way again.
            let again = Option::<ReadValue<Read, ()>>::decode_from(&mut stream).await;
            if matches!(error, DecodeEncoderInstructionError::Prefix { .. }) {
                assert!(matches!(
                    again,
                    Err(DecodeEncoderInstructionError::Prefix { .. })
                ));
            } else {
                assert!(matches!(
                    again,
                    Err(DecodeEncoderInstructionError::Interrupted)
                ));
            }
            Outcome::Failed(Failure::of(&error))
        }
    }
}

fn limits(wire: usize, decoded: usize) -> EncoderStreamLimits {
    EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    }
}

#[call(sync)]
async fn write_back<W: Write<Report = ()>>(
    out: &mut impl ReceiverAccess<Family = W>,
    instruction: Read,
    wire: usize,
    decoded: usize,
) -> bool {
    let mut writer = EncoderStream::new(out, limits(wire, decoded));
    instruction.encode_into(&mut writer).await.is_ok()
}

#[call(sync)]
async fn write_insertion<W: Write<Report = ()>>(
    out: &mut impl ReceiverAccess<Family = W>,
    insertion: Made<'_>,
    wire: usize,
    decoded: usize,
) -> bool {
    let mut writer = EncoderStream::new(out, limits(wire, decoded));
    insertion.encode_into(&mut writer).await.is_ok()
}

fn literal<'a>(octets: &'a [u8], coded: bool) -> StringLiteral<&'a [u8], &'a [u8]> {
    if coded {
        StringLiteral::huffman(octets).unwrap()
    } else {
        let mut length = core::pin::pin!(StringLiteral::raw(octets));
        let Poll::Ready(literal) = core::future::Future::poll(
            length.as_mut(),
            &mut Context::from_waker(core::task::Waker::noop()),
        ) else {
            unreachable!("a slice knows its length");
        };
        literal.unwrap()
    }
}

/// An independent encoding of a literal with an `N`-bit length prefix.
fn encode_literal<const N: u8>(out: &mut Vec<u8>, flags: u8, octets: &[u8], coded: bool) {
    let mut payload = Vec::new();
    if coded {
        huffman::encode(&mut payload, octets).unwrap();
    } else {
        payload.extend_from_slice(octets);
    }
    let length = integer::PrefixedField::shortest(integer::PrefixedInt::from(payload.len() as u64));
    let h = if coded { 1 << N } else { 0 };
    integer::write::<N, _>(out, flags | h, length).unwrap();
    out.extend(payload);
}

fn check_writer(body: &[u8], split: u8, wire: usize, decoded: usize) {
    let (name, value) = body.split_at(usize::from(split).min(body.len()));
    for flags in 0..4u8 {
        let (name_coded, value_coded) = (flags & 1 != 0, flags & 2 != 0);
        let mut expected = Vec::new();
        encode_literal::<5>(&mut expected, 0x40, name, name_coded);
        encode_literal::<7>(&mut expected, 0, value, value_coded);
        let insertion = EncoderInstruction::InsertWithLiteralName {
            name: literal(name, name_coded),
            value: literal(value, value_coded),
        };
        assert_eq!(insertion.wire_len() as usize, expected.len());
        assert_eq!(insertion.decoded_len() as usize, body.len());
        let fits = expected.len() <= wire && body.len() <= decoded;
        let mut output = Vec::new();
        assert_eq!(
            output.sync_write_insertion_unpin(insertion, wire, decoded),
            fits
        );
        // A refused instruction writes nothing.
        assert_eq!(output, if fits { expected } else { Vec::new() });
        if fits {
            let mut written = output.as_slice();
            assert_eq!(
                reference(&mut written, decoded),
                Some(Parsed::Literal(name.to_vec(), value.to_vec()))
            );
            assert!(written.is_empty());
        }
    }
}

/// A literal of `octets` padded by `padding` where its `N`-bit length
/// prefix allows it.
fn padded_literal<const N: u8>(
    octets: &[u8],
    coded: bool,
    padding: u8,
) -> StringLiteral<&[u8], &[u8]> {
    let literal = literal(octets, coded);
    literal
        .clone()
        .with_length_padding::<N>(padding)
        .unwrap_or(literal)
}

/// A field of `value` padded by `padding` where its `N`-bit prefix allows
/// it.
fn padded<const N: u8, T: Copy + Into<PrefixedInt>>(value: T, padding: u8) -> PrefixedField<T> {
    PrefixedField::new::<N>(value, padding).unwrap_or(PrefixedField::shortest(value))
}

/// Writes an instruction of the input with padded integers and length
/// prefixes, and reads it back.
fn check_padded(mode: u8, numeric: u64, padding: u8, body: &[u8], split: u8, block: usize) {
    let (name, value) = body.split_at(usize::from(split).min(body.len()));
    let (name_coded, value_coded) = (mode & 8 != 0, mode & 16 != 0);
    let (made, expected): (Made<'_>, Parsed) = match (mode >> 1) & 3 {
        0 => (
            EncoderInstruction::SetDynamicTableCapacity {
                capacity: padded::<5, _>(PrefixedInt::from(numeric), padding),
            },
            Parsed::Capacity(numeric),
        ),
        1 => (
            EncoderInstruction::Duplicate {
                index: padded::<5, _>(PrefixedInt::from(numeric), padding),
            },
            Parsed::Duplicate(numeric),
        ),
        2 => {
            let (name, parsed) = if mode & 32 != 0 {
                let index = numeric % 99;
                (
                    NameReference::Static {
                        index: padded::<6, _>(Index::try_from(index).unwrap(), padding),
                    },
                    Name::Static(index),
                )
            } else {
                (
                    NameReference::Relative {
                        index: padded::<6, _>(PrefixedInt::from(numeric), padding),
                    },
                    Name::Relative(numeric),
                )
            };
            (
                EncoderInstruction::InsertWithNameReference {
                    name,
                    value: padded_literal::<7>(body, value_coded, padding),
                },
                Parsed::Reference(parsed, body.to_vec()),
            )
        }
        _ => (
            EncoderInstruction::InsertWithLiteralName {
                name: padded_literal::<5>(name, name_coded, padding),
                value: padded_literal::<7>(value, value_coded, padding),
            },
            Parsed::Literal(name.to_vec(), value.to_vec()),
        ),
    };
    let wire_len = made.wire_len() as usize;
    let mut written = Vec::new();
    assert!(written.sync_write_insertion_unpin(made, usize::MAX, usize::MAX));
    assert_eq!(written.len(), wire_len);
    // A reader that decodes the padding gets the values that were made.
    let decoded = 2 * written.len() + 16;
    let mut cursor = written.as_slice();
    assert_eq!(reference(&mut cursor, decoded), Some(expected));
    assert!(cursor.is_empty());
    // The stream reads it whole, and writes the same octets back.
    let mut input = Blocks {
        rest: &written,
        block,
    };
    let Outcome::Item(read) = input.sync_parse_unpin(written.len(), decoded) else {
        panic!("a written instruction is read");
    };
    assert!(input.rest.is_empty());
    let mut again = Vec::new();
    assert!(again.sync_write_back_unpin(read, written.len(), decoded));
    assert_eq!(again, written);
}

fuzz_target!(|data: &[u8]| {
    let [mode, exponent, wire, decoded, chunk, selector, body @ ..] = data else {
        return;
    };
    // The limits come from the input, or from a table capacity of up to 2^60
    // or so.
    let limits = if mode & 1 != 0 {
        let capacity = (u64::from(*decoded) << 8 | u64::from(*wire)) << (exponent % 44);
        EncoderStreamLimits::for_table_capacity(capacity)
    } else {
        limits(usize::from(*wire), usize::from(*decoded))
    };
    let (wire, decoded) = (limits.max_wire_len, limits.max_decoded_len);
    let block = usize::from(*chunk) + 1;
    let mut numeric = [0; 8];
    let count = body.len().min(8);
    numeric[..count].copy_from_slice(&body[..count]);
    check_padded(
        *mode,
        u64::from_le_bytes(numeric),
        selector >> 4,
        body,
        *selector,
        block,
    );
    check_writer(body, *chunk, wire, decoded);
    let mut src = body;
    while !src.is_empty() {
        let before = src;
        let size = src.len().min(wire);
        let first = src[0];
        let mut bounded = &src[..size];
        let expected = reference(&mut bounded, decoded);
        let mut input = Blocks { rest: src, block };
        let actual = input.sync_parse_unpin(wire, decoded);
        let consumed = before.len() - input.rest.len();
        // The stream is not empty, so it cannot end at the boundary.
        match (actual, expected) {
            (Outcome::Item(read), Some(expected)) => {
                assert_eq!(parsed(&read), expected);
                let literals = match &expected {
                    Parsed::Reference(_, value) => value.len(),
                    Parsed::Literal(name, value) => name.len() + value.len(),
                    _ => 0,
                };
                assert_eq!(read.decoded_len() as usize, literals);
                assert_eq!(consumed, size - bounded.len());
                assert_eq!(read.wire_len() as usize, consumed);
                assert!(consumed > 0);
                // Written back within the limits it was read within, the
                // instruction is the octets it was read from.
                let mut written = Vec::new();
                assert!(written.sync_write_back_unpin(read, wire, decoded));
                assert_eq!(written, &before[..consumed]);
            }
            (Outcome::Failed(failure), None) => {
                assert!(consumed <= size);
                // Nothing is read from an empty budget, and an octet is
                // read otherwise.
                assert_eq!(consumed == 0, wire == 0);
                assert!(
                    failure.possible(first, wire),
                    "{failure:?} after {first:#x}"
                );
                return;
            }
            (actual, expected) => panic!("{actual:?} against {expected:?}"),
        }
        src = &before[consumed..];
    }
    // Every instruction was taken: the end is at the boundary.
    if wire > 0 {
        assert_eq!(
            Blocks { rest: &[], block }.sync_parse_unpin(wire, decoded),
            Outcome::End
        );
    }
});
