//! Compare whole-instruction encoder-stream reading with in-memory decoding
//! from the bounded wire region, from sources that hand out chunks of
//! different sizes; write each instruction read back and compare it with the
//! octets it was read from. Write instructions made of the input and compare
//! them with an independent encoding.
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
    huffman, integer,
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

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The stream ended at the instruction boundary.
    End,
    Item(Read),
    Failed,
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
        Err(_) => {
            // A failed instruction leaves the stream interrupted.
            assert!(matches!(
                Option::<ReadValue<Read, ()>>::decode_from(&mut stream).await,
                Err(DecodeEncoderInstructionError::Interrupted)
            ));
            Outcome::Failed
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

fuzz_target!(|data: &[u8]| {
    let [wire, decoded, chunk, body @ ..] = data else {
        return;
    };
    let wire = usize::from(*wire);
    let decoded = usize::from(*decoded);
    let block = usize::from(*chunk) + 1;
    check_writer(body, *chunk, wire, decoded);
    let mut src = body;
    while !src.is_empty() {
        let before = src;
        let size = src.len().min(wire);
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
            (Outcome::Failed, None) => {
                assert!(consumed <= size);
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
