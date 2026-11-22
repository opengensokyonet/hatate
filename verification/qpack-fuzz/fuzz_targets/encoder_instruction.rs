//! Compare incremental encoder-stream parsing with in-memory decoding from
//! the bounded wire region. Drive literal sources at different read sizes.
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use bytes::{Buf, BufMut};
use core::num::NonZeroUsize;
use hatate_qpack::{
    encoder_instruction::{NameReference, Reader, Started, literal::LiteralSource},
    huffman, integer,
    static_table::Index,
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;

#[derive(Debug, PartialEq, Eq)]
enum Parsed {
    Capacity(u64),
    Duplicate(u64),
    Reference(NameReference, Vec<u8>),
    Literal(Vec<u8>, Vec<u8>),
}

fn string<const N: u8>(first: u8, src: &mut &[u8], remaining: &mut usize) -> Option<Vec<u8>> {
    let n = usize::try_from(integer::read::<N>(first, src).ok()?).ok()?;
    let (body, tail) = src.split_at_checked(n)?;
    *src = tail;
    let bytes = if first & (1 << N) != 0 {
        huffman::decode(body, *remaining).ok()?.to_vec()
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
        0..=0x1f => Parsed::Duplicate(integer::read::<5>(first, src).ok()?),
        0x20..=0x3f => Parsed::Capacity(integer::read::<5>(first, src).ok()?),
        0x40..=0x7f => {
            let name = string::<5>(first, src, &mut decoded)?;
            let head = src.try_get_u8().ok()?;
            Parsed::Literal(name, string::<7>(head, src, &mut decoded)?)
        }
        _ => {
            let n = integer::read::<6>(first, src).ok()?;
            let name = if first & 0x40 != 0 {
                NameReference::Static(Index::try_from(n).ok()?)
            } else {
                NameReference::Relative(n)
            };
            let head = src.try_get_u8().ok()?;
            Parsed::Reference(name, string::<7>(head, src, &mut decoded)?)
        }
    })
}

async fn collect<A: ReceiverAccess>(
    src: LiteralSource<'_, A>,
    block: NonZeroUsize,
) -> Option<Vec<u8>>
where
    A::Family: ReadChunk,
{
    let mut out = Vec::new();
    match src {
        LiteralSource::Raw(mut raw) => {
            while let Some(chunk) = raw.read_chunk(block).await.ok()? {
                out.put(chunk);
            }
        }
        LiteralSource::Huffman(mut decoded) => {
            while decoded
                .read(&mut (&mut out).limit(block.get()))
                .await
                .ok()?
                != 0
            {}
        }
    }
    Some(out)
}

#[call(sync)]
async fn parse<F: ReadChunk, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    wire: usize,
    decoded: usize,
    block: NonZeroUsize,
) -> Option<Parsed> {
    let mut reader = Reader::new(io);
    let start = reader.start(wire, decoded).await.ok()?;
    match start {
        Started::SetDynamicTableCapacity(n) => Some(Parsed::Capacity(n)),
        Started::Duplicate(n) => Some(Parsed::Duplicate(n)),
        Started::InsertWithNameReference { name, value } => {
            let mut value = value.open().await.ok()?;
            let data = collect(value.source(), block).await?;
            value.finish().ok()?;
            Some(Parsed::Reference(name, data))
        }
        Started::InsertWithLiteralName(mut name) => {
            let key = collect(name.source(), block).await?;
            let mut value = name.finish().ok()?.open().await.ok()?;
            let data = collect(value.source(), block).await?;
            value.finish().ok()?;
            Some(Parsed::Literal(key, data))
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let [wire, decoded, chunk, body @ ..] = data else {
        return;
    };
    let mut src = body;
    let wire = usize::from(*wire);
    let decoded = usize::from(*decoded);
    let block = NonZeroUsize::new(usize::from(*chunk) + 1).unwrap();
    while !src.is_empty() {
        let before = src;
        let size = src.len().min(wire);
        let mut bounded = &src[..size];
        let expected = reference(&mut bounded, decoded);
        let mut input = src;
        let actual = input.sync_parse_unpin(wire, decoded, block);
        assert_eq!(actual, expected);
        assert!(before.len() - input.len() <= size);
        if actual.is_none() {
            break;
        }
        assert_eq!(input.len(), before.len() - (size - bounded.len()));
        assert!(input.len() < before.len());
        src = input;
    }
});
