//! Compare incremental encoder-stream parsing with in-memory decoding from
//! the bounded wire region. Drive literal sources at different read sizes.
#![no_main]
#![feature(impl_trait_in_assoc_type)]

use bytes::{Buf, BufMut};
use core::num::NonZeroUsize;
use hatate_qpack::{
    encoder_instruction::{
        EncoderStream, EncoderStreamLimits, NameReference, Started,
        codec::StartError,
        literal::LiteralSource,
        write::{Payload, Writer},
    },
    huffman, integer,
    static_table::Index,
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_codec::DecodeFrom;
use nitori_io::{calls::ReadValue, prelude::*};

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
    A::Family: ReadChunk<Metadata = ()>,
{
    let mut out = Vec::new();
    match src {
        LiteralSource::Raw(mut raw) => {
            while let Some(chunk) = raw.read_chunk(block).await.ok()? {
                out.put(chunk.chunk);
            }
        }
        LiteralSource::Huffman(mut decoded) => {
            while decoded
                .read(&mut (&mut out).limit(block.get()))
                .await
                .ok()?
                .is_some()
            {}
        }
    }
    Some(out)
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// The stream ended at the instruction boundary.
    End,
    Item(Parsed),
    Failed,
}

async fn one<A: ReceiverAccess>(
    stream: &mut EncoderStream<A>,
    wire: usize,
    decoded: usize,
    block: NonZeroUsize,
) -> Outcome
where
    A::Family: ReadChunk<Metadata = ()>,
{
    stream.set_limits(EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    });
    let start = match Option::<ReadValue<Started<'_, A>, ()>>::decode_from(&mut *stream).await {
        Ok(Some(start)) => start.value,
        Ok(None) => return Outcome::End,
        Err(_) => return Outcome::Failed,
    };
    match item(start, block).await {
        Some(parsed) => Outcome::Item(parsed),
        None => Outcome::Failed,
    }
}

async fn item<A: ReceiverAccess>(start: Started<'_, A>, block: NonZeroUsize) -> Option<Parsed>
where
    A::Family: ReadChunk<Metadata = ()>,
{
    match start {
        Started::SetDynamicTableCapacity(n) => Some(Parsed::Capacity(n)),
        Started::Duplicate(n) => Some(Parsed::Duplicate(n)),
        Started::InsertWithNameReference { name, value } => {
            let mut value = value.open().await.ok()?.value;
            let data = collect(value.source(), block).await?;
            value.finish().ok()?;
            Some(Parsed::Reference(name, data))
        }
        Started::InsertWithLiteralName(mut name) => {
            let key = collect(name.source(), block).await?;
            let mut value = name.finish().ok()?.open().await.ok()?.value;
            let data = collect(value.source(), block).await?;
            value.finish().ok()?;
            Some(Parsed::Literal(key, data))
        }
    }
}

#[call(sync)]
async fn parse<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    wire: usize,
    decoded: usize,
    block: NonZeroUsize,
) -> Outcome {
    let mut stream = EncoderStream::new(
        io,
        EncoderStreamLimits {
            max_wire_len: wire,
            max_decoded_len: decoded,
        },
    );
    let outcome = one(&mut stream, wire, decoded, block).await;
    if outcome == Outcome::Failed {
        // A failed or unfinished instruction leaves the stream interrupted.
        assert!(matches!(
            Option::<ReadValue<Started<'_, _>, ()>>::decode_from(&mut stream).await,
            Err(StartError::Interrupted)
        ));
    }
    outcome
}

#[call(sync)]
async fn write_literals<N: Read<Metadata = ()> + ExactLen<LengthError = !>, V: Read<Metadata = ()> + ExactLen<LengthError = !>, W: Write<Report = ()>>(
    name: &mut impl ReceiverAccess<Family = N>,
    value: &mut impl ReceiverAccess<Family = V>,
    out: &mut impl ReceiverAccess<Family = W>,
    flags: u8,
    wire: usize,
    decoded: usize,
) -> bool
where
    N::Length: TryInto<u64>,
    V::Length: TryInto<u64>,
{
    let mut writer = Writer::new(out);
    let name = if flags & 1 == 0 {
        Payload::Raw(name)
    } else {
        Payload::Huffman(name)
    };
    let value = if flags & 2 == 0 {
        Payload::Raw(value)
    } else {
        Payload::Huffman(value)
    };
    let Ok(next) = writer.literal_name(name, wire, decoded).await else {
        return false;
    };
    next.pending.value(value).await.is_ok()
}

fn check_raw_writer(body: &[u8], split: usize, wire: usize, decoded: usize) {
    let (name, value) = body.split_at(split.min(body.len()));
    let mut expected = Vec::new();
    integer::write::<5>(&mut expected, 0x40, name.len() as u64).unwrap();
    let name_end = expected.len() + name.len();
    let name_fits = name_end < wire && name.len() <= decoded;
    if name_fits {
        expected.extend_from_slice(name);
        integer::write::<7>(&mut expected, 0, value.len() as u64).unwrap();
    }
    let fits = name_fits && expected.len() + value.len() <= wire && body.len() <= decoded;
    if fits {
        expected.extend_from_slice(value);
    } else {
        expected.truncate(if name_fits { name_end } else { 0 });
    }

    let mut hosts = (name, value, Vec::new());
    assert_eq!(hosts.sync_write_literals_unpin(0, wire, decoded), fits);
    assert_eq!(hosts.2, expected);
    assert_eq!(hosts.0.len(), if name_fits { 0 } else { name.len() });
    assert_eq!(hosts.1.len(), if fits { 0 } else { value.len() });
}

// Independently frame the supplied wire payloads. The contiguous reader
// checks both H bits, padding and the combined decoded-symbol budget.
fn check_coded_writer(body: &[u8], split: u8, wire: usize, decoded: usize) {
    let (name, value) = body.split_at(usize::from(split).min(body.len()));
    for flags in 1..=3 {
        let mut expected = Vec::new();
        integer::write::<5>(&mut expected, 0x40 | ((flags & 1) << 5), name.len() as u64).unwrap();
        expected.extend_from_slice(name);
        integer::write::<7>(&mut expected, (flags & 2) << 6, value.len() as u64).unwrap();
        expected.extend_from_slice(value);
        let fits = expected.len() <= wire && reference(&mut expected.as_slice(), decoded).is_some();
        let mut hosts = (name, value, Vec::new());
        assert_eq!(hosts.sync_write_literals_unpin(flags, wire, decoded), fits);
        assert!(expected.starts_with(&hosts.2));
        if fits {
            assert_eq!(hosts.2, expected);
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
    check_coded_writer(body, *chunk, wire, decoded);
    check_raw_writer(body, usize::from(*chunk), wire, decoded);
    while !src.is_empty() {
        let before = src;
        let size = src.len().min(wire);
        let mut bounded = &src[..size];
        let expected = reference(&mut bounded, decoded);
        let mut input = src;
        let actual = input.sync_parse_unpin(wire, decoded, block);
        // The stream is not empty, so it cannot end at the boundary.
        assert_eq!(
            actual,
            expected.map_or(Outcome::Failed, Outcome::Item)
        );
        assert!(before.len() - input.len() <= size);
        if actual == Outcome::Failed {
            return;
        }
        assert_eq!(input.len(), before.len() - (size - bounded.len()));
        assert!(input.len() < before.len());
        src = input;
    }
    // Every instruction was taken: the end is at the boundary.
    if wire > 0 {
        assert_eq!(
            (&[][..]).sync_parse_unpin(wire, decoded, block),
            Outcome::End
        );
    }
});
