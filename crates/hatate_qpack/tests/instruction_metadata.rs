//! The metadata of the bytes of an instruction, merged into what is read
//! from them, and the reports of what is written.
use bytes::{Buf, BufMut};
use core::{
    convert::Infallible,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, DecoderStream, DecoderStreamLimits, StreamId,
        codec::WriteDecoderInstructionHostExt,
    },
    encoder_instruction::{
        EncoderStream, EncoderStreamLimits, NameReference, Started,
        literal::LiteralSource,
        write::{Payload, Writer},
    },
    static_table::Index,
};
use nitori_call::{ConstructedAccess, family_receiver};
use nitori_codec::DecodeFrom;
use nitori_io::{Combine, Read, ReadSegment, Write, WriteSegment, calls::ReadValue, prelude::*};

/// The positions in the stream of the bytes read, in the order they were
/// merged: a metadata that shows which segments were merged and how.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Positions(Vec<usize>);

impl Combine for Positions {
    fn combine(mut self, next: Self) -> Self {
        self.0.extend(next.0);
        self
    }
}

fn at(positions: &[usize]) -> Positions {
    Positions(positions.to_vec())
}

/// A stream that hands out one byte per read; the metadata of each byte is
/// its position.
struct Numbered<'a> {
    data: &'a [u8],
    position: usize,
}

family_receiver!(impl ['a] for Numbered<'a>);

impl Read for Numbered<'_> {
    type Error = Infallible;
    type Metadata = Positions;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        out: &mut O,
    ) -> Poll<Result<Option<ReadSegment<Positions>>, Infallible>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let Some((&byte, rest)) = this.data.split_first().filter(|_| out.has_remaining_mut())
        else {
            return Poll::Ready(Ok(None));
        };
        out.put_u8(byte);
        this.data = rest;
        let metadata = Positions(vec![this.position]);
        this.position += 1;
        Poll::Ready(Ok(Some(ReadSegment {
            count: NonZeroUsize::MIN,
            metadata,
        })))
    }
}

fn numbered(data: &[u8]) -> ConstructedAccess<Numbered<'_>> {
    ConstructedAccess::new(Numbered { data, position: 0 })
}

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    nitori_call::__private::run_sync(future)
}

const LIMITS: EncoderStreamLimits = EncoderStreamLimits {
    max_wire_len: 64,
    max_decoded_len: 64,
};

#[test]
fn an_integer_instruction_has_the_metadata_of_its_octets() {
    // Set Dynamic Table Capacity 220 (three octets), Duplicate 1, Duplicate
    // 31 (two octets) and Set Dynamic Table Capacity 0.
    let wire = [0x3f, 0xbd, 0x01, 0x01, 0x1f, 0x00, 0x20];
    let mut stream = EncoderStream::new(numbered(&wire), LIMITS);
    let capacity = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(
        capacity.value,
        Started::SetDynamicTableCapacity(220)
    ));
    assert_eq!(capacity.metadata, at(&[0, 1, 2]));
    let duplicate = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(duplicate.value, Started::Duplicate(1)));
    assert_eq!(duplicate.metadata, at(&[3]));
    let duplicate = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(duplicate.value, Started::Duplicate(31)));
    assert_eq!(duplicate.metadata, at(&[4, 5]));
    let capacity = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(
        capacity.value,
        Started::SetDynamicTableCapacity(0)
    ));
    assert_eq!(capacity.metadata, at(&[6]));
    // The end at the boundary has read nothing, so it has no metadata.
    assert!(
        run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
            &mut stream
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn an_insertion_with_a_name_reference_has_the_metadata_of_each_part() {
    // A relative index of 64 (two octets), then the value "xy" with its
    // length, and Set Dynamic Table Capacity 0.
    let wire = [0xbf, 0x01, 0x02, b'x', b'y', 0x20];
    let mut stream = EncoderStream::new(numbered(&wire), LIMITS);
    let start = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(start.metadata, at(&[0, 1]));
    let Started::InsertWithNameReference {
        name: NameReference::Relative(64),
        value,
    } = start.value
    else {
        panic!("a reference to a dynamic entry");
    };
    let mut value = run(value.open()).unwrap();
    assert_eq!(value.metadata, at(&[2]));
    // A raw literal reports the metadata of its own bytes.
    let LiteralSource::Raw(mut source) = value.value.source() else {
        panic!("a raw value");
    };
    let mut seen = Vec::new();
    let mut byte = [0u8; 1];
    while let Some(segment) = run(source.read(&mut &mut byte[..])).unwrap() {
        seen.push((byte[0], segment.metadata));
    }
    assert_eq!(seen, [(b'x', at(&[3])), (b'y', at(&[4]))]);
    value.value.finish().unwrap();
    let next = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert!(matches!(next.value, Started::SetDynamicTableCapacity(0)));
    assert_eq!(next.metadata, at(&[5]));
}

#[test]
fn an_insertion_with_a_literal_name_has_the_metadata_of_each_part() {
    // The name "ab" (raw), the value "c" (raw).
    let wire = [0x42, b'a', b'b', 0x01, b'c'];
    let mut stream = EncoderStream::new(numbered(&wire), LIMITS);
    let start = run(Option::<ReadValue<Started<'_, _>, Positions>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(start.metadata, at(&[0]));
    let Started::InsertWithLiteralName(mut name) = start.value else {
        panic!("a literal name");
    };
    {
        let LiteralSource::Raw(mut source) = name.source() else {
            panic!("a raw name");
        };
        let mut byte = [0u8; 1];
        let first = run(source.read(&mut &mut byte[..])).unwrap().unwrap();
        assert_eq!((byte[0], first.metadata), (b'a', at(&[1])));
        let second = run(source.read(&mut &mut byte[..])).unwrap().unwrap();
        assert_eq!((byte[0], second.metadata), (b'b', at(&[2])));
    }
    let mut value = run(name.finish().unwrap().open()).unwrap();
    assert_eq!(value.metadata, at(&[3]));
    let LiteralSource::Raw(mut source) = value.value.source() else {
        panic!("a raw value");
    };
    let mut byte = [0u8; 1];
    let third = run(source.read(&mut &mut byte[..])).unwrap().unwrap();
    assert_eq!((byte[0], third.metadata), (b'c', at(&[4])));
    value.value.finish().unwrap();
}

#[test]
fn a_decoder_instruction_has_the_metadata_of_its_octets() {
    // Section acknowledgment of stream 4, Insert Count Increment 5, and the
    // cancellation of stream 64 (two octets).
    let wire = [0x84, 0x05, 0x7f, 0x01];
    let mut stream = DecoderStream::new(numbered(&wire), DecoderStreamLimits { max_wire_len: 8 });
    let mut seen = Vec::new();
    while let Some(read) = run(Option::<ReadValue<D, Positions>>::decode_from(&mut stream)).unwrap()
    {
        seen.push((read.value, read.metadata));
    }
    assert_eq!(
        seen,
        [
            (
                D::SectionAcknowledgment(StreamId::try_from(4).unwrap()),
                at(&[0])
            ),
            (D::InsertCountIncrement(5.try_into().unwrap()), at(&[1])),
            (
                D::StreamCancellation(StreamId::try_from(64).unwrap()),
                at(&[2, 3])
            ),
        ]
    );
}

#[test]
fn the_first_octet_of_every_instruction_is_read_through_the_merged_source() {
    // The same stream read without metadata gives the same instructions.
    let wire = [0xbf, 0x01, 0x02, b'x', b'y', 0x20];
    let mut input = &wire[..];
    let mut stream = EncoderStream::new(ConstructedAccess::new(&mut input), LIMITS);
    let start = run(Option::<ReadValue<Started<'_, _>, ()>>::decode_from(
        &mut stream,
    ))
    .unwrap()
    .unwrap();
    assert_eq!(start.metadata, ());
    assert!(matches!(
        start.value,
        Started::InsertWithNameReference {
            name: NameReference::Relative(64),
            ..
        }
    ));
}

/// What a sink counts of the writes it accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Writes(u32);

impl Combine for Writes {
    fn combine(self, next: Self) -> Self {
        Self(self.0 + next.0)
    }
}

/// A sink that accepts one byte at a time and reports one write for each.
#[derive(Default)]
struct Tally {
    bytes: Vec<u8>,
}

family_receiver!(impl [] for Tally);

impl Write for Tally {
    type Error = Infallible;
    type Report = Writes;
    fn poll_write<'v, B: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        input: &mut B,
    ) -> Poll<Result<Option<WriteSegment<Writes>>, Infallible>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if !input.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        this.bytes.push(input.get_u8());
        Poll::Ready(Ok(Some(WriteSegment {
            count: NonZeroUsize::MIN,
            report: Writes(1),
        })))
    }
}

#[test]
fn a_decoder_instruction_is_written_with_the_report_of_its_octets() {
    let mut sink = Tally::default();
    let report = sink
        .sync_write_decoder_instruction_unpin(D::StreamCancellation(64.try_into().unwrap()), 8)
        .unwrap();
    assert_eq!(sink.bytes, [0x7f, 0x01]);
    assert_eq!(report, Writes(2));
}

#[test]
fn an_encoder_instruction_is_written_with_the_report_of_all_of_it() {
    let mut sink = ConstructedAccess::new(Tally::default());
    let mut writer = Writer::new(&mut sink);
    // The integer instructions: the report of their octets.
    assert_eq!(
        run(writer.set_dynamic_table_capacity(220, 8)).unwrap(),
        Writes(3)
    );
    assert_eq!(run(writer.duplicate(31, 8)).unwrap(), Writes(2));
    // An insertion with a name reference: the reference and the value,
    // header and payload, are one report.
    let mut value = ConstructedAccess::new(&b"xy"[..]);
    let index = Index::try_from(1).unwrap();
    let pending = run(writer.name_reference(NameReference::Static(index), 8, 8)).unwrap();
    assert_eq!(
        run(pending.value(Payload::Raw(&mut value))).unwrap(),
        Writes(4)
    );
    // An insertion with a literal name: the name's header and payload, the
    // value's header and payload.
    let mut name = ConstructedAccess::new(&b"ab"[..]);
    let mut value = ConstructedAccess::new(&b"c"[..]);
    let pending = run(writer.literal_name(Payload::Raw(&mut name), 16, 16)).unwrap();
    assert_eq!(
        run(pending.value(Payload::Raw(&mut value))).unwrap(),
        Writes(5)
    );
    assert_eq!(
        sink.into_inner().bytes,
        b"\x3f\xbd\x01\x1f\x00\xc1\x02xy\x42ab\x01c"
    );
}
