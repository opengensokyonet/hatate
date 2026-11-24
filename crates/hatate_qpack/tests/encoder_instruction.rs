#![feature(impl_trait_in_assoc_type)]
use bytes::Buf;
use core::fmt::Debug;
use core::num::NonZeroUsize;
use hatate_qpack::{
    encoder_instruction::{
        EncoderStream, NameReference, Started,
        codec::{LiteralHeaderError, StartError, ValueError},
        literal::{FinishError, HuffmanReadError, InputError, LiteralSource},
    },
    huffman,
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;

#[call(sync)]
async fn insertion<F: ReadChunk, A: ReceiverAccess<Family = F>>(io: &mut A, bad: bool)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    let Started::InsertWithLiteralName(mut name) =
        reader.next_instruction(4, 2).await.unwrap().unwrap()
    else {
        panic!()
    };
    {
        let LiteralSource::Raw(mut source) = name.source() else {
            panic!()
        };
        let mut raw = source
            .read_chunk(NonZeroUsize::new(32).unwrap())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(raw.remaining(), 1);
        assert_eq!(raw.get_u8(), b'x');
        assert!(
            source
                .read_chunk(NonZeroUsize::MIN)
                .await
                .unwrap()
                .is_none()
        );
    }
    let mut value = name.finish().unwrap().open().await.unwrap();
    let mut byte = [0u8; 1];
    {
        let LiteralSource::Huffman(mut source) = value.source() else {
            panic!()
        };
        assert_eq!(source.read(&mut &mut byte[..]).await.unwrap(), 1);
    }
    assert_eq!(byte, [b'a']);
    if bad {
        assert!(matches!(
            value.finish(),
            Err(FinishError::Coding {
                source: huffman::DecodeError::InvalidPadding
            })
        ));
        assert!(matches!(
            reader.next_instruction(8, 8).await,
            Err(StartError::Interrupted)
        ));
    } else {
        value.finish().unwrap();
        assert!(matches!(
            reader.next_instruction(1, 0).await.unwrap().unwrap(),
            Started::Duplicate(0)
        ));
    }
}

#[test]
fn name_then_huffman_value_on_the_same_cursor() {
    let mut good = &[0x41, b'x', 0x81, 0x1f, 0, 0x20][..];
    good.sync_insertion_unpin(false);
    assert_eq!(good, [0x20]);
    let mut bad = &[0x41, b'x', 0x81, 0x18, 0, 0x20][..];
    bad.sync_insertion_unpin(true);
    assert_eq!(bad, [0, 0x20]);
}

#[call(sync)]
async fn unread<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A, drop_name: bool)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    let Started::InsertWithLiteralName(name) =
        reader.next_instruction(32, 32).await.unwrap().unwrap()
    else {
        panic!()
    };
    if drop_name {
        drop(name)
    } else {
        assert!(matches!(name.finish(), Err(FinishError::Unread)))
    }
    assert!(matches!(
        reader.next_instruction(32, 32).await,
        Err(StartError::Interrupted)
    ));
}

#[test]
fn abandoned_name_never_advances_to_its_value_or_another_opcode() {
    for drop_name in [true, false] {
        let mut input = &[0x41, b'x', 0, 0x20][..];
        input.sync_unread_unpin(drop_name);
        assert_eq!(input, [b'x', 0, 0x20]);
    }
}

#[call(sync)]
async fn limits<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A, wire: usize, decoded: usize)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    let Started::InsertWithLiteralName(mut name) = reader
        .next_instruction(wire, decoded)
        .await
        .unwrap()
        .unwrap()
    else {
        panic!()
    };
    {
        let LiteralSource::Raw(mut raw) = name.source() else {
            panic!()
        };
        assert_eq!(raw.read_array::<1>().await.unwrap(), [b'x']);
    }
    let next = name.finish().unwrap();
    if wire == 7 {
        assert!(
            matches!(next.open().await,Err(ValueError::Value{source:LiteralHeaderError::WireLimit{source}}) if source.required()==8)
        );
        return;
    }
    let mut value = next.open().await.unwrap();
    let LiteralSource::Huffman(mut source) = value.source() else {
        panic!()
    };
    let mut output = Vec::new();
    loop {
        match source.read(&mut output).await {
            Ok(0) => {
                assert_eq!(decoded, 9);
                break;
            }
            Ok(_) => {}
            Err(HuffmanReadError::Coding {
                source: huffman::DecodeError::OutputTooLong { limit },
            }) => {
                assert_eq!(decoded, 8);
                assert_eq!(limit, 7);
                assert_eq!(output, b"0000000");
                return;
            }
            Err(other) => panic!("{other:?}"),
        }
    }
    assert_eq!(output, b"00000000");
    value.finish().unwrap();
}

#[test]
fn two_budgets_follow_name_and_value_across_state_transitions() {
    for (wire, decoded) in [(8, 9), (7, 9), (8, 8)] {
        let mut input = &[0x41, b'x', 0x85, 0, 0, 0, 0, 0, 0x20][..];
        input.sync_limits_unpin(wire, decoded);
        assert_eq!(
            input,
            if wire == 7 {
                &[0, 0, 0, 0, 0, 0x20][..]
            } else {
                &[0x20][..]
            }
        );
    }
}

#[call(sync)]
async fn reference<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A, truncated: bool)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    assert!(matches!(
        reader.next_instruction(3, 0).await.unwrap().unwrap(),
        Started::SetDynamicTableCapacity(220)
    ));
    let Started::InsertWithNameReference {
        name: NameReference::Static(index),
        value,
    } = reader.next_instruction(64, 64).await.unwrap().unwrap()
    else {
        panic!()
    };
    assert_eq!(index.entry().0, b":authority");
    let mut value = value.open().await.unwrap();
    let LiteralSource::Raw(mut source) = value.source() else {
        panic!()
    };
    if truncated {
        let mut dst = Vec::new();
        assert_eq!(source.read(&mut dst).await.unwrap(), 3);
        assert!(
            matches!(source.read(&mut dst).await,Err(InputError::Truncated{missing}) if missing.get()==12)
        );
    } else {
        assert_eq!(
            source.read_array::<15>().await.unwrap(),
            *b"www.example.com"
        );
        value.finish().unwrap();
    }
}

#[test]
fn appendix_b2_and_truncated_raw_literal() {
    let mut src = &b"\x3f\xbd\x01\xc0\x0fwww.example.com\x20"[..];
    src.sync_reference_unpin(false);
    assert_eq!(src, [0x20]);
    let mut src = &b"\x3f\xbd\x01\xc0\x0fwww"[..];
    src.sync_reference_unpin(true);
}

struct Trickle<'a> {
    rest: &'a [u8],
    waiting: bool,
}
nitori_call::family_receiver!(impl ['a] for Trickle<'a>);
impl Read for Trickle<'_> {
    type Error = core::convert::Infallible;
    fn poll_read<'v, B: bytes::BufMut + ?Sized>(
        host: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        dst: &mut B,
    ) -> core::task::Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::Poll;
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        if !dst.has_remaining_mut() {
            return Poll::Ready(Ok(0));
        }
        let Some((&b, rest)) = this.rest.split_first() else {
            return Poll::Ready(Ok(0));
        };
        this.rest = rest;
        dst.put_u8(b);
        Poll::Ready(Ok(1))
    }
}

#[call(sync)]
async fn across_chunks<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A)
where
    <F as Read>::Error: Debug,
{
    use nitori_io::adapters::ReadLimit;
    let mut reader = EncoderStream::new(io);
    let Started::InsertWithLiteralName(mut name) =
        reader.next_instruction(16, 16).await.unwrap().unwrap()
    else {
        panic!()
    };
    {
        let LiteralSource::Huffman(mut decoded) = name.source() else {
            panic!()
        };
        let mut first_six = decoded.compose(ReadLimit(6usize));
        assert_eq!(first_six.read_array::<6>().await.unwrap(), *b"www.ex");
        assert_eq!(first_six.read(&mut Vec::new()).await.unwrap(), 0);
        assert_eq!(first_six.into_state().0, 0);
        assert_eq!(decoded.read_array::<9>().await.unwrap(), *b"ample.com");
    }
    let mut value = name.finish().unwrap().open().await.unwrap();
    let LiteralSource::Raw(mut raw) = value.source() else {
        panic!()
    };
    assert_eq!(raw.read_array::<1>().await.unwrap(), *b"x");
    value.finish().unwrap();
    assert!(matches!(
        reader.next_instruction(1, 0).await.unwrap().unwrap(),
        Started::Duplicate(0)
    ));
}

#[test]
fn huffman_source_composes_and_resumes_after_each_encoded_octet() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;
    // RFC 7541 Appendix C.4 hostname in an RFC 9204 literal name.
    let mut host = Trickle {
        rest: b"\x6c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff\x01x\x00\x20",
        waiting: false,
    };
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            AcrossChunks::new()
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..16 {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert!(matches!(call.as_mut().poll(&mut cx), Poll::Ready(())));
    }
    assert_eq!(host.rest, [0x20]);
}

#[call(sync)]
async fn raw_chunks<F: ReadChunk, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (<F as ReadChunk>::Chunk, <F as ReadChunk>::Chunk)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    let Started::InsertWithNameReference {
        name: NameReference::Relative(0),
        value,
    } = reader.next_instruction(5, 3).await.unwrap().unwrap()
    else {
        panic!()
    };
    let mut value = value.open().await.unwrap();
    let LiteralSource::Raw(mut src) = value.source() else {
        panic!()
    };
    let first = src.read_chunk(NonZeroUsize::MIN).await.unwrap().unwrap();
    let rest = src
        .read_chunk(NonZeroUsize::new(8).unwrap())
        .await
        .unwrap()
        .unwrap();
    value.finish().unwrap();
    (first, rest)
}

#[test]
fn bounded_raw_chunks_borrow_the_original_input() {
    let wire = b"\x80\x03abc\x20";
    let mut input = &wire[..];
    let (a, bc) = input.sync_raw_chunks_unpin();
    assert!(core::ptr::eq(a, &wire[2..3]));
    assert!(core::ptr::eq(bc, &wire[3..5]));
    assert_eq!(input, [0x20]);
}

use hatate_qpack::encoder_instruction::write::{HeaderError, LiteralError, Payload, Writer};

#[call(sync)]
async fn relay_raw<F: Read, G: Write>(
    input: &mut impl ReceiverAccess<Family = F>,
    output: &mut impl ReceiverAccess<Family = G>,
    wire: usize,
    decoded: usize,
) -> bool
where
    F::Error: Debug,
    G::Error: Debug,
{
    let mut reader = EncoderStream::new(input);
    let mut writer = Writer::new(output);
    let Started::InsertWithLiteralName(mut name) =
        reader.next_instruction(256, 256).await.unwrap().unwrap()
    else {
        panic!("expected literal name")
    };
    let pending = {
        let LiteralSource::Raw(mut src) = name.source() else {
            panic!("expected raw name")
        };
        writer
            .literal_name(Payload::Raw(&mut src), wire, decoded)
            .await
            .unwrap()
    };
    let mut value = name.finish().unwrap().open().await.unwrap();
    let LiteralSource::Raw(mut src) = value.source() else {
        panic!("expected raw value")
    };
    match pending.value(Payload::Raw(&mut src)).await {
        Ok(()) => {
            value.finish().unwrap();
            writer.duplicate(0, 1).await.unwrap();
            true
        }
        Err(error) => {
            match error {
                LiteralError::DecodedLength { source } => {
                    assert_eq!((source.length(), source.remaining()), (4, 3));
                }
                LiteralError::Header {
                    source: HeaderError::WireLimit { source },
                } => {
                    assert_eq!((source.required(), source.limit()), (11, 10));
                }
                LiteralError::Read {
                    source: InputError::Truncated { missing },
                } => {
                    assert_eq!(missing.get(), 2);
                }
                other => panic!("{other:?}"),
            }
            assert!(matches!(
                writer.duplicate(0, 1).await,
                Err(HeaderError::NotAtBoundary)
            ));
            false
        }
    }
}

#[test]
fn writer_can_relay_successive_literals_from_one_cursor() {
    let mut hosts = (&b"\x45color\x04blue\x20"[..], Vec::new());
    assert!(hosts.sync_relay_raw_unpin(11, 9));
    assert_eq!(hosts.0, [0x20]);
    assert_eq!(hosts.1, b"\x45color\x04blue\x00");
}

#[test]
fn rejected_or_truncated_value_cannot_be_followed_by_an_opcode() {
    for (wire, decoded) in [(10, 9), (11, 8)] {
        let mut hosts = (&b"\x45color\x04blue"[..], Vec::new());
        assert!(!hosts.sync_relay_raw_unpin(wire, decoded));
        assert_eq!(hosts.0, b"blue");
        assert_eq!(hosts.1, b"\x45color");
    }
    let mut hosts = (&b"\x45color\x04bl"[..], Vec::new());
    assert!(!hosts.sync_relay_raw_unpin(11, 9));
    assert_eq!(hosts.1, b"\x45color\x04bl");
}

#[call(sync)]
async fn reference_output<F: Read + ExactLen, G: Write>(
    input: &mut impl ReceiverAccess<Family = F>,
    output: &mut impl ReceiverAccess<Family = G>,
) where
    F::Error: Debug,
    G::Error: Debug,
    F::Length: TryInto<u64>,
{
    let mut writer = Writer::new(output);
    writer.set_dynamic_table_capacity(220, 3).await.unwrap();
    assert!(matches!(
        writer
            .name_reference(NameReference::Relative(0), 1, 0)
            .await,
        Err(HeaderError::WireLimit { .. })
    ));
    let index = hatate_qpack::static_table::Index::try_from(0).unwrap();
    writer
        .name_reference(NameReference::Static(index), 17, 15)
        .await
        .unwrap()
        .value(Payload::Raw(input))
        .await
        .unwrap();
    writer
        .name_reference(NameReference::Relative(63), 3, 0)
        .await
        .unwrap()
        .value(Payload::Raw(input))
        .await
        .unwrap();
    writer.duplicate(31, 2).await.unwrap();
    {
        let _unfinished = writer
            .name_reference(NameReference::Relative(0), 2, 0)
            .await
            .unwrap();
    }
    assert!(matches!(
        writer.set_dynamic_table_capacity(0, 1).await,
        Err(HeaderError::NotAtBoundary)
    ));
}

#[test]
fn encoder_output_matches_appendix_b_and_keeps_an_abandoned_insertion_open() {
    let mut hosts = (&b"www.example.com"[..], Vec::new());
    hosts.sync_reference_output_unpin();
    assert_eq!(
        hosts.1,
        b"\x3f\xbd\x01\xc0\x0fwww.example.com\xbf\x00\x00\x1f\x00\x80"
    );
}

#[call(sync)]
async fn coded_insert<N: Read + ExactLen, V: Read + ExactLen, O: Write>(
    name: &mut impl ReceiverAccess<Family = N>,
    value: &mut impl ReceiverAccess<Family = V>,
    out: &mut impl ReceiverAccess<Family = O>,
    limit: usize,
) -> Result<(), huffman::DecodeError>
where
    N::Length: TryInto<u64>,
    V::Length: TryInto<u64>,
    N::Error: Debug,
    V::Error: Debug,
    O::Error: Debug,
{
    let mut writer = Writer::new(out);
    let pending = match writer
        .literal_name(Payload::Huffman(name), usize::MAX, limit)
        .await
    {
        Ok(pending) => pending,
        Err(LiteralError::Huffman { source }) => return Err(source),
        Err(error) => panic!("{error:?}"),
    };
    match pending.value(Payload::Huffman(value)).await {
        Ok(()) => writer.duplicate(2, 1).await.unwrap(),
        Err(LiteralError::Huffman { source }) => {
            assert!(matches!(
                writer.duplicate(2, 1).await,
                Err(HeaderError::NotAtBoundary)
            ));
            return Err(source);
        }
        Err(error) => panic!("{error:?}"),
    }
    Ok(())
}

#[test]
fn encoded_sources_count_decoded_symbols_and_keep_their_wire_bytes() {
    const HOST: &[u8] = b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    let mut hosts = (HOST, &[0x1fu8][..], Vec::new());
    hosts.sync_coded_insert_unpin(16).unwrap();
    let mut expected = vec![0x6c];
    expected.extend_from_slice(HOST);
    expected.extend_from_slice(&[0x81, 0x1f, 2]);
    assert_eq!(hosts.2, expected);
    let mut tight = (HOST, &[0x1fu8][..], Vec::new());
    assert_eq!(
        tight.sync_coded_insert_unpin(15),
        Err(huffman::DecodeError::OutputTooLong { limit: 0 })
    );
    assert_eq!(tight.2, expected[..14]);
    let mut empty = (&[][..], &[][..], Vec::new());
    empty.sync_coded_insert_unpin(0).unwrap();
    assert_eq!(empty.2, [0x60, 0x80, 2]);
}

#[test]
fn encoded_value_checks_padding_eos_and_the_last_partial_block() {
    use huffman::DecodeError::{EndOfString, ExcessPadding, InvalidPadding};
    for (tail, expected) in [
        (&b"\x18"[..], InvalidPadding),
        (&b"\xff"[..], ExcessPadding),
        (&b"\xff\xff\xff\xff"[..], EndOfString),
    ] {
        let mut hosts = (&[][..], tail, Vec::new());
        assert_eq!(hosts.sync_coded_insert_unpin(32), Err(expected));
        assert_eq!(hosts.2, [0x60, 0x80 | tail.len() as u8]);
    }
    let mut body = vec![0; 1025]; // five-bit symbols straddle the 1024-octet transfer boundary
    body.push(0x18);
    let mut hosts = (&[][..], &body[..], Vec::new());
    assert_eq!(hosts.sync_coded_insert_unpin(2000), Err(InvalidPadding));
    assert!(hosts.2.ends_with(&[0; 1024]));
    assert!(hosts.2.len() < body.len() + 4);
}

#[test]
fn appendix_b3_insertion_round_trips_from_the_wire() {
    let example = b"\x4acustom-key\x0ccustom-value";
    let mut hosts = (&example[..], Vec::new());
    assert!(hosts.sync_relay_raw_unpin(example.len(), 22));
    assert!(hosts.0.is_empty());
    assert_eq!(&hosts.1[..example.len()], example);
}

impl ExactLen for Trickle<'_> {
    type Length = usize;
    fn remaining_len<'v>(view: core::pin::Pin<&mut Self::ReceiverView<'v>>) -> usize
    where
        Self: 'v,
    {
        view.get_pin_mut().rest.len()
    }
}

#[derive(Default)]
struct PausingSink {
    wire: Vec<u8>,
    waiting: bool,
}
nitori_call::family_receiver!(impl [] for PausingSink);
impl Write for PausingSink {
    type Error = core::convert::Infallible;
    fn poll_write<'v, B: Buf + ?Sized>(
        view: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        src: &mut B,
    ) -> core::task::Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::Poll;
        let sink = view.get_pin_mut().get_mut();
        if !sink.waiting {
            sink.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        sink.waiting = false;
        if !src.has_remaining() {
            return Poll::Ready(Ok(0));
        }
        sink.wire.push(src.get_u8());
        Poll::Ready(Ok(1))
    }
}

#[test]
fn pending_on_both_sides_does_not_repeat_octets_or_restart_huffman_state() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;
    let name = b"\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
    let mut hosts = (
        Trickle {
            rest: name,
            waiting: false,
        },
        Trickle {
            rest: &[0x1f],
            waiting: false,
        },
        PausingSink::default(),
    );
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut hosts),
            CodedInsert::new(16)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        // One pending read per payload octet and one pending write per wire octet.
        for _ in 0..(13 + 16) {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(Ok(())));
    }
    assert_eq!(
        hosts.2.wire,
        [&[0x6c], &name[..], &[0x81, 0x1f, 2]].concat()
    );
}

#[call(sync)]
async fn zero_budget<F: Read>(io: &mut impl ReceiverAccess<Family = F>)
where
    <F as Read>::Error: Debug,
{
    let mut reader = EncoderStream::new(io);
    assert!(matches!(
        reader.next_instruction(0, 0).await,
        Err(StartError::Prefix {
            source: hatate_qpack::instruction::OctetError::WireLimit { .. }
        })
    ));
    // The failed call left the stream interrupted.
    assert!(matches!(
        reader.next_instruction(1, 0).await,
        Err(StartError::Interrupted)
    ));
    assert!(matches!(
        reader.next_instruction(1, 0).await,
        Err(StartError::Interrupted)
    ));
}

#[test]
fn zero_budget_failure_interrupts_without_reading() {
    let mut input = &[2, 0x20][..];
    input.sync_zero_budget_unpin();
    assert_eq!(input, [2, 0x20]);
}

/// Drops the call after `polls` pending polls, then asks again.
#[call(sync)]
async fn dropped_start<F: Read>(io: &mut impl ReceiverAccess<Family = F>, polls: usize) -> bool
where
    <F as Read>::Error: Debug,
{
    use core::{
        future::{Future, poll_fn},
        pin::pin,
        task::Poll,
    };
    let mut reader = EncoderStream::new(io);
    {
        let mut first = pin!(reader.next_instruction(8, 8));
        poll_fn(|cx| {
            for _ in 0..polls {
                assert!(first.as_mut().poll(cx).is_pending());
            }
            Poll::Ready(())
        })
        .await;
    }
    matches!(
        reader.next_instruction(8, 8).await,
        Err(StartError::Interrupted)
    )
}

#[test]
fn dropped_call_interrupts_even_before_the_first_octet() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;
    // One poll: the opcode has not arrived. Two and three: the opcode is
    // consumed and a continuation is awaited. All leave the stream
    // interrupted (a known, conservative behavior for the first case).
    for polls in [1, 2, 3] {
        let mut host = Trickle {
            rest: &[0x3f, 0xbd, 0x01, 0x20],
            waiting: false,
        };
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            DroppedStart::new(polls)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        assert_eq!(call.as_mut().poll(&mut cx), Poll::Ready(true), "{polls}");
    }
}

/// What each of `count` successive instructions came to.
#[call(sync)]
async fn walk<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    count: usize,
) -> Vec<&'static str> {
    let mut stream = EncoderStream::new(io);
    let mut outcomes = Vec::new();
    for _ in 0..count {
        outcomes.push(match stream.next_instruction(64, 64).await {
            Ok(None) => "end",
            Ok(Some(Started::SetDynamicTableCapacity(_))) => "capacity",
            Ok(Some(Started::Duplicate(_))) => "duplicate",
            Ok(Some(_)) => "insertion",
            Err(StartError::Interrupted) => "interrupted",
            Err(_) => "error",
        });
    }
    outcomes
}

#[test]
fn stream_ending_at_a_boundary_gives_none() {
    let mut empty = &[][..];
    assert_eq!(empty.sync_walk_unpin(2), ["end", "end"]);
    // Instructions and then the end.
    let mut input = &[0x02, 0x3f, 0xbd, 0x01][..];
    assert_eq!(
        input.sync_walk_unpin(4),
        ["duplicate", "capacity", "end", "end"]
    );
    assert!(input.is_empty());
}

#[test]
fn unfinished_failed_or_truncated_instruction_interrupts_the_stream() {
    // The end inside a number: an error, not the end.
    let mut input = &[0x02, 0x3f][..];
    assert_eq!(
        input.sync_walk_unpin(4),
        ["duplicate", "error", "interrupted", "interrupted"]
    );
    // An insertion state dropped unread.
    let mut input = &[0x41, b'x', 0x02][..];
    assert_eq!(
        input.sync_walk_unpin(3),
        ["insertion", "interrupted", "interrupted"]
    );
    assert_eq!(input, [b'x', 0x02]);
}

#[call(sync)]
async fn handed_back<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> [&'static str; 4] {
    let mut stream = EncoderStream::new(io);
    let first = match stream.next_instruction(64, 64).await {
        Ok(Some(Started::Duplicate(2))) => "duplicate",
        _ => "other",
    };
    let mut stream = EncoderStream::new(stream.into_io());
    // This one fails on its wire limit before the opcode is read; the
    // interrupted stream still gives the access back.
    let second = match stream.next_instruction(0, 0).await {
        Err(StartError::Prefix { .. }) => "limit error",
        _ => "other",
    };
    let third = match stream.next_instruction(64, 64).await {
        Err(StartError::Interrupted) => "interrupted",
        _ => "other",
    };
    let mut stream = EncoderStream::new(stream.into_io());
    let fourth = match stream.next_instruction(64, 64).await {
        Ok(Some(Started::SetDynamicTableCapacity(32))) => "capacity",
        _ => "other",
    };
    [first, second, third, fourth]
}

#[test]
fn into_io_gives_back_the_access_at_the_cursor() {
    let mut input = &[0x02, 0x3f, 0x01, 0x20][..];
    assert_eq!(
        input.sync_handed_back_unpin(),
        ["duplicate", "limit error", "interrupted", "capacity"]
    );
    assert_eq!(input, [0x20]);
}

#[call(sync)]
async fn short_insertion<F: Read>(io: &mut impl ReceiverAccess<Family = F>, limit: usize) -> u128 {
    let mut reader = EncoderStream::new(io);
    match reader.next_instruction(limit, usize::MAX).await {
        Err(StartError::WireLimit { source }) => {
            assert_eq!(source.limit(), limit);
            source.required()
        }
        _ => panic!("expected the known minimum insertion size to exceed the limit"),
    }
}

#[test]
fn reject_impossible_insertions_at_the_first_decisive_octet() {
    // Each tuple specifies the first decisive prefix, unconsumed bytes,
    // maximum wire size, and minimum size known from just that prefix.
    let cases: &[(&[u8], &[u8], usize, u128)] = &[
        (&[0x41], b"x\0", 2, 3),             // raw literal name
        (&[0x61], &[0x1f, 0], 2, 3),         // Huffman literal name
        (&[0x80], &[0], 1, 2),               // dynamic name reference
        (&[0xc1], &[0], 1, 2),               // static name reference
        (&[0xff], &[0, 0], 2, 3),            // index needs another digit
        (&[0xbf, 0x80], &[0, 0], 3, 4),      // nonminimal, still incomplete
        (&[0x5f], &[0, b'x'], 33, 34),       // name length is already >= 31
        (&[0x7f, 0x82], &[0, 0x1f], 36, 37), // >= 33 octets, still needs a digit
        (&[0x5f, 4], b"x", 37, 38),          // full length 35 now known
    ];
    for &(prefix, tail, limit, required) in cases {
        let input = [prefix, tail].concat();
        let mut src = input.as_slice();
        assert_eq!(src.sync_short_insertion_unpin(limit), required);
        assert_eq!(src, tail);
    }
}
