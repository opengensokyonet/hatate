#![feature(impl_trait_in_assoc_type)]
use bytes::Buf;
use core::fmt::Debug;
use core::num::NonZeroUsize;
use hatate_qpack::{
    encoder_instruction::{
        NameReference, Reader, Started,
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
    let mut reader = Reader::new(io);
    let Started::InsertWithLiteralName(mut name) = reader.start(4, 2).await.unwrap() else {
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
            reader.start(8, 8).await,
            Err(StartError::NotAtBoundary)
        ));
    } else {
        value.finish().unwrap();
        assert!(matches!(
            reader.start(1, 0).await.unwrap(),
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
    let mut reader = Reader::new(io);
    let Started::InsertWithLiteralName(name) = reader.start(32, 32).await.unwrap() else {
        panic!()
    };
    if drop_name {
        drop(name)
    } else {
        assert!(matches!(name.finish(), Err(FinishError::Unread)))
    }
    assert!(matches!(
        reader.start(32, 32).await,
        Err(StartError::NotAtBoundary)
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
    let mut reader = Reader::new(io);
    let Started::InsertWithLiteralName(mut name) = reader.start(wire, decoded).await.unwrap()
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
    let mut reader = Reader::new(io);
    assert!(matches!(
        reader.start(3, 0).await.unwrap(),
        Started::SetDynamicTableCapacity(220)
    ));
    let Started::InsertWithNameReference {
        name: NameReference::Static(index),
        value,
    } = reader.start(64, 64).await.unwrap()
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
    let mut reader = Reader::new(io);
    let Started::InsertWithLiteralName(mut name) = reader.start(16, 16).await.unwrap() else {
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
        reader.start(1, 0).await.unwrap(),
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
    let mut reader = Reader::new(io);
    let Started::InsertWithNameReference {
        name: NameReference::Relative(0),
        value,
    } = reader.start(5, 3).await.unwrap()
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

use hatate_qpack::encoder_instruction::write::{HeaderError, LiteralError, Writer};

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
    let mut reader = Reader::new(input);
    let mut writer = Writer::new(output);
    let Started::InsertWithLiteralName(mut name) = reader.start(256, 256).await.unwrap() else {
        panic!("expected literal name")
    };
    let pending = {
        let LiteralSource::Raw(mut src) = name.source() else {
            panic!("expected raw name")
        };
        writer.literal_name(&mut src, wire, decoded).await.unwrap()
    };
    let mut value = name.finish().unwrap().open().await.unwrap();
    let LiteralSource::Raw(mut src) = value.source() else {
        panic!("expected raw value")
    };
    match pending.value(&mut src).await {
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
        .value(input)
        .await
        .unwrap();
    writer
        .name_reference(NameReference::Relative(63), 3, 0)
        .await
        .unwrap()
        .value(input)
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
