#![feature(impl_trait_in_assoc_type)]
//! The instruction streams of QPACK, `EncoderStream` and `DecoderStream`, on the two
//! layers: inside an operation, where they hold the operation's access, and
//! outside any operation, where they hold a `ConstructedAccess` on a
//! receiver and are kept across any number of separate polls. The same
//! script runs on both, and what it sees must agree: on the receiver layer
//! each step is its own poll loop, with the stream kept between them.
use bytes::BufMut;
use core::{
    convert::Infallible,
    fmt::Debug,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction, DecoderStream, DecoderStreamLimits, codec::ReadError,
    },
    encoder_instruction::{
        EncoderStream, EncoderStreamLimits, NameReference, Started, codec::StartError,
        literal::LiteralSource,
    },
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_codec::DecodeFrom;
use nitori_io::{Read, calls::ReadValue, prelude::*};

async fn next_encoder<'a, F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &'a mut EncoderStream<A>,
    wire: usize,
    decoded: usize,
) -> Result<Option<Started<'a, A>>, StartError<F::Error>> {
    reader.set_limits(EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    });
    let next = Option::<ReadValue<Started<'a, A>, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

fn encoder_stream<A>(io: A) -> EncoderStream<A> {
    EncoderStream::new(io, EncoderStreamLimits::default())
}

async fn next_decoder<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &mut DecoderStream<A>,
    wire: usize,
) -> Result<Option<DecoderInstruction>, ReadError<F::Error>> {
    reader.set_limits(DecoderStreamLimits { max_wire_len: wire });
    let next = Option::<ReadValue<DecoderInstruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

fn decoder_stream<A>(io: A) -> DecoderStream<A> {
    DecoderStream::new(io, DecoderStreamLimits::default())
}

/// A stream that gives one byte per read and answers Pending once before
/// each read.
struct Trickle<'a> {
    rest: &'a [u8],
    waiting: bool,
}

impl<'a> Trickle<'a> {
    fn new(rest: &'a [u8]) -> Self {
        Self {
            rest,
            waiting: false,
        }
    }
}

nitori_call::family_receiver!(impl ['a] for Trickle<'a>);

impl Read for Trickle<'_> {
    type Error = Infallible;
    type Metadata = ();
    fn poll_read<'v, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        if !dst.has_remaining_mut() {
            return Poll::Ready(Ok(None));
        }
        let Some((&byte, rest)) = this.rest.split_first() else {
            return Poll::Ready(Ok(None));
        };
        this.rest = rest;
        dst.put_u8(byte);
        Poll::Ready(Ok(Some(nitori_io::ReadSegment {
            count: core::num::NonZeroUsize::MIN,
            metadata: (),
        })))
    }
}

/// Polls a future to completion, counting the polls that were pending.
fn run<T>(future: impl Future<Output = T>) -> (T, usize) {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = 0;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return (value, pending),
            Poll::Pending => {
                pending += 1;
                assert!(pending < 100_000, "the future never completes");
            }
        }
    }
}

/// Polls `future` `polls` times and drops it; true if it completed.
fn poll_then_drop<T>(future: impl Future<Output = T>, polls: usize) -> bool {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    (0..polls).any(|_| future.as_mut().poll(&mut cx).is_ready())
}

/// What is left in the access, a byte at a time.
async fn rest_of<A: ReceiverAccess<Family: Read<Metadata = ()>>>(io: &mut A) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0u8; 1];
        match io.read(&mut &mut byte[..]).await {
            Ok(None) | Err(_) => return bytes,
            Ok(Some(_)) => bytes.push(byte[0]),
        }
    }
}

// The two ways of waiting for a step: inside an operation the script is an
// async function and awaits; on the receiver layer it is a plain function and
// every step is its own poll loop.
macro_rules! aw {
    ($step:expr) => {
        $step.await
    };
}
macro_rules! ru {
    ($step:expr) => {
        run($step).0
    };
}

/// Reads a literal to its end a byte at a time, each read a step.
macro_rules! drain_literal {
    ($w:ident, $source:expr) => {{
        let mut got = Vec::new();
        match $source {
            LiteralSource::Raw(mut source) => loop {
                let mut byte = [0u8; 1];
                if $w!(source.read(&mut &mut byte[..])).unwrap().is_none() {
                    break;
                }
                got.push(byte[0]);
            },
            LiteralSource::Huffman(mut source) => loop {
                let mut byte = [0u8; 1];
                if $w!(source.read(&mut &mut byte[..])).unwrap().is_none() {
                    break;
                }
                got.push(byte[0]);
            },
        }
        String::from_utf8(got).unwrap()
    }};
}

fn describe<A: ReceiverAccess, E: Debug>(
    result: Result<Option<Started<'_, A>>, StartError<E>>,
) -> String {
    match result {
        Ok(None) => "end".to_string(),
        Ok(Some(Started::SetDynamicTableCapacity(n))) => format!("capacity {n}"),
        Ok(Some(Started::Duplicate(n))) => format!("duplicate {n}"),
        Ok(Some(Started::InsertWithNameReference { .. })) => "insert with reference".to_string(),
        Ok(Some(Started::InsertWithLiteralName(_))) => "insert with literal name".to_string(),
        Err(error) => format!("error {error:?}"),
    }
}

/// Every instruction of an encoder stream to the end or the first failure,
/// with its literals read a byte at a time; what the access has left.
macro_rules! encoder_log {
    ($io:expr, $w:ident) => {{
        let mut log = Vec::new();
        let mut reader = encoder_stream($io);
        loop {
            let started = match $w!(next_encoder(&mut reader, 64, 64)) {
                Ok(Some(started)) => started,
                Ok(None) => {
                    log.push("end".to_string());
                    break;
                }
                Err(error) => {
                    log.push(format!("error {error:?}"));
                    break;
                }
            };
            match started {
                Started::SetDynamicTableCapacity(n) => log.push(format!("capacity {n}")),
                Started::Duplicate(n) => log.push(format!("duplicate {n}")),
                Started::InsertWithNameReference { name, value } => {
                    let name = match name {
                        NameReference::Static(index) => {
                            format!("static {}", String::from_utf8_lossy(index.entry().0))
                        }
                        NameReference::Relative(n) => format!("relative {n}"),
                    };
                    let mut value = $w!(value.open()).unwrap().value;
                    let text = drain_literal!($w, value.source());
                    value.finish().unwrap();
                    log.push(format!("{name} = {text}"));
                }
                Started::InsertWithLiteralName(mut name) => {
                    let name_text = drain_literal!($w, name.source());
                    let mut value = $w!(name.finish().unwrap().open()).unwrap().value;
                    let text = drain_literal!($w, value.source());
                    value.finish().unwrap();
                    log.push(format!("{name_text} = {text}"));
                }
            }
        }
        let mut io = reader.into_io();
        let rest = $w!(rest_of(&mut io));
        (log, rest)
    }};
}

#[call(sync)]
async fn encoder_in_call<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    encoder_log!(&mut *io, aw)
}

fn encoder_on_receiver<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    encoder_log!(io, ru)
}

/// A literal name that is read and then dropped, or left unfinished, never
/// advances to its value: the stream is interrupted, and the access is where
/// the name left it.
macro_rules! abandon_log {
    ($io:expr, $w:ident) => {{
        let mut reader = encoder_stream($io);
        let first = describe($w!(next_encoder(&mut reader, 32, 32)));
        let second = describe($w!(next_encoder(&mut reader, 32, 32)));
        let mut io = reader.into_io();
        let rest = $w!(rest_of(&mut io));
        (vec![first, second], rest)
    }};
}

#[call(sync)]
async fn abandon_in_call<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    abandon_log!(&mut *io, aw)
}

fn abandon_on_receiver<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    abandon_log!(io, ru)
}

/// The read of an instruction dropped after `polls` polls, then what the
/// next read of the stream says, and what the access has left.
macro_rules! dropped_log {
    ($io:expr, $w:ident, $polls:expr) => {{
        let mut reader = encoder_stream($io);
        let done = poll_then_drop(next_encoder(&mut reader, 32, 32), $polls);
        let again = describe($w!(next_encoder(&mut reader, 32, 32)));
        let mut io = reader.into_io();
        let rest = $w!(rest_of(&mut io));
        (done, again, rest)
    }};
}

#[call(sync)]
async fn dropped_in_call<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> (bool, String, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    dropped_log!(&mut *io, aw, polls)
}

fn dropped_on_receiver<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
    polls: usize,
) -> (bool, String, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    dropped_log!(io, ru, polls)
}

/// Capacity 220; static ":authority" with a raw value; a raw literal name
/// with a Huffman value; a literal name with a raw value; Duplicate 0.
const ENCODER_WIRE: &[u8] = b"\x3f\xbd\x01\xc0\x0fwww.example.com\x41x\x81\x1f\x42ab\x01y\x00";

fn expected_encoder_log() -> Vec<String> {
    [
        "capacity 220",
        "static :authority = www.example.com",
        "x = a",
        "ab = y",
        "duplicate 0",
        "end",
    ]
    .map(String::from)
    .to_vec()
}

#[test]
fn encoder_instructions_read_across_runs_agree_with_the_call_layer() {
    let mut slice = ENCODER_WIRE;
    let in_call = slice.sync_encoder_in_call_unpin();
    assert_eq!(in_call, (expected_encoder_log(), vec![]));

    let mut host = Trickle::new(ENCODER_WIRE);
    let (suspended, pending) = run(host.encoder_in_call_unpin());
    assert!(pending > 0);
    assert_eq!(suspended, in_call);

    // By value, each step its own poll loop.
    let on_receiver = encoder_on_receiver(ConstructedAccess::new(Trickle::new(ENCODER_WIRE)));
    assert_eq!(on_receiver, in_call);
    let on_receiver = encoder_on_receiver(ConstructedAccess::new(ENCODER_WIRE));
    assert_eq!(on_receiver, in_call);
}

#[test]
fn encoder_instructions_on_a_borrowed_receiver_leave_what_they_did_not_read() {
    let mut input = ENCODER_WIRE;
    {
        let mut reader = encoder_stream(ConstructedAccess::new(&mut input));
        assert_eq!(
            describe(run(next_encoder(&mut reader, 64, 64)).0),
            "capacity 220"
        );
        let Some(Started::InsertWithNameReference { value, .. }) =
            run(next_encoder(&mut reader, 64, 64)).0.unwrap()
        else {
            panic!("not an insertion with a reference");
        };
        let mut value = run(value.open()).0.unwrap().value;
        let LiteralSource::Raw(mut source) = value.source() else {
            panic!("not raw");
        };
        // The literal is read in two separate runs.
        assert_eq!(run(source.read_array::<4>()).0.unwrap().value, *b"www.");
        assert_eq!(
            run(source.read_array::<11>()).0.unwrap().value,
            *b"example.com"
        );
        value.finish().unwrap();
        // The stream is at a boundary again.
        assert_eq!(
            describe(run(next_encoder(&mut reader, 64, 64)).0),
            "insert with literal name"
        );
    }
    // The literal name was dropped unfinished: its first byte is still there.
    assert_eq!(input, b"x\x81\x1f\x42ab\x01y\x00");
}

#[test]
fn a_literal_name_left_unfinished_interrupts_the_stream_on_the_receiver_layer() {
    let wire = [0x41, b'x', 0, 0x20];
    let mut slice = &wire[..];
    let in_call = slice.sync_abandon_in_call_unpin();
    assert_eq!(
        in_call,
        (
            vec![
                "insert with literal name".to_string(),
                "error Interrupted".to_string()
            ],
            vec![b'x', 0, 0x20]
        )
    );
    let on_receiver = abandon_on_receiver(ConstructedAccess::new(Trickle::new(&wire)));
    assert_eq!(on_receiver, in_call);
    let mut host = Trickle::new(&wire);
    assert_eq!(run(host.abandon_in_call_unpin()).0, in_call);
}

#[test]
fn an_instruction_read_dropped_in_the_middle_behaves_as_it_does_in_a_call() {
    // Capacity 220 in three bytes, then a literal name with a raw value.
    let wire = b"\x3f\xbd\x01\x41x\x01y";
    let mut outcomes = Vec::new();
    for polls in 0..14 {
        let mut host = Trickle::new(wire);
        let in_call = run(host.dropped_in_call_unpin(polls)).0;
        let on_receiver = dropped_on_receiver(ConstructedAccess::new(Trickle::new(wire)), polls);
        assert_eq!(on_receiver, in_call, "polls {polls}");
        outcomes.push(in_call);
    }
    // Dropped before the first byte was read and after the capacity was
    // complete are different outcomes, so the loop covered both.
    assert!(outcomes.iter().any(|(done, ..)| !done));
    assert!(outcomes.iter().any(|(done, ..)| *done));
    assert!(
        outcomes
            .iter()
            .any(|(_, again, _)| again == "error Interrupted")
    );
}

/// Every instruction of a decoder stream, `count` reads, each failure
/// included; what the access has left.
macro_rules! decoder_log {
    ($io:expr, $w:ident, $count:expr) => {{
        let mut reader = decoder_stream($io);
        let mut log = Vec::new();
        for _ in 0..$count {
            match $w!(next_decoder(&mut reader, 8)) {
                Ok(Some(instruction)) => log.push(format!("{instruction:?}")),
                Ok(None) => log.push("end".to_string()),
                Err(error) => log.push(format!("error {error:?}")),
            }
        }
        let mut io = reader.into_io();
        let rest = $w!(rest_of(&mut io));
        (log, rest)
    }};
}

#[call(sync)]
async fn decoder_in_call<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    count: usize,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    decoder_log!(&mut *io, aw, count)
}

fn decoder_on_receiver<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
    count: usize,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    decoder_log!(io, ru, count)
}

#[call(sync)]
async fn decoder_dropped_in_call<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> (bool, String, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    let mut reader = decoder_stream(&mut *io);
    let done = poll_then_drop(next_decoder(&mut reader, 8), polls);
    let again = format!("{:?}", next_decoder(&mut reader, 8).await);
    let mut io = reader.into_io();
    (done, again, rest_of(&mut io).await)
}

fn decoder_dropped_on_receiver<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
    polls: usize,
) -> (bool, String, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    let mut reader = decoder_stream(io);
    let done = poll_then_drop(next_decoder(&mut reader, 8), polls);
    let again = format!("{:?}", run(next_decoder(&mut reader, 8)).0);
    let mut io = reader.into_io();
    (done, again, run(rest_of(&mut io)).0)
}

#[test]
fn decoder_instructions_read_across_runs_agree_with_the_call_layer() {
    // Section Acknowledgment of stream 4, Insert Count Increment 1, Stream
    // Cancellation of stream 8, then the end.
    let wire = [0x84, 0x01, 0x48];
    let mut slice = &wire[..];
    let in_call = slice.sync_decoder_in_call_unpin(5);
    assert_eq!(in_call.0.len(), 5);
    assert!(in_call.0[0].starts_with("SectionAcknowledgment"));
    assert!(in_call.0[1].starts_with("InsertCountIncrement"));
    assert!(in_call.0[2].starts_with("StreamCancellation"));
    // The end at a boundary stays the end.
    assert_eq!(in_call.0[3..], ["end", "end"]);
    assert!(in_call.1.is_empty());

    let mut host = Trickle::new(&wire);
    assert_eq!(run(host.decoder_in_call_unpin(5)).0, in_call);
    let on_receiver = decoder_on_receiver(ConstructedAccess::new(Trickle::new(&wire)), 5);
    assert_eq!(on_receiver, in_call);

    // Borrowed: the stream is dropped after one instruction, and the access
    // keeps the rest.
    let mut input = &wire[..];
    {
        let mut reader = decoder_stream(ConstructedAccess::new(&mut input));
        assert!(run(next_decoder(&mut reader, 8)).0.unwrap().is_some());
    }
    assert_eq!(input, [0x01, 0x48]);
}

#[test]
fn a_decoder_stream_cut_in_a_number_is_interrupted_on_the_receiver_layer_too() {
    // Insert Count Increment 5, then a number that goes on, then the end.
    let wire = [0x05, 0x3f, 0x80];
    let mut slice = &wire[..];
    let in_call = slice.sync_decoder_in_call_unpin(4);
    assert!(in_call.0[0].starts_with("InsertCountIncrement"));
    assert!(in_call.0[1].starts_with("error"));
    assert_eq!(in_call.0[2], "error Interrupted");
    assert_eq!(in_call.0[3], "error Interrupted");
    assert!(in_call.1.is_empty());
    let on_receiver = decoder_on_receiver(ConstructedAccess::new(Trickle::new(&wire)), 4);
    assert_eq!(on_receiver, in_call);
}

#[test]
fn a_decoder_read_dropped_in_the_middle_behaves_as_it_does_in_a_call() {
    let wire = [0x3f, 0x80, 0x01, 0x84];
    let mut outcomes = Vec::new();
    for polls in 0..8 {
        let mut host = Trickle::new(&wire);
        let in_call = run(host.decoder_dropped_in_call_unpin(polls)).0;
        let on_receiver =
            decoder_dropped_on_receiver(ConstructedAccess::new(Trickle::new(&wire)), polls);
        assert_eq!(on_receiver, in_call, "polls {polls}");
        outcomes.push(in_call);
    }
    assert!(
        outcomes
            .iter()
            .any(|(_, again, _)| again.contains("Interrupted"))
    );
}
