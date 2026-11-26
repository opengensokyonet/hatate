#![feature(impl_trait_in_assoc_type)]
//! The instruction streams of QPACK, `EncoderStream` and `DecoderStream`, on the two
//! layers: inside an operation, where they hold the operation's access, and
//! outside any operation, where they hold a `ConstructedAccess` on a
//! receiver and are kept across any number of separate polls. The same
//! script runs on both, and what it sees must agree: on the receiver layer
//! each step is its own poll loop, with the stream kept between them.
mod common;
mod support;

use common::{Read as Instruction, Trickle, encoder_stream, next_encoder, octets};
use core::{
    fmt::Debug,
    future::Future,
    num::NonZeroU64,
    pin::pin,
    task::{Context, Poll, Waker},
};
use hatate_qpack::{
    decoder_instruction::{
        DecodeDecoderInstructionError as ReadError, DecoderInstruction, DecoderStream,
        DecoderStreamLimits, Increment,
    },
    encoder_instruction::{
        DecodeEncoderInstructionError as StartError, EncoderInstruction, NameReference,
    },
    integer::PrefixedField,
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{Read, calls::ReadValue, prelude::*};

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
fn trickle(rest: &[u8]) -> Trickle<'_> {
    Trickle {
        rest,
        waiting: false,
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

fn text(octets: &[u8]) -> String {
    String::from_utf8_lossy(octets).into_owned()
}

fn describe<E: Debug>(result: Result<Option<Instruction>, StartError<E>>) -> String {
    match result {
        Ok(None) => "end".to_string(),
        Ok(Some(EncoderInstruction::SetDynamicTableCapacity { capacity })) => {
            format!("capacity {}", capacity.value())
        }
        Ok(Some(EncoderInstruction::Duplicate { index })) => {
            format!("duplicate {}", index.value())
        }
        Ok(Some(EncoderInstruction::InsertWithNameReference { name, value })) => {
            let name = match name {
                NameReference::Static { index } => {
                    format!("static {}", text(index.value().entry().0))
                }
                NameReference::Relative { index } => format!("relative {}", index.value()),
            };
            format!("{name} = {}", text(octets(&value)))
        }
        Ok(Some(EncoderInstruction::InsertWithLiteralName { name, value })) => {
            format!("{} = {}", text(octets(&name)), text(octets(&value)))
        }
        Err(error) => format!("error {error:?}"),
    }
}

/// Every instruction of an encoder stream to the end or the first failure;
/// what the access has left.
macro_rules! encoder_log {
    ($io:expr, $w:ident) => {{
        let mut log = Vec::new();
        let mut reader = encoder_stream($io);
        loop {
            let entry = describe($w!(next_encoder(&mut reader, 64, 64)));
            let last = entry == "end" || entry.starts_with("error");
            log.push(entry);
            if last {
                break;
            }
        }
        let mut io = reader.into_io();
        let rest = $w!(rest_of(&mut io));
        (log, rest)
    }};
}

#[call(sync)]
async fn encoder_in_call<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    encoder_log!(&mut *io, aw)
}

fn encoder_on_receiver<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: A,
) -> (Vec<String>, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    encoder_log!(io, ru)
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
async fn dropped_in_call<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    polls: usize,
) -> (bool, String, Vec<u8>)
where
    <F as Read>::Error: Debug,
{
    dropped_log!(&mut *io, aw, polls)
}

fn dropped_on_receiver<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
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

    let mut host = trickle(ENCODER_WIRE);
    let (suspended, pending) = run(host.encoder_in_call_unpin());
    assert!(pending > 0);
    assert_eq!(suspended, in_call);

    // By value, each step its own poll loop.
    let on_receiver = encoder_on_receiver(ConstructedAccess::new(trickle(ENCODER_WIRE)));
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
        assert_eq!(
            describe(run(next_encoder(&mut reader, 64, 64)).0),
            "static :authority = www.example.com"
        );
    }
    // The stream was dropped at a boundary: the next instruction is there.
    assert_eq!(input, b"\x41x\x81\x1f\x42ab\x01y\x00");
}

#[test]
fn an_insertion_cut_in_its_value_interrupts_the_stream_on_the_receiver_layer_too() {
    let wire = [0x41, b'x', 0x02, b'y'];
    let mut slice = &wire[..];
    let in_call = slice.sync_encoder_in_call_unpin();
    assert_eq!(in_call.0.len(), 1);
    assert!(in_call.0[0].contains("Truncated"), "{in_call:?}");
    assert!(in_call.1.is_empty());
    let on_receiver = encoder_on_receiver(ConstructedAccess::new(trickle(&wire)));
    assert_eq!(on_receiver, in_call);
    let mut host = trickle(&wire);
    assert_eq!(run(host.encoder_in_call_unpin()).0, in_call);
}

#[test]
fn an_instruction_read_dropped_in_the_middle_behaves_as_it_does_in_a_call() {
    // Capacity 220 in three bytes, then a literal name with a raw value.
    let wire = b"\x3f\xbd\x01\x41x\x01y";
    let mut outcomes = Vec::new();
    for polls in 0..14 {
        let mut host = trickle(wire);
        let in_call = run(host.dropped_in_call_unpin(polls)).0;
        let on_receiver = dropped_on_receiver(ConstructedAccess::new(trickle(wire)), polls);
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

    let mut host = trickle(&wire);
    assert_eq!(run(host.decoder_in_call_unpin(5)).0, in_call);
    let on_receiver = decoder_on_receiver(ConstructedAccess::new(trickle(&wire)), 5);
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
    let on_receiver = decoder_on_receiver(ConstructedAccess::new(trickle(&wire)), 4);
    assert_eq!(on_receiver, in_call);
}

#[test]
fn a_decoder_read_dropped_in_the_middle_behaves_as_it_does_in_a_call() {
    let wire = [0x3f, 0x80, 0x01, 0x84];
    let mut outcomes = Vec::new();
    for polls in 0..8 {
        let mut host = trickle(&wire);
        let in_call = run(host.decoder_dropped_in_call_unpin(polls)).0;
        let on_receiver =
            decoder_dropped_on_receiver(ConstructedAccess::new(trickle(&wire)), polls);
        assert_eq!(on_receiver, in_call, "polls {polls}");
        outcomes.push(in_call);
    }
    assert!(
        outcomes
            .iter()
            .any(|(_, again, _)| again.contains("Interrupted"))
    );
}

fn assert_send<T: Send>(_: &T) {}

#[test]
fn the_instruction_streams_and_their_futures_are_send_when_the_receiver_is() {
    let wire = [0x3f, 0xbd, 0x01];
    // The access held by value.
    let mut encoder = encoder_stream(ConstructedAccess::new(trickle(&wire)));
    assert_send(&encoder);
    {
        let next = next_encoder(&mut encoder, 64, 64);
        assert_send(&next);
    }
    // The access held by `&mut`.
    let mut host = ConstructedAccess::new(trickle(&wire));
    let mut encoder = encoder_stream(&mut host);
    assert_send(&encoder);
    {
        let next = next_encoder(&mut encoder, 64, 64);
        assert_send(&next);
    }
    // An instruction read, and its write.
    let mut encoder = encoder_stream(ConstructedAccess::new(trickle(ENCODER_WIRE)));
    let _ = run(next_encoder(&mut encoder, 64, 64));
    let instruction = run(next_encoder(&mut encoder, 64, 64)).0.unwrap().unwrap();
    assert_send(&instruction);
    let mut output = encoder_stream(ConstructedAccess::new(Vec::new()));
    let made: EncoderInstruction<&[u8], &[u8]> = EncoderInstruction::InsertWithLiteralName {
        name: support::raw(&b"x"[..]),
        value: support::huffman(&b"y"[..]),
    };
    {
        let write = made.encode_into(&mut output);
        assert_send(&write);
    }
    let mut decoder = decoder_stream(ConstructedAccess::new(trickle(&wire)));
    assert_send(&decoder);
    {
        let next = next_decoder(&mut decoder, 8);
        assert_send(&next);
    }
    let mut host = ConstructedAccess::new(trickle(&wire));
    let mut decoder = decoder_stream(&mut host);
    assert_send(&decoder);
    {
        let next = next_decoder(&mut decoder, 8);
        assert_send(&next);
    }
    let mut output = decoder_stream(ConstructedAccess::new(Vec::new()));
    let increment = DecoderInstruction::InsertCountIncrement {
        increment: PrefixedField::shortest(Increment::new(NonZeroU64::MIN)),
    };
    {
        let write = increment.encode_into(&mut output);
        assert_send(&write);
    }
}
