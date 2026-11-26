#![feature(impl_trait_in_assoc_type)]
mod common;

use common::{Trickle, encoder_stream, next_encoder};
use core::fmt::Debug;
use hatate_qpack::encoder_instruction::{Started, codec::StartError};
use nitori_call::{ReceiverAccess, call};
use nitori_io::prelude::*;

#[call(sync)]
async fn zero_budget<F: Read<Metadata = ()>>(io: &mut impl ReceiverAccess<Family = F>)
where
    <F as Read>::Error: Debug,
{
    let mut reader = encoder_stream(io);
    assert!(matches!(
        next_encoder(&mut reader, 0, 0).await,
        Err(StartError::Prefix {
            source: hatate_qpack::instruction::OctetError::WireLimit { .. }
        })
    ));
    // The failed call left the stream interrupted.
    assert!(matches!(
        next_encoder(&mut reader, 1, 0).await,
        Err(StartError::Interrupted)
    ));
    assert!(matches!(
        next_encoder(&mut reader, 1, 0).await,
        Err(StartError::Interrupted)
    ));
}

#[test]
fn zero_budget_failure_interrupts_without_reading() {
    let mut input = &[2, 0x20][..];
    input.sync_zero_budget_unpin();
    assert_eq!(input, [2, 0x20]);
}

/// Drops the call after `polls` pending polls, then asks again: the
/// capacity the next instruction sets, or `None` if the stream was left
/// interrupted.
#[call(sync)]
async fn dropped_start<F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
    polls: usize,
) -> Option<u64>
where
    <F as Read>::Error: Debug,
{
    use core::{
        future::{Future, poll_fn},
        pin::pin,
        task::Poll,
    };
    let mut reader = encoder_stream(io);
    {
        let mut first = pin!(next_encoder(&mut reader, 8, 8));
        poll_fn(|cx| {
            for _ in 0..polls {
                assert!(first.as_mut().poll(cx).is_pending());
            }
            Poll::Ready(())
        })
        .await;
    }
    match next_encoder(&mut reader, 8, 8).await {
        Ok(Some(Started::SetDynamicTableCapacity(capacity))) => Some(capacity),
        Err(StartError::Interrupted) => None,
        _ => panic!("the next instruction was not a capacity or an interruption"),
    }
}

#[test]
fn dropped_call_before_the_first_octet_leaves_the_stream_at_the_boundary() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use nitori_call::CallExecutor;

    let read_after = |polls| {
        let mut host = Trickle {
            rest: &[0x3f, 0xbd, 0x01, 0x20],
            waiting: false,
        };
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            DroppedStart::new(polls)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..64 {
            if let Poll::Ready(value) = call.as_mut().poll(&mut cx) {
                return value;
            }
        }
        panic!("the call did not finish");
    };
    // No poll, or one in which the opcode has not arrived: nothing was read,
    // so the next call reads the instruction as if the first had not been
    // made.
    assert_eq!(read_after(0), Some(220));
    assert_eq!(read_after(1), Some(220));
    // Once the opcode is consumed, a dropped call leaves the stream
    // interrupted.
    for polls in [2, 3] {
        assert_eq!(read_after(polls), None, "{polls}");
    }
}

/// What each of `count` successive instructions came to.
#[call(sync)]
async fn walk<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    count: usize,
) -> Vec<&'static str> {
    let mut stream = encoder_stream(io);
    let mut outcomes = Vec::new();
    for _ in 0..count {
        outcomes.push(match next_encoder(&mut stream, 64, 64).await {
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
async fn handed_back<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> [&'static str; 4] {
    let mut stream = encoder_stream(io);
    let first = match next_encoder(&mut stream, 64, 64).await {
        Ok(Some(Started::Duplicate(2))) => "duplicate",
        _ => "other",
    };
    let mut stream = encoder_stream(stream.into_io());
    // This one fails on its wire limit before the opcode is read; the
    // interrupted stream still gives the access back.
    let second = match next_encoder(&mut stream, 0, 0).await {
        Err(StartError::Prefix { .. }) => "limit error",
        _ => "other",
    };
    let third = match next_encoder(&mut stream, 64, 64).await {
        Err(StartError::Interrupted) => "interrupted",
        _ => "other",
    };
    let mut stream = encoder_stream(stream.into_io());
    let fourth = match next_encoder(&mut stream, 64, 64).await {
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
async fn short_insertion<F: Read<Metadata = ()>>(
    io: &mut impl ReceiverAccess<Family = F>,
    limit: usize,
) -> u128 {
    let mut reader = encoder_stream(io);
    match next_encoder(&mut reader, limit, usize::MAX).await {
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
