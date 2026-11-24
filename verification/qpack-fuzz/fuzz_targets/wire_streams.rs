//! The Stream Type at the start of a unidirectional stream, and HTTP/3
//! datagrams, with the parts of HTTP/3, HTTP Datagrams and Extended CONNECT.
//!
//! The low bit of the first byte picks the mode. In stream mode the rest is a
//! stream whose Stream Type is read, however it arrives (the high four bits
//! of the first byte are the bytes given per read, minus one, and the
//! period of a `Pending`), and checked against an independent decoding of
//! the first integer; the field is written back and must equal its bytes. In
//! datagram mode the rest is the payload of a QUIC DATAGRAM frame, read as a
//! datagram, written back, and compared; a failure must be the one the first
//! bytes call for, and carry H3_DATAGRAM_ERROR.
#![no_main]
use bytes::BufMut;
use core::{
    convert::Infallible,
    future::Future,
    marker::PhantomData,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::stream_type::{
    StreamType, StreamTypeSet, codec::ReadStreamTypeHostExt as _,
};
use hatate_wire_datagram::{H3_DATAGRAM_ERROR, read_datagram, write_datagram};
use libfuzzer_sys::fuzz_target;
use nitori_io::Read;
use sakuya_var_int::codec::write_var_int_field;

type Parts = HList![
    hatate_wire::Part,
    hatate_wire_datagram::Part,
    hatate_wire_extended_connect::Part
];

/// A stream that gives `chunk` bytes at most per read and is pending on every
/// `period`-th read.
struct Arrival<'a> {
    input: &'a [u8],
    chunk: usize,
    period: usize,
    reads: usize,
    woken: bool,
}

nitori_call::family_receiver!(impl ['a] for Arrival<'a>);

impl Read for Arrival<'_> {
    type Error = Infallible;
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.period != 0 && !this.woken && this.reads % this.period == 0 {
            this.woken = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.woken = false;
        this.reads += 1;
        let count = this.chunk.min(this.input.len()).min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(count))
    }
}

fn complete<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut cx) {
            return value;
        }
    }
}

/// The length and value of the variable-length integer at the start of
/// `bytes`, if it is all there.
fn integer(bytes: &[u8]) -> Result<(usize, u64), usize> {
    let Some(&first) = bytes.first() else {
        return Err(1);
    };
    let length = 1usize << (first >> 6);
    if bytes.len() < length {
        return Err(length);
    }
    let value = bytes[..length]
        .iter()
        .enumerate()
        .fold(0u64, |value, (index, &byte)| {
            let byte = if index == 0 { byte & 0x3f } else { byte };
            (value << 8) | u64::from(byte)
        });
    Ok((length, value))
}

fn stream_type(control: u8, wire: &[u8]) {
    let mut arrival = Arrival {
        input: wire,
        chunk: usize::from(control >> 4 & 0x07) + 1,
        period: usize::from(control >> 1 & 0x07),
        reads: 0,
        woken: false,
    };
    let result = complete(arrival.read_stream_type_unpin(PhantomData::<Parts>));
    match (integer(wire), result) {
        (Err(_), Ok(None)) => assert!(wire.is_empty()),
        (Err(_), Err(error)) => {
            assert!(!wire.is_empty());
            assert!(error.is_incomplete());
        }
        (Ok((length, value)), Ok(Some(head))) => {
            assert_eq!(head.field().get().get(), value);
            assert_eq!(head.field().encoded_len(), length);
            // The Stream Type bytes are consumed, and no others.
            assert_eq!(arrival.input, &wire[length..]);
            let mut written = Vec::new();
            write_var_int_field(&mut written, head.field());
            assert_eq!(written, &wire[..length]);
            match head.stream_type() {
                StreamType::Known(known) => {
                    assert!(value <= 3);
                    assert_eq!(<Parts as StreamTypeSet>::value_of(known).get(), value);
                }
                StreamType::Unknown(unknown) => {
                    assert!(value > 3);
                    assert_eq!(unknown.get(), value);
                }
            }
        }
        (integer, result) => panic!("{integer:?} read as {result:?}"),
    }
}

fn datagram(payload: &[u8]) {
    let expected = integer(payload);
    match read_datagram(payload) {
        Ok(datagram) => {
            let Ok((length, value)) = expected else {
                panic!("a datagram was read from {payload:?}");
            };
            assert!(value < 1 << 60);
            assert_eq!(datagram.quarter_stream_id().get().get().get(), value);
            assert_eq!(datagram.quarter_stream_id().encoded_len(), length);
            assert_eq!(*datagram.payload(), &payload[length..]);
            let mut written = Vec::new();
            write_datagram(&mut written, datagram);
            assert_eq!(written, payload);
        }
        Err(error) => {
            assert_eq!(error.error_code(), H3_DATAGRAM_ERROR);
            match expected {
                Err(_) => {}
                Ok((_, value)) => assert!(value >= 1 << 60),
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, rest)) = data.split_first() else {
        return;
    };
    if control & 1 == 0 {
        stream_type(control, rest);
    } else {
        datagram(rest);
    }
});
