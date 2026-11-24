//! The Stream Type at the start of a unidirectional stream, and HTTP/3
//! datagrams, with the parts of HTTP/3, HTTP Datagrams and Extended CONNECT.
//!
//! The low bit of the first byte picks the mode. In stream mode the rest is a
//! stream whose Stream Type is read (and, on a push stream, the Push ID),
//! however it arrives (bits 4 to 6 of the first byte are the bytes given per
//! read, minus one, bits 1 to 3 the period of a `Pending`, and bit 7 the
//! role of the endpoint: a server does not accept a push stream), and checked against an independent decoding of
//! the first integer; the field is written back and must equal its bytes. In
//! datagram mode the rest is the payload of a QUIC DATAGRAM frame, read as a
//! datagram, written back, and compared; a failure must be the one the first
//! bytes call for, and carry H3_DATAGRAM_ERROR.
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use bytes::BufMut;
use core::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::HList;
use hatate_wire::{
    Role,
    error_code::ErrorCodeOf as _,
    frame::PushId,
    stream::{
        UnidirectionalStream,
        codec::{ReadUnidirectionalStreamError, read_unidirectional_stream},
    },
    stream_type::{StreamType, StreamTypeSet},
};
use hatate_wire_datagram::{H3_DATAGRAM_ERROR, read_datagram, write_datagram};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, codec::write_var_int_field};

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

type Value = <Parts as StreamTypeSet>::TypeValue;

/// What reading the start of a unidirectional stream gave.
#[derive(Debug)]
enum Started {
    Control,
    Push(VarIntField<PushId>),
    Other(StreamType<Value>, VarIntField<VarInt>),
}

#[call(sync)]
async fn start<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    role: Role,
) -> Result<Option<Started>, ReadUnidirectionalStreamError<F::Error, Value>> {
    Ok(read_unidirectional_stream::<Parts, _>(&mut *io, role)
        .await?
        .map(|stream| match stream {
            UnidirectionalStream::Control(_) => Started::Control,
            UnidirectionalStream::Push { push_id, .. } => Started::Push(push_id),
            UnidirectionalStream::Other(stream) => {
                let head = stream.head();
                Started::Other(head.stream_type(), head.field())
            }
        }))
}

fn stream_type(control: u8, wire: &[u8]) {
    let mut arrival = Arrival {
        input: wire,
        chunk: usize::from(control >> 4 & 0x07) + 1,
        period: usize::from(control >> 1 & 0x07),
        reads: 0,
        woken: false,
    };
    let role = if control & 0x80 == 0 {
        Role::Client
    } else {
        Role::Server
    };
    let result = complete(arrival.start_unpin(role));
    match (integer(wire), result) {
        (Err(_), Ok(None)) => assert!(wire.is_empty()),
        (Err(_), Err(ReadUnidirectionalStreamError::Type { source })) => {
            assert!(!wire.is_empty());
            assert!(source.is_incomplete());
        }
        (Ok((length, 1)), Err(ReadUnidirectionalStreamError::NotAcceptableByRole { .. })) => {
            assert_eq!(role, Role::Server);
            let _ = length;
        }
        (Ok((length, 1)), Err(ReadUnidirectionalStreamError::PushId { source })) => {
            assert_eq!(role, Role::Client);
            assert!(source.is_incomplete());
            assert!(integer(&wire[length..]).is_err());
        }
        (Ok((length, value)), Ok(Some(started))) => {
            // The Stream Type bytes are consumed, and for a push stream the
            // Push ID after them, and no others.
            let mut consumed = length;
            let mut written = Vec::new();
            match started {
                Started::Control => assert_eq!(value, 0),
                Started::Push(push_id) => {
                    assert_eq!(value, 1);
                    assert_eq!(role, Role::Client);
                    let Ok((id_length, id)) = integer(&wire[length..]) else {
                        panic!("a Push ID was read from {wire:?}");
                    };
                    assert_eq!(push_id.get().get().get(), id);
                    assert_eq!(push_id.encoded_len(), id_length);
                    write_var_int_field(&mut written, push_id);
                    assert_eq!(written, &wire[length..length + id_length]);
                    written.clear();
                    consumed += id_length;
                }
                Started::Other(stream_type, field) => {
                    assert_eq!(field.get().get(), value);
                    assert_eq!(field.encoded_len(), length);
                    write_var_int_field(&mut written, field);
                    assert_eq!(written, &wire[..length]);
                    match stream_type {
                        StreamType::Known(known) => {
                            assert!((2..=3).contains(&value));
                            assert_eq!(<Parts as StreamTypeSet>::value_of(known).get(), value);
                        }
                        StreamType::Unknown(unknown) => {
                            assert!(value > 3);
                            assert_eq!(unknown.get(), value);
                        }
                    }
                }
            }
            assert_eq!(arrival.input, &wire[consumed..]);
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
            assert_eq!(error.error_code(), Some(H3_DATAGRAM_ERROR));
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
