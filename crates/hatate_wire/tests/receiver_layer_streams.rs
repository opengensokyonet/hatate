#![feature(impl_trait_in_assoc_type)]
//! The unidirectional and bidirectional streams that hold their access, on
//! the two layers (see `receiver_layer_frames.rs`): the constructors, the
//! critical streams, and whether the streams and their futures are Send.
#[macro_use]
mod common;

use common::{
    Dribble, Ty, next_critical_decoder, next_critical_encoder, read_some, receiver_layer::Outcome,
    run,
};
use core::convert::Infallible;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_qpack::encoder_instruction::{NameReference, Started, literal::LiteralSource};
use hatate_wire::{
    Part, Role,
    error_code::ErrorCodeOf,
    stream::{
        FrameStream, ReceivedStream, TypedStream as _,
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedUnidirectional,
        },
        codec::{read_bidirectional_stream, read_unidirectional_stream},
        http3::Http3UnidirectionalStream,
        kind::RequestStreamKind,
    },
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_io::{Read, Skip};

type Parts = HList![Part];

// The constructors.

macro_rules! drain_code {
    ($w:ident, $source:expr) => {
        match $source {
            LiteralSource::Raw(mut source) => {
                $w!(read_some(&mut source, 1000)).map_err(|error| error.error_code())
            }
            LiteralSource::Huffman(mut source) => {
                $w!(read_some(&mut source, 1000)).map_err(|error| error.error_code())
            }
        }
    };
}

/// The start of a unidirectional stream of `$class`, then what its kind of
/// stream reads to its end or failure.
macro_rules! start_log {
    ($io:expr, $w:ident, $class:ty, $discard:expr) => {{
        let mut log: Vec<String> = Vec::new();
        match $w!(read_unidirectional_stream::<Parts, $class, _, ()>($io)) {
            Ok(None) => {
                log.push("no stream".to_string());
                (log, None)
            }
            Err(error) => {
                log.push(format!("start error {:?}", error.error_code()));
                (log, None)
            }
            Ok(Some(stream)) => match stream.transpose() {
                ReceivedStream::Unknown(unknown) => {
                    log.push(format!("unknown {}", unknown.stream().stream_type().get()));
                    if $discard {
                        $w!(unknown.into_stream().discard()).unwrap();
                        log.push("discarded".to_string());
                    }
                    (log, None)
                }
                ReceivedStream::Known(known) => match known.transpose() {
                    Coproduct::Inr(none) => match none.into_stream() {},
                    Coproduct::Inl(http3) => match http3.transpose() {
                        Http3UnidirectionalStream::Control(stream) => {
                            let mut control = stream.into_stream();
                            {
                                let mut frame = control.frame();
                                let payload = $w!(read_some(frame.payload(), 100))
                                    .map_err(|error| error.error_code());
                                log.push(format!(
                                    "control {} {:?}",
                                    frame.frame_type().value().get(),
                                    payload
                                ));
                            }
                            loop {
                                match $w!(control.next_frame()) {
                                    Ok(frame) => log.push(format!(
                                        "frame {}",
                                        frame.frame_type().value().get()
                                    )),
                                    Err(error) => {
                                        log.push(format!("error {:?}", error.error_code()));
                                        break;
                                    }
                                }
                            }
                            (log, Some(control.into_io()))
                        }
                        Http3UnidirectionalStream::Push(stream) => {
                            let mut push = stream.into_stream();
                            log.push(format!("push id {}", push.push_id().get().get().get()));
                            {
                                let frames = push.frames();
                                walk_stream!($w, frames, log, 100, false, usize::MAX);
                            }
                            (log, Some(push.into_parts().1.into_io()))
                        }
                        Http3UnidirectionalStream::QpackEncoder(stream) => {
                            let mut encoder = stream.into_stream();
                            loop {
                                let started = match $w!(next_critical_encoder(&mut encoder, 32, 32))
                                {
                                    Ok(started) => started,
                                    Err(error) => {
                                        log.push(format!("error {:?}", error.error_code()));
                                        break;
                                    }
                                };
                                match started {
                                    Started::SetDynamicTableCapacity(n) => {
                                        log.push(format!("capacity {n}"))
                                    }
                                    Started::Duplicate(n) => log.push(format!("duplicate {n}")),
                                    Started::InsertWithNameReference { name, value } => {
                                        let name = match name {
                                            NameReference::Static(index) => {
                                                index.entry().0.to_vec()
                                            }
                                            NameReference::Relative(n) => vec![n as u8],
                                        };
                                        let mut value = match $w!(value.open())
                                            .map(|read| read.value)
                                        {
                                            Ok(value) => value,
                                            Err(error) => {
                                                log.push(format!("error {:?}", error.error_code()));
                                                break;
                                            }
                                        };
                                        match drain_code!($w, value.source()) {
                                            Ok(bytes) => {
                                                value.finish().unwrap();
                                                log.push(format!("insert {name:?} = {bytes:?}"));
                                            }
                                            Err(code) => {
                                                log.push(format!("value error {code:?}"));
                                                break;
                                            }
                                        }
                                    }
                                    Started::InsertWithLiteralName(mut name) => {
                                        let bytes = match drain_code!($w, name.source()) {
                                            Ok(bytes) => bytes,
                                            Err(code) => {
                                                log.push(format!("name error {code:?}"));
                                                break;
                                            }
                                        };
                                        let mut value = match $w!(name.finish().unwrap().open())
                                            .map(|read| read.value)
                                        {
                                            Ok(value) => value,
                                            Err(error) => {
                                                log.push(format!("error {:?}", error.error_code()));
                                                break;
                                            }
                                        };
                                        match drain_code!($w, value.source()) {
                                            Ok(text) => {
                                                value.finish().unwrap();
                                                log.push(format!("insert {bytes:?} = {text:?}"));
                                            }
                                            Err(code) => {
                                                log.push(format!("value error {code:?}"));
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            (log, Some(encoder.into_io()))
                        }
                        Http3UnidirectionalStream::QpackDecoder(stream) => {
                            let mut decoder = stream.into_stream();
                            loop {
                                match $w!(next_critical_decoder(&mut decoder, 16)) {
                                    Ok(instruction) => log.push(format!("{instruction:?}")),
                                    Err(error) => {
                                        log.push(format!("error {:?}", error.error_code()));
                                        break;
                                    }
                                }
                            }
                            (log, Some(decoder.into_io()))
                        }
                    },
                },
            },
        }
    }};
}

macro_rules! start_pair {
    ($call:ident, $recv:ident, $class:ty) => {
        #[call(sync)]
        #[allow(unreachable_code)]
        async fn $call<F, A: ReceiverAccess<Family = F>>(io: &mut A, discard: bool) -> Outcome
        where
            F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
        {
            let (log, back) = start_log!(&mut *io, aw, $class, discard);
            match back {
                Some(mut back) => (log, Some(read_some(&mut back, 1000).await.unwrap())),
                None => (log, None),
            }
        }

        #[allow(unreachable_code)]
        fn $recv<F, I: ReceiverAccess<Family = F>>(io: I, discard: bool) -> (Vec<String>, Option<I>)
        where
            F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
        {
            start_log!(io, ru, $class, discard)
        }
    };
}

start_pair!(
    start_server_in_call,
    start_server_on_receiver,
    ServerInitiatedUnidirectional
);
start_pair!(
    start_client_in_call,
    start_client_on_receiver,
    ClientInitiatedUnidirectional
);

macro_rules! server {
    ($input:expr, $discard:expr) => {
        agree!(
            sync_start_server_in_call_unpin,
            start_server_in_call_unpin,
            start_server_on_receiver,
            $input,
            $discard
        )
    };
}

fn closed(line: &str) -> bool {
    // H3_CLOSED_CRITICAL_STREAM is 0x104.
    line.contains("VarInt(260)")
}

#[test]
fn unidirectional_streams_are_the_same_on_both_layers() {
    // Control: SETTINGS, a reserved frame, GOAWAY; the end is a failure.
    let (log, _) = server!(
        &[0x00, 0x04, 0x00, 0x21, 0x01, 0xaa, 0x07, 0x01, 0x04],
        false
    );
    assert_eq!(log[0], "control 4 Ok([])");
    assert_eq!(log.len(), 4, "{log:?}");
    assert!(closed(log.last().unwrap()), "{log:?}");
    // Push: Push ID 9, HEADERS "aa bb", then a byte of a head, cut.
    let (log, _) = server!(&[0x01, 0x09, 0x01, 0x02, 0xaa, 0xbb, 0x00], false);
    assert_eq!(log[0], "push id 9");
    assert_eq!(
        log[1],
        format!("{:?} Ok({:?})", Ty::Known(1), [0xaau8, 0xbb])
    );
    // QPACK encoder: capacity 5, duplicate 1, an insertion with a literal
    // name, then the end.
    let (log, _) = server!(b"\x02\x25\x01\x41x\x01y", false);
    assert_eq!(
        log[..3],
        ["capacity 5", "duplicate 1", "insert [120] = [121]"]
    );
    assert!(closed(log.last().unwrap()), "{log:?}");
    // QPACK encoder cut inside a name, and a name reference with a value.
    let (log, _) = server!(b"\x02\x42a", false);
    assert!(closed(log.last().unwrap()), "{log:?}");
    let (log, _) = server!(b"\x02\xc1\x02xy", false);
    assert!(log[0].ends_with(" = [120, 121]"), "{log:?}");
    // QPACK decoder: an increment, an acknowledgment, then the end.
    let (log, _) = server!(&[0x03, 0x05, 0x82], false);
    assert_eq!(log.len(), 3, "{log:?}");
    assert!(closed(log.last().unwrap()), "{log:?}");
    let (log, _) = server!(&[0x03, 0x3f], false);
    assert!(closed(log.last().unwrap()), "{log:?}");
}

#[test]
fn critical_streams_cut_anywhere_are_closed_on_the_receiver_layer() {
    for wire in [
        // Control: in the payload being skipped, in the next head.
        &[0x00, 0x04, 0x02, 0xaa][..],
        &[0x00, 0x04, 0x00, 0x40],
        // Encoder: in a name, in a value, in an integer.
        b"\x02\x41",
        b"\x02\x41x\x02y",
        &[0x02, 0x3f],
        // Decoder: in an integer, at a boundary.
        &[0x03, 0x7f],
        &[0x03],
    ] {
        let (log, _) = server!(wire, false);
        assert!(log.iter().any(|line| closed(line)), "{wire:?}: {log:?}");
    }
}

#[test]
fn unknown_and_rejected_streams_are_the_same_on_both_layers() {
    for discard in [false, true] {
        let (log, _) = server!(&[0x21, 0xde, 0xad], discard);
        assert_eq!(log[0], "unknown 33");
        assert_eq!(log.len(), 1 + usize::from(discard));
        let (log, _) = server!(&[0x40, 0x40, 0xde], discard);
        assert_eq!(log[0], "unknown 64");
    }
    let (log, _) = server!(&[], false);
    assert_eq!(log, ["no stream"]);
    // A type that is cut has no code.
    let (log, _) = server!(&[0x40], false);
    assert_eq!(log, ["start error None"]);
    // A control stream that ends before its first frame.
    let (log, _) = server!(&[0x00], false);
    assert!(closed(&log[0]), "{log:?}");
    // A client may not open a push stream.
    let (log, _) = agree!(
        sync_start_client_in_call_unpin,
        start_client_in_call_unpin,
        start_client_on_receiver,
        &[0x01, 0x00, 0x00],
        false
    );
    assert!(log[0].contains("VarInt(259)"), "{log:?}");
}

/// The start of a bidirectional stream a client opened, and, for a request
/// stream, its frames to the end.
macro_rules! bidi_log {
    ($io:expr, $w:ident, $discard:expr) => {{
        let mut log: Vec<String> = Vec::new();
        match $w!(read_bidirectional_stream::<
            Parts,
            ClientInitiatedBidirectional,
            _,
            (),
        >($io))
        {
            Ok(None) => {
                log.push("no stream".to_string());
                (log, None)
            }
            Err(error) => {
                log.push(format!("start error {:?}", error.error_code()));
                (log, None)
            }
            Ok(Some(ReceivedStream::Unknown(unknown))) => {
                log.push(format!("unknown {}", unknown.value().get()));
                if $discard {
                    $w!(unknown.discard()).unwrap();
                    log.push("discarded".to_string());
                }
                (log, None)
            }
            Ok(Some(ReceivedStream::Known(Coproduct::Inr(none)))) => match none {},
            Ok(Some(ReceivedStream::Known(Coproduct::Inl(mut request)))) => {
                walk_stream!($w, request, log, 100, false, usize::MAX);
                (log, Some(request.into_io()))
            }
        }
    }};
}

#[call(sync)]
async fn bidi_in_call<F, A: ReceiverAccess<Family = F>>(io: &mut A, discard: bool) -> Outcome
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
{
    let (log, back) = bidi_log!(&mut *io, aw, discard);
    match back {
        Some(mut back) => (log, Some(read_some(&mut back, 1000).await.unwrap())),
        None => (log, None),
    }
}

fn bidi_on_receiver<F, I: ReceiverAccess<Family = F>>(
    io: I,
    discard: bool,
) -> (Vec<String>, Option<I>)
where
    F: Skip<Count = usize, Metadata = ()> + Read<Error = Infallible, Metadata = ()>,
{
    bidi_log!(io, ru, discard)
}

#[test]
fn bidirectional_streams_are_the_same_on_both_layers() {
    for discard in [false, true] {
        // A reserved frame, then a request stream of two frames.
        let (log, rest) = agree!(
            sync_bidi_in_call_unpin,
            bidi_in_call_unpin,
            bidi_on_receiver,
            &[0x21, 0x01, 0xaa, 0x01, 0x02, 0xab, 0xcd, 0x00, 0x01, 0xee],
            discard
        );
        assert_eq!(log.last().unwrap(), "again: end");
        assert_eq!(rest, Some(vec![]));
        // An unknown stream.
        let (log, _) = agree!(
            sync_bidi_in_call_unpin,
            bidi_in_call_unpin,
            bidi_on_receiver,
            &[0x0a, 0x00, 0xaa],
            discard
        );
        assert_eq!(log[0], "unknown 10");
        // Cut starts, and an empty stream.
        for wire in [&[0x40][..], &[0x21, 0x02, 0xaa], &[0x01], &[]] {
            agree!(
                sync_bidi_in_call_unpin,
                bidi_in_call_unpin,
                bidi_on_receiver,
                wire,
                discard
            );
        }
    }
}

// Send.

fn assert_send<T: Send>(_: &T) {}

#[test]
fn the_streams_and_their_futures_are_send_when_the_receiver_is() {
    let input = [0x01, 0x01, b'a', 0x00, 0x00];
    let read = FrameStream::<Parts, RequestStreamKind, _>::read(
        ConstructedAccess::new(Dribble::new(&input, 1)),
        Role::Server,
    );
    assert_send(&read);
    let mut stream = run(read).0.unwrap().unwrap();
    assert_send(&stream);
    {
        let next = stream.next_frame();
        assert_send(&next);
    }
    {
        let next = stream.next_known_frame();
        assert_send(&next);
    }
    let start = read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _, ()>(
        ConstructedAccess::new(Dribble::new(&input, 1)),
    );
    assert_send(&start);
    let bidirectional = read_bidirectional_stream::<Parts, ClientInitiatedBidirectional, _, ()>(
        ConstructedAccess::new(Dribble::new(&input, 1)),
    );
    assert_send(&bidirectional);
}
