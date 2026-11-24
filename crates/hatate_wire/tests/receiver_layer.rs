#![feature(impl_trait_in_assoc_type)]
//! The streams that hold their access, on the two layers: inside an
//! operation, where the access is the operation's, and outside any
//! operation, where it is a `ConstructedAccess` on a receiver, held by value, by
//! `&mut` or pinned, and the stream is kept across any number of separate
//! polls. The same script runs on both, with every step its own poll loop on
//! the receiver layer, and what it sees must agree: frame streams of the three
//! kinds, the constructors of unidirectional and bidirectional streams, the
//! critical streams, a read dropped in the middle, and whether the streams
//! and their futures are Send.
mod common;

use common::{Dribble, Ty, read_some, run, ty};
use core::{
    convert::Infallible,
    fmt::Debug,
    future::Future,
    marker::PhantomPinned,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_qpack::encoder_instruction::{NameReference, Started, literal::LiteralSource};
use hatate_wire::{
    Part, Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::set::FrameSetOn,
    stream::{
        FrameStream, ReceivedStream, TypedStream as _,
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedUnidirectional,
        },
        codec::{read_bidirectional_stream, read_unidirectional_stream},
        http3::Http3UnidirectionalStream,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind, StreamKind},
    },
};
use nitori_call::{ConstructedAccess, ReceiverAccess, call};
use nitori_io::{Read, Skip};

type Parts = HList![Part];

/// A receiver that is not Unpin: at most three bytes per read or skip.
struct Fixed<'a> {
    input: &'a [u8],
    _pinned: PhantomPinned,
}

impl<'a> Fixed<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            _pinned: PhantomPinned,
        }
    }
    fn rest(&self) -> &'a [u8] {
        self.input
    }
}

nitori_call::family_receiver!(impl ['a] for Fixed<'a>);

impl Read for Fixed<'_> {
    type Error = Infallible;
    fn poll_read<'visit, B: bytes::BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        // SAFETY: nothing is moved out of the pinned receiver.
        let this = unsafe { host.get_pin_mut().get_unchecked_mut() };
        let count = 3.min(this.input.len()).min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(count))
    }
}

impl Skip for Fixed<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        // SAFETY: as above.
        let this = unsafe { host.get_pin_mut().get_unchecked_mut() };
        let allowed = nitori_io::Min::min(maximum, 3usize);
        if allowed != 0 && this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = allowed.min(this.input.len());
        this.input = &this.input[count..];
        Poll::Ready(Ok(Some(count)))
    }
}

type Outcome = (Vec<String>, Option<Vec<u8>>);

/// Runs a script on every layer and every way of holding a receiver, and
/// checks that all agree with the call layer on a slice. The call-layer
/// function ends with the bytes the access has left (if the stream was
/// given back); the receiver-layer function gives the access back.
macro_rules! agree {
    ($sync:ident, $suspended:ident, $recv:ident, $input:expr $(, $arg:expr)*) => {{
        let input: &[u8] = $input;
        let mut slice = input;
        let expected: Outcome = slice.$sync($($arg),*);
        let mut host = Dribble::new(input, 1);
        let (dribbled, _) = run(host.$suspended($($arg),*));
        assert_eq!(dribbled, expected, "call layer, suspended");
        let check = |way: &str, got: Outcome| {
            assert_eq!(got.0, expected.0, "{way}");
            if expected.1.is_some() {
                assert_eq!(got.1, expected.1, "{way}");
            }
        };
        let (log, io) = $recv(ConstructedAccess::new(Dribble::new(input, 1)) $(, $arg)*);
        check("by value", (log, io.map(|io| io.into_inner().rest().to_vec())));
        let (log, io) = $recv(ConstructedAccess::new(input) $(, $arg)*);
        check("a slice by value", (log, io.map(|io| io.into_inner().to_vec())));
        let mut borrowed = input;
        let (log, _) = $recv(ConstructedAccess::new(&mut borrowed) $(, $arg)*);

        check("borrowed", (log, Some(borrowed.to_vec())));
        let (log, io) = $recv(ConstructedAccess::new(Box::pin(Fixed::new(input))) $(, $arg)*);
        check("pinned in a box", (log, io.map(|io| io.into_inner().rest().to_vec())));
        let mut pinned = pin!(Fixed::new(input));
        let (log, _) = $recv(ConstructedAccess::new(pinned.as_mut()) $(, $arg)*);

        check("pinned on the stack", (log, Some(pinned.rest().to_vec())));
        expected
    }};
}

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

/// Whether a step ended the stream (end or failure), and how, as text.
fn step_text<T, E: ErrorCodeOf<ErrorCode> + Debug>(result: Result<Option<T>, E>) -> (bool, String) {
    match result {
        Ok(Some(_)) => (false, "frame".to_string()),
        Ok(None) => (true, "end".to_string()),
        Err(error) => (true, format!("error {:?} {error:?}", error.error_code())),
    }
}

/// From the current frame of `$stream`: its type and at most `$take` payload
/// bytes, then the next frame (`$known` skips reserved and unknown), until
/// `$stop` frames were seen or the stream ended or failed; the step after
/// that is logged once more.
macro_rules! walk_stream {
    ($w:ident, $stream:ident, $log:ident, $take:expr, $known:expr, $stop:expr) => {{
        let mut seen = 0usize;
        loop {
            {
                let mut frame = $stream.frame();
                let payload = $w!(read_some(frame.payload(), $take))
                    .map_err(|error| format!("payload error {:?}", error.error_code()));
                $log.push(format!("{:?} {:?}", ty(frame.frame_type()), payload));
            }
            seen += 1;
            if seen >= $stop {
                break;
            }
            let (over, text) = if $known {
                step_text($w!($stream.next_known_frame()))
            } else {
                step_text($w!($stream.next_frame()))
            };
            if over {
                $log.push(text);
                let (_, again) = step_text($w!($stream.next_frame()));
                $log.push(format!("again: {again}"));
                break;
            }
        }
    }};
}

macro_rules! walk_log {
    ($io:expr, $w:ident, $kind:ty, $role:expr, $take:expr, $known:expr, $stop:expr) => {{
        let mut log: Vec<String> = Vec::new();
        match $w!(FrameStream::<Parts, $kind, _>::read($io, $role)) {
            Ok(Some(mut stream)) => {
                walk_stream!($w, stream, log, $take, $known, $stop);
                (log, Some(stream.into_io()))
            }
            Ok(None) => {
                log.push("no frames".to_string());
                (log, None)
            }
            Err(error) => {
                log.push(format!("head error {:?}", error.error_code()));
                (log, None)
            }
        }
    }};
}

#[call(sync)]
async fn walk_in_call<K: StreamKind, F, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    _kind: K,
    role: Role,
    take: usize,
    known: bool,
    stop: usize,
) -> Outcome
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
    Parts: FrameSetOn<K>,
{
    let (log, back) = walk_log!(&mut *io, aw, K, role, take, known, stop);
    match back {
        Some(mut back) => (log, Some(read_some(&mut back, 1000).await.unwrap())),
        None => (log, None),
    }
}

fn walk_on_receiver<K: StreamKind, F, I: ReceiverAccess<Family = F>>(
    io: I,
    _kind: K,
    role: Role,
    take: usize,
    known: bool,
    stop: usize,
) -> (Vec<String>, Option<I>)
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
    Parts: FrameSetOn<K>,
{
    walk_log!(io, ru, K, role, take, known, stop)
}

fn walk<K: StreamKind + Copy>(kind: K, role: Role, input: &[u8]) -> Outcome
where
    Parts: FrameSetOn<K>,
{
    let mut first = None;
    for take in [0, 2, 100] {
        for known in [false, true] {
            for stop in [1, 2, usize::MAX] {
                let result = agree!(
                    sync_walk_in_call_unpin,
                    walk_in_call_unpin,
                    walk_on_receiver,
                    input,
                    kind,
                    role,
                    take,
                    known,
                    stop
                );
                if (take, known, stop) == (2, false, usize::MAX) {
                    first = Some(result);
                }
            }
        }
    }
    first.unwrap()
}

#[test]
fn a_request_stream_is_the_same_on_both_layers() {
    // HEADERS "abc"; an unknown type 0x33 with "d"; a reserved type 0x21;
    // DATA "hello".
    let input = [
        &[0x01, 0x03][..],
        b"abc",
        &[0x33, 0x01, b'd'],
        &[0x40, 0x21, 0x00],
        &[0x00, 0x05],
        b"hello",
    ]
    .concat();
    let (log, rest) = walk(RequestStreamKind, Role::Server, &input);
    assert_eq!(
        log,
        [
            format!("{:?} Ok({:?})", Ty::Known(1), b"ab"),
            format!("{:?} Ok({:?})", Ty::Unknown(0x33), b"d"),
            format!("{:?} Ok({:?})", Ty::Reserved(0x21), b""),
            format!("{:?} Ok({:?})", Ty::Known(0), b"he"),
            "end".to_string(),
            "again: end".to_string(),
        ]
    );
    // The stream ended at a frame boundary: nothing is left.
    assert_eq!(rest, Some(vec![]));
}

#[test]
fn a_control_stream_and_a_push_stream_are_the_same_on_both_layers() {
    // SETTINGS, a reserved frame, GOAWAY 4.
    let control = [0x04, 0x00, 0x21, 0x01, 0xaa, 0x07, 0x01, 0x04];
    let (log, rest) = walk(ControlStreamKind, Role::Client, &control);
    assert_eq!(log.last().unwrap(), "again: end");
    assert_eq!(rest, Some(vec![]));
    // HEADERS "ab", DATA "c".
    let push = [0x01, 0x02, b'a', b'b', 0x00, 0x01, b'c'];
    let (log, rest) = walk(PushStreamKind, Role::Client, &push);
    assert_eq!(log.last().unwrap(), "again: end");
    assert_eq!(rest, Some(vec![]));
}

#[test]
fn a_stream_that_is_not_read_to_its_end_gives_back_the_access_where_it_is() {
    // One payload byte of HEADERS "abcd" read, then the access is given
    // back: the rest of the payload and the next frame are still there.
    let input = [0x01, 0x04, b'a', b'b', b'c', b'd', 0x00, 0x00];
    let (log, rest) = agree!(
        sync_walk_in_call_unpin,
        walk_in_call_unpin,
        walk_on_receiver,
        &input,
        RequestStreamKind,
        Role::Server,
        1,
        false,
        1
    );
    assert_eq!(log, [format!("{:?} Ok({:?})", Ty::Known(1), b"a")]);
    assert_eq!(rest, Some(vec![b'b', b'c', b'd', 0x00, 0x00]));
}

#[test]
fn failures_are_the_same_on_both_layers() {
    for input in [
        // The payload cut while it is skipped.
        &[0x01, 0x03, b'a'][..],
        // The head of the next frame cut.
        &[0x01, 0x00, 0x40],
        // A type of HTTP/2.
        &[0x01, 0x00, 0x06],
        // SETTINGS, which a request stream does not have.
        &[0x01, 0x00, 0x04, 0x00],
        // The head of the first frame cut, and no frame.
        &[0x40],
        &[],
    ] {
        let (log, _) = walk(RequestStreamKind, Role::Server, input);
        assert!(!log.is_empty(), "{input:?}");
    }
    let (log, _) = walk(RequestStreamKind, Role::Server, &[0x01, 0x00, 0x06]);
    assert!(
        log.iter()
            .any(|line| line.contains("H3_FRAME_UNEXPECTED") || line.contains("Some(")),
        "{log:?}"
    );
}

// A read of the next frame dropped in the middle.

/// DATA with a payload of six bytes, then HEADERS with a Type of two bytes
/// and a payload of one, then a byte that no frame owns.
const FRAMES: [u8; 13] = [0x00, 0x06, 1, 2, 3, 4, 5, 6, 0x40, 0x01, 0x01, 0xaa, 0xbb];

fn poll_then_drop_frame<T, E>(
    future: impl Future<Output = Result<Option<T>, E>>,
    polls: usize,
) -> bool {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..polls {
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            return matches!(result, Ok(Some(_)));
        }
    }
    false
}

macro_rules! dropped_log {
    ($io:expr, $w:ident, $drops:expr) => {{
        let mut log: Vec<String> = Vec::new();
        let mut stream = $w!(FrameStream::<Parts, RequestStreamKind, _>::read(
            $io,
            Role::Server
        ))
        .unwrap()
        .unwrap();
        let mut completed = false;
        for polls in $drops {
            if poll_then_drop_frame(stream.next_frame(), polls) {
                completed = true;
                break;
            }
        }
        let left = stream.frame().into_payload().into_parts().1.remaining();
        log.push(format!("completed {completed}, payload left {left}"));
        let step = if completed {
            format!("reached {:?}", ty(stream.frame().frame_type()))
        } else {
            match $w!(stream.next_frame()) {
                Ok(Some(frame)) => format!("frame {:?}", ty(frame.frame_type())),
                Ok(None) => "end".to_string(),
                Err(error) => format!("error {:?} {error:?}", error.error_code()),
            }
        };
        log.push(step);
        (log, Some(stream.into_io()))
    }};
}

#[call(sync)]
async fn dropped_in_call<F, A: ReceiverAccess<Family = F>>(io: &mut A, drops: Vec<usize>) -> Outcome
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
{
    let (log, back) = dropped_log!(&mut *io, aw, drops);
    let mut back = back.unwrap();
    (log, Some(read_some(&mut back, 1000).await.unwrap()))
}

fn dropped_on_receiver<F, I: ReceiverAccess<Family = F>>(
    io: I,
    drops: Vec<usize>,
) -> (Vec<String>, Option<I>)
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
{
    dropped_log!(io, ru, drops)
}

#[test]
fn next_frame_dropped_in_the_middle_behaves_as_in_a_call() {
    let mut interrupted = 0;
    let mut resumed = 0;
    for first in 0..14 {
        for drops in [vec![first], vec![first, 3]] {
            // Only hosts that suspend, since a drop is a number of polls.
            let mut host = Dribble::new(&FRAMES, 1);
            let expected = run(host.dropped_in_call_unpin(drops.clone())).0;
            let (log, io) = dropped_on_receiver(
                ConstructedAccess::new(Dribble::new(&FRAMES, 1)),
                drops.clone(),
            );
            let rest = io.map(|io| io.into_inner().rest().to_vec());
            assert_eq!((log, rest), expected, "{drops:?}");
            let mut borrowed = Dribble::new(&FRAMES, 1);
            let (log, _) =
                dropped_on_receiver(ConstructedAccess::new(&mut borrowed), drops.clone());

            assert_eq!(log, expected.0, "{drops:?}");
            assert_eq!(Some(borrowed.rest().to_vec()), expected.1, "{drops:?}");
            let log = expected.0;
            if log[1].contains("Interrupted") {
                interrupted += 1;
            } else if log[1].starts_with("frame") || log[1].starts_with("reached") {
                resumed += 1;
            }
        }
    }
    // Both outcomes occur: dropped while skipping, and while reading a head.
    assert!(interrupted > 0 && resumed > 0, "{interrupted} {resumed}");
}

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
        match $w!(read_unidirectional_stream::<Parts, $class, _>($io)) {
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
                                let started = match $w!(encoder.next_instruction(32, 32)) {
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
                                        let mut value = match $w!(value.open()) {
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
                                        let mut value = match $w!(name.finish().unwrap().open()) {
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
                                match $w!(decoder.next_instruction(16)) {
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
            F: Skip<Count = usize> + Read<Error = Infallible>,
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
            F: Skip<Count = usize> + Read<Error = Infallible>,
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
    F: Skip<Count = usize> + Read<Error = Infallible>,
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
    F: Skip<Count = usize> + Read<Error = Infallible>,
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
    let start = read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _>(
        ConstructedAccess::new(Dribble::new(&input, 1)),
    );
    assert_send(&start);
    let bidirectional = read_bidirectional_stream::<Parts, ClientInitiatedBidirectional, _>(
        ConstructedAccess::new(Dribble::new(&input, 1)),
    );
    assert_send(&bidirectional);
}
