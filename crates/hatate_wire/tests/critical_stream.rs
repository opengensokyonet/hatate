#![feature(impl_trait_in_assoc_type)]
//! Critical streams do not end (RFC 9114 §6.2.1, RFC 9204 §4.2): the end of
//! the control stream and of the two QPACK streams, at a boundary or in the
//! middle of a frame or an instruction, is H3_CLOSED_CRITICAL_STREAM. The
//! streams that are not critical keep their ends.
mod common;

use bytes::{BufMut, Bytes};
use common::{
    Boom, Broken, ReadOnly, next_critical_decoder, next_critical_encoder, read_some, run,
};
use core::{
    convert::Infallible,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_qpack::encoder_instruction::{Started, literal::LiteralSource};
use hatate_wire::{
    Part, Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::GoawayId,
    settings::{
        codec::SettingParameter,
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream, ReceivedStream, class::ServerInitiatedUnidirectional,
        codec::read_unidirectional_stream, http3::Http3UnidirectionalStream,
        kind::RequestStreamKind,
    },
};
use hatate_wire_qpack::stream::{
    CriticalStream, CriticalStreamError, QpackDecoderStream, QpackEncoderStream,
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, ReadChunk, Skip, calls::ReadValue, prelude::*};
use sakuya_var_int::VarIntField;

type Parts = HList![Part];

const CLOSED: Option<ErrorCode> = Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM);

// CriticalStream itself.

/// The error of a [`Coded`] stream, which has a code of its own.
#[derive(Debug, PartialEq, Eq)]
struct Coded;

impl ErrorCodeOf<ErrorCode> for Coded {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(ErrorCode::H3_INTERNAL_ERROR)
    }
}

/// A stream whose every read, chunk read and skip fails with [`Coded`].
struct Failing;

nitori_call::family_receiver!(impl [] for Failing);

impl Read for Failing {
    type Error = Coded;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Coded))
    }
}

impl ReadChunk for Failing {
    type Chunk = Bytes;
    fn poll_read_chunk<'visit>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _maximum: NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<Bytes, ()>>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Coded))
    }
}

impl Skip for Failing {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Coded))
    }
}

/// Reads by bytes until the failure: what came, and the failure.
#[call(sync)]
async fn read_to_failure<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (Vec<u8>, CriticalStreamError<F::Error>) {
    let mut critical = io.compose(CriticalStream);
    let mut got = Vec::new();
    loop {
        let mut buffer = [0; 4];
        match critical.read(&mut &mut buffer[..]).await {
            Ok(segment) => {
                got.extend_from_slice(&buffer[..segment.map_or(0, |segment| segment.count.get())])
            }
            Err(error) => return (got, error),
        }
    }
}

/// Reads by chunks until the failure.
#[call(sync)]
async fn read_chunks_to_failure<F: ReadChunk<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (Vec<u8>, CriticalStreamError<F::Error>)
where
    <F as ReadChunk>::Chunk: AsRef<[u8]>,
{
    let mut critical = io.compose(CriticalStream);
    let mut got = Vec::new();
    loop {
        match critical.read_chunk(NonZeroUsize::new(3).unwrap()).await {
            Ok(Some(chunk)) => got.extend_from_slice(chunk.chunk.as_ref()),
            Ok(None) => panic!("a critical stream ended without a failure"),
            Err(error) => return (got, error),
        }
    }
}

/// Skips until the failure: how many bytes were skipped, and the failure.
#[call(sync)]
async fn skip_to_failure<F: Skip<Count = usize, Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (usize, CriticalStreamError<F::Error>) {
    let mut critical = io.compose(CriticalStream);
    let mut skipped = 0;
    loop {
        match critical.skip(3usize).await {
            Ok(Some(count)) => skipped += count,
            Ok(None) => panic!("a critical stream ended without a failure"),
            Err(error) => return (skipped, error),
        }
    }
}

#[test]
fn a_critical_stream_that_ends_is_closed_on_every_path() {
    let input = [1, 2, 3, 4, 5, 6, 7];

    let mut access = &input[..];
    let (got, error) = access.sync_read_to_failure_unpin();
    assert_eq!(got, input);
    assert!(matches!(error, CriticalStreamError::Closed), "{error:?}");
    assert_eq!(error.error_code(), CLOSED);

    let mut access = &input[..];
    let (got, error) = access.sync_read_chunks_to_failure_unpin();
    assert_eq!(got, input);
    assert!(matches!(error, CriticalStreamError::Closed), "{error:?}");
    assert_eq!(error.error_code(), CLOSED);

    let mut access = &input[..];
    let (skipped, error) = access.sync_skip_to_failure_unpin();
    assert_eq!(skipped, input.len());
    assert!(matches!(error, CriticalStreamError::Closed), "{error:?}");
    assert_eq!(error.error_code(), CLOSED);

    // A stream that cannot skip, read by chunks and by bytes, suspending
    // before each read.
    let mut host = ReadOnly::new(&input, 2);
    let ((got, error), pending) = run(host.read_to_failure_unpin());
    assert!(pending > 0);
    assert_eq!(got, input);
    assert!(matches!(error, CriticalStreamError::Closed), "{error:?}");
    let mut host = ReadOnly::new(&input, 2);
    let ((got, error), _) = run(host.read_chunks_to_failure_unpin());
    assert_eq!(got, input);
    assert!(matches!(error, CriticalStreamError::Closed), "{error:?}");
}

/// Reads a little by each path, none of it to the end.
#[call(sync)]
async fn read_before_the_end<
    F: ReadChunk<Chunk = &'static [u8], Error = Infallible, Metadata = ()>
        + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> (usize, Vec<u8>, usize, usize) {
    let mut critical = io.compose(CriticalStream);
    let mut buffer = [0; 3];
    let first = critical
        .read(&mut &mut buffer[..])
        .await
        .unwrap()
        .map_or(0, |segment| segment.count.get());
    assert_eq!(buffer, [1, 2, 3]);
    let chunk = critical
        .read_chunk(NonZeroUsize::new(2).unwrap())
        .await
        .unwrap()
        .unwrap()
        .chunk;
    let skipped = critical.skip(1usize).await.unwrap().unwrap();
    let mut rest = [0; 5];
    let last = critical
        .read(&mut &mut rest[..])
        .await
        .unwrap()
        .map_or(0, |segment| segment.count.get());
    assert_eq!(rest[..last], [7]);
    (first, chunk.to_vec(), skipped, last)
}

#[test]
fn a_critical_stream_that_has_not_ended_reads_as_it_is() {
    let input: &'static [u8] = &[1, 2, 3, 4, 5, 6, 7];
    let mut access = input;
    assert_eq!(
        access.sync_read_before_the_end_unpin(),
        (3, vec![4, 5], 1, 1)
    );
}

/// An empty destination reads nothing and is not the end.
#[call(sync)]
async fn read_nothing<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> Option<usize> {
    let mut critical = io.compose(CriticalStream);
    critical
        .read(&mut &mut [0u8; 0][..])
        .await
        .ok()
        .map(|segment| segment.map_or(0, |segment| segment.count.get()))
}

#[test]
fn an_empty_destination_is_not_the_end_of_a_critical_stream() {
    let mut access = &[][..];
    assert_eq!(access.sync_read_nothing_unpin(), Some(0));
}

#[test]
fn a_failure_of_the_stream_is_the_hosts_with_its_own_code() {
    let mut host = Failing;
    let (got, error) = host.sync_read_to_failure_unpin();
    assert!(got.is_empty());
    assert!(
        matches!(error, CriticalStreamError::Host { source: Coded }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_INTERNAL_ERROR));

    let mut host = Failing;
    let (_, error) = host.sync_read_chunks_to_failure_unpin();
    assert!(matches!(error, CriticalStreamError::Host { source: Coded }));
    assert_eq!(error.error_code(), Some(ErrorCode::H3_INTERNAL_ERROR));

    let mut host = Failing;
    let (skipped, error) = host.sync_skip_to_failure_unpin();
    assert_eq!(skipped, 0);
    assert!(matches!(error, CriticalStreamError::Host { source: Coded }));
    assert_eq!(error.error_code(), Some(ErrorCode::H3_INTERNAL_ERROR));

    // A host with no code of its own gives none.
    let mut host = Broken;
    let (_, error) = host.sync_read_to_failure_unpin();
    assert!(matches!(error, CriticalStreamError::Host { source: Boom }));
    assert_eq!(error.error_code(), None);
}

// The control stream.

/// What to read from the control stream after its first frame.
#[derive(Clone, Copy, Debug)]
enum Then {
    /// Frame after frame.
    Frames,
    /// The first frame is SETTINGS: its settings.
    Settings,
    /// The second frame is GOAWAY: its reader.
    Goaway,
}

/// Reads a control stream the server opened until something fails, and
/// gives the code of the failure: of the start of the stream when its first
/// frame cannot be read, else of the failure of `then`.
#[call(sync)]
async fn control_failure<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    then: Then,
) -> Option<ErrorCode> {
    let stream =
        match read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _, ()>(&mut *io)
            .await
        {
            Ok(stream) => stream.expect("a type"),
            Err(error) => return error.error_code(),
        };
    let ReceivedStream::Known(known) = stream.transpose() else {
        panic!("not a stream of a part");
    };
    let Coproduct::Inl(http3) = known.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Control(control) = http3.transpose() else {
        panic!("not a control stream");
    };
    let mut control = control.into_stream();
    if let Then::Settings = then {
        let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
        let mut frame = control.frame();
        loop {
            assert!(frame.payload().remaining() > 0, "the settings ended");
            let parameter = match frame.payload().decode::<SettingParameter, _>().await {
                Ok(parameter) => parameter,
                Err(error) => return error.error_code(),
            };
            if let Err(error) = settings.insert(parameter) {
                return error.error_code();
            }
        }
    }
    loop {
        match control.next_frame().await {
            Ok(mut frame) => {
                if let Then::Goaway = then {
                    match frame
                        .payload()
                        .decode_to_end::<ReadValue<VarIntField<GoawayId>, ()>, _>()
                        .await
                    {
                        Ok(_) => panic!("a whole GOAWAY"),
                        Err(error) => return error.error_code(),
                    }
                }
            }
            Err(error) => return error.error_code(),
        }
    }
}

fn control(wire: &[u8], then: Then) -> Option<ErrorCode> {
    let mut input = wire;
    let code = input.sync_control_failure_unpin(then);
    // The same, a byte at a time with a suspension before each read.
    let mut dribbled = common::Dribble::new(wire, 1);
    let (again, _) = run(dribbled.control_failure_unpin(then));
    assert_eq!(code, again, "{wire:?}");
    code
}

#[test]
fn the_control_stream_ending_at_a_frame_boundary_is_closed() {
    for wire in [
        // SETTINGS, empty, then the end.
        &[0x00, 0x04, 0x00][..],
        // SETTINGS, an unknown frame and a GOAWAY, then the end.
        &[0x00, 0x04, 0x00, 0x21, 0x01, 0xaa, 0x07, 0x01, 0x00],
    ] {
        assert_eq!(control(wire, Then::Frames), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_control_stream_ending_in_a_frame_head_is_closed() {
    for wire in [
        // The type of the next frame, cut inside its two bytes.
        &[0x00, 0x04, 0x00, 0x40][..],
        // The type, then no Length.
        &[0x00, 0x04, 0x00, 0x07],
        // The Length, cut inside its two bytes.
        &[0x00, 0x04, 0x00, 0x07, 0x40],
    ] {
        assert_eq!(control(wire, Then::Frames), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_control_stream_ending_in_a_payload_skipped_is_closed() {
    // An unknown frame whose payload is cut: the next frame is read past it.
    assert_eq!(
        control(&[0x00, 0x04, 0x00, 0x21, 0x05, 0xaa], Then::Frames),
        CLOSED
    );
    // The payload of the first frame, which is skipped to get to the next.
    assert_eq!(control(&[0x00, 0x04, 0x03, 0x01], Then::Frames), CLOSED);
}

#[test]
fn the_control_stream_ending_in_the_settings_is_closed_for_the_reader_of_the_payload() {
    for wire in [
        // A payload of three bytes, one there.
        &[0x00, 0x04, 0x03, 0x01][..],
        // A setting whose value is cut: the identifier and the first of two bytes.
        &[0x00, 0x04, 0x04, 0x01, 0x40],
        // The identifier cut.
        &[0x00, 0x04, 0x04, 0x40],
    ] {
        assert_eq!(control(wire, Then::Settings), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_control_stream_ending_in_a_goaway_is_closed_for_the_reader_of_the_payload() {
    for wire in [
        // GOAWAY with a payload of one byte, none there.
        &[0x00, 0x04, 0x00, 0x07, 0x01][..],
        // A Stream ID in two bytes, one there.
        &[0x00, 0x04, 0x00, 0x07, 0x02, 0x40],
    ] {
        assert_eq!(control(wire, Then::Goaway), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_control_stream_ending_before_its_first_frame_is_closed() {
    for wire in [
        // Only the type of the stream.
        &[0x00][..],
        // The first frame's type cut, and its Length missing or cut.
        &[0x00, 0x40],
        &[0x00, 0x04],
        &[0x00, 0x04, 0x40],
    ] {
        assert_eq!(control(wire, Then::Frames), CLOSED, "{wire:?}");
    }
}

// The QPACK streams.

/// Reads the encoder stream's instructions until one fails, and gives the
/// code of the failure. `part` says how far into an insertion to read.
#[derive(Clone, Copy, Debug)]
enum Reach {
    /// Only the start of each instruction.
    Start,
    /// A literal name, read to its end or the failure.
    Name,
    /// A value, header and bytes.
    Value,
}

/// Reads a literal's source to its end: `Err` with the code of its failure.
macro_rules! drain {
    ($source:expr) => {
        match $source {
            LiteralSource::Raw(mut source) => read_some(&mut source, 1000)
                .await
                .map(drop)
                .map_err(|error| error.error_code()),
            LiteralSource::Huffman(mut source) => read_some(&mut source, 1000)
                .await
                .map(drop)
                .map_err(|error| error.error_code()),
        }
    };
}

#[call(sync)]
async fn encoder_failure<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    reach: Reach,
) -> Option<ErrorCode> {
    let mut stream = QpackEncoderStream::new(&mut *io);
    loop {
        let started = match next_critical_encoder(&mut stream, 1000, 1000).await {
            Ok(started) => started,
            Err(error) => return error.error_code(),
        };
        let value = match started {
            Started::SetDynamicTableCapacity(_) | Started::Duplicate(_) => continue,
            Started::InsertWithNameReference { value, .. } => value,
            Started::InsertWithLiteralName(mut name) => {
                if let Reach::Start = reach {
                    continue;
                }
                if let Err(code) = drain!(name.source()) {
                    return code;
                }
                name.finish().expect("a whole name")
            }
        };
        if let Reach::Start | Reach::Name = reach {
            continue;
        }
        let mut value = match value.open().await.map(|read| read.value) {
            Ok(value) => value,
            Err(error) => return error.error_code(),
        };
        if let Err(code) = drain!(value.source()) {
            return code;
        }
        value.finish().expect("a whole value");
    }
}

fn encoder(wire: &[u8], reach: Reach) -> Option<ErrorCode> {
    let mut input = wire;
    let code = input.sync_encoder_failure_unpin(reach);
    let mut dribbled = common::Dribble::new(wire, 1);
    let (again, _) = run(dribbled.encoder_failure_unpin(reach));
    assert_eq!(code, again, "{wire:?}");
    code
}

#[test]
fn the_encoder_stream_ending_at_an_instruction_boundary_is_closed() {
    assert_eq!(encoder(&[], Reach::Start), CLOSED);
    // Set Dynamic Table Capacity 5, Duplicate 1, then the end.
    assert_eq!(encoder(&[0x25, 0x01], Reach::Start), CLOSED);
    // A whole insertion with a name reference, then the end.
    assert_eq!(encoder(&[0xc1, 0x02, b'x', b'y'], Reach::Value), CLOSED);
    // A whole insertion with a literal name, then the end.
    assert_eq!(
        encoder(&[0x42, b'a', b'b', 0x02, b'x', b'y'], Reach::Value),
        CLOSED
    );
}

#[test]
fn the_encoder_stream_ending_at_the_start_of_an_instruction_is_closed() {
    for wire in [
        // Set Dynamic Table Capacity, Duplicate and the two insertions, each
        // with an integer that goes on, then the end.
        &[0x3f][..],
        &[0x1f],
        &[0xbf],
        &[0x7f],
        &[0x3f, 0x80],
    ] {
        assert_eq!(encoder(wire, Reach::Start), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_encoder_stream_ending_in_a_literal_name_is_closed() {
    for wire in [
        // Raw: a name of two bytes, one there; and none there.
        &[0x42, b'a'][..],
        &[0x42],
        // Huffman: a name of two bytes, one there; and none there.
        &[0x62, 0x1f],
        &[0x62],
        // A name length that goes on.
        &[0x5f],
    ] {
        assert_eq!(encoder(wire, Reach::Name), CLOSED, "{wire:?}");
    }
}

#[test]
fn the_encoder_stream_ending_in_a_value_is_closed() {
    for wire in [
        // After a literal name: no value header, a header that goes on, a
        // raw value of two bytes with one there, a Huffman value of two
        // bytes with one there.
        &[0x42, b'a', b'b'][..],
        &[0x42, b'a', b'b', 0x7f],
        &[0x42, b'a', b'b', 0x02, b'x'],
        &[0x42, b'a', b'b', 0x82, 0x1f],
        // After a name reference, the same.
        &[0xc1][..],
        &[0xc1, 0x7f],
        &[0xc1, 0x02, b'x'],
        &[0xc1, 0x82, 0x1f],
        // Raw and Huffman values of one whole byte, cut after a whole
        // instruction: ends at the boundary, and so also closed.
        &[0xc1, 0x01, b'x'],
        &[0xc1, 0x81, 0x1f],
    ] {
        assert_eq!(encoder(wire, Reach::Value), CLOSED, "{wire:?}");
    }
}

/// Reads the decoder stream's instructions until one fails.
#[call(sync)]
async fn decoder_failure<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> (usize, Option<ErrorCode>) {
    let mut stream = QpackDecoderStream::new(&mut *io);
    let mut count = 0;
    loop {
        match next_critical_decoder(&mut stream, 1000).await {
            Ok(_) => count += 1,
            Err(error) => return (count, error.error_code()),
        }
    }
}

#[test]
fn the_decoder_stream_ending_is_closed_at_a_boundary_and_inside_a_number() {
    for (wire, whole) in [
        (&[][..], 0),
        // Insert Count Increment 5, Stream Cancellation of stream 1, Section
        // Acknowledgment of stream 2, then the end.
        (&[0x05, 0x41, 0x82], 3),
        // A number that goes on, in each of the three instructions, and after
        // a continuation byte.
        (&[0x3f], 0),
        (&[0x7f], 0),
        (&[0xff], 0),
        (&[0x05, 0x3f, 0x80], 1),
    ] {
        let mut input = wire;
        assert_eq!(
            input.sync_decoder_failure_unpin(),
            (whole, CLOSED),
            "{wire:?}"
        );
        let mut dribbled = common::Dribble::new(wire, 1);
        let (found, _) = run(dribbled.decoder_failure_unpin());
        assert_eq!(found, (whole, CLOSED), "{wire:?}");
    }
}

// Streams that are not critical.

/// Reads every frame of a request stream and of a push stream, and gives
/// how reading them ended: `Ok(count)` at the end of the stream after
/// `count` frames, or the code of the failure.
#[call(sync)]
async fn request_ends<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> Result<usize, Option<ErrorCode>> {
    let Some(mut stream) = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .map_err(|error| error.error_code())?
    else {
        return Ok(0);
    };
    let mut count = 1;
    loop {
        match stream.next_frame().await {
            Ok(Some(_)) => count += 1,
            Ok(None) => return Ok(count),
            Err(error) => return Err(error.error_code()),
        }
    }
}

#[call(sync)]
async fn push_ends<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> Result<usize, Option<ErrorCode>> {
    let stream =
        match read_unidirectional_stream::<Parts, ServerInitiatedUnidirectional, _, ()>(&mut *io)
            .await
        {
            Ok(stream) => stream.expect("a type"),
            Err(error) => return Err(error.error_code()),
        };
    let ReceivedStream::Known(known) = stream.transpose() else {
        panic!("not a stream of a part");
    };
    let Coproduct::Inl(http3) = known.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Push(push) = http3.transpose() else {
        panic!("not a push stream");
    };
    let mut push = push.into_stream();
    let frames = push.frames();
    let mut count = 1;
    loop {
        match frames.next_frame().await {
            Ok(Some(_)) => count += 1,
            Ok(None) => return Ok(count),
            Err(error) => return Err(error.error_code()),
        }
    }
}

#[test]
fn a_request_stream_keeps_its_end() {
    // HEADERS with an empty payload and DATA with one byte, then the end.
    let wire = [0x01, 0x00, 0x00, 0x01, 0xaa];
    let mut input = &wire[..];
    assert_eq!(input.sync_request_ends_unpin(), Ok(2));
    // No frame at all.
    let mut input = &[][..];
    assert_eq!(input.sync_request_ends_unpin(), Ok(0));
    // Cut in a payload that is skipped, and in the head of the next frame.
    for wire in [
        &[0x01, 0x02, 0xaa][..],
        &[0x01, 0x00, 0x00, 0x05],
        &[0x01, 0x00, 0x40],
    ] {
        let mut input = wire;
        assert_eq!(
            input.sync_request_ends_unpin(),
            Err(Some(ErrorCode::H3_FRAME_ERROR)),
            "{wire:?}"
        );
    }
}

#[test]
fn a_push_stream_keeps_its_end() {
    // Type 0x01, Push ID 0, a HEADERS frame and a DATA frame, then the end.
    let wire = [0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0xaa];
    let mut input = &wire[..];
    assert_eq!(input.sync_push_ends_unpin(), Ok(2));
    for wire in [
        &[0x01, 0x00, 0x01, 0x02, 0xaa][..],
        &[0x01, 0x00, 0x01, 0x00, 0x00],
        &[0x01, 0x00, 0x01, 0x00, 0x40],
    ] {
        let mut input = wire;
        assert_eq!(
            input.sync_push_ends_unpin(),
            Err(Some(ErrorCode::H3_FRAME_ERROR)),
            "{wire:?}"
        );
    }
}
