#![feature(impl_trait_in_assoc_type)]
//! Streams that carry frames, at both layers: a `FrameStream` composed onto
//! an access inside a call, and one kept with a receiver
//! (`ComposedReceiver`). Each stream is read both ways, and once more one
//! byte at a time with a suspension before every read, and the results must
//! agree.
mod common;

use common::{Dribble, run};
use core::convert::Infallible;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        Frame, FrameType, Http3FrameType,
        codec::{
            NextFrameError, ReadFrameError, ReadReceivedFrameError, WriteFrameExt as _, read_frame,
            read_received_frame,
        },
        set::FrameSet,
    },
    settings::{
        Setting,
        codec::ReadSettingExt as _,
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream, FrameStreamInfo, UnidirectionalStream,
        codec::{ReadUnidirectionalStreamError, read_unidirectional_stream},
    },
    stream_type::{Http3StreamType, StreamType, StreamTypeSet},
};
use hatate_wire_qpack::QpackStreamType;
use nitori_call::{ComposedReceiver, ReceiverAccess, call};
use nitori_io::{ExactLen, Read, Skip, Write, prelude::*};

type Parts = HList![hatate_wire::Part];
type FrameTypeValue = <Parts as FrameSet>::TypeValue;
type StreamTypeValue = <Parts as StreamTypeSet>::TypeValue;

/// What was seen of one frame: its type, and the payload bytes read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    frame_type: FrameType<FrameTypeValue>,
    payload: Vec<u8>,
}

/// How reading frames ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum End {
    /// At a frame boundary.
    Clean,
    /// With a failure: its code, and which failure.
    Failed(Option<ErrorCode>, Failure),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Failure {
    Type,
    Length,
    Http2Type,
    NotAllowedOnStream,
    NotReceivableByRole,
    Payload,
}

fn failure<E, T>(error: &ReadReceivedFrameError<E, T>) -> End {
    let failure = match error {
        ReadReceivedFrameError::Frame {
            source: ReadFrameError::Type { .. },
        } => Failure::Type,
        ReadReceivedFrameError::Frame {
            source: ReadFrameError::Length { .. },
        } => Failure::Length,
        ReadReceivedFrameError::Http2Type { .. } => Failure::Http2Type,
        ReadReceivedFrameError::NotAllowedOnStream { .. } => Failure::NotAllowedOnStream,
        ReadReceivedFrameError::NotReceivableByRole { .. } => Failure::NotReceivableByRole,
    };
    End::Failed(error.error_code(), failure)
}

/// Reads at most `take` bytes from `io`, stopping at EOF.
async fn read_some<A: ReceiverAccess<Family: Read>>(
    io: &mut A,
    take: usize,
) -> Result<Vec<u8>, <A::Family as Read>::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 7];
    while bytes.len() < take {
        let want = (take - bytes.len()).min(buffer.len());
        let count = io.read(&mut &mut buffer[..want]).await?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

/// Reads every frame of a stream that carries frames: of each, at most
/// `take` bytes of its payload, then on to the next frame.
#[call(sync)]
async fn frames<F>(io: &mut impl ReceiverAccess<Family = F>, take: usize) -> (Vec<Seen>, End)
where
    F: Skip<Count = usize> + Read<Error = Infallible> + FrameStreamInfo<Parts = Parts>,
{
    let mut seen = Vec::new();
    let mut next = read_received_frame(&mut *io).await;
    loop {
        let mut frame = match next {
            Ok(Some(frame)) => frame,
            Ok(None) => return (seen, End::Clean),
            Err(error) => return (seen, failure(&error)),
        };
        let payload = match read_some(frame.payload(), take).await {
            Ok(payload) => payload,
            Err(error) => return (seen, End::Failed(error.error_code(), Failure::Payload)),
        };
        seen.push(Seen {
            frame_type: frame.frame_type(),
            payload,
        });
        next = match frame.next().await {
            Ok(frame) => Ok(frame),
            Err(NextFrameError::Finish { source }) => {
                return (seen, End::Failed(source.error_code(), Failure::Payload));
            }
            Err(NextFrameError::Read { source }) => Err(source),
        };
    }
}

/// [`frames`] on a request stream composed in the call.
#[call(sync)]
async fn request_frames<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    role: Role,
    take: usize,
) -> (Vec<Seen>, End) {
    let mut stream = io.compose(FrameStream::<Parts>::request(role));
    stream.frames(take).await
}

/// Reads a request stream at the access layer and at the receiver layer,
/// on a slice and on a stream that gives one byte at a time.
fn request(input: &[u8], role: Role, take: usize) -> (Vec<Seen>, End) {
    let mut access = input;
    let by_access = access.sync_request_frames_unpin(role, take);
    let state = FrameStream::<Parts>::request(role);
    let by_receiver = ComposedReceiver::new(input, state).sync_frames_unpin(take);
    assert_eq!(by_access, by_receiver, "the layers disagree");
    let mut dribbled = ComposedReceiver::new(Dribble::new(input, 1), state);
    let (by_dribble, pending) = run(dribbled.frames_unpin(take));
    assert_eq!(by_access, by_dribble, "a suspended read disagrees");
    assert!(input.is_empty() || pending > 0);
    by_access
}

const fn h3(frame_type: Http3FrameType) -> FrameType<FrameTypeValue> {
    FrameType::Known(Coproduct::Inl(frame_type))
}

fn seen(frame_type: FrameType<FrameTypeValue>, payload: &[u8]) -> Seen {
    Seen {
        frame_type,
        payload: payload.to_vec(),
    }
}

#[test]
fn a_request_stream_reads_frames_and_skips_what_is_left() {
    // HEADERS "abc"; a reserved type 0x21 with 4 bytes; DATA "hello", of
    // which two bytes are read before moving on; then the end.
    let input = [
        &[0x01, 0x03][..],
        b"abc",
        &[0x40, 0x21, 0x04],
        b"wxyz",
        &[0x00, 0x05],
        b"hello",
    ]
    .concat();
    let (frames, end) = request(&input, Role::Server, 2);
    assert_eq!(end, End::Clean);
    assert_eq!(
        frames,
        [
            seen(h3(Http3FrameType::Headers), b"ab"),
            seen(
                FrameType::Unknown(sakuya_var_int::VarInt::from_u32(0x21)),
                b"wx"
            ),
            seen(h3(Http3FrameType::Data), b"he"),
        ]
    );
    // Reading nothing of any payload skips each one whole.
    let (frames, end) = request(&input, Role::Server, 0);
    assert_eq!(end, End::Clean);
    assert_eq!(frames.len(), 3);
    assert!(frames.iter().all(|frame| frame.payload.is_empty()));
}

#[test]
fn an_empty_request_stream_has_no_frames() {
    assert_eq!(request(&[], Role::Server, 8), (vec![], End::Clean));
}

#[test]
fn a_frame_type_of_http2_is_unexpected() {
    // DATA, then PING (0x06), whose Length is never read.
    let (frames, end) = request(&[0x00, 0x00, 0x06], Role::Client, 8);
    assert_eq!(frames, [seen(h3(Http3FrameType::Data), b"")]);
    assert_eq!(
        end,
        End::Failed(Some(ErrorCode::H3_FRAME_UNEXPECTED), Failure::Http2Type)
    );
}

#[test]
fn control_frames_are_unexpected_on_a_request_stream() {
    // SETTINGS, whose Length is never read.
    let (frames, end) = request(&[0x04], Role::Server, 8);
    assert!(frames.is_empty());
    assert_eq!(
        end,
        End::Failed(
            Some(ErrorCode::H3_FRAME_UNEXPECTED),
            Failure::NotAllowedOnStream
        )
    );
}

#[test]
fn only_a_client_receives_push_promise() {
    // PUSH_PROMISE with Push ID 0 and an empty field section.
    let input = [0x05, 0x01, 0x00];
    let (frames, end) = request(&input, Role::Server, 8);
    assert!(frames.is_empty());
    assert_eq!(
        end,
        End::Failed(
            Some(ErrorCode::H3_FRAME_UNEXPECTED),
            Failure::NotReceivableByRole
        )
    );
    let (frames, end) = request(&input, Role::Client, 8);
    assert_eq!(end, End::Clean);
    assert_eq!(frames, [seen(h3(Http3FrameType::PushPromise), &[0x00])]);
}

#[test]
fn a_stream_that_ends_inside_a_frame_is_a_frame_error() {
    let frame_error = Some(ErrorCode::H3_FRAME_ERROR);
    // Inside the Type, which is two bytes.
    assert_eq!(
        request(&[0x40], Role::Server, 8),
        (vec![], End::Failed(frame_error, Failure::Type))
    );
    // Inside the Length.
    assert_eq!(
        request(&[0x00, 0x40], Role::Server, 8),
        (vec![], End::Failed(frame_error, Failure::Length))
    );
    // Inside the payload, while reading it.
    assert_eq!(
        request(&[0x00, 0x05, b'a', b'b'], Role::Server, 8),
        (vec![], End::Failed(frame_error, Failure::Payload))
    );
    // Inside the payload, while skipping what is left of it.
    assert_eq!(
        request(&[0x00, 0x05, b'a', b'b'], Role::Server, 1),
        (
            vec![seen(h3(Http3FrameType::Data), b"a")],
            End::Failed(frame_error, Failure::Payload)
        )
    );
}

/// Reads one byte of the first frame's payload, finishes the frame, and
/// reads the rest of the stream as bytes.
#[call(sync)]
async fn finish_then_read<F>(io: &mut impl ReceiverAccess<Family = F>) -> (Vec<u8>, Vec<u8>)
where
    F: Skip<Count = usize> + Read<Error = Infallible> + FrameStreamInfo<Parts = Parts>,
{
    let mut frame = read_received_frame(&mut *io).await.unwrap().unwrap();
    let first = read_some(frame.payload(), 1).await.unwrap();
    let stream = frame.finish().await.unwrap();
    (first, read_some(stream, 100).await.unwrap())
}

#[call(sync)]
async fn request_finish_then_read<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (Vec<u8>, Vec<u8>) {
    io.compose(FrameStream::<Parts>::request(Role::Server))
        .finish_then_read()
        .await
}

#[test]
fn finishing_a_frame_gives_the_stream_back_at_the_next_frame() {
    let input = [&[0x00, 0x03][..], b"abc", b"rest"].concat();
    let expected = (b"a".to_vec(), b"rest".to_vec());
    let mut access = &input[..];
    assert_eq!(access.sync_request_finish_then_read_unpin(), expected);
    assert!(access.is_empty());
    let mut receiver =
        ComposedReceiver::new(&input[..], FrameStream::<Parts>::request(Role::Server));
    assert_eq!(receiver.sync_finish_then_read_unpin(), expected);
    assert!(receiver.into_parts().0.is_empty());
}

/// How a unidirectional stream was read.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Unidirectional {
    /// The stream ended before its type.
    Empty,
    /// A control stream, and its frames.
    Control(Vec<Seen>, End),
    /// A push stream: its Push ID, and its frames.
    Push(u64, Vec<Seen>, End),
    /// Another stream: its type, the width of the type, and the rest.
    Other(StreamType<StreamTypeValue>, usize, Vec<u8>),
    /// Reading the type or Push ID failed.
    Failed(Option<ErrorCode>),
}

fn stream_failure<E, T>(error: &ReadUnidirectionalStreamError<E, T>) -> Unidirectional {
    Unidirectional::Failed(error.error_code())
}

/// Reads a unidirectional stream at the access layer: its type, and then
/// its frames on the stream it gives back.
#[call(sync)]
async fn unidirectional_frames<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    role: Role,
    take: usize,
) -> Unidirectional {
    match read_unidirectional_stream::<Parts, _>(&mut *io, role).await {
        Ok(None) => Unidirectional::Empty,
        Ok(Some(UnidirectionalStream::Control { mut stream, .. })) => {
            let (frames, end) = stream.frames(take).await;
            Unidirectional::Control(frames, end)
        }
        Ok(Some(UnidirectionalStream::Push {
            push_id,
            mut stream,
            ..
        })) => {
            let (frames, end) = stream.frames(take).await;
            Unidirectional::Push(push_id.get().get().get(), frames, end)
        }
        Ok(Some(UnidirectionalStream::Other(stream))) => {
            let (head, io) = stream.into_parts();
            let rest = read_some(io, 100).await.unwrap();
            Unidirectional::Other(head.stream_type(), head.field().encoded_len(), rest)
        }
        Err(error) => stream_failure(&error),
    }
}

/// The start of a unidirectional stream, for the receiver layer: the
/// stream to keep with the receiver, or what else was read.
enum Start {
    Frames(FrameStream<Parts>, Option<u64>),
    Done(Unidirectional),
}

#[call(sync)]
async fn stream_start<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
    role: Role,
) -> Start {
    match read_unidirectional_stream::<Parts, _>(&mut *io, role).await {
        Ok(None) => Start::Done(Unidirectional::Empty),
        Ok(Some(UnidirectionalStream::Control { stream, .. })) => {
            Start::Frames(stream.into_parts().1, None)
        }
        Ok(Some(UnidirectionalStream::Push {
            push_id, stream, ..
        })) => Start::Frames(stream.into_parts().1, Some(push_id.get().get().get())),
        Ok(Some(UnidirectionalStream::Other(stream))) => {
            let (head, io) = stream.into_parts();
            let rest = read_some(io, 100).await.unwrap();
            Start::Done(Unidirectional::Other(
                head.stream_type(),
                head.field().encoded_len(),
                rest,
            ))
        }
        Err(error) => Start::Done(stream_failure(&error)),
    }
}

/// Reads a unidirectional stream at both layers.
fn unidirectional(input: &[u8], role: Role, take: usize) -> Unidirectional {
    let mut access = input;
    let by_access = access.sync_unidirectional_frames_unpin(role, take);
    let mut rest = input;
    let by_receiver = match rest.sync_stream_start_unpin(role) {
        Start::Frames(state, push_id) => {
            assert_eq!(state.role(), role);
            let (frames, end) = ComposedReceiver::new(rest, state).sync_frames_unpin(take);
            match push_id {
                None => Unidirectional::Control(frames, end),
                Some(push_id) => Unidirectional::Push(push_id, frames, end),
            }
        }
        Start::Done(done) => done,
    };
    assert_eq!(by_access, by_receiver, "the layers disagree");
    by_access
}

#[test]
fn a_control_stream_reads_settings_and_goaway() {
    // SETTINGS with SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x40; GOAWAY 4.
    let input = [0x00, 0x04, 0x03, 0x01, 0x40, 0x40, 0x07, 0x01, 0x04];
    assert_eq!(
        unidirectional(&input, Role::Client, 8),
        Unidirectional::Control(
            vec![
                seen(h3(Http3FrameType::Settings), &[0x01, 0x40, 0x40]),
                seen(h3(Http3FrameType::Goaway), &[0x04]),
            ],
            End::Clean
        )
    );
}

/// Reads the SETTINGS and GOAWAY of a control stream with their readers.
#[call(sync)]
async fn settings_and_goaway<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (usize, u64) {
    let Ok(Some(UnidirectionalStream::Control { stream, .. })) =
        read_unidirectional_stream::<Parts, _>(&mut *io, Role::Server).await
    else {
        panic!("not a control stream");
    };
    let mut frame = read_received_frame(stream).await.unwrap().unwrap();
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    let mut count = 0;
    while let Some(setting) = frame.payload().read_setting(&mut settings).await.unwrap() {
        assert!(matches!(setting, Setting::Known(_)));
        count += 1;
    }
    let mut frame = frame.next().await.unwrap().unwrap();
    assert_eq!(frame.frame_type(), h3(Http3FrameType::Goaway));
    let widths = frame.frame().widths();
    use hatate_wire::frame::control::codec::ReadGoawayFrameExt as _;
    let goaway = frame.payload().read_goaway_frame(widths).await.unwrap();
    assert!(frame.next().await.unwrap().is_none());
    (count, goaway.id().get().get().get())
}

#[test]
fn the_frames_of_a_control_stream_read_with_their_readers() {
    let mut input = &[0x00, 0x04, 0x03, 0x01, 0x40, 0x40, 0x07, 0x01, 0x04][..];
    assert_eq!(input.sync_settings_and_goaway_unpin(), (1, 4));
}

#[test]
fn frames_check_the_kind_of_unidirectional_stream_and_the_role() {
    let unexpected = Some(ErrorCode::H3_FRAME_UNEXPECTED);
    // DATA on a control stream.
    assert_eq!(
        unidirectional(&[0x00, 0x00, 0x00], Role::Client, 8),
        Unidirectional::Control(vec![], End::Failed(unexpected, Failure::NotAllowedOnStream))
    );
    // MAX_PUSH_ID, which only a server receives, at a client.
    assert_eq!(
        unidirectional(&[0x00, 0x0d, 0x01, 0x00], Role::Client, 8),
        Unidirectional::Control(
            vec![],
            End::Failed(unexpected, Failure::NotReceivableByRole)
        )
    );
    assert_eq!(
        unidirectional(&[0x00, 0x0d, 0x01, 0x00], Role::Server, 8),
        Unidirectional::Control(
            vec![seen(h3(Http3FrameType::MaxPushId), &[0x00])],
            End::Clean
        )
    );
}

#[test]
fn a_push_stream_reads_its_push_id_then_frames() {
    // Push ID 0x1234 in two bytes; HEADERS "ab"; DATA "c"; PUSH_PROMISE,
    // which is not allowed on a push stream.
    let input = [
        0x01, 0x52, 0x34, 0x01, 0x02, b'a', b'b', 0x00, 0x01, b'c', 0x05,
    ];
    assert_eq!(
        unidirectional(&input, Role::Client, 8),
        Unidirectional::Push(
            0x1234,
            vec![
                seen(h3(Http3FrameType::Headers), b"ab"),
                seen(h3(Http3FrameType::Data), b"c"),
            ],
            End::Failed(
                Some(ErrorCode::H3_FRAME_UNEXPECTED),
                Failure::NotAllowedOnStream
            )
        )
    );
}

#[test]
fn a_server_does_not_accept_a_push_stream() {
    assert_eq!(
        unidirectional(&[0x01, 0x00], Role::Server, 8),
        Unidirectional::Failed(Some(ErrorCode::H3_STREAM_CREATION_ERROR))
    );
}

#[test]
fn a_qpack_stream_comes_back_with_its_type() {
    // The encoder stream type in two bytes, then its instructions.
    assert_eq!(
        unidirectional(&[0x40, 0x02, 0x3f, 0xe1], Role::Server, 8),
        Unidirectional::Other(
            StreamType::Known(Coproduct::Inl(Http3StreamType::Qpack(
                QpackStreamType::Encoder
            ))),
            2,
            vec![0x3f, 0xe1]
        )
    );
}

#[test]
fn an_unknown_stream_type_comes_back_as_it_is() {
    assert_eq!(
        unidirectional(&[0x40, 0x21, 0xaa], Role::Client, 8),
        Unidirectional::Other(
            StreamType::Unknown(sakuya_var_int::VarInt::from_u32(0x21)),
            2,
            vec![0xaa]
        )
    );
}

#[test]
fn a_receiver_tolerates_a_stream_that_ends_before_its_header() {
    assert_eq!(unidirectional(&[], Role::Client, 8), Unidirectional::Empty);
    // Inside the type, and inside the Push ID: no connection error.
    assert_eq!(
        unidirectional(&[0x40], Role::Client, 8),
        Unidirectional::Failed(None)
    );
    assert_eq!(
        unidirectional(&[0x01, 0x40], Role::Client, 8),
        Unidirectional::Failed(None)
    );
}

/// Reads every frame of any source with `read_frame`, which checks nothing
/// about the type: of each, its Type and Length fields and its payload.
#[call(sync)]
async fn plain_frames<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> Vec<(u64, usize, u64, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut next = read_frame(&mut *io).await.unwrap();
    while let Some(mut frame) = next {
        let payload = read_some(frame.payload(), 100).await.unwrap();
        frames.push((
            frame.r#type().get().get(),
            frame.r#type().encoded_len(),
            frame.length().get().get(),
            payload,
        ));
        next = frame.next().await.unwrap();
    }
    frames
}

#[test]
fn read_frame_reads_any_type_from_any_source() {
    // PING of HTTP/2 and SETTINGS, neither checked; the Type of the second
    // in two bytes.
    let mut input = &[0x06, 0x01, 0xaa, 0x40, 0x04, 0x00][..];
    assert_eq!(
        input.sync_plain_frames_unpin(),
        [(0x06, 1, 1, vec![0xaa]), (0x04, 2, 0, vec![])]
    );
}

/// Reads one frame and writes it back with `write_frame`, its payload
/// copied from the frame's own payload.
#[call(sync)]
async fn copy_frame<
    R: Skip<Count = usize> + Read<Error = Infallible>,
    W: Write<Error = Infallible>,
>(
    input: &mut impl ReceiverAccess<Family = R>,
    output: &mut impl ReceiverAccess<Family = W>,
) {
    let frame = read_frame(&mut *input).await.unwrap().unwrap();
    let (r#type, length) = (frame.r#type(), frame.length());
    let mut payload = frame.into_payload();
    output
        .write_frame(Frame::new(r#type, length, &mut payload))
        .await
        .unwrap();
    assert_eq!(poll_len(&mut payload).await, 0);
}

async fn poll_len<A: ReceiverAccess<Family: ExactLen>>(
    io: &mut A,
) -> <A::Family as ExactLen>::Length {
    core::future::poll_fn(|cx| {
        io.poll_access(cx, |mut view, _| {
            core::task::Poll::Ready(view.remaining_len())
        })
    })
    .await
}

#[test]
fn a_frame_read_writes_back_to_the_same_bytes() {
    // DATA with its Type in two bytes and its Length in four.
    let input = [0x40, 0x00, 0x80, 0x00, 0x00, 0x03, b'a', b'b', b'c'];
    let mut hosts = (&input[..], Vec::new());
    hosts.sync_copy_frame_unpin();
    assert!(hosts.0.is_empty());
    assert_eq!(hosts.1, input);
}

/// Reads CANCEL_PUSH and MAX_PUSH_ID of a control stream with their
/// readers, through the payload of the frame read from the stream.
#[call(sync)]
async fn cancel_push_and_max_push_id<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (u64, usize, u64, usize) {
    use hatate_wire::frame::control::codec::{
        ReadCancelPushFrameExt as _, ReadMaxPushIdFrameExt as _,
    };
    let Ok(Some(UnidirectionalStream::Control { stream, .. })) =
        read_unidirectional_stream::<Parts, _>(&mut *io, Role::Server).await
    else {
        panic!("not a control stream");
    };
    let mut frame = read_received_frame(stream).await.unwrap().unwrap();
    assert_eq!(frame.frame_type(), h3(Http3FrameType::CancelPush));
    let widths = frame.frame().widths();
    let cancel = frame
        .payload()
        .read_cancel_push_frame(widths)
        .await
        .unwrap();
    let mut frame = frame.next().await.unwrap().unwrap();
    assert_eq!(frame.frame_type(), h3(Http3FrameType::MaxPushId));
    let widths = frame.frame().widths();
    let max = frame
        .payload()
        .read_max_push_id_frame(widths)
        .await
        .unwrap();
    assert!(frame.next().await.unwrap().is_none());
    (
        cancel.push_id().get().get().get(),
        cancel.push_id().encoded_len(),
        max.push_id().get().get().get(),
        max.push_id().encoded_len(),
    )
}

#[test]
fn cancel_push_and_max_push_id_read_through_the_payload_of_a_received_frame() {
    // CANCEL_PUSH with the Push ID 7 in two bytes, MAX_PUSH_ID with 9.
    let mut input = &[0x00, 0x03, 0x02, 0x40, 0x07, 0x0d, 0x01, 0x09][..];
    assert_eq!(input.sync_cancel_push_and_max_push_id_unpin(), (7, 2, 9, 1));
}

/// Reads PUSH_PROMISE of a request stream with its reader, through the
/// payload of the frame read from the stream: the Push ID, the rest of the
/// payload, and what follows.
#[call(sync)]
async fn push_promise<
    F: Skip<Count = usize> + Read<Error = Infallible> + FrameStreamInfo<Parts = Parts>,
>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (u64, Vec<u8>, bool) {
    use hatate_wire::frame::codec::ReadPushPromisePushIdExt as _;
    let mut frame = read_received_frame(&mut *io).await.unwrap().unwrap();
    assert_eq!(frame.frame_type(), h3(Http3FrameType::PushPromise));
    let push_id = frame.payload().read_push_promise_push_id().await.unwrap();
    let section = read_some(frame.payload(), 100).await.unwrap();
    let next = frame.next().await.unwrap();
    (push_id.get().get().get(), section, next.is_none())
}

#[call(sync)]
async fn client_push_promise<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (u64, Vec<u8>, bool) {
    io.compose(FrameStream::<Parts>::request(Role::Client))
        .push_promise()
        .await
}

#[test]
fn push_promise_reads_its_push_id_through_the_payload_of_a_received_frame() {
    // Push ID 7, then a field section of two bytes.
    let mut input = &[0x05, 0x03, 0x07, 0xaa, 0xbb][..];
    assert_eq!(
        input.sync_client_push_promise_unpin(),
        (7, vec![0xaa, 0xbb], true)
    );
    let receiver = ComposedReceiver::new(
        &[0x05, 0x03, 0x07, 0xaa, 0xbb][..],
        FrameStream::<Parts>::request(Role::Client),
    );
    let mut receiver = receiver;
    assert_eq!(
        receiver.sync_push_promise_unpin(),
        (7, vec![0xaa, 0xbb], true)
    );
}
