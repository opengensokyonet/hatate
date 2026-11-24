#![feature(impl_trait_in_assoc_type)]
//! Streams that carry frames: a `FrameStream` of each kind of stream
//! holds the current frame and moves from one frame to the next. Each stream
//! is read on a slice, and once more one byte at a time with a suspension
//! before every read, and the results must agree.
mod common;

use common::{Dribble, Ty, known, read_some, run, ty};
use core::convert::Infallible;
use frunk_core::HList;
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        Http3FrameType,
        codec::{ReadFrameError, ReadFrameHeadError, UnexpectedFrameTypeError, WriteFrameExt as _},
        set::FrameSetOn,
    },
    registry::reserved,
    settings::{
        Setting,
        codec::ReadSettingExt as _,
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream, NextFrameError,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind, StreamKind},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, Skip, Write};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

fn var_int(value: u64, width: VarIntWidth) -> Vec<u8> {
    let (bytes, len) = VarIntField::new(VarInt::new(value).unwrap(), width)
        .unwrap()
        .to_encoding();
    bytes[..len].to_vec()
}

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

/// What was seen of one frame: its type, and the payload bytes read.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Seen {
    ty: Ty,
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
    Interrupted,
}

fn head_failure<E>(error: &ReadFrameHeadError<E>) -> Failure {
    match error {
        ReadFrameHeadError::Frame {
            source: ReadFrameError::Type { .. },
        } => Failure::Type,
        ReadFrameHeadError::Frame {
            source: ReadFrameError::Length { .. },
        } => Failure::Length,
        ReadFrameHeadError::Unexpected {
            source: UnexpectedFrameTypeError::Http2Type { .. },
        } => Failure::Http2Type,
        ReadFrameHeadError::Unexpected {
            source: UnexpectedFrameTypeError::NotAllowedOnStream { .. },
        } => Failure::NotAllowedOnStream,
        ReadFrameHeadError::Unexpected {
            source: UnexpectedFrameTypeError::NotReceivableByRole { .. },
        } => Failure::NotReceivableByRole,
    }
}

fn next_failure<E: hatate_wire::error_code::ErrorCodeOf<ErrorCode>>(
    error: &NextFrameError<E>,
) -> End {
    match error {
        NextFrameError::Skip { source } => End::Failed(source.error_code(), Failure::Payload),
        NextFrameError::Head { source } => End::Failed(source.error_code(), head_failure(source)),
        NextFrameError::Interrupted => End::Failed(error.error_code(), Failure::Interrupted),
    }
}

/// Reads every frame of a stream of kind `K` that carries frames: of each, at
/// most `take` bytes of its payload, then on to the next frame.
#[call(sync)]
async fn walk<K: StreamKind, F>(
    io: &mut impl ReceiverAccess<Family = F>,
    _kind: K,
    role: Role,
    take: usize,
) -> (Vec<Seen>, End)
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
    Parts: FrameSetOn<K>,
{
    let mut seen = Vec::new();
    let mut stream = match FrameStream::<Parts, K, _>::read(&mut *io, role).await {
        Ok(Some(stream)) => stream,
        Ok(None) => return (seen, End::Clean),
        Err(error) => return (seen, End::Failed(error.error_code(), head_failure(&error))),
    };
    assert_eq!(stream.role(), role);
    loop {
        let mut frame = stream.frame();
        let payload = match read_some(frame.payload(), take).await {
            Ok(payload) => payload,
            Err(error) => return (seen, End::Failed(error.error_code(), Failure::Payload)),
        };
        seen.push(Seen {
            ty: ty(frame.frame_type()),
            payload,
        });
        match stream.next_frame().await {
            Ok(Some(_)) => {}
            Ok(None) => return (seen, End::Clean),
            Err(error) => return (seen, next_failure(&error)),
        }
    }
}

/// Reads a stream on a slice and on a stream that gives one byte at a time
/// after a suspension; the results agree.
fn frames<K: StreamKind + Copy>(kind: K, input: &[u8], role: Role, take: usize) -> (Vec<Seen>, End)
where
    Parts: FrameSetOn<K>,
{
    let mut access = input;
    let by_slice = access.sync_walk_unpin(kind, role, take);
    let mut dribbled = Dribble::new(input, 1);
    let (by_dribble, pending) = run(dribbled.walk_unpin(kind, role, take));
    assert_eq!(by_slice, by_dribble, "a suspended read disagrees");
    assert!(input.is_empty() || pending > 0);
    by_slice
}

fn request(input: &[u8], role: Role, take: usize) -> (Vec<Seen>, End) {
    frames(RequestStreamKind, input, role, take)
}

fn seen(ty: Ty, payload: &[u8]) -> Seen {
    Seen {
        ty,
        payload: payload.to_vec(),
    }
}

const fn h3(frame_type: Http3FrameType) -> Ty {
    known(frame_type)
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
            seen(Ty::Reserved(0x21), b"wx"),
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
fn an_empty_stream_has_no_frames() {
    assert_eq!(request(&[], Role::Server, 8), (vec![], End::Clean));
    assert_eq!(
        frames(ControlStreamKind, &[], Role::Client, 8),
        (vec![], End::Clean)
    );
    assert_eq!(
        frames(PushStreamKind, &[], Role::Client, 8),
        (vec![], End::Clean)
    );
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
fn a_frame_is_known_only_on_the_kinds_of_stream_that_have_it() {
    let unexpected = End::Failed(
        Some(ErrorCode::H3_FRAME_UNEXPECTED),
        Failure::NotAllowedOnStream,
    );
    for frame_type in Http3FrameType::ALL {
        // A frame of no payload, at a role that receives it.
        let role = match frame_type {
            Http3FrameType::MaxPushId => Role::Server,
            _ => Role::Client,
        };
        let input = [frame_type.value().get() as u8, 0x00];
        let allowed = |request: bool, control: bool, push: bool| {
            let expected = |yes| {
                if yes {
                    (vec![seen(h3(frame_type), b"")], End::Clean)
                } else {
                    (vec![], unexpected)
                }
            };
            assert_eq!(
                frames(RequestStreamKind, &input, role, 8),
                expected(request),
                "{frame_type:?} on a request stream"
            );
            assert_eq!(
                frames(ControlStreamKind, &input, role, 8),
                expected(control),
                "{frame_type:?} on a control stream"
            );
            assert_eq!(
                frames(PushStreamKind, &input, role, 8),
                expected(push),
                "{frame_type:?} on a push stream"
            );
        };
        match frame_type {
            Http3FrameType::Data | Http3FrameType::Headers => allowed(true, false, true),
            Http3FrameType::PushPromise => allowed(true, false, false),
            Http3FrameType::CancelPush
            | Http3FrameType::Settings
            | Http3FrameType::Goaway
            | Http3FrameType::MaxPushId => allowed(false, true, false),
        }
    }
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
fn frames_check_the_kind_of_stream_and_the_role_after_the_first_frame_too() {
    let unexpected = Some(ErrorCode::H3_FRAME_UNEXPECTED);
    // DATA is followed by SETTINGS on a request stream.
    assert_eq!(
        request(&[0x00, 0x00, 0x04, 0x00], Role::Client, 8),
        (
            vec![seen(h3(Http3FrameType::Data), b"")],
            End::Failed(unexpected, Failure::NotAllowedOnStream)
        )
    );
    // MAX_PUSH_ID, which only a server receives, at a client, after a
    // frame it receives.
    let input = [0x07, 0x01, 0x04, 0x0d, 0x01, 0x00];
    assert_eq!(
        frames(ControlStreamKind, &input, Role::Client, 8),
        (
            vec![seen(h3(Http3FrameType::Goaway), &[0x04])],
            End::Failed(unexpected, Failure::NotReceivableByRole)
        )
    );
    assert_eq!(
        frames(ControlStreamKind, &input, Role::Server, 8),
        (
            vec![
                seen(h3(Http3FrameType::Goaway), &[0x04]),
                seen(h3(Http3FrameType::MaxPushId), &[0x00]),
            ],
            End::Clean
        )
    );
}

#[test]
fn a_push_stream_reads_its_frames() {
    // HEADERS "ab"; DATA "c"; PUSH_PROMISE, which is not allowed on a push
    // stream.
    let input = [0x01, 0x02, b'a', b'b', 0x00, 0x01, b'c', 0x05];
    assert_eq!(
        frames(PushStreamKind, &input, Role::Client, 8),
        (
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
    // Inside the head of a later frame.
    assert_eq!(
        request(&[0x00, 0x00, 0x01], Role::Server, 8),
        (
            vec![seen(h3(Http3FrameType::Data), b"")],
            End::Failed(frame_error, Failure::Length)
        )
    );
}

#[test]
fn the_types_no_part_has_are_told_reserved_from_unknown() {
    let small = reserved(0).unwrap().get();
    let large = reserved(1 << 30).unwrap().get();
    assert_eq!(small, 0x21);
    // Types and their Type fields: reserved, undeclared, and both in more
    // bytes than they need.
    let input = [
        &[0x21, 0x00][..],
        &[0x0a, 0x00],
        &[0x40, 0x21, 0x00],
        &[0x40, 0x0e, 0x00],
        &[0x40, 0x40, 0x00],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0x0b, 0x00],
    ]
    .concat();
    let expected = [
        Ty::Reserved(0x21),
        Ty::Unknown(0x0a),
        Ty::Reserved(0x21),
        Ty::Unknown(0x0e),
        Ty::Reserved(0x40),
        Ty::Unknown(0x0b),
    ];
    for kind in 0..3 {
        let (frames, end) = match kind {
            0 => request(&input, Role::Server, 8),
            1 => frames(ControlStreamKind, &input, Role::Server, 8),
            _ => frames(PushStreamKind, &input, Role::Client, 8),
        };
        assert_eq!(end, End::Clean);
        assert_eq!(
            frames.iter().map(|frame| frame.ty).collect::<Vec<_>>(),
            expected
        );
    }
    // A large reserved value is reserved too.
    let mut input = var_int(large, VarIntWidth::Eight);
    input.push(0x00);
    let (frames, end) = request(&input, Role::Server, 8);
    assert_eq!(end, End::Clean);
    assert_eq!(frames, [seen(Ty::Reserved(large), b"")]);
}

/// Reads the first frame of a request stream, then the known ones with
/// `next_known_frame` to the end, and what the stream holds after it.
#[call(sync)]
async fn known_frames<F>(io: &mut impl ReceiverAccess<Family = F>) -> (Ty, Vec<Seen>, Seen, u64)
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
{
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    // The first frame is given whatever it is.
    let first = ty(stream.frame().frame_type());
    let mut known = Vec::new();
    loop {
        let Some(mut frame) = stream.next_known_frame().await.unwrap() else {
            break;
        };
        assert!(matches!(ty(frame.frame_type()), Ty::Known(_)));
        let payload = read_some(frame.payload(), 8).await.unwrap();
        known.push(Seen {
            ty: ty(frame.frame_type()),
            payload,
        });
    }
    // The stream ended: it stays ended, and holds the last frame it read,
    // which is skipped to its end.
    assert!(stream.next_known_frame().await.unwrap().is_none());
    assert!(stream.next_frame().await.unwrap().is_none());
    let mut last = stream.frame();
    let last_ty = ty(last.frame_type());
    let payload = read_some(last.payload(), 8).await.unwrap();
    let remaining = last.into_payload().into_parts().1.remaining();
    (
        first,
        known,
        Seen {
            ty: last_ty,
            payload,
        },
        remaining,
    )
}

#[test]
fn next_known_frame_skips_reserved_and_unknown_frames() {
    // RESERVED 0x21 "xx" (the first frame); UNKNOWN 0x0a "y"; HEADERS "h";
    // RESERVED 0x40 (two bytes); DATA "d"; UNKNOWN 0x22 "z"; the end.
    let input = [
        &[0x21, 0x02][..],
        b"xx",
        &[0x0a, 0x01],
        b"y",
        &[0x01, 0x01],
        b"h",
        &[0x40, 0x40, 0x00],
        &[0x00, 0x01],
        b"d",
        &[0x22, 0x01],
        b"z",
    ]
    .concat();
    let expected = (
        Ty::Reserved(0x21),
        vec![
            seen(h3(Http3FrameType::Headers), b"h"),
            seen(h3(Http3FrameType::Data), b"d"),
        ],
        // After the end the stream still holds the last frame, which is
        // empty to read.
        seen(Ty::Unknown(0x22), b""),
        0,
    );
    let mut access = &input[..];
    assert_eq!(access.sync_known_frames_unpin(), expected);
    assert!(access.is_empty());
    let mut dribbled = Dribble::new(&input, 1);
    assert_eq!(run(dribbled.known_frames_unpin()).0, expected);
    assert!(dribbled.rest().is_empty());
}

#[test]
fn next_known_frame_of_a_stream_of_one_known_frame_ends_at_it() {
    let mut access = &[0x00, 0x02, b'a', b'b'][..];
    let (first, known, last, remaining) = access.sync_known_frames_unpin();
    assert_eq!(first, h3(Http3FrameType::Data));
    assert!(known.is_empty());
    // The only frame is the current frame, skipped to its end.
    assert_eq!(last, seen(h3(Http3FrameType::Data), b""));
    assert_eq!(remaining, 0);
}

/// Walks to the end of a stream with `next_frame`, and asks what it holds
/// there.
#[call(sync)]
async fn past_the_end<F>(io: &mut impl ReceiverAccess<Family = F>) -> Vec<u8>
where
    F: Skip<Count = usize> + Read<Error = Infallible>,
{
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ty(stream.frame().frame_type()), h3(Http3FrameType::Data));
    assert_eq!(read_some(stream.frame().payload(), 1).await.unwrap(), b"a");
    let mut second = stream.next_frame().await.unwrap().unwrap();
    assert_eq!(ty(second.frame_type()), h3(Http3FrameType::Headers));
    assert_eq!(read_some(second.payload(), 8).await.unwrap(), b"cd");
    // The end of the stream at a frame boundary: no frame, over and over.
    for _ in 0..3 {
        assert!(stream.next_frame().await.unwrap().is_none());
    }
    // The stream still holds the last frame, with nothing left of its
    // payload.
    let mut last = stream.frame();
    assert_eq!(ty(last.frame_type()), h3(Http3FrameType::Headers));
    assert_eq!(last.length().get().get(), 2);
    assert_eq!(last.widths().length_width(), VarIntWidth::One);
    assert!(read_some(last.payload(), 8).await.unwrap().is_empty());
    assert!(stream.next_frame().await.unwrap().is_none());
    // The access is at the end of the stream.
    let mut io = stream.into_io();
    read_some(&mut io, 8).await.unwrap()
}

#[test]
fn after_the_end_a_stream_holds_the_last_frame_with_an_empty_payload() {
    let input = [&[0x00, 0x03][..], b"abc", &[0x01, 0x02], b"cd"].concat();
    let mut access = &input[..];
    assert!(access.sync_past_the_end_unpin().is_empty());
    assert!(access.is_empty());
    let mut dribbled = Dribble::new(&input, 1);
    assert!(run(dribbled.past_the_end_unpin()).0.is_empty());
}

/// The first frame's head is read when the stream is made, and the access
/// comes back at the start of its payload.
#[call(sync)]
async fn io_after_the_first_head<F: Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> Vec<u8> {
    let stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    let mut io = stream.into_io();
    read_some(&mut io, 100).await.unwrap()
}

#[test]
fn the_access_comes_back_at_the_payload_of_the_current_frame() {
    let mut access = &[0x00, 0x03, b'a', b'b', b'c', b'r', b'e', b's', b't'][..];
    assert_eq!(access.sync_io_after_the_first_head_unpin(), b"abcrest");
}

/// Reads the SETTINGS and GOAWAY of a control stream with their readers.
#[call(sync)]
async fn settings_and_goaway<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (usize, u64) {
    let mut stream = FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    let mut frame = stream.frame();
    assert_eq!(ty(frame.frame_type()), h3(Http3FrameType::Settings));
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    let mut count = 0;
    while let Some(setting) = frame.payload().read_setting(&mut settings).await.unwrap() {
        assert!(matches!(setting, Setting::Known(_)));
        count += 1;
    }
    let mut frame = stream.next_frame().await.unwrap().unwrap();
    assert_eq!(ty(frame.frame_type()), h3(Http3FrameType::Goaway));
    let widths = frame.widths();
    use hatate_wire::frame::control::codec::ReadGoawayFrameExt as _;
    let goaway = frame.payload().read_goaway_frame(widths).await.unwrap();
    assert!(stream.next_frame().await.unwrap().is_none());
    (count, goaway.id().get().get().get())
}

#[test]
fn the_frames_of_a_control_stream_read_with_their_readers() {
    // SETTINGS with SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0x40; GOAWAY 4.
    let input = [0x04, 0x03, 0x01, 0x40, 0x40, 0x07, 0x01, 0x04];
    let mut access = &input[..];
    assert_eq!(access.sync_settings_and_goaway_unpin(), (1, 4));
    assert_eq!(
        frames(ControlStreamKind, &input, Role::Client, 8),
        (
            vec![
                seen(h3(Http3FrameType::Settings), &[0x01, 0x40, 0x40]),
                seen(h3(Http3FrameType::Goaway), &[0x04]),
            ],
            End::Clean
        )
    );
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
    let mut stream = FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap();
    let mut frame = stream.frame();
    assert_eq!(ty(frame.frame_type()), h3(Http3FrameType::CancelPush));
    let widths = frame.widths();
    let cancel = frame
        .payload()
        .read_cancel_push_frame(widths)
        .await
        .unwrap();
    let mut frame = stream.next_frame().await.unwrap().unwrap();
    assert_eq!(ty(frame.frame_type()), h3(Http3FrameType::MaxPushId));
    let widths = frame.widths();
    let max = frame
        .payload()
        .read_max_push_id_frame(widths)
        .await
        .unwrap();
    assert!(stream.next_frame().await.unwrap().is_none());
    (
        cancel.push_id().get().get().get(),
        cancel.push_id().encoded_len(),
        max.push_id().get().get().get(),
        max.push_id().encoded_len(),
    )
}

#[test]
fn cancel_push_and_max_push_id_read_through_the_payload_of_the_current_frame() {
    // CANCEL_PUSH with the Push ID 7 in two bytes, MAX_PUSH_ID with 9.
    let mut input = &[0x03, 0x02, 0x40, 0x07, 0x0d, 0x01, 0x09][..];
    assert_eq!(input.sync_cancel_push_and_max_push_id_unpin(), (7, 2, 9, 1));
}

/// Reads PUSH_PROMISE of a request stream with its reader, through the
/// payload of the frame read from the stream: the Push ID, the rest of the
/// payload, and whether the stream ends after it.
#[call(sync)]
async fn push_promise<F: Skip<Count = usize> + Read<Error = Infallible>>(
    io: &mut impl ReceiverAccess<Family = F>,
) -> (u64, Vec<u8>, bool) {
    use hatate_wire::frame::codec::ReadPushPromisePushIdExt as _;
    let mut stream = FrameStream::<Parts, RequestStreamKind, _>::read(&mut *io, Role::Client)
        .await
        .unwrap()
        .unwrap();
    let mut frame = stream.frame();
    assert_eq!(ty(frame.frame_type()), h3(Http3FrameType::PushPromise));
    let push_id = frame.payload().read_push_promise_push_id().await.unwrap();
    let section = read_some(frame.payload(), 100).await.unwrap();
    let next = stream.next_frame().await.unwrap();
    (push_id.get().get().get(), section, next.is_none())
}

#[test]
fn push_promise_reads_its_push_id_through_the_payload_of_the_current_frame() {
    // Push ID 7, then a field section of two bytes.
    let mut input = &[0x05, 0x03, 0x07, 0xaa, 0xbb][..];
    assert_eq!(input.sync_push_promise_unpin(), (7, vec![0xaa, 0xbb], true));
}

/// Reads every frame of a stream and writes each back with `write_frame`,
/// its payload copied from the frame's own payload; the types it saw.
#[call(sync)]
async fn copy_frames<
    K: StreamKind,
    R: Skip<Count = usize> + Read<Error = Infallible>,
    W: Write<Error = Infallible>,
>(
    input: &mut impl ReceiverAccess<Family = R>,
    output: &mut impl ReceiverAccess<Family = W>,
    _kind: K,
    role: Role,
) -> Vec<Ty>
where
    Parts: FrameSetOn<K>,
{
    let mut types = Vec::new();
    let Some(mut stream) = FrameStream::<Parts, K, _>::read(&mut *input, role)
        .await
        .unwrap()
    else {
        return types;
    };
    loop {
        types.push(ty(stream.frame().frame_type()));
        output.write_frame(stream.frame()).await.unwrap();
        // The frame's payload was copied to its end.
        assert_eq!(stream.frame().into_payload().into_parts().1.remaining(), 0);
        if stream.next_frame().await.unwrap().is_none() {
            return types;
        }
    }
}

fn copied<K: StreamKind>(kind: K, input: &[u8], role: Role) -> Vec<Ty>
where
    Parts: FrameSetOn<K>,
{
    let mut hosts = (input, Vec::new());
    let types = hosts.sync_copy_frames_unpin(kind, role);
    assert!(hosts.0.is_empty());
    assert_eq!(
        hosts.1, input,
        "the frames are written back as they were read"
    );
    types
}

#[test]
fn frames_read_write_back_to_the_same_bytes() {
    // DATA with its Type in two bytes and its Length in four; HEADERS with
    // a Length in eight; a reserved and an unknown type, in more bytes than
    // they need; an empty frame.
    let input = [
        &[0x40, 0x00, 0x80, 0x00, 0x00, 0x03, b'a', b'b', b'c'][..],
        &[0x01, 0xc0, 0, 0, 0, 0, 0, 0, 0x02, b'd', b'e'],
        &[0x80, 0, 0, 0x21, 0x40, 0x01, b'g'],
        &[0xc0, 0, 0, 0, 0, 0, 0, 0x0a, 0x00],
        &[0x00, 0x00],
    ]
    .concat();
    assert_eq!(
        copied(RequestStreamKind, &input, Role::Server),
        [
            h3(Http3FrameType::Data),
            h3(Http3FrameType::Headers),
            Ty::Reserved(0x21),
            Ty::Unknown(0x0a),
            h3(Http3FrameType::Data),
        ]
    );
    // The frames of the other kinds of stream.
    let control = [
        &[0x04, 0x02, 0x01, 0x40][..],
        &[0x40, 0x07, 0x40, 0x02, 0x40, 0x04],
        &[0x0d, 0x01, 0x09],
        &[0x40, 0x21, 0x00],
    ]
    .concat();
    assert_eq!(
        copied(ControlStreamKind, &control, Role::Server),
        [
            h3(Http3FrameType::Settings),
            h3(Http3FrameType::Goaway),
            h3(Http3FrameType::MaxPushId),
            Ty::Reserved(0x21),
        ]
    );
    let push = [&[0x01, 0x01, b'h'][..], &[0x00, 0x02, b'a', b'b']].concat();
    assert_eq!(
        copied(PushStreamKind, &push, Role::Client),
        [h3(Http3FrameType::Headers), h3(Http3FrameType::Data)]
    );
    assert!(copied(RequestStreamKind, &[], Role::Server).is_empty());
}
