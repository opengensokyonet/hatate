#![feature(impl_trait_in_assoc_type)]
//! The control stream a connection reads: its first frame must be SETTINGS
//! (RFC 9114 §6.2.1) and no later one may be (§7.2.4), and dropping a read of its next frame before the first
//! byte of the head leaves the stream where it was.
mod common;

use common::{Dribble, read_some, run};
use core::{
    convert::Infallible,
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Part,
    error_code::{ErrorCode, ErrorCodeOf as _},
    stream::{
        NextFrameError, ReceivedStream,
        class::{ClientInitiatedUnidirectional, ServerInitiatedUnidirectional},
        codec::{ReadUnidirectionalStreamError, read_unidirectional_stream},
        http3::ControlStreamError,
        http3::{Http3UnidirectionalStream, Http3UnidirectionalStreamError},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, Skip};

type Parts = HList![Part];

/// What opening a control stream came to.
#[derive(Debug, PartialEq, Eq)]
enum Opened {
    /// The stream came back at its first frame, which has this type.
    Control(u64),
    /// The first frame is not SETTINGS: its type on the wire and the code.
    MissingSettings {
        frame_type: u64,
        code: Option<ErrorCode>,
    },
    /// The head of the first frame was rejected or cut, with this code.
    Head(Option<ErrorCode>),
}

macro_rules! open {
    ($name:ident, $class:ty) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
        ) -> Opened {
            match read_unidirectional_stream::<Parts, $class, _, ()>(&mut *io).await {
                Ok(Some(stream)) => {
                    let ReceivedStream::Known(known) = stream.transpose() else {
                        panic!("not a stream of a part");
                    };
                    let Coproduct::Inl(http3) = known.transpose() else {
                        unreachable!("one part");
                    };
                    let Http3UnidirectionalStream::Control(control) = http3.transpose() else {
                        panic!("not a control stream");
                    };
                    Opened::Control(control.into_stream().frame().frame_type().value().get())
                }
                Ok(None) => panic!("the stream is empty"),
                Err(error @ ReadUnidirectionalStreamError::Part { .. }) => {
                    let code = error.error_code();
                    let ReadUnidirectionalStreamError::Part { source } = error else {
                        unreachable!();
                    };
                    match source.into_inner() {
                        Coproduct::Inl(Http3UnidirectionalStreamError::MissingSettings {
                            frame_type,
                        }) => Opened::MissingSettings {
                            frame_type: frame_type.get(),
                            code,
                        },
                        Coproduct::Inl(Http3UnidirectionalStreamError::Control { .. }) => {
                            Opened::Head(code)
                        }
                        _ => panic!("another failure of the part"),
                    }
                }
                Err(_) => panic!("not a failure of the part"),
            }
        }
    };
}

open!(open_from_client, ClientInitiatedUnidirectional);
open!(open_from_server, ServerInitiatedUnidirectional);

fn opened_from_client(wire: &[u8]) -> Opened {
    let mut input = wire;
    input.sync_open_from_client_unpin()
}

fn opened_from_server(wire: &[u8]) -> Opened {
    let mut input = wire;
    input.sync_open_from_server_unpin()
}

#[test]
fn a_control_stream_that_starts_with_settings_is_given() {
    let wire = [0x00, 0x04, 0x02, 0x21, 0x01];
    assert_eq!(opened_from_client(&wire), Opened::Control(0x04));
    assert_eq!(opened_from_server(&wire), Opened::Control(0x04));
}

#[test]
fn a_first_frame_other_than_settings_is_h3_missing_settings() {
    // The type of the first frame and its head; both sides receive each,
    // unless the head itself is rejected for the receiver.
    let cases: [(u64, &[u8], bool, bool); 5] = [
        // GOAWAY, CANCEL_PUSH: either side may receive them.
        (0x07, &[0x00, 0x07, 0x01, 0x00], true, true),
        (0x03, &[0x00, 0x03, 0x01, 0x00], true, true),
        // MAX_PUSH_ID goes from a client to a server only.
        (0x0d, &[0x00, 0x0d, 0x01, 0x00], true, false),
        // A reserved type, and one that no part has.
        (0x21, &[0x00, 0x21, 0x01, 0xaa], true, true),
        (0x3f, &[0x00, 0x3f, 0x01, 0xaa], true, true),
    ];
    for (frame_type, wire, server_receives, client_receives) in cases {
        for (opened, receives) in [
            (opened_from_client(wire), server_receives),
            (opened_from_server(wire), client_receives),
        ] {
            if receives {
                assert_eq!(
                    opened,
                    Opened::MissingSettings {
                        frame_type,
                        code: Some(ErrorCode::H3_MISSING_SETTINGS)
                    },
                    "{frame_type:#x}"
                );
            } else {
                // The head is rejected before the type is judged against
                // SETTINGS.
                assert_eq!(
                    opened,
                    Opened::Head(Some(ErrorCode::H3_FRAME_UNEXPECTED)),
                    "{frame_type:#x}"
                );
            }
        }
    }
}

#[test]
fn the_type_of_a_missing_settings_keeps_its_wire_value_at_any_width() {
    // GOAWAY with a Type of two bytes.
    let wire = [0x00, 0x40, 0x07, 0x01, 0x00];
    assert_eq!(
        opened_from_client(&wire),
        Opened::MissingSettings {
            frame_type: 0x07,
            code: Some(ErrorCode::H3_MISSING_SETTINGS)
        }
    );
}

/// SETTINGS with one setting, then a GOAWAY.
const WIRE: [u8; 8] = [0x00, 0x04, 0x02, 0x21, 0x01, 0x07, 0x01, 0x00];

/// What the call after the drops made of the stream.
#[derive(Debug, PartialEq, Eq)]
enum Step {
    Frame(u64),
    Interrupted,
    /// The stream ended after the frame a drop had reached.
    Closed,
}

/// Opens a control stream, drops a read of the next frame after each number
/// of polls in \`drops\`, and calls once more: what that gave and the bytes
/// the access has left.
#[call(sync)]
async fn drop_next<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    drops: Vec<usize>,
) -> (Step, Vec<u8>) {
    let stream =
        read_unidirectional_stream::<Parts, ClientInitiatedUnidirectional, _, ()>(&mut *io)
            .await
            .unwrap()
            .unwrap();
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
    for polls in drops {
        let mut next = pin!(control.next_frame());
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..polls {
            if let Poll::Ready(result) = next.as_mut().poll(&mut cx) {
                // The frame was reached before the drop.
                assert!(result.is_ok());
                break;
            }
        }
    }
    let step = match control.next_frame().await {
        Ok(frame) => Step::Frame(frame.frame_type().value().get()),
        Err(ControlStreamError::Next {
            source: NextFrameError::Interrupted,
        }) => Step::Interrupted,
        Err(error) => {
            assert_eq!(
                error.error_code(),
                Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
            );
            Step::Closed
        }
    };
    let mut io = control.into_io();
    let rest = read_some(&mut io, 100).await.unwrap();
    (step, rest)
}

#[test]
fn a_control_stream_read_dropped_before_the_first_byte_of_a_head_reads_the_next_frame() {
    let (undropped, _) = run(Dribble::new(&WIRE, 1).drop_next_unpin(vec![]));
    assert_eq!(undropped, (Step::Frame(0x07), vec![0x00]));
    let mut at_boundary = 0;
    let mut interrupted = 0;
    for polls in 0..30 {
        let (outcome, _) = run(Dribble::new(&WIRE, 1).drop_next_unpin(vec![polls]));
        match outcome {
            // Before the first byte of the head of the GOAWAY frame: the
            // read starts over and gives it, as if nothing was dropped.
            (Step::Frame(frame_type), rest) => {
                assert_eq!((frame_type, rest), (0x07, vec![0x00]), "polls {polls}");
                at_boundary += 1;
            }
            // After it: the stream is abandoned, and the access is past the
            // byte the dropped read took.
            (Step::Interrupted, rest) => {
                assert!(rest.len() < 3, "polls {polls}: {rest:?}");
                interrupted += 1;
            }
            (Step::Closed, _) => {}
        }
    }
    assert!(at_boundary > 0 && interrupted > 0);
}

/// How reading the frames after the first ended: the types read, and the
/// code of the failure.
#[call(sync)]
async fn frames_after_the_first<
    F: Read<Error = Infallible, Metadata = ()> + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    known: bool,
) -> (Vec<u64>, Option<ErrorCode>, bool) {
    let stream =
        read_unidirectional_stream::<Parts, ClientInitiatedUnidirectional, _, ()>(&mut *io)
            .await
            .unwrap()
            .unwrap();
    let ReceivedStream::Known(known_stream) = stream.transpose() else {
        panic!("not a stream of a part");
    };
    let Coproduct::Inl(http3) = known_stream.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Control(control) = http3.transpose() else {
        panic!("not a control stream");
    };
    let mut control = control.into_stream();
    let mut types = Vec::new();
    loop {
        let next = if known {
            control.next_known_frame().await
        } else {
            control.next_frame().await
        };
        match next {
            Ok(frame) => types.push(frame.frame_type().value().get()),
            Err(error) => {
                let second = matches!(error, ControlStreamError::SecondSettings);
                return (types, error.error_code(), second);
            }
        }
    }
}

#[test]
fn a_second_settings_frame_is_h3_frame_unexpected() {
    // SETTINGS, GOAWAY, a reserved frame, then SETTINGS again.
    let wire = [0x00, 0x04, 0x00, 0x07, 0x01, 0x00, 0x21, 0x00, 0x04, 0x00];
    for (known, types) in [(false, vec![0x07, 0x21]), (true, vec![0x07])] {
        let mut input = &wire[..];
        assert_eq!(
            input.sync_frames_after_the_first_unpin(known),
            (types, Some(ErrorCode::H3_FRAME_UNEXPECTED), true),
            "{known}"
        );
    }
    // Without a second SETTINGS, the stream ends as a critical stream does.
    let wire = [0x00, 0x04, 0x00, 0x07, 0x01, 0x00];
    let mut input = &wire[..];
    assert_eq!(
        input.sync_frames_after_the_first_unpin(false),
        (
            vec![0x07],
            Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM),
            false
        )
    );
}
