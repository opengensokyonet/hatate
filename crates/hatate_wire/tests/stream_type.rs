#![feature(impl_trait_in_assoc_type)]
//! Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2), and reading
//! the start of a unidirectional stream.
mod common;

use common::{Dribble, run};
use core::convert::Infallible;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{PushId, set::FrameStreamKind},
    stream::{
        FrameStream, UnidirectionalStream,
        codec::{ReadUnidirectionalStreamError, read_unidirectional_stream},
    },
    stream_type::{Http3StreamType, StreamType, StreamTypeKind, StreamTypeSet},
};
use hatate_wire_qpack::QpackStreamType;
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);
type Value = <Parts as StreamTypeSet>::TypeValue;

/// What reading the start of a unidirectional stream gave.
#[derive(Debug, PartialEq)]
enum Started {
    Control(FrameStream<Parts>),
    Push {
        push_id: VarIntField<PushId>,
        stream: FrameStream<Parts>,
    },
    Other {
        stream_type: StreamType<Value>,
        field: VarIntField<VarInt>,
    },
}

type StartResult<E> = Result<Option<Started>, ReadUnidirectionalStreamError<E, Value>>;

#[call(sync)]
async fn start<F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    role: Role,
) -> StartResult<<F as Read>::Error> {
    let stream = read_unidirectional_stream::<Parts, _>(&mut *io, role).await?;
    Ok(stream.map(|stream| match stream {
        UnidirectionalStream::Control(stream) => Started::Control(stream.into_parts().1),
        UnidirectionalStream::Push { push_id, stream } => Started::Push {
            push_id,
            stream: stream.into_parts().1,
        },
        UnidirectionalStream::Other(stream) => {
            let head = stream.head();
            Started::Other {
                stream_type: head.stream_type(),
                field: head.field(),
            }
        }
    }))
}

fn read_as(mut input: &[u8], role: Role) -> StartResult<Infallible> {
    input.sync_start_unpin(role)
}

fn read(input: &[u8]) -> StartResult<Infallible> {
    read_as(input, Role::Client)
}

/// The type of the stream an `Other` start reports.
fn other(started: Started) -> (StreamType<Value>, VarIntField<VarInt>) {
    match started {
        Started::Other { stream_type, field } => (stream_type, field),
        started => panic!("{started:?}"),
    }
}

#[test]
fn the_four_types_of_http3_and_qpack_are_known() {
    let expected = [
        (0x00, Http3StreamType::Control),
        (0x01, Http3StreamType::Push),
        (0x02, Http3StreamType::Qpack(QpackStreamType::Encoder)),
        (0x03, Http3StreamType::Qpack(QpackStreamType::Decoder)),
    ];
    for (byte, stream_type) in expected {
        // A push stream has its Push ID after the type.
        let started = read(&[byte, 0x09, 0xaa]).unwrap().unwrap();
        let kind = FrameStreamKind::Unidirectional(VarInt::from_u32(u32::from(byte)));
        match (stream_type, started) {
            (Http3StreamType::Control, Started::Control(stream)) => {
                assert_eq!(stream, FrameStream::new(kind, Role::Client));
            }
            (Http3StreamType::Push, Started::Push { push_id, stream }) => {
                assert_eq!(push_id.get().get().get(), 9);
                assert_eq!(stream, FrameStream::new(kind, Role::Client));
            }
            (Http3StreamType::Qpack(_), started) => {
                let (read_type, field) = other(started);
                assert_eq!(read_type, StreamType::Known(Coproduct::Inl(stream_type)));
                assert_eq!(field.get().get(), u64::from(byte));
            }
            (_, started) => panic!("{stream_type:?}: {started:?}"),
        }
        assert_eq!(stream_type.value().get(), u64::from(byte));
        assert_eq!(
            Http3StreamType::of(VarInt::from_u32(u32::from(byte))),
            Some(stream_type)
        );
    }
    assert_eq!(
        Http3StreamType::ALL
            .map(Http3StreamType::value)
            .map(VarInt::get),
        [0, 1, 2, 3]
    );
}

#[test]
fn other_and_reserved_types_are_unknown() {
    let cases: [(&[u8], u64); 5] = [
        (&[0x04], 0x04),
        (&[0x21], 0x21),
        (&[0x40, 0x40], 0x40),
        (&[0x7f, 0xff], 0x3fff),
        (&[0xff; 8], (1 << 62) - 1),
    ];
    for (wire, value) in cases {
        for role in [Role::Client, Role::Server] {
            let (stream_type, field) = other(read_as(wire, role).unwrap().unwrap());
            assert_eq!(
                stream_type,
                StreamType::Unknown(VarInt::new(value).unwrap())
            );
            assert_eq!(field.get().get(), value);
        }
    }
}

#[test]
fn an_empty_stream_has_no_type_and_a_cut_type_is_an_error() {
    assert!(read(&[]).unwrap().is_none());
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0]] {
        let error = read(wire).unwrap_err();
        assert!(
            matches!(&error, ReadUnidirectionalStreamError::Type { source }
                if source.is_incomplete() && source.completed() > 0),
            "{error:?}"
        );
        // A receiver tolerates a stream that ends inside the type.
        assert_eq!(error.error_code(), None);
    }
}

#[test]
fn a_cut_push_id_is_an_error_without_a_code() {
    for wire in [&[0x01][..], &[0x01, 0x40], &[0x01, 0xc0, 0, 0]] {
        let error = read(wire).unwrap_err();
        assert!(
            matches!(&error, ReadUnidirectionalStreamError::PushId { source }
                if source.is_incomplete()),
            "{error:?}"
        );
        assert_eq!(error.error_code(), None);
    }
}

#[test]
fn a_server_does_not_accept_a_push_stream() {
    let error = read_as(&[0x01, 0x00], Role::Server).unwrap_err();
    assert!(
        matches!(&error, ReadUnidirectionalStreamError::NotAcceptableByRole { stream_type, role }
            if *stream_type == Coproduct::Inl(Http3StreamType::Push) && *role == Role::Server),
        "{error:?}"
    );
    assert_eq!(
        error.error_code(),
        Some(ErrorCode::H3_STREAM_CREATION_ERROR)
    );
    // The other types are accepted by both roles.
    for byte in [0x00, 0x02, 0x03] {
        assert!(read_as(&[byte], Role::Server).unwrap().is_some());
    }
}

#[test]
fn the_width_of_the_type_and_of_the_push_id_is_kept() {
    for width in VarIntWidth::ALL {
        let (bytes, len) = VarIntField::new(VarInt::from_u32(0x02), width)
            .unwrap()
            .to_encoding();
        let (stream_type, field) = other(read(&bytes[..len]).unwrap().unwrap());
        assert_eq!(field.width(), width);
        assert_eq!(
            stream_type,
            StreamType::Known(Coproduct::Inl(Http3StreamType::Qpack(
                QpackStreamType::Encoder
            )))
        );

        let (bytes, len) = VarIntField::new(PushId::new(VarInt::from_u32(5)), width)
            .unwrap()
            .to_encoding();
        let wire = [&[0x01][..], &bytes[..len]].concat();
        let Some(Started::Push { push_id, .. }) = read(&wire).unwrap() else {
            panic!("not a push stream");
        };
        assert_eq!(push_id.width(), width);
        assert_eq!(push_id.get().get().get(), 5);
    }
}

#[test]
fn only_the_type_and_the_push_id_are_consumed() {
    let mut input = &[0x02, 0x07, 0x08][..];
    input.sync_start_unpin(Role::Client).unwrap();
    assert_eq!(input, [0x07, 0x08]);
    let mut input = &[0x00, 0x07, 0x08][..];
    input.sync_start_unpin(Role::Client).unwrap();
    assert_eq!(input, [0x07, 0x08]);
    let mut input = &[0x01, 0x07, 0x08][..];
    input.sync_start_unpin(Role::Client).unwrap();
    assert_eq!(input, [0x08]);
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let wire = [0xc0, 0, 0, 0, 0, 0, 0, 0x03, 0x55];
    let mut host = Dribble::new(&wire, 1);
    let (started, pending) = run(host.start_unpin(Role::Client));
    let (stream_type, field) = other(started.unwrap().unwrap());
    assert_eq!(field.width(), VarIntWidth::Eight);
    assert_eq!(
        stream_type,
        StreamType::Known(Coproduct::Inl(Http3StreamType::Qpack(
            QpackStreamType::Decoder
        )))
    );
    assert!(pending >= 8, "{pending}");
    assert_eq!(host.rest(), [0x55]);

    // A push stream: the type, then a Push ID in two bytes.
    let wire = [0x01, 0x40, 0x07, 0x55];
    let mut host = Dribble::new(&wire, 1);
    let (started, pending) = run(host.start_unpin(Role::Client));
    let Some(Started::Push { push_id, .. }) = started.unwrap() else {
        panic!("not a push stream");
    };
    assert_eq!(push_id.width(), VarIntWidth::Two);
    assert_eq!(push_id.get().get().get(), 7);
    assert!(pending >= 3, "{pending}");
    assert_eq!(host.rest(), [0x55]);
}

#[test]
fn a_push_stream_is_accepted_only_by_a_client_and_is_not_critical() {
    let push = Http3StreamType::Push;
    assert!(push.acceptable_by(Role::Client));
    assert!(!push.acceptable_by(Role::Server));
    assert!(!push.is_critical());
    assert!(!push.at_most_one());
}

#[test]
fn control_and_qpack_streams_are_critical_and_single() {
    for stream_type in [
        Http3StreamType::Control,
        Http3StreamType::Qpack(QpackStreamType::Encoder),
        Http3StreamType::Qpack(QpackStreamType::Decoder),
    ] {
        for role in [Role::Client, Role::Server] {
            assert!(stream_type.acceptable_by(role), "{stream_type:?} {role:?}");
        }
        assert!(stream_type.is_critical(), "{stream_type:?}");
        assert!(stream_type.at_most_one(), "{stream_type:?}");
    }
}

#[test]
fn the_kinds_of_a_list_are_those_of_its_parts() {
    for stream_type in Http3StreamType::ALL {
        let value = <Parts as StreamTypeSet>::type_value_of(stream_type.value()).unwrap();
        assert_eq!(
            <Parts as StreamTypeSet>::value_of(value),
            stream_type.value()
        );
        let kind = <Parts as StreamTypeSet>::kind_of(value);
        for role in [Role::Client, Role::Server] {
            assert_eq!(kind.acceptable_by(role), stream_type.acceptable_by(role));
        }
        assert_eq!(kind.is_critical(), stream_type.is_critical());
        assert_eq!(kind.at_most_one(), stream_type.at_most_one());
    }
    assert!(<Parts as StreamTypeSet>::type_value_of(VarInt::from_u32(4)).is_none());
}
