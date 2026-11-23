//! Unidirectional stream types (RFC 9114 §6.2, RFC 9204 §4.2).
mod common;

use common::{Dribble, run};
use core::marker::PhantomData;
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    stream_type::{
        Http3StreamType, StreamType, StreamTypeHead, StreamTypeKind, StreamTypeSet,
        codec::ReadStreamTypeHostExt as _,
    },
};
use hatate_wire_qpack::QpackStreamType;
use sakuya_var_int::{VarInt, VarIntWidth};

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

type Head = StreamTypeHead<<Parts as StreamTypeSet>::TypeValue>;

fn read(
    mut input: &[u8],
) -> Result<Option<Head>, sakuya_var_int::call::ReadVarIntError<core::convert::Infallible>> {
    input.sync_read_stream_type_unpin(PhantomData::<Parts>)
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
        let head = read(&[byte, 0xaa]).unwrap().unwrap();
        assert_eq!(
            head.stream_type(),
            StreamType::Known(Coproduct::Inl(stream_type))
        );
        assert_eq!(head.field().get().get(), u64::from(byte));
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
        let head = read(wire).unwrap().unwrap();
        assert_eq!(
            head.stream_type(),
            StreamType::Unknown(VarInt::new(value).unwrap())
        );
    }
}

#[test]
fn an_empty_stream_has_no_type_and_a_cut_type_is_an_error() {
    assert!(read(&[]).unwrap().is_none());
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0]] {
        let error = read(wire).unwrap_err();
        assert!(error.is_incomplete(), "{error:?}");
        assert!(error.completed() > 0);
    }
}

#[test]
fn the_width_of_the_type_is_kept() {
    for width in VarIntWidth::ALL {
        let (bytes, len) = sakuya_var_int::VarIntField::new(VarInt::from_u32(0x02), width)
            .unwrap()
            .to_encoding();
        let head = read(&bytes[..len]).unwrap().unwrap();
        assert_eq!(head.field().width(), width);
        assert_eq!(
            head.stream_type(),
            StreamType::Known(Coproduct::Inl(Http3StreamType::Qpack(
                QpackStreamType::Encoder
            )))
        );
    }
}

#[test]
fn only_the_type_is_consumed() {
    let mut input = &[0x01, 0x07, 0x08][..];
    input
        .sync_read_stream_type_unpin(PhantomData::<Parts>)
        .unwrap();
    assert_eq!(input, [0x07, 0x08]);
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let wire = [0xc0, 0, 0, 0, 0, 0, 0, 0x03, 0x55];
    let mut host = Dribble::new(&wire, 1);
    let (head, pending) = run(host.read_stream_type_unpin(PhantomData::<Parts>));
    let head = head.unwrap().unwrap();
    assert_eq!(head.field().width(), VarIntWidth::Eight);
    assert_eq!(
        head.stream_type(),
        StreamType::Known(Coproduct::Inl(Http3StreamType::Qpack(
            QpackStreamType::Decoder
        )))
    );
    assert!(pending >= 8, "{pending}");
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
