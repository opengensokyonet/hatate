//! HTTP Datagrams on the wire (RFC 9297 §2.1).
use bytes::Bytes;
use hatate_wire_datagram::{
    Datagram, H3_DATAGRAM_ERROR, QuarterStreamId, QuarterStreamIdError, read_datagram,
    write_datagram,
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth, codec::ReadVarIntFieldError};

fn id(value: u64, width: VarIntWidth) -> VarIntField<QuarterStreamId> {
    VarIntField::new(
        QuarterStreamId::try_from(VarInt::new(value).unwrap()).unwrap(),
        width,
    )
    .unwrap()
}

#[test]
fn a_datagram_of_every_width_is_written_and_read_back() {
    for width in VarIntWidth::ALL {
        let quarter_stream_id = id(5, width);
        let mut wire = Vec::new();
        write_datagram(&mut wire, Datagram::new(quarter_stream_id, &b"payload"[..]));
        assert_eq!(wire.len(), width.encoded_len() + 7);
        assert_eq!(&wire[width.encoded_len()..], b"payload");
        let datagram = read_datagram(&wire[..]).unwrap();
        assert_eq!(datagram.quarter_stream_id(), quarter_stream_id);
        assert_eq!(datagram.quarter_stream_id().width(), width);
        assert_eq!(*datagram.payload(), b"payload");
        assert_eq!(datagram.into_payload(), b"payload");
    }
}

#[test]
fn an_empty_payload_is_a_datagram() {
    let mut wire = Vec::new();
    write_datagram(&mut wire, Datagram::new(id(1, VarIntWidth::One), &[][..]));
    assert_eq!(wire, [0x01]);
    let datagram = read_datagram(&wire[..]).unwrap();
    assert_eq!(datagram.quarter_stream_id().get().get().get(), 1);
    assert!(datagram.payload().is_empty());
}

#[test]
fn a_bytes_payload_is_written_and_read_as_bytes() {
    let payload = Bytes::from_static(b"\x00\x01\x02 bytes");
    let mut wire = Vec::new();
    write_datagram(
        &mut wire,
        Datagram::new(id(0x1234, VarIntWidth::Four), payload.clone()),
    );
    assert_eq!(&wire[..4], [0x80, 0, 0x12, 0x34]);
    let datagram = read_datagram(Bytes::from(wire)).unwrap();
    assert_eq!(datagram.quarter_stream_id().get().get().get(), 0x1234);
    assert_eq!(datagram.into_payload(), payload);
}

#[test]
fn writing_to_a_buffer_without_room_panics_like_buf_mut_put() {
    let result = std::panic::catch_unwind(|| {
        let mut buffer = [0u8; 3];
        let mut dst = &mut buffer[..];
        write_datagram(
            &mut dst,
            Datagram::new(id(1, VarIntWidth::One), &b"abcd"[..]),
        );
    });
    assert!(result.is_err());
}

#[test]
fn an_empty_input_has_no_quarter_stream_id() {
    let error = read_datagram(&[][..]).unwrap_err();
    assert!(
        matches!(error.read_error(), ReadVarIntFieldError::VarInt { .. }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), H3_DATAGRAM_ERROR);
    // A cut Quarter Stream ID is the same failure.
    for wire in [&[0x40][..], &[0x80, 0, 0], &[0xc0, 0, 0, 0, 0, 0, 0]] {
        let error = read_datagram(wire).unwrap_err();
        assert!(
            matches!(error.read_error(), ReadVarIntFieldError::VarInt { .. }),
            "{error:?}"
        );
        assert_eq!(error.error_code(), H3_DATAGRAM_ERROR);
    }
}

#[test]
fn a_quarter_stream_id_of_two_to_the_sixty_is_refused() {
    let wire = [0xd0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
    let error = read_datagram(&wire[..]).unwrap_err();
    assert_eq!(error.error_code(), H3_DATAGRAM_ERROR);
    let ReadVarIntFieldError::Value { value, source } = error.read_error() else {
        panic!("{error:?}");
    };
    assert_eq!(value.get(), 1 << 60);
    assert_eq!(source.value().get(), 1 << 60);
    assert_eq!(
        source.to_string(),
        "Quarter Stream ID 1152921504606846976 exceeds 2^60 - 1"
    );
    // The largest allowed value is accepted, with the 8-byte width kept.
    let wire = [0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa];
    let datagram = read_datagram(&wire[..]).unwrap();
    assert_eq!(datagram.quarter_stream_id().get(), QuarterStreamId::MAX);
    assert_eq!(*datagram.payload(), [0xaa]);
    // And the largest variable-length integer is refused.
    let error = read_datagram(&[0xff; 8][..]).unwrap_err();
    assert!(
        matches!(error.read_error(), ReadVarIntFieldError::Value { .. }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), H3_DATAGRAM_ERROR);
}

#[test]
fn the_largest_quarter_stream_id_is_two_to_the_sixty_minus_one() {
    assert_eq!(QuarterStreamId::MAX.get().get(), (1 << 60) - 1);
    assert_eq!(QuarterStreamId::MAX.stream_id().get(), (1 << 62) - 4);
    let error: QuarterStreamIdError =
        QuarterStreamId::try_from(VarInt::new(1 << 60).unwrap()).unwrap_err();
    assert_eq!(error.value().get(), 1 << 60);
    assert_eq!(
        QuarterStreamId::try_from(VarInt::new((1 << 60) - 1).unwrap()),
        Ok(QuarterStreamId::MAX)
    );
    assert_eq!(
        VarInt::from(QuarterStreamId::MAX),
        VarInt::new((1 << 60) - 1).unwrap()
    );
}

#[test]
fn only_client_initiated_bidirectional_streams_have_a_quarter_stream_id() {
    for stream_id in [0u64, 4, 8, 400, 1 << 40, (1 << 62) - 4] {
        let quarter = QuarterStreamId::of_stream_id(VarInt::new(stream_id).unwrap()).unwrap();
        assert_eq!(quarter.get().get(), stream_id / 4);
        assert_eq!(quarter.stream_id().get(), stream_id);
    }
    for stream_id in [1u64, 2, 3, 5, 6, 7, 10, 401, (1 << 62) - 1, (1 << 62) - 3] {
        assert_eq!(
            QuarterStreamId::of_stream_id(VarInt::new(stream_id).unwrap()),
            None,
            "{stream_id}"
        );
    }
    assert_eq!(
        QuarterStreamId::of_stream_id(VarInt::new((1 << 62) - 4).unwrap()),
        Some(QuarterStreamId::try_from(VarInt::new((1 << 60) - 1).unwrap()).unwrap())
    );
}

#[test]
fn the_quarter_stream_ids_are_ordered_by_value() {
    let one = QuarterStreamId::of_stream_id(VarInt::from_u32(4)).unwrap();
    let two = QuarterStreamId::of_stream_id(VarInt::from_u32(8)).unwrap();
    assert!(one < two);
    assert!(two < QuarterStreamId::MAX);
}

#[test]
fn the_error_code_of_a_malformed_datagram_is_0x33() {
    assert_eq!(H3_DATAGRAM_ERROR.value().get(), 0x33);
    assert_eq!(H3_DATAGRAM_ERROR.to_string(), "0x0033");
}
