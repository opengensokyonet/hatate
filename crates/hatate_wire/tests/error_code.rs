//! HTTP/3 error codes (RFC 9114 §8.1) and those of QPACK (RFC 9204 §6).
use hatate_wire::error_code::ErrorCode;
use hatate_wire_qpack::QpackErrorCode;
use sakuya_var_int::VarInt;

#[test]
fn the_constants_have_the_values_of_rfc_9114_section_8_1() {
    let table = [
        (ErrorCode::H3_NO_ERROR, 0x0100),
        (ErrorCode::H3_GENERAL_PROTOCOL_ERROR, 0x0101),
        (ErrorCode::H3_INTERNAL_ERROR, 0x0102),
        (ErrorCode::H3_STREAM_CREATION_ERROR, 0x0103),
        (ErrorCode::H3_CLOSED_CRITICAL_STREAM, 0x0104),
        (ErrorCode::H3_FRAME_UNEXPECTED, 0x0105),
        (ErrorCode::H3_FRAME_ERROR, 0x0106),
        (ErrorCode::H3_EXCESSIVE_LOAD, 0x0107),
        (ErrorCode::H3_ID_ERROR, 0x0108),
        (ErrorCode::H3_SETTINGS_ERROR, 0x0109),
        (ErrorCode::H3_MISSING_SETTINGS, 0x010a),
        (ErrorCode::H3_REQUEST_REJECTED, 0x010b),
        (ErrorCode::H3_REQUEST_CANCELLED, 0x010c),
        (ErrorCode::H3_REQUEST_INCOMPLETE, 0x010d),
        (ErrorCode::H3_MESSAGE_ERROR, 0x010e),
        (ErrorCode::H3_CONNECT_ERROR, 0x010f),
        (ErrorCode::H3_VERSION_FALLBACK, 0x0110),
    ];
    for (code, value) in table {
        assert_eq!(code.value().get(), value);
        assert_eq!(code, ErrorCode::new(VarInt::new(value).unwrap()));
        assert!(!code.is_reserved());
    }
}

#[test]
fn the_codes_of_qpack_convert_with_their_values() {
    let table = [
        (QpackErrorCode::DecompressionFailed, 0x0200),
        (QpackErrorCode::EncoderStreamError, 0x0201),
        (QpackErrorCode::DecoderStreamError, 0x0202),
    ];
    for (code, value) in table {
        let converted = ErrorCode::from(code);
        assert_eq!(converted.value().get(), value);
        assert_eq!(converted.value(), code.value());
        assert_eq!(converted.to_string(), format!("{value:#06x}"));
    }
}

#[test]
fn any_variable_length_integer_is_an_error_code() {
    for value in [0, 0x33, 0x1234_5678, (1 << 62) - 1] {
        let var_int = VarInt::new(value).unwrap();
        let code = ErrorCode::from(var_int);
        assert_eq!(VarInt::from(code), var_int);
        assert_eq!(code.value(), var_int);
    }
}

#[test]
fn reserved_codes_follow_the_formula_of_rfc_9114() {
    let mut reserved = Vec::new();
    for n in [0u64, 1, 2, 100, 0xffff_ffff] {
        let value = 0x1f * n + 0x21;
        reserved.push(value);
        assert!(
            ErrorCode::new(VarInt::new(value).unwrap()).is_reserved(),
            "{value:#x}"
        );
    }
    assert_eq!(reserved[..2], [0x21, 0x40]);
    for value in [0, 0x20, 0x22, 0x3f, 0x41, 0x0100, 0x0200, 0x33] {
        assert!(
            !ErrorCode::new(VarInt::new(value).unwrap()).is_reserved(),
            "{value:#x}"
        );
    }
    assert!(ErrorCode::new(VarInt::new(0x3fff_ffff_ffff_fffe).unwrap()).is_reserved());
    assert!(!ErrorCode::new(VarInt::MAX).is_reserved());
}

#[test]
fn display_is_hexadecimal_with_at_least_four_digits() {
    let show = |value: u64| ErrorCode::new(VarInt::new(value).unwrap()).to_string();
    assert_eq!(show(0x0100), "0x0100");
    assert_eq!(show(0x010a), "0x010a");
    assert_eq!(show(0x33), "0x0033");
    assert_eq!(show(0), "0x0000");
    assert_eq!(show(0x1234_5678), "0x12345678");
    assert_eq!(ErrorCode::H3_VERSION_FALLBACK.to_string(), "0x0110");
}

#[test]
fn codes_are_ordered_by_value() {
    assert!(ErrorCode::H3_NO_ERROR < ErrorCode::H3_GENERAL_PROTOCOL_ERROR);
    assert!(ErrorCode::H3_VERSION_FALLBACK < ErrorCode::from(QpackErrorCode::DecompressionFailed));
}
