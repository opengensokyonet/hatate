//! The codes of the failures to read QPACK instructions (RFC 9204 §6): an
//! instruction that cannot be interpreted is QPACK_ENCODER_STREAM_ERROR on
//! the encoder stream and QPACK_DECODER_STREAM_ERROR on the decoder stream;
//! a failure of the stream is the stream's own code, and the end of a
//! critical stream is H3_CLOSED_CRITICAL_STREAM; a limit of the caller's
//! choice, an abandoned stream and the end of a stream that is not critical
//! have no code. Each is read on the streams of hatate_qpack, which are not
//! critical, and on the QPACK streams of hatate_wire_qpack, which are. The
//! limits of the critical encoder stream are those of the table capacity
//! this endpoint allows, which the peer's encoder may not exceed: an
//! insertion beyond them is QPACK_ENCODER_STREAM_ERROR (RFC 9204 §3.2.2).
mod common;

use common::{next_critical_decoder, next_critical_encoder, next_decoder, next_encoder, run};
use hatate_qpack::{decoder_instruction::DecoderStream, encoder_instruction::EncoderStream};
use hatate_wire::error_code::{ErrorCode, ErrorCodeOf};
use hatate_wire_qpack::{
    QpackErrorCode,
    stream::{QpackDecoderStream, QpackEncoderStream},
};
use nitori_call::ConstructedAccess;

fn encoder_error() -> Option<ErrorCode> {
    Some(QpackErrorCode::EncoderStreamError.into())
}

fn decoder_error() -> Option<ErrorCode> {
    Some(QpackErrorCode::DecoderStreamError.into())
}

fn closed() -> Option<ErrorCode> {
    Some(ErrorCode::H3_CLOSED_CRITICAL_STREAM)
}

/// How reading ended: Ok at the end of a stream that is not critical, or the
/// code of the first failure.
type Ended = Result<(), Option<ErrorCode>>;

macro_rules! decoder_plain {
    ($reader:ident, $wire:expr) => {
        run(next_decoder(&mut $reader, $wire)).0
    };
}
macro_rules! decoder_critical {
    ($reader:ident, $wire:expr) => {
        run(next_critical_decoder(&mut $reader, $wire)).0.map(Some)
    };
}

/// Reads every instruction of a stream that is not critical within
/// `max_wire` and `max_decoded`, until the stream ends or fails.
fn encoder_plain(wire: &[u8], max_wire: usize, max_decoded: usize) -> Ended {
    let mut reader = EncoderStream::new(ConstructedAccess::new(wire), Default::default());
    loop {
        match run(next_encoder(&mut reader, max_wire, max_decoded)).0 {
            Ok(Some(_)) => {}
            Ok(None) => break Ok(()),
            Err(error) => break Err(error.error_code()),
        }
    }
}

/// Reads every instruction of a critical encoder stream within the limits
/// of a table of `capacity` octets, until the stream fails.
fn encoder_critical(wire: &[u8], capacity: u64) -> Ended {
    let mut reader = QpackEncoderStream::new(ConstructedAccess::new(wire));
    loop {
        if let Err(error) = run(next_critical_encoder(&mut reader, capacity)).0 {
            break Err(error.error_code());
        }
    }
}

macro_rules! decoder_ended {
    ($make:expr, $next:ident, $wire:expr) => {{
        let mut reader = $make;
        loop {
            match $next!(reader, $wire) {
                Ok(Some(_)) => {}
                Ok(None) => break Ok(()),
                Err(error) => break Err(error.error_code()),
            }
        }
    }};
}

fn decoder_plain(wire: &[u8], max_wire: usize) -> Ended {
    decoder_ended!(
        DecoderStream::new(ConstructedAccess::new(wire), Default::default()),
        decoder_plain,
        max_wire
    )
}

fn decoder_critical(wire: &[u8], max_wire: usize) -> Ended {
    decoder_ended!(
        QpackDecoderStream::new(ConstructedAccess::new(wire)),
        decoder_critical,
        max_wire
    )
}

/// An integer of a prefix of `first` that goes on for eleven continuation
/// bytes, which no integer of QPACK does.
fn endless(first: u8) -> Vec<u8> {
    let mut wire = vec![first];
    wire.extend([0xff; 11]);
    wire.push(0x00);
    wire
}

/// What the encoder stream reads of `wire` on both kinds of stream, with
/// limits no instruction here reaches: 64 decoded octets, from a capacity of
/// 96 on the critical stream.
fn encoder(wire: &[u8]) -> (Ended, Ended) {
    (encoder_plain(wire, 300, 64), encoder_critical(wire, 96))
}

fn decoder(wire: &[u8]) -> (Ended, Ended) {
    (decoder_plain(wire, 16), decoder_critical(wire, 16))
}

#[test]
fn an_instruction_that_cannot_be_interpreted_is_an_encoder_stream_error() {
    let cases: [(&str, Vec<u8>); 11] = [
        // An integer that goes on for more than ten continuation bytes, in
        // Set Dynamic Table Capacity and in a name index.
        ("capacity integer", endless(0x3f)),
        ("name index integer", endless(0xff)),
        // A static name index the table does not have.
        ("static name", vec![0xff, 0x25, 0x00]),
        // A Huffman name that is the EOS code, that has more than seven bits
        // of padding, and whose padding is not the prefix of the EOS code.
        ("Huffman EOS", vec![0x64, 0xff, 0xff, 0xff, 0xff, 0x00]),
        ("Huffman excess padding", vec![0x62, 0x1f, 0xff, 0x00]),
        ("Huffman invalid padding", vec![0x61, 0x18, 0x00]),
        // The same in a value after a name reference.
        (
            "Huffman value EOS",
            vec![0xc1, 0x84, 0xff, 0xff, 0xff, 0xff],
        ),
        // The ending of a literal found after its last decoded byte: 'a' is
        // 00011, so the padding after it is 000, which is not the prefix of
        // the EOS code; a second octet of ones is more than seven bits of
        // padding. In a name and in a value.
        ("Huffman name ending", vec![0x61, 0x18]),
        ("Huffman name excess ending", vec![0x62, 0x1f, 0xff]),
        ("Huffman value ending", vec![0x41, b'x', 0x81, 0x18]),
        (
            "Huffman value excess ending",
            vec![0x41, b'x', 0x82, 0x1f, 0xff],
        ),
    ];
    for (name, wire) in cases {
        let (plain, critical) = encoder(&wire);
        assert_eq!(plain, Err(encoder_error()), "{name}: not critical");
        assert_eq!(critical, Err(encoder_error()), "{name}: critical");
    }
}

#[test]
fn a_limit_of_the_callers_choice_has_no_code_on_the_encoder_stream() {
    // The wire budget, in the first octet and in the integer after it; the
    // decoded budget, for a literal name that is too long.
    for (wire, max_wire, max_decoded) in [
        (&[0x3f, 0xbd, 0x01][..], 1, 64),
        (&[0x3f, 0xbd, 0x01], 2, 64),
        (&[0x45, b'a', b'b', b'c', b'd', b'e', 0x00], 64, 2),
    ] {
        assert_eq!(
            encoder_plain(wire, max_wire, max_decoded),
            Err(None),
            "{wire:?}"
        );
    }
}

#[test]
fn an_insertion_beyond_the_table_capacity_is_an_encoder_stream_error_on_the_critical_stream() {
    let defaults = hatate_qpack::encoder_instruction::EncoderStreamLimits::default();
    for (case, wire) in [
        // A raw name of one octet, with no dynamic table: its decoded length.
        ("raw name", &[0x41, b'x', 0x00][..]),
        // A Huffman name of one decoded octet: found as it is decoded.
        ("Huffman name", &[0x61, 0x1f, 0x00]),
        // A raw value of 200 octets after a name reference: its wire length.
        ("value wire", &[0xc1, 0x7f, 0x49]),
        // A name length of at least 31, before its next digit: the least
        // wire length the octets read allow.
        ("name lower bound", &[0x5f, 0xff]),
    ] {
        // The limits of a capacity of 0, the default of both streams.
        assert_eq!(
            encoder_plain(wire, defaults.max_wire_len, defaults.max_decoded_len),
            Err(None),
            "{case}: not critical"
        );
        assert_eq!(
            encoder_critical(wire, 0),
            Err(encoder_error()),
            "{case}: critical"
        );
    }
    // A capacity that leaves room for the raw name admits it.
    assert_eq!(encoder_critical(&[0x41, b'x', 0x00], 33), Err(closed()));
}

#[test]
fn the_end_of_the_encoder_stream_is_closed_if_critical_and_has_no_code_if_not() {
    // At a boundary the stream that is not critical ends well.
    assert_eq!(encoder(&[0x25, 0x01]), (Ok(()), Err(closed())));
    assert_eq!(encoder(&[]), (Ok(()), Err(closed())));
    // Inside an instruction: in an integer, a raw name, a value, a Huffman
    // name.
    for wire in [
        &[0x3f][..],
        &[0x42, b'a'],
        &[0x42, b'a', b'b', 0x02, b'x'],
        &[0xc1, 0x02, b'x'],
        &[0x62, 0x1f],
    ] {
        assert_eq!(encoder(wire), (Err(None), Err(closed())), "{wire:?}");
    }
}

#[test]
fn an_abandoned_encoder_stream_has_no_code() {
    // An instruction that cannot be interpreted, then the next read: it is
    // Interrupted, on both kinds of stream.
    let wire = [0xff, 0x25, 0x00, 0x20];
    let mut plain = EncoderStream::new(ConstructedAccess::new(&wire[..]), Default::default());
    let first = run(next_encoder(&mut plain, 64, 64)).0.unwrap_err();
    assert_eq!(first.error_code(), encoder_error());
    assert_eq!(
        run(next_encoder(&mut plain, 64, 64))
            .0
            .err()
            .unwrap()
            .error_code(),
        None
    );
    let mut critical = QpackEncoderStream::new(ConstructedAccess::new(&wire[..]));
    let first = run(next_critical_encoder(&mut critical, 96)).0.unwrap_err();
    assert_eq!(first.error_code(), encoder_error());
    assert_eq!(
        run(next_critical_encoder(&mut critical, 96))
            .0
            .err()
            .unwrap()
            .error_code(),
        None
    );
}

#[test]
fn an_instruction_that_cannot_be_interpreted_is_a_decoder_stream_error() {
    let mut acknowledgment = Vec::new();
    hatate_qpack::integer::write::<7, _>(
        &mut acknowledgment,
        0x80,
        hatate_qpack::integer::PrefixedField::shortest(hatate_qpack::integer::PrefixedInt::from(
            1u64 << 62,
        )),
    )
    .unwrap();
    let mut cancellation = Vec::new();
    hatate_qpack::integer::write::<6, _>(
        &mut cancellation,
        0x40,
        hatate_qpack::integer::PrefixedField::shortest(hatate_qpack::integer::PrefixedInt::from(
            1u64 << 62,
        )),
    )
    .unwrap();
    let cases: [(&str, Vec<u8>); 6] = [
        // Insert Count Increment of zero.
        ("zero increment", vec![0x00]),
        // A stream ID that is not a stream ID.
        ("acknowledgment stream", acknowledgment),
        ("cancellation stream", cancellation),
        // An integer that goes on for more than ten continuation bytes.
        ("increment integer", endless(0x3f)),
        ("acknowledgment integer", endless(0xff)),
        ("cancellation integer", endless(0x7f)),
    ];
    for (name, wire) in cases {
        let (plain, critical) = decoder(&wire);
        assert_eq!(plain, Err(decoder_error()), "{name}: not critical");
        assert_eq!(critical, Err(decoder_error()), "{name}: critical");
    }
}

#[test]
fn a_limit_the_end_and_an_abandoned_decoder_stream_are_not_interpretation_failures() {
    // The wire budget.
    assert_eq!(decoder_plain(&[0x3f, 0x00], 1), Err(None));
    assert_eq!(decoder_critical(&[0x3f, 0x00], 1), Err(None));
    // The end at a boundary and inside an integer.
    assert_eq!(decoder(&[0x84]), (Ok(()), Err(closed())));
    assert_eq!(decoder(&[]), (Ok(()), Err(closed())));
    assert_eq!(decoder(&[0x3f]), (Err(None), Err(closed())));
    assert_eq!(decoder(&[0x84, 0x7f, 0x80]), (Err(None), Err(closed())));
    // After a failure the stream is abandoned.
    let mut plain = DecoderStream::new(ConstructedAccess::new(&[0x3f][..]), Default::default());
    assert!(run(next_decoder(&mut plain, 16)).0.is_err());
    assert_eq!(
        run(next_decoder(&mut plain, 16))
            .0
            .err()
            .unwrap()
            .error_code(),
        None
    );
    let mut critical = QpackDecoderStream::new(ConstructedAccess::new(&[0x00][..]));
    assert_eq!(
        run(next_critical_decoder(&mut critical, 16))
            .0
            .err()
            .unwrap()
            .error_code(),
        decoder_error()
    );
    assert_eq!(
        run(next_critical_decoder(&mut critical, 16))
            .0
            .err()
            .unwrap()
            .error_code(),
        None
    );
}
