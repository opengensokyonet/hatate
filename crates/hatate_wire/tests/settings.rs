#![feature(impl_trait_in_assoc_type)]
//! SETTINGS (RFC 9114 §7.2.4) with the parts of HTTP/3 alone.
mod common;

use common::{Dribble, run};
use core::{convert::Infallible, marker::PhantomData};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Part,
    defaults::RejectKnownDuplicates,
    error_code::ErrorCode,
    frame::{
        FrameType, FrameWidths, Http3FrameType, codec::ReadFrameHeadExt as _, payload::PayloadError,
    },
    settings::{
        Http2SettingIdentifier, Http3Setting, Http3SettingIdentifier, Setting, UnknownSetting,
        codec::{
            DuplicateSettingError, DuplicateSettingPolicy, ReadSettingError, ReadSettingExt as _,
            SettingsFrame, SettingsFrameError, WriteSettingsFrameHostExt as _,
        },
        set::SettingsSet,
    },
};
use hatate_wire_qpack::QpackSettingIdentifier;
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![Part];
type Item = Setting<<Parts as SettingsSet>::Setting>;
type Error = ReadSettingError<PayloadError<Infallible>, <Parts as SettingsSet>::ValueError>;

/// Reads one whole SETTINGS frame with `policy`, and finishes its payload
/// when every setting was read.
#[call(sync)]
async fn read_settings<P, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    policy: &mut P,
) -> Result<
    Vec<Setting<<P::Parts as SettingsSet>::Setting>>,
    ReadSettingError<PayloadError<F::Error>, <P::Parts as SettingsSet>::ValueError>,
>
where
    P: DuplicateSettingPolicy,
{
    let Ok(Some(head)) = io.read_frame_head(PhantomData::<Parts>).await else {
        panic!("no frame head");
    };
    assert_eq!(
        head.frame_type(),
        FrameType::Known(Coproduct::Inl(Http3FrameType::Settings))
    );
    let mut payload = head.payload();
    let mut settings = Vec::new();
    {
        let mut source = io.compose(&mut payload);
        while let Some(setting) = source.read_setting(policy).await? {
            settings.push(setting);
        }
    }
    payload.finish().expect("the payload was read to its end");
    Ok(settings)
}

fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 64);
    [&[0x04, payload.len() as u8][..], payload].concat()
}

fn read(payload: &[u8]) -> Result<Vec<Item>, Error> {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
}

fn http3(setting: &Item) -> Http3Setting {
    match setting {
        Setting::Known(Coproduct::Inl(setting)) => *setting,
        other => panic!("not a setting of HTTP/3: {other:?}"),
    }
}

fn unknown(setting: &Item) -> UnknownSetting {
    match setting {
        Setting::Unknown(setting) => *setting,
        other => panic!("not an unknown setting: {other:?}"),
    }
}

fn value_field(value: u32, width: VarIntWidth) -> VarIntField<VarInt> {
    VarIntField::new(VarInt::from_u32(value), width).unwrap()
}

#[test]
fn settings_of_http3_are_read_with_their_widths() {
    let settings = read(&[
        0x01, 0x40, 0x40, // QPACK_MAX_TABLE_CAPACITY = 0x40, two bytes
        0x40, 0x06, 0x80, 0x00, 0x01, 0x00, // MAX_FIELD_SECTION_SIZE (2-byte id) = 256
        0x07, 0x00, // QPACK_BLOCKED_STREAMS = 0
    ])
    .unwrap();
    assert_eq!(settings.len(), 3);
    let first = http3(&settings[0]);
    assert_eq!(
        first.identifier(),
        Http3SettingIdentifier::Qpack(QpackSettingIdentifier::MaxTableCapacity)
    );
    assert_eq!(first.identifier_width(), VarIntWidth::One);
    assert_eq!(first.value(), value_field(0x40, VarIntWidth::Two));
    let second = http3(&settings[1]);
    assert_eq!(
        second.identifier(),
        Http3SettingIdentifier::MaxFieldSectionSize
    );
    assert_eq!(second.identifier_width(), VarIntWidth::Two);
    assert_eq!(second.value(), value_field(256, VarIntWidth::Four));
    let third = http3(&settings[2]);
    assert_eq!(
        third.identifier(),
        Http3SettingIdentifier::Qpack(QpackSettingIdentifier::BlockedStreams)
    );
    assert_eq!(third.value(), value_field(0, VarIntWidth::One));
}

#[test]
fn reserved_zero_and_undefined_identifiers_are_unknown() {
    // 0x21 and 0x40 (two bytes) are of the form 0x1f * N + 0x21; 0x00 is
    // reserved; 0x0b is undefined.
    let settings = read(&[
        0x21, 0x05, 0x40, 0x40, 0x00, 0x00, 0x21, 0x0b, 0x01, 0x07, 0x00,
    ])
    .unwrap();
    assert_eq!(settings.len(), 5);
    let expected = [
        (0x21, VarIntWidth::One, 5),
        (0x40, VarIntWidth::Two, 0),
        (0x00, VarIntWidth::One, 0x21),
        (0x0b, VarIntWidth::One, 1),
    ];
    for (setting, (identifier, width, value)) in settings.iter().zip(expected) {
        let setting = unknown(setting);
        assert_eq!(setting.identifier().get().get(), identifier);
        assert_eq!(setting.identifier().width(), width);
        assert_eq!(setting.value().get().get(), value);
    }
    // The known setting after them is still read.
    assert_eq!(
        http3(&settings[4]).identifier(),
        Http3SettingIdentifier::Qpack(QpackSettingIdentifier::BlockedStreams)
    );
}

#[test]
fn identifiers_of_http2_are_a_settings_error() {
    for (identifier, expected) in [
        (0x02, Http2SettingIdentifier::EnablePush),
        (0x03, Http2SettingIdentifier::MaxConcurrentStreams),
        (0x04, Http2SettingIdentifier::InitialWindowSize),
        (0x05, Http2SettingIdentifier::MaxFrameSize),
    ] {
        for payload in [
            vec![identifier, 0x01],
            vec![0x40, identifier, 0x01],
            // Rejected at the identifier, before the value is read.
            vec![identifier],
        ] {
            let error = read(&payload).unwrap_err();
            assert!(
                matches!(&error, ReadSettingError::Http2Identifier { identifier } if *identifier == expected),
                "{error:?}"
            );
            assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
        }
    }
}

#[test]
fn a_repeated_known_identifier_is_a_settings_error() {
    for (identifier, again) in [
        (vec![0x01], vec![0x01]),
        (vec![0x06], vec![0x06]),
        (vec![0x07], vec![0x07]),
        // The same identifier in another encoding is the same identifier.
        (vec![0x06], vec![0x40, 0x06]),
        (vec![0x80, 0, 0, 0x07], vec![0x07]),
    ] {
        let payload = [identifier.clone(), vec![0x00], again, vec![0x01]].concat();
        let error = read(&payload).unwrap_err();
        assert!(
            matches!(&error, ReadSettingError::Duplicate { source }
                if source.identifier().get() == u64::from(*identifier.last().unwrap())),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
    }
}

#[test]
fn repeated_unknown_identifiers_are_not_an_error() {
    let settings = read(&[0x21, 0x00, 0x21, 0x01, 0x00, 0x00, 0x00, 0x02]).unwrap();
    assert_eq!(settings.len(), 4);
    assert_eq!(unknown(&settings[1]).value().get().get(), 1);
}

#[test]
fn a_payload_that_ends_between_the_pair_is_a_frame_error() {
    // Identifier only; the Length cuts the pair although the stream goes on.
    let mut wire = frame(&[0x01]);
    wire.extend([0x00, 0x04, 0x00]);
    let error = (&wire[..])
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
        .unwrap_err();
    assert!(matches!(error, ReadSettingError::Value { .. }), "{error:?}");
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));

    // Inside the identifier.
    let error = read(&[0x40]).unwrap_err();
    assert!(
        matches!(error, ReadSettingError::Identifier { .. }),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));

    // Inside the value, after a complete setting.
    let error = read(&[0x06, 0x01, 0x07, 0x80, 0x00]).unwrap_err();
    assert!(matches!(error, ReadSettingError::Value { .. }), "{error:?}");
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn a_stream_that_ends_inside_the_payload_has_no_connection_error_of_its_own() {
    let wire = [0x04, 0x04, 0x06, 0x01];
    let error = (&wire[..])
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
        .unwrap_err();
    assert!(
        matches!(&error, ReadSettingError::Identifier { source }
            if matches!(source.host_error(), Some(PayloadError::Truncated { .. }))),
        "{error:?}"
    );
    assert_eq!(error.error_code(), None);
}

#[test]
fn an_empty_settings_frame_has_no_settings() {
    assert!(read(&[]).unwrap().is_empty());
}

struct AcceptAll;

impl DuplicateSettingPolicy for AcceptAll {
    type Parts = Parts;
    fn check(&mut self, _setting: &Item) -> Result<(), DuplicateSettingError> {
        Ok(())
    }
}

#[test]
fn the_duplicate_policy_can_be_replaced() {
    let wire = frame(&[0x06, 0x01, 0x06, 0x02, 0x01, 0x00, 0x01, 0x00]);
    let settings = (&wire[..])
        .sync_read_settings_unpin(&mut AcceptAll)
        .unwrap();
    assert_eq!(settings.len(), 4);
    assert_eq!(http3(&settings[0]).value().get().get(), 1);
    assert_eq!(http3(&settings[1]).value().get().get(), 2);
    // The default policy rejects the same frame.
    assert!(matches!(
        (&wire[..]).sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new()),
        Err(ReadSettingError::Duplicate { .. })
    ));
}

#[test]
fn a_policy_that_rejects_everything_is_honoured() {
    struct RejectAll;
    impl DuplicateSettingPolicy for RejectAll {
        type Parts = Parts;
        fn check(&mut self, _setting: &Item) -> Result<(), DuplicateSettingError> {
            Err(DuplicateSettingError::new(VarInt::from_u32(9)))
        }
    }
    let wire = frame(&[0x21, 0x00]);
    let error = (&wire[..])
        .sync_read_settings_unpin(&mut RejectAll)
        .unwrap_err();
    assert!(
        matches!(&error, ReadSettingError::Duplicate { source } if source.identifier().get() == 9)
    );
}

fn built(
    settings: Vec<Item>,
    widths: FrameWidths,
) -> Result<SettingsFrame<<Parts as SettingsSet>::Setting>, SettingsFrameError> {
    SettingsFrame::new::<Parts>(settings, widths)
}

fn write(frame: &SettingsFrame<<Parts as SettingsSet>::Setting>) -> Vec<u8> {
    let mut out = Vec::new();
    out.sync_write_settings_frame_unpin(frame, PhantomData::<Parts>)
        .unwrap();
    out
}

#[test]
fn written_frames_read_back_with_the_same_bytes() {
    // Non-shortest widths everywhere: Type, Length, identifiers and values.
    let wire = vec![
        0x40, 0x04, 0x80, 0, 0, 0x13, // SETTINGS, Length 19 in four bytes
        0x40, 0x01, 0x80, 0, 0x04, 0x00, // QPACK_MAX_TABLE_CAPACITY = 1024
        0x06, 0xc0, 0, 0, 0, 0, 0, 0x10, 0x00, // MAX_FIELD_SECTION_SIZE = 4096
        0x21, 0x00, // reserved
        0x07, 0x05, // QPACK_BLOCKED_STREAMS = 5
    ];
    let mut input = &wire[..];
    let head_widths = {
        let mut peek = &wire[..];
        use hatate_wire::frame::codec::ReadFrameHeadHostExt as _;
        peek.sync_read_frame_head_unpin(PhantomData::<Parts>)
            .unwrap()
            .unwrap()
            .widths()
    };
    assert_eq!(
        head_widths,
        FrameWidths::new(VarIntWidth::Two, VarIntWidth::Four)
    );
    let settings = input
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
        .unwrap();
    assert!(input.is_empty());
    let frame = built(settings, head_widths).unwrap();
    assert_eq!(frame.payload_len(), 19);
    assert_eq!(frame.widths(), head_widths);
    assert_eq!(frame.settings().len(), 4);
    assert_eq!(write(&frame), wire);
}

#[test]
fn a_frame_of_new_settings_is_written_in_order() {
    let settings = vec![
        Setting::Known(Coproduct::Inl(Http3Setting::new(
            Http3SettingIdentifier::MaxFieldSectionSize,
            VarIntField::shortest(VarInt::from_u32(0x1000)),
        ))),
        Setting::Unknown(
            UnknownSetting::new(
                VarIntField::shortest(VarInt::from_u32(0x21)),
                VarIntField::shortest(VarInt::from_u32(0)),
            )
            .unwrap(),
        ),
        Setting::Known(Coproduct::Inl(Http3Setting::with_identifier_width(
            Http3SettingIdentifier::Qpack(QpackSettingIdentifier::BlockedStreams),
            VarIntWidth::Eight,
            VarIntField::shortest(VarInt::from_u32(1)),
        ))),
    ];
    let frame = built(settings.clone(), FrameWidths::SHORTEST).unwrap();
    let wire = write(&frame);
    assert_eq!(
        wire,
        [
            &[0x04, 14, 0x06, 0x50, 0x00, 0x21, 0x00][..],
            &[0xc0, 0, 0, 0, 0, 0, 0, 0x07, 0x01],
        ]
        .concat()
    );
    let mut input = &wire[..];
    let read = input
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
        .unwrap();
    assert_eq!(read, settings);
}

#[test]
fn a_frame_refuses_a_repeated_identifier_even_if_unknown() {
    let setting = |identifier: u32, width| {
        Setting::Unknown(
            UnknownSetting::new(
                value_field(identifier, width),
                value_field(0, VarIntWidth::One),
            )
            .unwrap(),
        )
    };
    let error = built(
        vec![
            setting(0x21, VarIntWidth::One),
            setting(0x21, VarIntWidth::Two),
        ],
        FrameWidths::SHORTEST,
    )
    .unwrap_err();
    assert!(
        matches!(&error, SettingsFrameError::Duplicate { source } if source.identifier().get() == 0x21),
        "{error:?}"
    );
    let known = |identifier| {
        Setting::Known(Coproduct::Inl(Http3Setting::new(
            identifier,
            VarIntField::shortest(VarInt::from_u32(0)),
        )))
    };
    let error = built(
        vec![
            known(Http3SettingIdentifier::MaxFieldSectionSize),
            known(Http3SettingIdentifier::MaxFieldSectionSize),
        ],
        FrameWidths::SHORTEST,
    )
    .unwrap_err();
    assert!(
        matches!(error, SettingsFrameError::Duplicate { .. }),
        "{error:?}"
    );
}

#[test]
fn a_length_that_does_not_fit_its_width_is_refused() {
    // Each setting takes three bytes: 21 of them make 63, 22 make 66.
    let settings = |count: u32| -> Vec<Item> {
        (0..count)
            .map(|n| {
                Setting::Unknown(
                    UnknownSetting::new(
                        VarIntField::shortest(VarInt::from_u32(0x21 + 0x1f * n)),
                        value_field(0, VarIntWidth::One),
                    )
                    .unwrap(),
                )
            })
            .collect()
    };
    // Identifiers 0x21 and 0x40 take one and two bytes: count the length.
    let fits = built(settings(2), FrameWidths::SHORTEST).unwrap();
    assert_eq!(fits.payload_len(), 2 + 3);
    let many = settings(30);
    let error = built(many.clone(), FrameWidths::SHORTEST).unwrap_err();
    assert!(
        matches!(error, SettingsFrameError::LengthWidth { .. }),
        "{error:?}"
    );
    let wide = built(many, FrameWidths::new(VarIntWidth::One, VarIntWidth::Two)).unwrap();
    assert!(wide.payload_len() > 63);
    let wire = write(&wide);
    assert_eq!(wire.len() as u64, 1 + 2 + wide.payload_len());
}

#[test]
fn unknown_settings_cannot_be_the_identifiers_of_http2() {
    for identifier in 0x02..=0x05 {
        assert!(
            UnknownSetting::new(
                value_field(identifier, VarIntWidth::One),
                value_field(0, VarIntWidth::One)
            )
            .is_none()
        );
    }
    assert!(
        UnknownSetting::new(
            value_field(0, VarIntWidth::One),
            value_field(0, VarIntWidth::One)
        )
        .is_some()
    );
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let wire = [
        0x04, 0x0b, 0x40, 0x01, 0x40, 0x40, 0x21, 0x00, 0x06, 0x80, 0, 0, 0x10, 0xff,
    ];
    let expected = (&wire[..])
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Parts>::new())
        .unwrap();
    let mut host = Dribble::new(&wire, 1);
    let mut policy = RejectKnownDuplicates::<Parts>::new();
    let (settings, pending) = run(host.read_settings_unpin(&mut policy));
    assert_eq!(settings.unwrap(), expected);
    assert!(pending >= wire.len() - 1, "{pending}");
    assert_eq!(host.rest(), [0xff]);
}
