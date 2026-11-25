#![feature(impl_trait_in_assoc_type)]
//! SETTINGS (RFC 9114 §7.2.4) with the parts of HTTP/3 alone.
mod common;

use common::{Dribble, run};
use core::convert::Infallible;
use frunk_core::{
    HList,
    coproduct::{CoprodInjector, CoproductSelector},
};
use hatate_wire::{
    Part, Role,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{FrameWidths, Http3FrameType, payload::PayloadError},
    settings::{
        Http2SettingIdentifier, Keyed, KeyedSetting, MaxFieldSectionSize, Setting, UnknownSetting,
        codec::{
            ReadSettingError, ReadSettingExt as _, SettingsFrame, SettingsFrameError,
            WriteSettingsFrameHostExt as _,
        },
        set::{SettingList, Settings, SettingsOf, SettingsPart},
    },
    stream::{FrameStream, kind::ControlStreamKind},
};
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type Parts = HList![Part];
type List = <Parts as SettingsOf>::Settings;
type Item = Setting<<List as SettingList>::Setting>;
type Error = ReadSettingError<PayloadError<Infallible>, <List as SettingList>::ValueErrors>;

/// Reads one whole SETTINGS frame into `settings`, and finishes its payload
/// when every setting was read.
#[call(sync)]
async fn read_settings<L: SettingList, F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    settings: &mut Settings<L>,
) -> Result<Vec<Setting<L::Setting>>, ReadSettingError<PayloadError<F::Error>, L::ValueErrors>> {
    let Ok(Some(mut stream)) =
        FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Server).await
    else {
        panic!("no frame head");
    };
    let mut head = stream.frame();
    assert_eq!(head.frame_type().value(), Http3FrameType::Settings.value());
    let mut read = Vec::new();
    while let Some(setting) = head.payload().read_setting(settings).await? {
        read.push(setting);
    }
    assert_eq!(
        stream.frame().into_payload().into_parts().1.remaining(),
        0,
        "the payload was read to its end"
    );
    Ok(read)
}

/// The widths of Type and Length of the frame at the start of the stream.
#[call(sync)]
async fn head_widths<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> FrameWidths
where
    <F as Read>::Error: core::fmt::Debug,
{
    FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Server)
        .await
        .unwrap()
        .unwrap()
        .frame()
        .widths()
}

fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 64);
    [&[0x04, payload.len() as u8][..], payload].concat()
}

fn read_into(payload: &[u8], settings: &mut Settings<List>) -> Result<Vec<Item>, Error> {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(settings)
}

fn read(payload: &[u8]) -> Result<Vec<Item>, Error> {
    read_into(payload, &mut Settings::new())
}

/// The setting of the type `T` that `setting` holds.
fn known<T: Copy, I>(setting: &Item) -> Keyed<T>
where
    <List as SettingList>::Setting: CoproductSelector<Keyed<T>, I>,
{
    match setting {
        Setting::Known(known) => *known.get::<Keyed<T>, I>().expect("a setting of the type"),
        Setting::Unknown(other) => panic!("not a known setting: {other:?}"),
    }
}

fn keyed<T: KeyedSetting, I>(setting: T) -> Item
where
    <List as SettingList>::Setting: CoprodInjector<Keyed<T>, I>,
{
    Setting::Known(<List as SettingList>::Setting::inject(Keyed::new(setting)))
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
    let mut settings = Settings::new();
    let read = read_into(
        &[
            0x01, 0x40, 0x40, // QPACK_MAX_TABLE_CAPACITY = 0x40, two bytes
            0x40, 0x06, 0x80, 0x00, 0x01, 0x00, // MAX_FIELD_SECTION_SIZE (2-byte id) = 256
            0x07, 0x00, // QPACK_BLOCKED_STREAMS = 0
        ],
        &mut settings,
    )
    .unwrap();
    assert_eq!(read.len(), 3);
    let first = known::<QpackMaxTableCapacity, _>(&read[0]);
    assert_eq!(first.identifier(), value_field(0x01, VarIntWidth::One));
    assert_eq!(first.setting().value(), value_field(0x40, VarIntWidth::Two));
    let second = known::<MaxFieldSectionSize, _>(&read[1]);
    assert_eq!(second.identifier_width(), VarIntWidth::Two);
    assert_eq!(second.identifier(), value_field(0x06, VarIntWidth::Two));
    assert_eq!(
        second.setting().value(),
        value_field(256, VarIntWidth::Four)
    );
    let third = known::<QpackBlockedStreams, _>(&read[2]);
    assert_eq!(third.setting().value(), value_field(0, VarIntWidth::One));
    // The slots hold what was read.
    assert_eq!(
        settings.get::<QpackMaxTableCapacity, _>(),
        Some(first.setting())
    );
    assert_eq!(
        settings.get::<MaxFieldSectionSize, _>(),
        Some(second.setting())
    );
    assert_eq!(
        settings.get::<QpackBlockedStreams, _>(),
        Some(third.setting())
    );
}

#[test]
fn an_absent_setting_has_an_empty_slot() {
    let mut settings = Settings::new();
    read_into(&[0x06, 0x10], &mut settings).unwrap();
    assert_eq!(
        settings
            .get::<MaxFieldSectionSize, _>()
            .unwrap()
            .value()
            .get()
            .get(),
        0x10
    );
    assert!(settings.get::<QpackMaxTableCapacity, _>().is_none());
    assert!(settings.get::<QpackBlockedStreams, _>().is_none());
    assert_eq!(Settings::<List>::default(), Settings::new());
}

#[test]
fn reserved_zero_and_undefined_identifiers_are_unknown_and_not_kept() {
    // 0x21 and 0x40 (two bytes) are of the form 0x1f * N + 0x21; 0x00 is
    // reserved; 0x0b is undefined.
    let mut settings = Settings::new();
    let read = read_into(
        &[
            0x21, 0x05, 0x40, 0x40, 0x00, 0x00, 0x21, 0x0b, 0x01, 0x07, 0x00,
        ],
        &mut settings,
    )
    .unwrap();
    assert_eq!(read.len(), 5);
    let expected = [
        (0x21, VarIntWidth::One, 5),
        (0x40, VarIntWidth::Two, 0),
        (0x00, VarIntWidth::One, 0x21),
        (0x0b, VarIntWidth::One, 1),
    ];
    for (setting, (identifier, width, value)) in read.iter().zip(expected) {
        let setting = unknown(setting);
        assert_eq!(setting.identifier().get().get(), identifier);
        assert_eq!(setting.identifier().width(), width);
        assert_eq!(setting.value().get().get(), value);
    }
    // The known setting after them is still read, and is the only one kept.
    known::<QpackBlockedStreams, _>(&read[4]);
    let mut only_blocked = Settings::<List>::new();
    read_into(&[0x07, 0x00], &mut only_blocked).unwrap();
    assert_eq!(settings, only_blocked);
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
                matches!(&error, ReadSettingError::Http2Identifier { source } if source.identifier() == expected),
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
        let mut settings = Settings::new();
        let error = read_into(&payload, &mut settings).unwrap_err();
        assert!(
            matches!(&error, ReadSettingError::Duplicate { source }
                if source.identifier().get() == u64::from(*identifier.last().unwrap())),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
        // The slot keeps the first.
        let kept = [
            settings
                .get::<QpackMaxTableCapacity, _>()
                .map(|s| s.value()),
            settings.get::<MaxFieldSectionSize, _>().map(|s| s.value()),
            settings.get::<QpackBlockedStreams, _>().map(|s| s.value()),
        ];
        assert_eq!(
            kept.iter()
                .flatten()
                .map(|value| value.get().get())
                .collect::<Vec<_>>(),
            [0]
        );
    }
}

#[test]
fn a_new_set_of_settings_takes_each_identifier_again() {
    let wire = frame(&[0x06, 0x01]);
    let mut settings = Settings::<List>::new();
    (&wire[..]).sync_read_settings_unpin(&mut settings).unwrap();
    assert!(matches!(
        (&wire[..]).sync_read_settings_unpin(&mut settings),
        Err(ReadSettingError::Duplicate { .. })
    ));
    (&wire[..])
        .sync_read_settings_unpin(&mut Settings::<List>::new())
        .unwrap();
}

#[test]
fn repeated_unknown_identifiers_are_not_an_error() {
    let read = read(&[0x21, 0x00, 0x21, 0x01, 0x00, 0x00, 0x00, 0x02]).unwrap();
    assert_eq!(read.len(), 4);
    assert_eq!(unknown(&read[1]).value().get().get(), 1);
}

#[test]
fn a_payload_that_ends_between_the_pair_is_a_frame_error() {
    // Identifier only; the Length cuts the pair although the stream goes on.
    let mut wire = frame(&[0x01]);
    wire.extend([0x00, 0x04, 0x00]);
    let error = (&wire[..])
        .sync_read_settings_unpin(&mut Settings::<List>::new())
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
fn a_stream_that_ends_inside_the_payload_is_a_frame_error() {
    let wire = [0x04, 0x04, 0x06, 0x01];
    let error = (&wire[..])
        .sync_read_settings_unpin(&mut Settings::<List>::new())
        .unwrap_err();
    assert!(
        matches!(&error, ReadSettingError::Identifier { source }
            if matches!(source.host_error(), Some(PayloadError::Truncated { .. }))),
        "{error:?}"
    );
    assert_eq!(error.error_code(), Some(ErrorCode::H3_FRAME_ERROR));
}

#[test]
fn an_empty_settings_frame_has_no_settings() {
    assert!(read(&[]).unwrap().is_empty());
}

fn built(
    settings: Vec<Item>,
    widths: FrameWidths,
) -> Result<SettingsFrame<List>, SettingsFrameError> {
    SettingsFrame::new(settings, widths)
}

fn write(frame: &SettingsFrame<List>) -> Vec<u8> {
    let mut out = Vec::new();
    out.sync_write_settings_frame_unpin(frame).unwrap();
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
        peek.sync_head_widths_unpin()
    };
    assert_eq!(
        head_widths,
        FrameWidths::new(VarIntWidth::Two, VarIntWidth::Four)
    );
    let read = input
        .sync_read_settings_unpin(&mut Settings::<List>::new())
        .unwrap();
    assert!(input.is_empty());
    let frame = built(read, head_widths).unwrap();
    assert_eq!(frame.payload_len(), 19);
    assert_eq!(frame.widths(), head_widths);
    assert_eq!(frame.settings().len(), 4);
    assert_eq!(write(&frame), wire);
}

#[test]
fn each_setting_of_http3_is_written_and_read_back() {
    let value = value_field(0x1234, VarIntWidth::Eight);
    for (setting, identifier) in [
        (keyed(QpackMaxTableCapacity::new(value)), 0x01),
        (keyed(MaxFieldSectionSize::new(value)), 0x06),
        (keyed(QpackBlockedStreams::new(value)), 0x07),
    ] {
        let frame = built(vec![setting], FrameWidths::SHORTEST).unwrap();
        let wire = write(&frame);
        assert_eq!(wire, [0x04, 9, identifier, 0xc0, 0, 0, 0, 0, 0, 0x12, 0x34]);
        let mut input = &wire[..];
        let read = input
            .sync_read_settings_unpin(&mut Settings::<List>::new())
            .unwrap();
        assert_eq!(read, [setting]);
    }
}

#[test]
fn a_frame_of_new_settings_is_written_in_order() {
    let settings = vec![
        keyed(MaxFieldSectionSize::new(VarIntField::shortest(
            VarInt::from_u32(0x1000),
        ))),
        Setting::Unknown(
            UnknownSetting::new(
                VarIntField::shortest(VarInt::from_u32(0x21)),
                VarIntField::shortest(VarInt::from_u32(0)),
            )
            .unwrap(),
        ),
        Setting::Known(<List as SettingList>::Setting::inject(
            Keyed::with_identifier_width(
                QpackBlockedStreams::new(VarIntField::shortest(VarInt::from_u32(1))),
                VarIntWidth::Eight,
            )
            .unwrap(),
        )),
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
        .sync_read_settings_unpin(&mut Settings::<List>::new())
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
    let max = || {
        keyed(MaxFieldSectionSize::new(VarIntField::shortest(
            VarInt::ZERO,
        )))
    };
    let error = built(vec![max(), max()], FrameWidths::SHORTEST).unwrap_err();
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
        matches!(error, SettingsFrameError::Length { .. }),
        "{error:?}"
    );
    let wide = built(many, FrameWidths::new(VarIntWidth::One, VarIntWidth::Two)).unwrap();
    assert!(wide.payload_len() > 63);
    let wire = write(&wide);
    assert_eq!(wire.len() as u64, 1 + 2 + wide.payload_len());
}

#[test]
fn unknown_settings_cannot_be_the_identifiers_of_http2() {
    for (identifier, expected) in [
        (0x02, Http2SettingIdentifier::EnablePush),
        (0x03, Http2SettingIdentifier::MaxConcurrentStreams),
        (0x04, Http2SettingIdentifier::InitialWindowSize),
        (0x05, Http2SettingIdentifier::MaxFrameSize),
    ] {
        for width in VarIntWidth::ALL {
            let error = UnknownSetting::new(
                value_field(identifier, width),
                value_field(0, VarIntWidth::One),
            )
            .unwrap_err();
            assert_eq!(error.identifier(), expected);
            assert_eq!(error.identifier().value().get(), u64::from(identifier));
            assert_eq!(
                error,
                hatate_wire::settings::Http2SettingIdentifierError::new(expected)
            );
        }
    }
    assert!(
        UnknownSetting::new(
            value_field(0, VarIntWidth::One),
            value_field(0, VarIntWidth::One)
        )
        .is_ok()
    );
}

#[test]
fn a_pending_between_every_byte_changes_nothing() {
    let wire = [
        0x04, 0x0b, 0x40, 0x01, 0x40, 0x40, 0x21, 0x00, 0x06, 0x80, 0, 0, 0x10, 0xff,
    ];
    let mut expected_settings = Settings::<List>::new();
    let expected = (&wire[..])
        .sync_read_settings_unpin(&mut expected_settings)
        .unwrap();
    let mut host = Dribble::new(&wire, 1);
    let mut settings = Settings::<List>::new();
    let (read, pending) = run(host.read_settings_unpin(&mut settings));
    assert_eq!(read.unwrap(), expected);
    assert_eq!(settings, expected_settings);
    assert!(pending >= wire.len() - 1, "{pending}");
    assert_eq!(host.rest(), [0xff]);
}

#[test]
fn an_unknown_setting_cannot_take_an_identifier_a_type_claims() {
    let unknown = |identifier: u32, width| {
        Setting::Unknown(
            UnknownSetting::new(
                value_field(identifier, width),
                value_field(0, VarIntWidth::One),
            )
            .unwrap(),
        )
    };
    // MAX_FIELD_SECTION_SIZE and the two settings of QPACK, in any width.
    for identifier in [0x01, 0x06, 0x07] {
        for width in [VarIntWidth::Two, VarIntWidth::Four, VarIntWidth::Eight] {
            let error = built(vec![unknown(identifier, width)], FrameWidths::SHORTEST).unwrap_err();
            assert!(
                matches!(&error, SettingsFrameError::ClaimedIdentifier { identifier: found }
                    if found.get() == u64::from(identifier)),
                "{error:?}"
            );
        }
    }
    // Where the claimed identifier comes second the first is fine.
    let error = built(
        vec![
            unknown(0x22, VarIntWidth::One),
            unknown(0x06, VarIntWidth::One),
        ],
        FrameWidths::SHORTEST,
    )
    .unwrap_err();
    assert!(
        matches!(error, SettingsFrameError::ClaimedIdentifier { .. }),
        "{error:?}"
    );
    // Identifiers that no type claims are accepted, reserved or not.
    for identifier in [0x00, 0x08, 0x0a, 0x21, 0x33, 0x40] {
        let frame = built(
            vec![unknown(identifier, VarIntWidth::Two)],
            FrameWidths::SHORTEST,
        )
        .unwrap_or_else(|error| panic!("{identifier:#x}: {error:?}"));
        assert_eq!(frame.settings().len(), 1);
    }
}

#[test]
fn a_stream_that_ends_between_the_pair_is_a_frame_error_too() {
    // After the identifier, inside the value, and inside a later identifier.
    for wire in [
        &[0x04, 0x02, 0x06, 0x80][..],
        &[0x04, 0x05, 0x06, 0x01, 0x07, 0x80, 0x00][..],
        &[0x04, 0x03, 0x06, 0x01, 0x40][..],
    ] {
        let error = (&wire[..])
            .sync_read_settings_unpin(&mut Settings::<List>::new())
            .unwrap_err();
        assert!(
            matches!(&error, ReadSettingError::Identifier { source } | ReadSettingError::Value { source }
                if matches!(source.host_error(), Some(PayloadError::Truncated { .. }))
                    || source.is_incomplete()),
            "{error:?}"
        );
        assert_eq!(
            error.error_code(),
            Some(ErrorCode::H3_FRAME_ERROR),
            "{wire:x?}"
        );
    }
}

/// A setting type with the identifier `IDENTIFIER` and any value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Probe<const IDENTIFIER: u32>(VarIntField<VarInt>);

impl<const IDENTIFIER: u32> KeyedSetting for Probe<IDENTIFIER> {
    type ValueError = Infallible;
    const IDENTIFIER: VarInt = VarInt::from_u32(IDENTIFIER);

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, Infallible> {
        Ok(Self(value))
    }

    fn value(&self) -> VarIntField<VarInt> {
        self.0
    }
}

#[test]
fn an_identifier_width_must_hold_the_identifier() {
    let probe = Probe::<0x4000>(VarIntField::shortest(VarInt::ZERO));
    assert_eq!(Keyed::new(probe).identifier_width(), VarIntWidth::Four);
    for width in [VarIntWidth::One, VarIntWidth::Two] {
        let error = Keyed::with_identifier_width(probe, width).unwrap_err();
        assert_eq!(error.width(), width);
        assert_eq!(error.value().get(), 0x4000);
    }
    let keyed = Keyed::with_identifier_width(probe, VarIntWidth::Eight).unwrap();
    assert_eq!(keyed.identifier(), value_field(0x4000, VarIntWidth::Eight));
    assert_eq!(keyed.into_setting(), probe);
}

/// A part with one setting type, `Probe<IDENTIFIER>`.
struct ProbePart<const IDENTIFIER: u32>;

impl<const IDENTIFIER: u32> SettingsPart for ProbePart<IDENTIFIER> {
    type Settings = HList![Probe<IDENTIFIER>];
}

#[test]
fn the_lists_of_the_parts_are_joined_in_order_and_checked_for_repeats() {
    type Joined = <HList![Part, ProbePart<0x0a>, ProbePart<0x0b>] as SettingsOf>::Settings;
    let _: core::marker::PhantomData<Joined> = core::marker::PhantomData::<
        HList![
            QpackMaxTableCapacity,
            MaxFieldSectionSize,
            QpackBlockedStreams,
            Probe<0x0a>,
            Probe<0x0b>
        ],
    >;
    for identifier in [0x01, 0x06, 0x07, 0x0a, 0x0b] {
        assert!(Joined::IDENTIFIERS.contains(VarInt::from_u32(identifier)));
    }
    assert!(!Joined::IDENTIFIERS.contains(VarInt::from_u32(0x08)));
    const {
        assert!(Joined::CLAIMS_VALID);
        assert!(List::CLAIMS_VALID);
        // A repeat across parts, and within one list.
        assert!(
            !<<HList![Part, ProbePart<0x06>] as SettingsOf>::Settings as SettingList>::CLAIMS_VALID
        );
        assert!(!<<HList![ProbePart<0x0a>, ProbePart<0x0a>] as SettingsOf>::Settings as SettingList>::CLAIMS_VALID);
        assert!(!<HList![MaxFieldSectionSize, MaxFieldSectionSize] as SettingList>::CLAIMS_VALID);
        // Reserved identifiers: 0x00, those of HTTP/2, and 0x1f * N + 0x21.
        assert!(!<HList![Probe<0x00>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x02>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x03>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x04>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x05>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x21>] as SettingList>::CLAIMS_VALID);
        assert!(!<HList![Probe<0x40>] as SettingList>::CLAIMS_VALID);
        assert!(<HList![Probe<0x22>] as SettingList>::CLAIMS_VALID);
    }
}
