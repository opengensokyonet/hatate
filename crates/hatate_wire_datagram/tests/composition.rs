#![feature(impl_trait_in_assoc_type)]
//! The parts of HTTP/3, HTTP Datagrams and Extended CONNECT in one list
//! (RFC 9114 §9, RFC 9297 §2.1.1, RFC 8441 §3, RFC 9220 §3).
use core::{convert::Infallible, marker::PhantomData};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    defaults::RejectKnownDuplicates,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameType, FrameWidths, Http3FrameType,
        codec::{ReadFrameHeadExt as _, ReadFrameHeadHostExt as _},
        payload::PayloadError,
        set::FrameSet,
    },
    settings::{
        Http3Setting, Http3SettingIdentifier, Setting,
        codec::{
            DuplicateSettingPolicy, ReadSettingError, ReadSettingExt as _, SettingsFrame,
            WriteSettingsFrameHostExt as _,
        },
        set::SettingsSet,
    },
    stream_type::{StreamType, StreamTypeSet, codec::ReadStreamTypeHostExt as _},
};
use hatate_wire_datagram::{H3DatagramSetting, H3DatagramValueError};
use hatate_wire_extended_connect::{EnableConnectProtocolSetting, EnableConnectProtocolValueError};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

type All = HList![
    hatate_wire::Part,
    hatate_wire_datagram::Part,
    hatate_wire_extended_connect::Part
];
type Http3Only = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(All);
hatate_wire::assert_claims_valid!(HList![
    hatate_wire_extended_connect::Part,
    hatate_wire_datagram::Part,
    hatate_wire::Part
]);

type AllSetting = <All as SettingsSet>::Setting;
type AllValueError = <All as SettingsSet>::ValueError;

/// Reads one whole SETTINGS frame with `policy`.
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
    P::Parts: FrameSet,
{
    let Ok(Some(head)) = io.read_frame_head(PhantomData::<P::Parts>).await else {
        panic!("no frame head");
    };
    assert_eq!(head.type_field().get().get(), 0x04);
    assert!(matches!(head.frame_type(), FrameType::Known(_)));
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

fn read_all(
    payload: &[u8],
) -> Result<Vec<Setting<AllSetting>>, ReadSettingError<PayloadError<Infallible>, AllValueError>> {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(&mut RejectKnownDuplicates::<All>::new())
}

type Http3Result = Result<
    Vec<Setting<<Http3Only as SettingsSet>::Setting>>,
    ReadSettingError<PayloadError<Infallible>, <Http3Only as SettingsSet>::ValueError>,
>;

fn read_http3(payload: &[u8]) -> Http3Result {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(&mut RejectKnownDuplicates::<Http3Only>::new())
}

#[test]
fn each_part_takes_its_own_settings_out_of_one_frame() {
    // QPACK_MAX_TABLE_CAPACITY = 0, MAX_FIELD_SECTION_SIZE = 16,
    // QPACK_BLOCKED_STREAMS = 1, ENABLE_CONNECT_PROTOCOL = 1,
    // H3_DATAGRAM = 1 and a reserved identifier.
    let settings = read_all(&[
        0x01, 0x00, 0x06, 0x10, 0x07, 0x01, 0x08, 0x01, 0x33, 0x01, 0x21, 0x00,
    ])
    .unwrap();
    assert_eq!(settings.len(), 6);

    let mut http3 = Vec::new();
    let mut datagram = Vec::new();
    let mut connect = Vec::new();
    let mut unknown = Vec::new();
    for setting in settings {
        match setting {
            Setting::Known(known) => match known.uninject::<Http3Setting, _>() {
                Ok(setting) => http3.push(setting),
                Err(rest) => match rest.uninject::<H3DatagramSetting, _>() {
                    Ok(setting) => datagram.push(setting),
                    Err(rest) => match rest.uninject::<EnableConnectProtocolSetting, _>() {
                        Ok(setting) => connect.push(setting),
                        Err(rest) => match rest {},
                    },
                },
            },
            Setting::Unknown(setting) => unknown.push(setting),
        }
    }
    assert_eq!(http3.len(), 3);
    assert_eq!(
        http3[1].identifier(),
        Http3SettingIdentifier::MaxFieldSectionSize
    );
    assert_eq!(http3[1].value().get().get(), 16);
    assert_eq!(datagram.len(), 1);
    assert!(datagram[0].enabled());
    assert_eq!(connect.len(), 1);
    assert!(connect[0].enabled());
    assert_eq!(unknown.len(), 1);
    assert_eq!(unknown[0].identifier().get().get(), 0x21);
}

#[test]
fn a_setting_is_found_by_its_type_in_the_sum() {
    let settings = read_all(&[0x33, 0x00, 0x08, 0x01]).unwrap();
    let Setting::Known(datagram) = &settings[0] else {
        panic!("unknown")
    };
    assert!(datagram.get::<Http3Setting, _>().is_none());
    assert!(!datagram.get::<H3DatagramSetting, _>().unwrap().enabled());
    assert!(datagram.get::<EnableConnectProtocolSetting, _>().is_none());
    let Setting::Known(connect) = &settings[1] else {
        panic!("unknown")
    };
    assert!(
        connect
            .get::<EnableConnectProtocolSetting, _>()
            .unwrap()
            .enabled()
    );
    assert!(connect.get::<H3DatagramSetting, _>().is_none());
}

#[test]
fn the_order_of_the_parts_decides_the_position_in_the_sum() {
    type Reversed = HList![
        hatate_wire_extended_connect::Part,
        hatate_wire_datagram::Part,
        hatate_wire::Part
    ];
    let wire = frame(&[0x33, 0x01, 0x08, 0x00, 0x06, 0x02]);
    let settings = (&wire[..])
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<Reversed>::new())
        .unwrap();
    let positions: Vec<usize> = settings
        .iter()
        .map(|setting| match setting {
            Setting::Known(Coproduct::Inl(_)) => 0,
            Setting::Known(Coproduct::Inr(Coproduct::Inl(_))) => 1,
            Setting::Known(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(_)))) => 2,
            _ => 9,
        })
        .collect();
    assert_eq!(positions, [1, 0, 2]);
}

#[test]
fn widths_of_the_settings_of_the_extensions_are_kept() {
    let payload = [0x40, 0x33, 0x40, 0x01, 0x80, 0, 0, 0x08, 0x80, 0, 0, 0x00];
    let settings = read_all(&payload).unwrap();
    let Setting::Known(datagram) = &settings[0] else {
        panic!()
    };
    let datagram = datagram.get::<H3DatagramSetting, _>().unwrap();
    assert_eq!(datagram.identifier_width(), VarIntWidth::Two);
    assert_eq!(datagram.value().width(), VarIntWidth::Two);
    assert!(datagram.enabled());
    let Setting::Known(connect) = &settings[1] else {
        panic!()
    };
    let connect = connect.get::<EnableConnectProtocolSetting, _>().unwrap();
    assert_eq!(connect.identifier_width(), VarIntWidth::Four);
    assert_eq!(connect.value().width(), VarIntWidth::Four);
    assert!(!connect.enabled());
}

#[test]
fn h3_datagram_other_than_0_or_1_is_a_settings_error() {
    for value in [
        &[0x02][..],
        &[0x40, 0x02],
        &[0x7f, 0xff],
        &[0xc0, 0, 0, 1, 0, 0, 0, 0],
    ] {
        let error = read_all(&[&[0x33][..], value].concat()).unwrap_err();
        assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
        let ReadSettingError::Rejected { source } = &error else {
            panic!("{error:?}");
        };
        let Coproduct::Inr(Coproduct::Inl(rejected)) = source.get() else {
            panic!("{source:?}");
        };
        assert!(rejected.value().get() > 1);
    }
    let error = read_all(&[0x33, 0x02]).unwrap_err();
    let ReadSettingError::Rejected { source } = &error else {
        panic!()
    };
    assert_eq!(
        source.to_string(),
        "SETTINGS_H3_DATAGRAM is 2 rather than 0 or 1"
    );
}

#[test]
fn enable_connect_protocol_other_than_0_or_1_is_a_settings_error() {
    let error = read_all(&[0x08, 0x02]).unwrap_err();
    assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
    let ReadSettingError::Rejected { source } = &error else {
        panic!("{error:?}");
    };
    let Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(rejected))) = source.get() else {
        panic!("{source:?}");
    };
    assert_eq!(rejected.value().get(), 2);
    assert_eq!(
        source.to_string(),
        "SETTINGS_ENABLE_CONNECT_PROTOCOL is 2 rather than 0 or 1"
    );
}

#[test]
fn the_value_errors_of_the_setting_types_report_the_value() {
    let value = VarIntField::shortest(VarInt::from_u32(5));
    let error = H3DatagramSetting::with_widths(VarIntWidth::One, value).unwrap_err();
    let _: H3DatagramValueError = error;
    assert_eq!(error.value().get(), 5);
    let error = EnableConnectProtocolSetting::with_widths(VarIntWidth::One, value).unwrap_err();
    let _: EnableConnectProtocolValueError = error;
    assert_eq!(error.value().get(), 5);
    assert!(H3DatagramSetting::new(true).enabled());
    assert!(!H3DatagramSetting::new(false).enabled());
    assert!(EnableConnectProtocolSetting::new(true).enabled());
    assert!(!EnableConnectProtocolSetting::new(false).enabled());
}

#[test]
fn a_value_of_the_extension_is_rejected_before_the_policy_sees_the_setting() {
    // 0x33 = 2 once: rejected as a value, not as a duplicate.
    assert!(matches!(
        read_all(&[0x33, 0x02, 0x33, 0x01]),
        Err(ReadSettingError::Rejected { .. })
    ));
}

#[test]
fn a_repeat_of_either_extension_is_rejected_by_the_default_policy() {
    for identifier in [0x33, 0x08, 0x06, 0x01, 0x07] {
        let error = read_all(&[identifier, 0x00, 0x21, 0x00, identifier, 0x01]).unwrap_err();
        assert!(
            matches!(&error, ReadSettingError::Duplicate { source }
                if source.identifier().get() == u64::from(identifier)),
            "{error:?}"
        );
        assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
    }
    // One of each is fine, and so is a repeat of an unknown identifier.
    read_all(&[0x33, 0x01, 0x08, 0x01, 0x21, 0x00, 0x21, 0x00]).unwrap();
    // The two parts keep separate records: a repeat in one is not in the other.
    read_all(&[0x33, 0x00, 0x08, 0x00, 0x01, 0x00, 0x06, 0x00, 0x07, 0x00]).unwrap();
}

#[test]
fn without_the_extensions_their_settings_are_unknown_and_unchecked() {
    // 0x33 = 2 and 0x08 = 7 would be rejected by the parts; the list of HTTP/3
    // alone does not know them, and does not mind repeats either.
    let settings = read_http3(&[0x33, 0x02, 0x08, 0x07, 0x33, 0x02, 0x08, 0x07]).unwrap();
    assert_eq!(settings.len(), 4);
    for (setting, (identifier, value)) in
        settings
            .iter()
            .zip([(0x33, 2), (0x08, 7), (0x33, 2), (0x08, 7)])
    {
        let Setting::Unknown(setting) = setting else {
            panic!("{setting:?}");
        };
        assert_eq!(setting.identifier().get().get(), identifier);
        assert_eq!(setting.value().get().get(), value);
    }
    // The list with only the datagram part knows 0x33, not 0x08.
    type DatagramOnly = HList![hatate_wire::Part, hatate_wire_datagram::Part];
    let wire = frame(&[0x33, 0x01, 0x08, 0x02]);
    let settings = (&wire[..])
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<DatagramOnly>::new())
        .unwrap();
    assert!(matches!(settings[0], Setting::Known(_)));
    assert!(matches!(settings[1], Setting::Unknown(_)));
}

#[test]
fn a_frame_of_settings_of_all_parts_is_written_and_read_back() {
    let settings: Vec<Setting<AllSetting>> = vec![
        Setting::Known(Coproduct::Inr(Coproduct::Inl(H3DatagramSetting::new(true)))),
        Setting::Known(Coproduct::Inl(Http3Setting::new(
            Http3SettingIdentifier::MaxFieldSectionSize,
            VarIntField::shortest(VarInt::from_u32(1000)),
        ))),
        Setting::Known(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(
            EnableConnectProtocolSetting::new(true),
        )))),
    ];
    let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two);
    let frame = SettingsFrame::new::<All>(settings.clone(), widths).unwrap();
    let mut wire = Vec::new();
    wire.sync_write_settings_frame_unpin(&frame, PhantomData::<All>)
        .unwrap();
    assert_eq!(
        wire,
        [
            0x40, 0x04, 0x40, 0x07, 0x33, 0x01, 0x06, 0x43, 0xe8, 0x08, 0x01
        ]
    );
    let mut input = &wire[..];
    let read = input
        .sync_read_settings_unpin(&mut RejectKnownDuplicates::<All>::new())
        .unwrap();
    assert_eq!(read, settings);
    assert!(input.is_empty());
}

#[test]
fn frame_types_and_stream_types_of_the_extensions_are_none() {
    // The two extensions add no frame or stream types: every value either
    // belongs to HTTP/3 or is unknown, in any list.
    for value in 0..0x80u32 {
        let value = VarInt::from_u32(value);
        let in_all = <All as FrameSet>::type_value_of(value).is_some();
        let in_http3 = <Http3Only as FrameSet>::type_value_of(value).is_some();
        assert_eq!(in_all, in_http3);
        assert_eq!(in_all, Http3FrameType::of(value).is_some());
        assert_eq!(
            <All as StreamTypeSet>::type_value_of(value).is_some(),
            <Http3Only as StreamTypeSet>::type_value_of(value).is_some()
        );
    }
    let mut input = &[0x33, 0x00][..];
    let head = input
        .sync_read_frame_head_unpin(PhantomData::<All>)
        .unwrap()
        .unwrap();
    assert_eq!(
        head.frame_type(),
        FrameType::Unknown(VarInt::from_u32(0x33))
    );
    let mut input = &[0x08][..];
    let head = input
        .sync_read_stream_type_unpin(PhantomData::<All>)
        .unwrap()
        .unwrap();
    assert_eq!(
        head.stream_type(),
        StreamType::Unknown(VarInt::from_u32(0x08))
    );
}

#[test]
fn an_unknown_setting_cannot_take_the_identifier_of_a_part_of_the_list() {
    use hatate_wire::settings::{UnknownSetting, codec::SettingsFrameError};
    fn unknown<T>(identifier: u32) -> Setting<T> {
        Setting::Unknown(
            UnknownSetting::new(
                VarIntField::new(VarInt::from_u32(identifier), VarIntWidth::Two).unwrap(),
                VarIntField::shortest(VarInt::from_u32(0)),
            )
            .unwrap(),
        )
    }
    // SETTINGS_H3_DATAGRAM and SETTINGS_ENABLE_CONNECT_PROTOCOL are claimed
    // when their parts are in the list, and free when they are not.
    for identifier in [0x33, 0x08] {
        let error = SettingsFrame::new::<All>(vec![unknown(identifier)], FrameWidths::SHORTEST)
            .unwrap_err();
        assert!(
            matches!(&error, SettingsFrameError::ClaimedIdentifier { identifier: found }
                if found.get() == u64::from(identifier)),
            "{error:?}"
        );
        SettingsFrame::new::<Http3Only>(vec![unknown(identifier)], FrameWidths::SHORTEST).unwrap();
    }
    let only_datagram = SettingsFrame::new::<HList![hatate_wire::Part, hatate_wire_datagram::Part]>(
        vec![unknown(0x08)],
        FrameWidths::SHORTEST,
    );
    assert!(only_datagram.is_ok());
}
