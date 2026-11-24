#![feature(impl_trait_in_assoc_type)]
//! The parts of HTTP/3, HTTP Datagrams and Extended CONNECT in one list
//! (RFC 9114 §9, RFC 9297 §2.1.1, RFC 8441 §3, RFC 9220 §3).
use core::{convert::Infallible, marker::PhantomData};
use frunk_core::{
    HList,
    coproduct::{CoprodInjector, Coproduct},
};
use hatate_wire::{
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        FrameType, FrameWidths, Http3FrameType,
        codec::{ReadFrameHeadExt as _, ReadFrameHeadHostExt as _},
        payload::PayloadError,
        set::FrameSet,
    },
    settings::{
        Keyed, KeyedSetting, MaxFieldSectionSize, Setting,
        codec::{
            ReadSettingError, ReadSettingExt as _, SettingsFrame, WriteSettingsFrameHostExt as _,
        },
        set::{SettingList, Settings, SettingsOf},
    },
    stream_type::{StreamType, StreamTypeSet, codec::ReadStreamTypeHostExt as _},
};
use hatate_wire_datagram::{H3Datagram, H3DatagramValueError};
use hatate_wire_extended_connect::{EnableConnectProtocol, EnableConnectProtocolValueError};
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
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

type AllList = <All as SettingsOf>::Settings;
type AllSetting = <AllList as SettingList>::Setting;
type AllValueErrors = <AllList as SettingList>::ValueErrors;
type Http3List = <Http3Only as SettingsOf>::Settings;

/// Reads one whole SETTINGS frame into `settings`.
#[call(sync)]
async fn read_settings<L: SettingList, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    settings: &mut Settings<L>,
) -> Result<Vec<Setting<L::Setting>>, ReadSettingError<PayloadError<F::Error>, L::ValueErrors>> {
    let Ok(Some(head)) = io.read_frame_head(PhantomData::<All>).await else {
        panic!("no frame head");
    };
    assert_eq!(head.type_field().get().get(), 0x04);
    assert!(matches!(head.frame_type(), FrameType::Known(_)));
    let mut payload = head.payload();
    let mut read = Vec::new();
    {
        let mut source = io.compose(&mut payload);
        while let Some(setting) = source.read_setting(settings).await? {
            read.push(setting);
        }
    }
    payload.finish().expect("the payload was read to its end");
    Ok(read)
}

fn frame(payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 64);
    [&[0x04, payload.len() as u8][..], payload].concat()
}

type AllResult =
    Result<Vec<Setting<AllSetting>>, ReadSettingError<PayloadError<Infallible>, AllValueErrors>>;

fn read_all_into(payload: &[u8], settings: &mut Settings<AllList>) -> AllResult {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(settings)
}

fn read_all(payload: &[u8]) -> AllResult {
    read_all_into(payload, &mut Settings::new())
}

type Http3Result = Result<
    Vec<Setting<<Http3List as SettingList>::Setting>>,
    ReadSettingError<PayloadError<Infallible>, <Http3List as SettingList>::ValueErrors>,
>;

fn read_http3(payload: &[u8]) -> Http3Result {
    let wire = frame(payload);
    (&wire[..]).sync_read_settings_unpin(&mut Settings::<Http3List>::new())
}

fn keyed<T: KeyedSetting, I>(setting: T) -> Setting<AllSetting>
where
    AllSetting: CoprodInjector<Keyed<T>, I>,
{
    Setting::Known(AllSetting::inject(Keyed::new(setting)))
}

#[test]
fn each_type_takes_its_own_setting_out_of_one_frame() {
    // QPACK_MAX_TABLE_CAPACITY = 0, MAX_FIELD_SECTION_SIZE = 16,
    // QPACK_BLOCKED_STREAMS = 1, ENABLE_CONNECT_PROTOCOL = 1,
    // H3_DATAGRAM = 1 and a reserved identifier.
    let mut settings = Settings::new();
    let read = read_all_into(
        &[
            0x01, 0x00, 0x06, 0x10, 0x07, 0x01, 0x08, 0x01, 0x33, 0x01, 0x21, 0x00,
        ],
        &mut settings,
    )
    .unwrap();
    assert_eq!(read.len(), 6);
    assert_eq!(
        settings
            .get::<QpackMaxTableCapacity, _>()
            .unwrap()
            .value()
            .get()
            .get(),
        0
    );
    assert_eq!(
        settings
            .get::<MaxFieldSectionSize, _>()
            .unwrap()
            .value()
            .get()
            .get(),
        16
    );
    assert_eq!(
        settings
            .get::<QpackBlockedStreams, _>()
            .unwrap()
            .value()
            .get()
            .get(),
        1
    );
    assert!(settings.get::<H3Datagram, _>().unwrap().enabled());
    assert!(
        settings
            .get::<EnableConnectProtocol, _>()
            .unwrap()
            .enabled()
    );
    let Setting::Unknown(unknown) = read[5] else {
        panic!("{:?}", read[5]);
    };
    assert_eq!(unknown.identifier().get().get(), 0x21);
}

#[test]
fn a_setting_is_found_by_its_type_in_the_sum() {
    let read = read_all(&[0x33, 0x00, 0x08, 0x01]).unwrap();
    let Setting::Known(datagram) = &read[0] else {
        panic!("unknown")
    };
    assert!(datagram.get::<Keyed<MaxFieldSectionSize>, _>().is_none());
    assert!(
        !datagram
            .get::<Keyed<H3Datagram>, _>()
            .unwrap()
            .setting()
            .enabled()
    );
    assert!(datagram.get::<Keyed<EnableConnectProtocol>, _>().is_none());
    let Setting::Known(connect) = &read[1] else {
        panic!("unknown")
    };
    assert!(
        connect
            .get::<Keyed<EnableConnectProtocol>, _>()
            .unwrap()
            .setting()
            .enabled()
    );
    assert!(connect.get::<Keyed<H3Datagram>, _>().is_none());
}

#[test]
fn the_order_of_the_parts_decides_the_position_in_the_sum() {
    type Reversed = <HList![
        hatate_wire_extended_connect::Part,
        hatate_wire_datagram::Part,
        hatate_wire::Part
    ] as SettingsOf>::Settings;
    let wire = frame(&[0x33, 0x01, 0x08, 0x00, 0x06, 0x02, 0x01, 0x00]);
    let read = (&wire[..])
        .sync_read_settings_unpin(&mut Settings::<Reversed>::new())
        .unwrap();
    let positions: Vec<usize> = read
        .iter()
        .map(|setting| match setting {
            Setting::Known(Coproduct::Inl(_)) => 0,
            Setting::Known(Coproduct::Inr(Coproduct::Inl(_))) => 1,
            Setting::Known(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(_)))) => 2,
            Setting::Known(Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(_))))) => 3,
            _ => 9,
        })
        .collect();
    assert_eq!(positions, [1, 0, 3, 2]);
}

#[test]
fn widths_of_the_settings_of_the_extensions_are_kept() {
    let payload = [0x40, 0x33, 0x40, 0x01, 0x80, 0, 0, 0x08, 0x80, 0, 0, 0x00];
    let read = read_all(&payload).unwrap();
    let Setting::Known(datagram) = &read[0] else {
        panic!()
    };
    let datagram = datagram.get::<Keyed<H3Datagram>, _>().unwrap();
    assert_eq!(datagram.identifier_width(), VarIntWidth::Two);
    assert_eq!(datagram.setting().value().width(), VarIntWidth::Two);
    assert!(datagram.setting().enabled());
    let Setting::Known(connect) = &read[1] else {
        panic!()
    };
    let connect = connect.get::<Keyed<EnableConnectProtocol>, _>().unwrap();
    assert_eq!(connect.identifier_width(), VarIntWidth::Four);
    assert_eq!(connect.setting().value().width(), VarIntWidth::Four);
    assert!(!connect.setting().enabled());
}

#[test]
fn h3_datagram_other_than_0_or_1_is_a_settings_error() {
    for value in [
        &[0x02][..],
        &[0x40, 0x02],
        &[0x7f, 0xff],
        &[0xc0, 0, 0, 1, 0, 0, 0, 0],
    ] {
        let mut settings = Settings::new();
        let error = read_all_into(&[&[0x33][..], value].concat(), &mut settings).unwrap_err();
        assert_eq!(error.error_code(), Some(ErrorCode::H3_SETTINGS_ERROR));
        let ReadSettingError::Rejected { source } = &error else {
            panic!("{error:?}");
        };
        let rejected: &H3DatagramValueError = source.get().get().expect("the datagram's failure");
        assert!(rejected.value().get() > 1);
        // A rejected value takes no slot.
        assert!(settings.get::<H3Datagram, _>().is_none());
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
    let rejected: &EnableConnectProtocolValueError =
        source.get().get().expect("the failure of Extended CONNECT");
    assert_eq!(rejected.value().get(), 2);
    assert_eq!(
        source.to_string(),
        "SETTINGS_ENABLE_CONNECT_PROTOCOL is 2 rather than 0 or 1"
    );
}

#[test]
fn the_value_errors_of_the_setting_types_report_the_value() {
    let value = VarIntField::shortest(VarInt::from_u32(5));
    let error = H3Datagram::from_value(value).unwrap_err();
    let _: H3DatagramValueError = error;
    assert_eq!(error.value().get(), 5);
    let error = EnableConnectProtocol::from_value(value).unwrap_err();
    let _: EnableConnectProtocolValueError = error;
    assert_eq!(error.value().get(), 5);
    for value in [0, 1] {
        let field = VarIntField::new(VarInt::from_u32(value), VarIntWidth::Two).unwrap();
        assert_eq!(H3Datagram::from_value(field).unwrap().value(), field);
        assert_eq!(
            EnableConnectProtocol::from_value(field).unwrap().value(),
            field
        );
    }
    assert!(H3Datagram::new(true).enabled());
    assert!(!H3Datagram::new(false).enabled());
    assert!(EnableConnectProtocol::new(true).enabled());
    assert!(!EnableConnectProtocol::new(false).enabled());
}

#[test]
fn a_repeat_is_found_before_the_value_is_checked() {
    // 0x33 = 2 after 0x33 = 1: the repeat, not the value.
    assert!(matches!(
        read_all(&[0x33, 0x01, 0x33, 0x02]),
        Err(ReadSettingError::Duplicate { .. })
    ));
    // 0x33 = 2 first: the value.
    assert!(matches!(
        read_all(&[0x33, 0x02, 0x33, 0x01]),
        Err(ReadSettingError::Rejected { .. })
    ));
}

#[test]
fn a_repeat_of_any_known_identifier_is_a_settings_error() {
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
    // Each type has its own slot: one does not take another's.
    read_all(&[0x33, 0x00, 0x08, 0x00, 0x01, 0x00, 0x06, 0x00, 0x07, 0x00]).unwrap();
}

#[test]
fn without_the_extensions_their_settings_are_unknown_and_unchecked() {
    // 0x33 = 2 and 0x08 = 7 would be rejected by the types; the list of HTTP/3
    // alone does not know them, and does not mind repeats either.
    let read = read_http3(&[0x33, 0x02, 0x08, 0x07, 0x33, 0x02, 0x08, 0x07]).unwrap();
    assert_eq!(read.len(), 4);
    for (setting, (identifier, value)) in
        read.iter()
            .zip([(0x33, 2), (0x08, 7), (0x33, 2), (0x08, 7)])
    {
        let Setting::Unknown(setting) = setting else {
            panic!("{setting:?}");
        };
        assert_eq!(setting.identifier().get().get(), identifier);
        assert_eq!(setting.value().get().get(), value);
    }
    // The list with only the datagram part knows 0x33, not 0x08.
    type DatagramOnly =
        <HList![hatate_wire::Part, hatate_wire_datagram::Part] as SettingsOf>::Settings;
    let wire = frame(&[0x33, 0x01, 0x08, 0x02]);
    let read = (&wire[..])
        .sync_read_settings_unpin(&mut Settings::<DatagramOnly>::new())
        .unwrap();
    assert!(matches!(read[0], Setting::Known(_)));
    assert!(matches!(read[1], Setting::Unknown(_)));
}

#[test]
fn a_frame_of_settings_of_all_parts_is_written_and_read_back() {
    let settings: Vec<Setting<AllSetting>> = vec![
        keyed(H3Datagram::new(true)),
        keyed(MaxFieldSectionSize::new(VarIntField::shortest(
            VarInt::from_u32(1000),
        ))),
        keyed(EnableConnectProtocol::new(true)),
    ];
    let widths = FrameWidths::new(VarIntWidth::Two, VarIntWidth::Two);
    let frame = SettingsFrame::<AllList>::new(settings.clone(), widths).unwrap();
    let mut wire = Vec::new();
    wire.sync_write_settings_frame_unpin(&frame).unwrap();
    assert_eq!(
        wire,
        [
            0x40, 0x04, 0x40, 0x07, 0x33, 0x01, 0x06, 0x43, 0xe8, 0x08, 0x01
        ]
    );
    let mut input = &wire[..];
    let read = input
        .sync_read_settings_unpin(&mut Settings::<AllList>::new())
        .unwrap();
    assert_eq!(read, settings);
    assert!(input.is_empty());
}

#[test]
fn each_setting_of_the_extensions_is_written_and_read_back() {
    for setting in [
        keyed(H3Datagram::new(false)),
        keyed(H3Datagram::new(true)),
        keyed(EnableConnectProtocol::new(false)),
        keyed(EnableConnectProtocol::new(true)),
    ] {
        let frame = SettingsFrame::<AllList>::new(vec![setting], FrameWidths::SHORTEST).unwrap();
        let mut wire = Vec::new();
        wire.sync_write_settings_frame_unpin(&frame).unwrap();
        assert_eq!(wire.len(), 4);
        let mut input = &wire[..];
        let read = input
            .sync_read_settings_unpin(&mut Settings::<AllList>::new())
            .unwrap();
        assert_eq!(read, [setting]);
    }
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
fn an_unknown_setting_cannot_take_the_identifier_of_a_type_of_the_list() {
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
        let error = SettingsFrame::<AllList>::new(vec![unknown(identifier)], FrameWidths::SHORTEST)
            .unwrap_err();
        assert!(
            matches!(&error, SettingsFrameError::ClaimedIdentifier { identifier: found }
                if found.get() == u64::from(identifier)),
            "{error:?}"
        );
        SettingsFrame::<Http3List>::new(vec![unknown(identifier)], FrameWidths::SHORTEST).unwrap();
    }
    let only_datagram = SettingsFrame::<
        <HList![hatate_wire::Part, hatate_wire_datagram::Part] as SettingsOf>::Settings,
    >::new(vec![unknown(0x08)], FrameWidths::SHORTEST);
    assert!(only_datagram.is_ok());
}
