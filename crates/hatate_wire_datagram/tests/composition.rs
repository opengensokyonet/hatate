#![feature(impl_trait_in_assoc_type)]
//! The parts of HTTP/3, HTTP Datagrams and Extended CONNECT in one list
//! (RFC 9114 §9, RFC 9297 §2.1.1, RFC 8441 §3, RFC 9220 §3).
use core::convert::Infallible;
use frunk_core::{
    HList,
    coproduct::{CoprodInjector, Coproduct},
};
use hatate_wire::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{FrameWidths, payload::PayloadError, set::FramePartOn},
    parts::PartsError,
    settings::{
        Http2SettingIdentifierError, Keyed, KeyedSetting, MaxFieldSectionSize, Setting,
        codec::{
            DecodeSettingParameterError, DuplicateSettingError, InsertSettingError,
            SettingParameter, SettingsFrame, WriteSettingsFrameHostExt as _,
        },
        set::{SettingList, Settings, SettingsOf},
    },
    stream::{
        FrameStream, ReceivedStream,
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedBidirectional, ServerInitiatedUnidirectional,
        },
        codec::{read_bidirectional_stream, read_unidirectional_stream},
        http3::Http3UnidirectionalStream,
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
        part::{StreamSet, StreamVerdict},
    },
};
use hatate_wire_datagram::{H3Datagram, H3DatagramValueError};
use hatate_wire_extended_connect::{EnableConnectProtocol, EnableConnectProtocolValueError};
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, Skip};
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

/// The failures of reading a parameter of a SETTINGS frame and of inserting
/// it into the settings.
#[derive(Debug)]
#[allow(dead_code)] // Read through `Debug`.
enum ReadSettingError<E, V> {
    Identifier {
        source: sakuya_var_int::stream::ReadVarIntError<E>,
    },
    Http2Identifier {
        source: Http2SettingIdentifierError,
    },
    Value {
        source: sakuya_var_int::stream::ReadVarIntError<E>,
    },
    Rejected {
        source: PartsError<V>,
    },
    Duplicate {
        source: DuplicateSettingError,
    },
}

impl<E, V> From<DecodeSettingParameterError<E>> for ReadSettingError<E, V> {
    fn from(error: DecodeSettingParameterError<E>) -> Self {
        match error {
            DecodeSettingParameterError::Identifier { source } => Self::Identifier { source },
            DecodeSettingParameterError::Http2Identifier { source } => {
                Self::Http2Identifier { source }
            }
            DecodeSettingParameterError::Value { source } => Self::Value { source },
        }
    }
}

impl<E, V> From<InsertSettingError<V>> for ReadSettingError<E, V> {
    fn from(error: InsertSettingError<V>) -> Self {
        match error {
            InsertSettingError::Rejected { source } => Self::Rejected { source },
            InsertSettingError::Duplicate { source } => Self::Duplicate { source },
        }
    }
}

impl<E: ErrorCodeOf<ErrorCode>, V> ErrorCodeOf<ErrorCode> for ReadSettingError<PayloadError<E>, V> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Identifier { source } | Self::Value { source } => source.error_code(),
            Self::Http2Identifier { .. } | Self::Rejected { .. } | Self::Duplicate { .. } => {
                Some(ErrorCode::H3_SETTINGS_ERROR)
            }
        }
    }
}

type AllList = <All as SettingsOf>::Settings;
type AllSetting = <AllList as SettingList>::Setting;
type AllValueErrors = <AllList as SettingList>::ValueErrors;
type Http3List = <Http3Only as SettingsOf>::Settings;

/// Reads one whole SETTINGS frame, the first frame of a control stream of
/// the parts of `All`, into `settings`.
#[call(sync)]
async fn read_settings<
    L: SettingList,
    F: Read + Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    settings: &mut Settings<L>,
) -> Result<Vec<Setting<L::Setting>>, ReadSettingError<PayloadError<F::Error>, L::ValueErrors>>
where
    <F as Read>::Error:
        core::fmt::Debug + hatate_wire::error_code::ErrorCodeOf<hatate_wire::error_code::ErrorCode>,
{
    let Ok(Some(mut stream)) =
        FrameStream::<All, ControlStreamKind, _>::read(&mut *io, Role::Server).await
    else {
        panic!("no frame head");
    };
    let mut frame = stream.frame();
    assert_eq!(frame.frame_type().value().get(), 0x04);
    let mut read = Vec::new();
    while frame.payload().remaining() > 0 {
        let parameter = frame
            .payload()
            .decode::<SettingParameter, _>()
            .await
            .map_err(ReadSettingError::from)?;
        read.push(settings.insert(parameter)?);
    }
    let payload = frame.into_payload();
    assert_eq!(payload.remaining(), 0, "the payload was read to its end");
    Ok(read)
}

/// How a stream of the parts of a list started.
#[derive(Debug, PartialEq, Eq)]
enum Started {
    /// A request stream at its first frame, of this type.
    Request(u64),
    /// A control stream at its first frame, of this type.
    Control(u64),
    /// A push stream with this Push ID, at its first frame, of this type.
    Push(u64, u64),
    QpackEncoder,
    QpackDecoder,
    /// A stream no part claims, with its value.
    Unknown(u64),
    /// No first value: the stream ended or held only reserved frames.
    Empty,
    /// A part rejects the stream with this code.
    Rejected(ErrorCode),
}

/// Reads the start of streams with the parts of a list. `$known` takes the
/// sum of the streams the parts of the list give and returns the stream of
/// HTTP/3, the only part that has any; the others' are empty.
macro_rules! streams {
    ($request:ident, $unidirectional:ident, $list:ty, |$known:ident| $http3:expr) => {
        /// A client-initiated bidirectional stream.
        #[call(sync)]
        async fn $request<
            F: Read + Skip<Count = usize, Metadata = ()>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
        ) -> Started
        where
            <F as Read>::Error: core::fmt::Debug
                + hatate_wire::error_code::ErrorCodeOf<hatate_wire::error_code::ErrorCode>,
        {
            match read_bidirectional_stream::<$list, ClientInitiatedBidirectional, _, ()>(&mut *io)
                .await
            {
                Err(error) => Started::Rejected(error.error_code().unwrap()),
                Ok(None) => Started::Empty,
                Ok(Some(ReceivedStream::Unknown(unknown))) => {
                    Started::Unknown(unknown.value().get())
                }
                Ok(Some(ReceivedStream::Known($known))) => {
                    let mut request = $http3;
                    Started::Request(request.frame().frame_type().value().get())
                }
            }
        }

        /// A unidirectional stream that the peer opened; `server` tells whether
        /// the server opened it.
        #[call(sync)]
        async fn $unidirectional<
            F: Read + Skip<Count = usize, Metadata = ()>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
            server: bool,
        ) -> Started
        where
            <F as Read>::Error: core::fmt::Debug
                + hatate_wire::error_code::ErrorCodeOf<hatate_wire::error_code::ErrorCode>,
        {
            let stream = if server {
                read_unidirectional_stream::<$list, ServerInitiatedUnidirectional, _, ()>(&mut *io)
                    .await
                    .unwrap()
                    .map(|stream| stream.into_stream())
            } else {
                read_unidirectional_stream::<$list, ClientInitiatedUnidirectional, _, ()>(&mut *io)
                    .await
                    .unwrap()
                    .map(|stream| stream.into_stream())
            };
            match stream {
                None => Started::Empty,
                Some(ReceivedStream::Unknown(unknown)) => Started::Unknown(unknown.value().get()),
                Some(ReceivedStream::Known($known)) => match $http3 {
                    Http3UnidirectionalStream::Control(mut control) => {
                        Started::Control(control.frame().frame_type().value().get())
                    }
                    Http3UnidirectionalStream::Push(mut push) => Started::Push(
                        push.push_id().get().get().get(),
                        push.frames().frame().frame_type().value().get(),
                    ),
                    Http3UnidirectionalStream::QpackEncoder(_) => Started::QpackEncoder,
                    Http3UnidirectionalStream::QpackDecoder(_) => Started::QpackDecoder,
                },
            }
        }
    };
}

streams!(request_all, unidirectional_all, All, |known| match known {
    Coproduct::Inl(http3) => http3,
    Coproduct::Inr(Coproduct::Inl(none)) => match none {},
    Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(none))) => match none {},
    Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(none))) => match none {},
});
streams!(
    request_reversed,
    unidirectional_reversed,
    Reversed,
    |known| match known {
        Coproduct::Inl(none) => match none {},
        Coproduct::Inr(Coproduct::Inl(none)) => match none {},
        Coproduct::Inr(Coproduct::Inr(Coproduct::Inl(http3))) => http3,
        Coproduct::Inr(Coproduct::Inr(Coproduct::Inr(none))) => match none {},
    }
);
streams!(
    request_http3_only,
    unidirectional_http3_only,
    Http3Only,
    |known| match known {
        Coproduct::Inl(http3) => http3,
        Coproduct::Inr(none) => match none {},
    }
);

type Reversed = HList![
    hatate_wire_extended_connect::Part,
    hatate_wire_datagram::Part,
    hatate_wire::Part
];

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
fn the_extensions_add_no_frame_types_or_streams_of_their_own() {
    // No frames on any kind of stream.
    fn none<K: hatate_wire::stream::kind::StreamKind, P: FramePartOn<K>>() -> bool
    where
        P::FrameType: 'static,
    {
        core::any::TypeId::of::<P::FrameType>()
            == core::any::TypeId::of::<frunk_core::coproduct::CNil>()
    }
    assert!(none::<RequestStreamKind, hatate_wire_datagram::Part>());
    assert!(none::<ControlStreamKind, hatate_wire_datagram::Part>());
    assert!(none::<PushStreamKind, hatate_wire_datagram::Part>());
    assert!(none::<RequestStreamKind, hatate_wire_extended_connect::Part>());
    assert!(none::<ControlStreamKind, hatate_wire_extended_connect::Part>());
    assert!(none::<PushStreamKind, hatate_wire_extended_connect::Part>());
    assert!(!none::<RequestStreamKind, hatate_wire::Part>());

    // No streams in any class: every value is not theirs.
    for value in 0..0x100u32 {
        let value = VarInt::from_u32(value);
        for skipped in [false, true] {
            assert_eq!(
                <HList![
                    hatate_wire_datagram::Part,
                    hatate_wire_extended_connect::Part
                ] as StreamSet<ClientInitiatedUnidirectional, All>>::judge(
                    value, skipped
                ),
                StreamVerdict::NotClaimed
            );
        }
    }
}

/// What a list's verdict on a value is, apart from the form of the claim.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Claimed,
    NotClaimed,
    Error(ErrorCode),
    ErrorUnlessClaimed(ErrorCode),
}

fn verdict<T, R: ErrorCodeOf<ErrorCode>>(verdict: StreamVerdict<T, R>) -> Verdict {
    let code = |reason: R| reason.error_code().expect("a rejection has a code");
    match verdict {
        StreamVerdict::Claimed(_) => Verdict::Claimed,
        StreamVerdict::NotClaimed => Verdict::NotClaimed,
        StreamVerdict::Error(reason) => Verdict::Error(code(reason)),
        StreamVerdict::ErrorUnlessClaimed(reason) => Verdict::ErrorUnlessClaimed(code(reason)),
    }
}

#[test]
fn the_extensions_change_no_verdict_of_the_list_in_any_class() {
    macro_rules! same {
        ($class:ty, $value:expr, $skipped:expr) => {
            assert_eq!(
                verdict(<All as StreamSet<$class, All>>::judge($value, $skipped)),
                verdict(<Http3Only as StreamSet<$class, Http3Only>>::judge(
                    $value, $skipped
                )),
                "{} {:?}",
                stringify!($class),
                $value
            );
            assert_eq!(
                verdict(<Reversed as StreamSet<$class, Reversed>>::judge(
                    $value, $skipped
                )),
                verdict(<Http3Only as StreamSet<$class, Http3Only>>::judge(
                    $value, $skipped
                )),
                "{} {:?}",
                stringify!($class),
                $value
            );
        };
    }
    let mut values: Vec<u64> = (0..0x100).chain([0x3fff, 0x4000, (1 << 62) - 1]).collect();
    for n in [0, 1, 2, 100, 1 << 30] {
        values.push(hatate_wire::registry::reserved(n).unwrap().get());
    }
    for value in values {
        let value = VarInt::new(value).unwrap();
        for skipped in [false, true] {
            same!(ClientInitiatedBidirectional, value, skipped);
            same!(ServerInitiatedBidirectional, value, skipped);
            same!(ClientInitiatedUnidirectional, value, skipped);
            same!(ServerInitiatedUnidirectional, value, skipped);
        }
    }
}

#[test]
fn a_list_with_the_extensions_reads_request_streams_wherever_the_part_of_http3_is() {
    let wire = [0x01, 0x02, 0xaa, 0xbb];
    for list in 0..3 {
        // A reserved frame before it changes nothing.
        let wire = [&[0x21, 0x00][..], &wire].concat();
        let mut input = &wire[..];
        let started = match list {
            0 => input.sync_request_all_unpin(),
            1 => input.sync_request_reversed_unpin(),
            _ => input.sync_request_http3_only_unpin(),
        };
        assert_eq!(started, Started::Request(0x01), "list {list}");
    }
    // The values the extensions do not claim are as unknown as without them.
    for value in [0x33u8, 0x0a, 0x0b] {
        let wire = [value, 0x00];
        let mut input = &wire[..];
        assert_eq!(
            input.sync_request_all_unpin(),
            Started::Unknown(u64::from(value))
        );
        let mut input = &wire[..];
        assert_eq!(
            input.sync_request_reversed_unpin(),
            Started::Unknown(u64::from(value))
        );
    }
    let mut input = &[][..];
    assert_eq!(input.sync_request_all_unpin(), Started::Empty);
    // PUSH_PROMISE, HTTP/2's types and the frames of other streams are
    // rejected as without the extensions.
    for value in [0x02u8, 0x03, 0x04, 0x05, 0x07, 0x0d] {
        let wire = [value, 0x00];
        for started in [
            (&wire[..]).sync_request_all_unpin(),
            (&wire[..]).sync_request_reversed_unpin(),
            (&wire[..]).sync_request_http3_only_unpin(),
        ] {
            assert_eq!(started, Started::Rejected(ErrorCode::H3_FRAME_UNEXPECTED));
        }
    }
}

#[test]
fn a_list_with_the_extensions_reads_control_push_and_qpack_streams() {
    macro_rules! check {
        ($module:ident) => {
            // The control stream, at its SETTINGS frame, from both sides.
            for server in [false, true] {
                let mut input = &[0x00, 0x04, 0x02, 0x33, 0x01][..];
                assert_eq!(input.$module(server), Started::Control(0x04));
            }
            // A server's push stream.
            let mut input = &[0x01, 0x07, 0x01, 0x00][..];
            assert_eq!(input.$module(true), Started::Push(7, 0x01));
            let mut input = &[0x02][..];
            assert_eq!(input.$module(true), Started::QpackEncoder);
            let mut input = &[0x03][..];
            assert_eq!(input.$module(false), Started::QpackDecoder);
            // What no part claims is unknown, the types of the extensions
            // included: they have none.
            for value in [0x04u8, 0x08, 0x33] {
                let mut input = &[value][..];
                assert_eq!(input.$module(true), Started::Unknown(u64::from(value)));
            }
            let mut input = &[][..];
            assert_eq!(input.$module(true), Started::Empty);
        };
    }
    check!(sync_unidirectional_all_unpin);
    check!(sync_unidirectional_reversed_unpin);
    check!(sync_unidirectional_http3_only_unpin);
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
