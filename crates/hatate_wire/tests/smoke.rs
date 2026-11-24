#![feature(impl_trait_in_assoc_type)]
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Role,
    frame::{
        FrameType, Http3FrameType, codec::read_received_frame,
        control::codec::ReadGoawayFrameExt as _,
    },
    settings::{
        Setting,
        codec::ReadSettingExt as _,
        set::{Settings, SettingsOf},
    },
    stream::{UnidirectionalStream, codec::read_unidirectional_stream},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Skip;

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

#[call(sync)]
async fn settings_then_goaway<F: Skip<Count = usize>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
) -> (usize, u64)
where
    <F as nitori_io::Read>::Error: core::fmt::Debug,
{
    let Some(UnidirectionalStream::Control(stream)) =
        read_unidirectional_stream::<Parts, _>(&mut *io, Role::Client)
            .await
            .unwrap()
    else {
        panic!("not a control stream");
    };
    let mut frame = read_received_frame(stream).await.unwrap().unwrap();
    assert!(matches!(
        frame.frame_type(),
        FrameType::Known(Coproduct::Inl(Http3FrameType::Settings))
    ));
    let mut count = 0;
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    while let Some(setting) = frame.payload().read_setting(&mut settings).await.unwrap() {
        assert!(matches!(setting, Setting::Known(_) | Setting::Unknown(_)));
        count += 1;
    }
    let mut frame = frame.next().await.unwrap().unwrap();
    let widths = frame.frame().widths();
    let goaway = frame.payload().read_goaway_frame(widths).await.unwrap();
    let stream = frame.finish().await.unwrap();
    assert!(read_received_frame(stream).await.unwrap().is_none());
    (count, goaway.id().get().get().get())
}

#[test]
fn reads_settings_and_goaway() {
    // A control stream: SETTINGS: QPACK_MAX_TABLE_CAPACITY = 0x40 (2
    // bytes), a reserved identifier 0x21 = 0; GOAWAY with ID 4 in two
    // bytes.
    let mut input = &[
        0x00, 0x04, 0x05, 0x01, 0x40, 0x40, 0x21, 0x00, 0x07, 0x02, 0x40, 0x04,
    ][..];
    assert_eq!(input.sync_settings_then_goaway_unpin(), (2, 4));
    assert!(input.is_empty());
}
