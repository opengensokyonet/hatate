#![feature(impl_trait_in_assoc_type)]
mod common;

use common::{Ty, known, ty};
use frunk_core::HList;
use hatate_wire::{
    Role,
    frame::{GoawayId, Http3FrameType},
    settings::{
        Setting,
        codec::SettingParameter,
        set::{Settings, SettingsOf},
    },
    stream::{FrameStream, kind::ControlStreamKind},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Skip, calls::ReadValue};
use sakuya_var_int::VarIntField;

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

#[call(sync)]
async fn settings_then_goaway<
    F: Skip<Count = usize, Metadata = ()>,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
) -> (usize, u64)
where
    <F as nitori_io::Read>::Error: core::fmt::Debug,
{
    let mut stream = FrameStream::<Parts, ControlStreamKind, _>::read(&mut *io, Role::Client)
        .await
        .unwrap()
        .expect("a first frame");
    let mut frame = stream.frame();
    assert_eq!(ty(frame.frame_type()), known(Http3FrameType::Settings));
    let mut count = 0;
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    while frame.payload().remaining() > 0 {
        let parameter = frame
            .payload()
            .decode::<SettingParameter, _>()
            .await
            .unwrap();
        let setting = settings.insert(parameter).unwrap();
        assert!(matches!(setting, Setting::Known(_) | Setting::Unknown(_)));
        count += 1;
    }
    let mut frame = stream.next_frame().await.unwrap().unwrap();
    assert_eq!(ty(frame.frame_type()), known(Http3FrameType::Goaway));
    let goaway = frame
        .payload()
        .decode_to_end::<ReadValue<VarIntField<GoawayId>, ()>, _>()
        .await
        .unwrap();
    assert!(stream.next_frame().await.unwrap().is_none());
    let _: Ty = ty(stream.frame().frame_type());
    (count, goaway.value.get().get().get())
}

#[test]
fn reads_settings_and_goaway() {
    // A control stream: SETTINGS: QPACK_MAX_TABLE_CAPACITY = 0x40 (2
    // bytes), a reserved identifier 0x21 = 0; GOAWAY with ID 4 in two
    // bytes.
    let mut input = &[
        0x04, 0x05, 0x01, 0x40, 0x40, 0x21, 0x00, 0x07, 0x02, 0x40, 0x04,
    ][..];
    assert_eq!(input.sync_settings_then_goaway_unpin(), (2, 4));
    assert!(input.is_empty());
}
