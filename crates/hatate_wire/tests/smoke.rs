#![feature(impl_trait_in_assoc_type)]
use core::marker::PhantomData;
use frunk_core::HList;
use hatate_wire::{
    defaults::RejectKnownDuplicates,
    frame::{
        FrameType, Http3FrameType, control::codec::ReadGoawayFrameExt as _, payload::FramePayload,
    },
    settings::{Setting, codec::ReadSettingExt as _},
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;

type Parts = HList![hatate_wire::Part];
hatate_wire::assert_claims_valid!(Parts);

#[call(sync)]
async fn settings_then_goaway<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> (usize, u64)
where
    <F as Read>::Error: core::fmt::Debug,
{
    use hatate_wire::frame::codec::ReadFrameHeadExt as _;
    let head = io
        .read_frame_head(PhantomData::<Parts>)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        head.frame_type(),
        FrameType::Known(frunk_core::coproduct::Coproduct::Inl(
            Http3FrameType::Settings
        ))
    ));
    let mut payload = head.payload();
    let mut count = 0;
    {
        let mut source = io.compose(&mut payload);
        let mut policy = RejectKnownDuplicates::<Parts>::new();
        while let Some(setting) = source.read_setting(&mut policy).await.unwrap() {
            assert!(matches!(setting, Setting::Known(_) | Setting::Unknown(_)));
            count += 1;
        }
    }
    payload.finish().unwrap();
    let head = io
        .read_frame_head(PhantomData::<Parts>)
        .await
        .unwrap()
        .unwrap();
    let mut payload: FramePayload = head.payload();
    let goaway = {
        let mut source = io.compose(&mut payload);
        source.read_goaway_frame(head.widths()).await.unwrap()
    };
    payload.finish().unwrap();
    (count, goaway.id().get().get().get())
}

#[test]
fn reads_settings_and_goaway() {
    // SETTINGS: QPACK_MAX_TABLE_CAPACITY = 0x40 (2 bytes), a reserved
    // identifier 0x21 = 0; GOAWAY with ID 4 in two bytes.
    let mut input = &[
        0x04, 0x05, 0x01, 0x40, 0x40, 0x21, 0x00, 0x07, 0x02, 0x40, 0x04,
    ][..];
    assert_eq!(input.sync_settings_then_goaway_unpin(), (2, 4));
    assert!(input.is_empty());
}
