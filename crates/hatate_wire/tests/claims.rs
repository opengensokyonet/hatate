//! The claimed values of a part agree with what the part reads: the
//! compile-time check of disjointness is only as good as that agreement.
use frunk_core::HList;
use hatate_wire::{
    frame::set::{FramePart, FramePartOn, FrameSet, FrameSetOn},
    registry::ClaimedValue,
    settings::set::{SettingList, SettingsOf, SettingsPart},
    stream::kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
    stream_type::{Http3StreamType, StreamTypePart, StreamTypeSet},
};
use sakuya_var_int::VarInt;

fn probes() -> Vec<VarInt> {
    let mut values: Vec<u64> = (0..0x100).collect();
    // The reserved values 0x1f * N + 0x21, small and large, and their
    // neighbours; the largest integer.
    for n in [0, 1, 2, 3, 7, 8, 100, 1 << 20, 1 << 40, 1 << 56] {
        if let Some(reserved) = hatate_wire::registry::reserved(n) {
            let reserved = reserved.get();
            values.extend([reserved - 1, reserved, reserved + 1]);
        }
    }
    values.extend([0x40, 0x3fff, 0x4000, (1 << 62) - 1]);
    values.sort_unstable();
    values.dedup();
    values
        .into_iter()
        .filter_map(|v| VarInt::new(v).ok())
        .collect()
}

/// Whether the frame types the part has on the request, control or push
/// stream include `value`.
fn on_some_stream<P>(value: VarInt) -> bool
where
    P: FramePartOn<RequestStreamKind>
        + FramePartOn<ControlStreamKind>
        + FramePartOn<PushStreamKind>,
{
    <<P as FramePartOn<RequestStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<P as FramePartOn<ControlStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<P as FramePartOn<PushStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
}

/// The same for a list of parts.
fn list_on_some_stream<L>(value: VarInt) -> bool
where
    L: FrameSetOn<RequestStreamKind> + FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
{
    <<L as FrameSetOn<RequestStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<L as FrameSetOn<ControlStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<L as FrameSetOn<PushStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
}

#[test]
fn the_claims_of_the_part_of_rfc_9114_agree_with_its_lookups() {
    assert!(!probes().is_empty());
    for value in probes() {
        // A frame type the part claims appears on at least one kind of
        // stream, and one it does not claim appears on none.
        assert_eq!(
            <hatate_wire::Part as FramePart>::FRAME_TYPES.contains(value),
            on_some_stream::<hatate_wire::Part>(value),
            "frame type {value:?}"
        );
        assert_eq!(
            <hatate_wire::Part as StreamTypePart>::STREAM_TYPES.contains(value),
            Http3StreamType::of(value).is_some(),
            "stream type {value:?}"
        );
    }
}

#[test]
fn the_claims_of_a_list_agree_with_its_lookups() {
    type List = HList![hatate_wire::Part];
    for value in probes() {
        assert_eq!(
            <List as FrameSet>::FRAME_TYPES.contains(value),
            list_on_some_stream::<List>(value),
            "{value:?}"
        );
        assert_eq!(
            <<List as SettingsOf>::Settings as SettingList>::IDENTIFIERS.contains(value),
            [0x01, 0x06, 0x07].contains(&value.get()),
            "{value:?}"
        );
        assert_eq!(
            <List as StreamTypeSet>::STREAM_TYPES.contains(value),
            Http3StreamType::of(value).is_some(),
            "{value:?}"
        );
    }
}

#[test]
fn the_part_claims_nothing_reserved() {
    for value in probes() {
        if hatate_wire::registry::is_reserved(value) {
            assert!(!<hatate_wire::Part as FramePart>::FRAME_TYPES.contains(value));
            assert!(
                !<<hatate_wire::Part as SettingsPart>::Settings as SettingList>::IDENTIFIERS
                    .contains(value)
            );
            assert!(!<hatate_wire::Part as StreamTypePart>::STREAM_TYPES.contains(value));
        }
    }
}
