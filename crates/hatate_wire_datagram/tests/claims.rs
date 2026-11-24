//! The claimed values of each part agree with what the part reads, for the
//! parts of the extensions too (the package of RFC 9114 cannot test them,
//! which would need a dependency on them).
use hatate_wire::{
    frame::set::{FramePart, FrameSet},
    settings::{
        KeyedSetting,
        set::{SettingList, SettingsOf, SettingsPart},
    },
    stream_type::{StreamTypePart, StreamTypeSet},
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

fn agree<P: FramePart + StreamTypePart>(name: &str) {
    assert!(!probes().is_empty());
    for value in probes() {
        assert_eq!(
            <P as FramePart>::FRAME_TYPES.contains(value),
            <P as FramePart>::type_value_of(value).is_some(),
            "{name}: frame type {value:?}"
        );
        assert_eq!(
            <P as StreamTypePart>::STREAM_TYPES.contains(value),
            <P as StreamTypePart>::type_value_of(value).is_some(),
            "{name}: stream type {value:?}"
        );
    }
}

#[test]
fn every_part_claims_what_it_reads() {
    agree::<hatate_wire::Part>("hatate_wire::Part");
    agree::<hatate_wire_datagram::Part>("hatate_wire_datagram::Part");
    agree::<hatate_wire_extended_connect::Part>("hatate_wire_extended_connect::Part");
}

#[test]
fn the_claims_of_the_list_of_all_parts_agree_with_its_lookups() {
    type All = frunk_core::HList![
        hatate_wire::Part,
        hatate_wire_datagram::Part,
        hatate_wire_extended_connect::Part
    ];
    for value in probes() {
        assert_eq!(
            <All as FrameSet>::FRAME_TYPES.contains(value),
            <All as FrameSet>::type_value_of(value).is_some(),
            "{value:?}"
        );
        assert_eq!(
            <<All as SettingsOf>::Settings as SettingList>::IDENTIFIERS.contains(value),
            [0x01, 0x06, 0x07, 0x08, 0x33].contains(&value.get()),
            "{value:?}"
        );
        assert_eq!(
            <All as StreamTypeSet>::STREAM_TYPES.contains(value),
            <All as StreamTypeSet>::type_value_of(value).is_some(),
            "{value:?}"
        );
    }
}

#[test]
fn the_extensions_claim_their_one_setting_and_nothing_else() {
    use hatate_wire_datagram::H3Datagram;
    use hatate_wire_extended_connect::EnableConnectProtocol;
    assert_eq!(H3Datagram::IDENTIFIER.get(), 0x33);
    assert_eq!(EnableConnectProtocol::IDENTIFIER.get(), 0x08);
    for value in probes() {
        let datagram = value == H3Datagram::IDENTIFIER;
        let connect = value == EnableConnectProtocol::IDENTIFIER;
        assert_eq!(
            <<hatate_wire_datagram::Part as SettingsPart>::Settings as SettingList>::IDENTIFIERS
                .contains(value),
            datagram
        );
        assert_eq!(
            <<hatate_wire_extended_connect::Part as SettingsPart>::Settings as SettingList>::IDENTIFIERS
                .contains(value),
            connect
        );
        for claimed in [
            <hatate_wire_datagram::Part as FramePart>::FRAME_TYPES.contains(value),
            <hatate_wire_datagram::Part as StreamTypePart>::STREAM_TYPES.contains(value),
            <hatate_wire_extended_connect::Part as FramePart>::FRAME_TYPES.contains(value),
            <hatate_wire_extended_connect::Part as StreamTypePart>::STREAM_TYPES.contains(value),
        ] {
            assert!(!claimed, "{value:?}");
        }
    }
}
