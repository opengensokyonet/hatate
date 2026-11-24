//! The claimed values of each part agree with what the part reads, for the
//! parts of the extensions too (the package of RFC 9114 cannot test them,
//! which would need a dependency on them): the frame types a part claims are
//! those it has on some kind of stream, and the stream types it claims are
//! the unidirectional stream values it does not leave to others.
use frunk_core::HList;
use hatate_wire::{
    frame::set::{FrameSet, FrameSetOn},
    registry::ClaimedValue,
    settings::{
        KeyedSetting,
        set::{SettingList, SettingsOf, SettingsPart},
    },
    stream::{
        class::{ClientInitiatedUnidirectional, ServerInitiatedUnidirectional},
        kind::{ControlStreamKind, PushStreamKind, RequestStreamKind},
        part::{StreamSet, StreamVerdict},
    },
    stream_type::StreamTypeSet,
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

/// Whether the list has `value` as a frame type on some kind of stream.
fn on_some_kind<L>(value: VarInt) -> bool
where
    L: FrameSetOn<RequestStreamKind> + FrameSetOn<ControlStreamKind> + FrameSetOn<PushStreamKind>,
{
    <<L as FrameSetOn<RequestStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<L as FrameSetOn<ControlStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
        || <<L as FrameSetOn<PushStreamKind>>::FrameType as ClaimedValue>::of(value).is_some()
}

fn agree<L>(name: &str)
where
    L: FrameSet
        + StreamTypeSet
        + FrameSetOn<RequestStreamKind>
        + FrameSetOn<ControlStreamKind>
        + FrameSetOn<PushStreamKind>
        + StreamSet<ClientInitiatedUnidirectional, L>
        + StreamSet<ServerInitiatedUnidirectional, L>,
{
    assert!(!probes().is_empty());
    for value in probes() {
        assert_eq!(
            <L as FrameSet>::FRAME_TYPES.contains(value),
            on_some_kind::<L>(value),
            "{name}: frame type {value:?}"
        );
        // What a server opens is claimed or not; what a client opens may
        // also be rejected, which only a claimed value is.
        let claimed = <L as StreamTypeSet>::STREAM_TYPES.contains(value);
        let by_server = <L as StreamSet<ServerInitiatedUnidirectional, L>>::judge(value, false);
        assert_eq!(
            matches!(by_server, StreamVerdict::Claimed(_)),
            claimed,
            "{name}: stream type {value:?} of a server"
        );
        assert!(!matches!(
            by_server,
            StreamVerdict::Error(_) | StreamVerdict::ErrorUnlessClaimed(_)
        ));
        let by_client = <L as StreamSet<ClientInitiatedUnidirectional, L>>::judge(value, false);
        assert_eq!(
            !matches!(by_client, StreamVerdict::NotClaimed),
            claimed,
            "{name}: stream type {value:?} of a client"
        );
    }
}

#[test]
fn every_part_claims_what_it_reads() {
    agree::<HList![hatate_wire::Part]>("hatate_wire::Part");
    agree::<HList![hatate_wire_datagram::Part]>("hatate_wire_datagram::Part");
    agree::<HList![hatate_wire_extended_connect::Part]>("hatate_wire_extended_connect::Part");
}

#[test]
fn the_claims_of_the_list_of_all_parts_agree_with_what_it_reads() {
    type All = HList![
        hatate_wire::Part,
        hatate_wire_datagram::Part,
        hatate_wire_extended_connect::Part
    ];
    agree::<All>("all parts");
    for value in probes() {
        assert_eq!(
            <<All as SettingsOf>::Settings as SettingList>::IDENTIFIERS.contains(value),
            [0x01, 0x06, 0x07, 0x08, 0x33].contains(&value.get()),
            "{value:?}"
        );
    }
}

#[test]
fn the_extensions_claim_their_one_setting_and_nothing_else() {
    use hatate_wire_datagram::H3Datagram;
    use hatate_wire_extended_connect::EnableConnectProtocol;
    type Datagram = HList![hatate_wire_datagram::Part];
    type Connect = HList![hatate_wire_extended_connect::Part];
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
            <Datagram as FrameSet>::FRAME_TYPES.contains(value),
            <Datagram as StreamTypeSet>::STREAM_TYPES.contains(value),
            <Connect as FrameSet>::FRAME_TYPES.contains(value),
            <Connect as StreamTypeSet>::STREAM_TYPES.contains(value),
        ] {
            assert!(!claimed, "{value:?}");
        }
    }
}
