//! The setting identifiers of a list of parts.
use super::RESERVED_SETTING_IDENTIFIERS;
use crate::registry::ClaimedValues;
use core::error::Error;
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil},
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

/// One part of the settings of a connection: those RFC 9114 and QPACK
/// define, or those of one extension.
///
/// It is implemented by the marker type of each part. A list of parts
/// implements [`SettingsSet`], which [`read_setting`](super::codec::read_setting)
/// reads with.
pub trait SettingsPart {
    /// A setting identifier this part claims, in the form of this part:
    /// obtained only from [`identifier_of`](Self::identifier_of).
    type Identifier: Copy + Eq;

    /// A setting of this part: an identifier, a valid value, and the widths
    /// of both on the wire.
    type Setting;

    /// The failures of a value that this part rejects. Each is a connection
    /// error of type H3_SETTINGS_ERROR.
    type ValueError: Error + 'static;

    /// Which identifiers of this part have occurred, for a
    /// [`DuplicateSettingPolicy`](super::codec::DuplicateSettingPolicy):
    /// none by default.
    type Occurrences: Default;

    /// The identifiers this part claims.
    const SETTING_IDENTIFIERS: &'static ClaimedValues;

    /// The identifier `value` in the form of this part, or `None` for one
    /// this part does not claim.
    fn identifier_of(value: VarInt) -> Option<Self::Identifier>;

    /// The setting `identifier`, at `identifier_width`, with `value`.
    ///
    /// # Errors
    ///
    /// [`ValueError`](Self::ValueError) if the value is not valid for the
    /// setting.
    fn setting_of(
        identifier: Self::Identifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Self::Setting, Self::ValueError>;

    /// The identifier of `setting`.
    fn identifier(setting: &Self::Setting) -> Self::Identifier;

    /// The identifier and value of `setting` as they are on the wire.
    fn fields(setting: &Self::Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>);

    /// Records that `identifier` occurred; `false` if it had already.
    fn record(occurrences: &mut Self::Occurrences, identifier: Self::Identifier) -> bool;
}

/// The settings of a list of parts, `HNil` or `HCons<P, Ps>`. An
/// identifier, setting or value failure of the list is a `Coproduct` of
/// those of the parts, in the order of the list, ending in `CNil`.
pub trait SettingsSet {
    /// An identifier a part of this list claims, in the form of that part.
    type Identifier: Copy + Eq;
    /// A setting of a part of this list.
    type Setting;
    /// A failure of a value that a part of this list rejects.
    type ValueError;
    /// The occurrences of the parts' identifiers.
    type Occurrences: Default;

    /// The identifiers the parts of this list claim.
    const SETTING_IDENTIFIERS: &'static ClaimedValues;

    /// Whether the parts claim disjoint identifiers, none of them reserved
    /// ([`is_reserved`](crate::registry::is_reserved)), 0x00, or left by
    /// HTTP/2 ([`Http2SettingIdentifier`](super::Http2SettingIdentifier)).
    const CLAIMS_VALID: bool;

    /// The identifier `value` in the form of the part that claims it.
    fn identifier_of(value: VarInt) -> Option<Self::Identifier>;

    /// The setting `identifier` with `value`, as its part checks it.
    ///
    /// # Errors
    ///
    /// The part's failure if it rejects the value.
    fn setting_of(
        identifier: Self::Identifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Self::Setting, Self::ValueError>;

    /// The identifier of `setting`.
    fn identifier(setting: &Self::Setting) -> Self::Identifier;

    /// The identifier and value of `setting` as they are on the wire.
    fn fields(setting: &Self::Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>);

    /// Records that `identifier` occurred; `false` if it had already.
    fn record(occurrences: &mut Self::Occurrences, identifier: Self::Identifier) -> bool;
}

impl SettingsSet for HNil {
    type Identifier = CNil;
    type Setting = CNil;
    type ValueError = CNil;
    type Occurrences = ();
    const SETTING_IDENTIFIERS: &'static ClaimedValues = &ClaimedValues::NONE;
    const CLAIMS_VALID: bool = true;

    fn identifier_of(_value: VarInt) -> Option<CNil> {
        None
    }

    fn setting_of(
        identifier: CNil,
        _identifier_width: VarIntWidth,
        _value: VarIntField<VarInt>,
    ) -> Result<CNil, CNil> {
        match identifier {}
    }

    fn identifier(setting: &CNil) -> CNil {
        match *setting {}
    }

    fn fields(setting: &CNil) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        match *setting {}
    }

    fn record(_occurrences: &mut (), identifier: CNil) -> bool {
        match identifier {}
    }
}

impl<P: SettingsPart, Ps: SettingsSet> SettingsSet for HCons<P, Ps> {
    type Identifier = Coproduct<P::Identifier, Ps::Identifier>;
    type Setting = Coproduct<P::Setting, Ps::Setting>;
    type ValueError = Coproduct<P::ValueError, Ps::ValueError>;
    type Occurrences = (P::Occurrences, Ps::Occurrences);
    const SETTING_IDENTIFIERS: &'static ClaimedValues =
        &ClaimedValues::join(P::SETTING_IDENTIFIERS, Ps::SETTING_IDENTIFIERS);
    const CLAIMS_VALID: bool = Ps::CLAIMS_VALID
        && P::SETTING_IDENTIFIERS.is_disjoint(Ps::SETTING_IDENTIFIERS)
        && P::SETTING_IDENTIFIERS.is_disjoint(&RESERVED_SETTING_IDENTIFIERS)
        && P::SETTING_IDENTIFIERS.avoids_reserved();

    fn identifier_of(value: VarInt) -> Option<Self::Identifier> {
        const {
            assert!(
                Self::CLAIMS_VALID,
                "the parts claim overlapping or reserved setting identifiers"
            );
        }
        P::identifier_of(value)
            .map(Coproduct::Inl)
            .or_else(|| Ps::identifier_of(value).map(Coproduct::Inr))
    }

    fn setting_of(
        identifier: Self::Identifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Result<Self::Setting, Self::ValueError> {
        match identifier {
            Coproduct::Inl(identifier) => P::setting_of(identifier, identifier_width, value)
                .map(Coproduct::Inl)
                .map_err(Coproduct::Inl),
            Coproduct::Inr(identifier) => Ps::setting_of(identifier, identifier_width, value)
                .map(Coproduct::Inr)
                .map_err(Coproduct::Inr),
        }
    }

    fn identifier(setting: &Self::Setting) -> Self::Identifier {
        match setting {
            Coproduct::Inl(setting) => Coproduct::Inl(P::identifier(setting)),
            Coproduct::Inr(setting) => Coproduct::Inr(Ps::identifier(setting)),
        }
    }

    fn fields(setting: &Self::Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        match setting {
            Coproduct::Inl(setting) => P::fields(setting),
            Coproduct::Inr(setting) => Ps::fields(setting),
        }
    }

    fn record(occurrences: &mut Self::Occurrences, identifier: Self::Identifier) -> bool {
        match identifier {
            Coproduct::Inl(identifier) => P::record(&mut occurrences.0, identifier),
            Coproduct::Inr(identifier) => Ps::record(&mut occurrences.1, identifier),
        }
    }
}
