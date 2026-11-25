//! The setting types of a list of parts, and the settings read with them.
use super::{Keyed, KeyedSetting, RESERVED_SETTING_IDENTIFIERS};
use crate::registry::is_reserved;
use core::{fmt, ops::Add};
use frunk_core::{
    coproduct::{CNil, Coproduct},
    hlist::{HCons, HNil, Selector},
};
use sakuya_var_int::{VarInt, VarIntField};

/// One part of the settings of a connection: those RFC 9114 and QPACK
/// define, or those of one extension.
///
/// It is implemented by the marker type of each part. A list of parts
/// implements [`SettingsOf`], which joins the lists of its parts.
pub trait SettingsPart {
    /// The setting types of the part, as a list used as a type only, such
    /// as `HList![QpackMaxTableCapacity, MaxFieldSectionSize]`.
    type Settings: SettingList;
}

/// The setting types of a list of parts: the lists of the parts
/// ([`SettingsPart::Settings`]) joined in the order of the parts.
///
/// It is implemented for `HNil` and for `HCons<P, Ps>` of a part `P` and a
/// list of parts `Ps`, such as `HList![hatate_wire::Part,
/// hatate_wire_datagram::Part]`.
pub trait SettingsOf {
    /// The joined list: one flat list of setting types.
    type Settings: SettingList;
}

impl SettingsOf for HNil {
    type Settings = HNil;
}

impl<P, Ps> SettingsOf for HCons<P, Ps>
where
    P: SettingsPart,
    Ps: SettingsOf,
    P::Settings: Add<Ps::Settings>,
    <P::Settings as Add<Ps::Settings>>::Output: SettingList,
{
    type Settings = <P::Settings as Add<Ps::Settings>>::Output;
}

/// The identifiers that the types of a [`SettingList`] claim, in the order
/// of the list.
#[derive(Debug)]
pub struct SettingIdentifiers(Option<(VarInt, &'static SettingIdentifiers)>);

impl SettingIdentifiers {
    /// No identifier.
    const EMPTY: Self = Self(None);

    /// `first`, then the identifiers of `rest`.
    const fn with(first: VarInt, rest: &'static Self) -> Self {
        Self(Some((first, rest)))
    }

    /// Whether `identifier` is one of the identifiers.
    pub const fn contains(&self, identifier: VarInt) -> bool {
        let mut identifiers = self;
        while let Some((first, rest)) = identifiers.0 {
            if first.get() == identifier.get() {
                return true;
            }
            identifiers = rest;
        }
        false
    }
}

/// A list of setting types: `HNil`, or `HCons<H, T>` of a setting type `H`
/// and a list `T`, such as `HList![MaxFieldSectionSize, H3Datagram]`. The
/// list is used as a type only; the values are in [`Settings`].
///
/// Each function handles the first type of the list and leaves the rest to
/// the rest of the list.
pub trait SettingList {
    /// One slot per type, in the order of the list: `HNil`, or
    /// `HCons<Option<Keyed<H>>, T::Slots>`.
    type Slots;

    /// A setting of a type of the list: `CNil`, or
    /// `Coproduct<Keyed<H>, T::Setting>`.
    type Setting;

    /// The sum of the [`KeyedSetting::ValueError`]s of the types: `CNil`,
    /// or `Coproduct<H::ValueError, T::ValueErrors>`.
    type ValueErrors;

    /// The identifiers the types claim.
    const IDENTIFIERS: &'static SettingIdentifiers;

    /// Whether no two types claim the same identifier, and none claims a
    /// reserved one ([`is_reserved`]), 0x00,
    /// or one left by HTTP/2
    /// ([`Http2SettingIdentifier`](super::Http2SettingIdentifier)).
    const CLAIMS_VALID: bool;

    /// The slots with every slot empty.
    fn empty() -> Self::Slots;

    /// Whether the slot of the type that claims `identifier` holds a
    /// setting; `false` if no type claims it.
    fn is_taken(slots: &Self::Slots, identifier: VarInt) -> bool;

    /// The setting of `identifier` with `value`, as the type that claims
    /// the identifier checks it; `None` if no type claims it.
    ///
    /// # Errors
    ///
    /// The failure of the type if it rejects the value.
    fn setting_of(
        identifier: VarIntField<VarInt>,
        value: VarIntField<VarInt>,
    ) -> Option<Result<Self::Setting, Self::ValueErrors>>;

    /// Puts `setting` into the slot of its type.
    fn insert(slots: &mut Self::Slots, setting: &Self::Setting);

    /// The identifier and value of `setting` as they are on the wire.
    fn fields(setting: &Self::Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>);
}

impl SettingList for HNil {
    type Slots = HNil;
    type Setting = CNil;
    type ValueErrors = CNil;
    const IDENTIFIERS: &'static SettingIdentifiers = &SettingIdentifiers::EMPTY;
    const CLAIMS_VALID: bool = true;

    fn empty() -> HNil {
        HNil
    }

    fn is_taken(_slots: &HNil, _identifier: VarInt) -> bool {
        false
    }

    fn setting_of(
        _identifier: VarIntField<VarInt>,
        _value: VarIntField<VarInt>,
    ) -> Option<Result<CNil, CNil>> {
        None
    }

    fn insert(_slots: &mut HNil, setting: &CNil) {
        match *setting {}
    }

    fn fields(setting: &CNil) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        match *setting {}
    }
}

impl<H: KeyedSetting, T: SettingList> SettingList for HCons<H, T> {
    type Slots = HCons<Option<Keyed<H>>, T::Slots>;
    type Setting = Coproduct<Keyed<H>, T::Setting>;
    type ValueErrors = Coproduct<H::ValueError, T::ValueErrors>;
    const IDENTIFIERS: &'static SettingIdentifiers =
        &SettingIdentifiers::with(H::IDENTIFIER, T::IDENTIFIERS);
    const CLAIMS_VALID: bool = T::CLAIMS_VALID
        && !T::IDENTIFIERS.contains(H::IDENTIFIER)
        && !RESERVED_SETTING_IDENTIFIERS.contains(H::IDENTIFIER)
        && !is_reserved(H::IDENTIFIER);

    fn empty() -> Self::Slots {
        HCons {
            head: None,
            tail: T::empty(),
        }
    }

    fn is_taken(slots: &Self::Slots, identifier: VarInt) -> bool {
        if identifier == H::IDENTIFIER {
            slots.head.is_some()
        } else {
            T::is_taken(&slots.tail, identifier)
        }
    }

    fn setting_of(
        identifier: VarIntField<VarInt>,
        value: VarIntField<VarInt>,
    ) -> Option<Result<Self::Setting, Self::ValueErrors>> {
        if identifier.get() != H::IDENTIFIER {
            return T::setting_of(identifier, value)
                .map(|result| result.map(Coproduct::Inr).map_err(Coproduct::Inr));
        }
        Some(
            H::from_value(value)
                .map(|setting| Coproduct::Inl(Keyed::read(identifier, setting)))
                .map_err(Coproduct::Inl),
        )
    }

    fn insert(slots: &mut Self::Slots, setting: &Self::Setting) {
        match setting {
            Coproduct::Inl(setting) => slots.head = Some(*setting),
            Coproduct::Inr(setting) => T::insert(&mut slots.tail, setting),
        }
    }

    fn fields(setting: &Self::Setting) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
        match setting {
            Coproduct::Inl(setting) => (setting.identifier(), setting.setting().value()),
            Coproduct::Inr(setting) => T::fields(setting),
        }
    }
}

/// The settings of one SETTINGS frame for the list of setting types `L`: a
/// slot for each type, filled as the parameters of the frame are
/// [inserted](Settings::insert).
///
/// Settings whose identifier no type of `L` claims are not kept: the peer
/// may send any number of them, and they are handed to the caller as they
/// are read.
pub struct Settings<L: SettingList> {
    slots: L::Slots,
}

impl<L: SettingList> Settings<L> {
    /// No setting: every slot empty.
    pub fn new() -> Self {
        const {
            assert!(
                L::CLAIMS_VALID,
                "two setting types of the list claim the same identifier, or one claims a reserved one"
            );
        }
        Self { slots: L::empty() }
    }

    /// The setting of the type `T`, or `None` if it is absent.
    ///
    /// `I` is the position of the type in the list, which the compiler
    /// infers: `settings.get::<MaxFieldSectionSize, _>()`.
    pub fn get<T, I>(&self) -> Option<&T>
    where
        L::Slots: Selector<Option<Keyed<T>>, I>,
        T: KeyedSetting,
    {
        self.slots.get().as_ref().map(Keyed::setting)
    }

    pub(crate) fn slots(&self) -> &L::Slots {
        &self.slots
    }

    pub(crate) fn slots_mut(&mut self) -> &mut L::Slots {
        &mut self.slots
    }
}

impl<L: SettingList> Default for Settings<L> {
    fn default() -> Self {
        Self::new()
    }
}

impl<L: SettingList> Clone for Settings<L>
where
    L::Slots: Clone,
{
    fn clone(&self) -> Self {
        Self {
            slots: self.slots.clone(),
        }
    }
}

impl<L: SettingList> fmt::Debug for Settings<L>
where
    L::Slots: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Settings")
            .field("slots", &self.slots)
            .finish()
    }
}

impl<L: SettingList> PartialEq for Settings<L>
where
    L::Slots: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.slots == other.slots
    }
}

impl<L: SettingList> Eq for Settings<L> where L::Slots: Eq {}
