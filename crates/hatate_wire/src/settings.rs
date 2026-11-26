//! SETTINGS ([RFC 9114 §7.2.4]).
//!
//! The payload of a SETTINGS frame is a sequence of settings, each an
//! identifier and a value. Each setting a part defines is a type of its own
//! ([`KeyedSetting`]); a part lists its types ([`set::SettingsPart`]), and a
//! connection's list of parts joins them into one list
//! ([`set::SettingsOf`]). The payload is read one parameter at a time
//! ([`codec::SettingParameter`]) and each is inserted
//! ([`set::Settings::insert`]) into a [`set::Settings`], which holds one slot
//! for each type of the list: the type that claims the identifier checks the
//! value, and an identifier that a type has already taken in the frame is a
//! connection error of type H3_SETTINGS_ERROR. An identifier that no type
//! claims is handed to the caller as [`Setting::Unknown`], to be ignored
//! ([RFC 9114 §9]), and is not kept.
//!
//! [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::registry::ClaimedValues;
use core::{convert::Infallible, error::Error};
use hatate_wire_qpack::{QpackBlockedStreams, QpackMaxTableCapacity};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth, VarIntWidthError};
use snafu::Snafu;

pub mod codec;
pub mod set;

/// A setting type: the value of one setting identifier.
///
/// The type checks the rules of its value when it is constructed, and
/// reading constructs it in the same way, so a setting that was read never
/// holds a value its type forbids. A setting's value is a variable-length
/// integer that keeps its width; [`Keyed`] adds the width of the
/// identifier.
pub trait KeyedSetting: Copy {
    /// Why a value is not a value of this type. Each is a connection error
    /// of type H3_SETTINGS_ERROR.
    type ValueError: Error + 'static;

    /// The identifier of the setting.
    const IDENTIFIER: VarInt;

    /// The setting with `value`, as it is on the wire.
    ///
    /// # Errors
    ///
    /// [`Self::ValueError`] if the value breaks a rule of the type.
    fn from_value(value: VarIntField<VarInt>) -> Result<Self, Self::ValueError>;

    /// The value as it is on the wire.
    fn value(&self) -> VarIntField<VarInt>;
}

/// A setting with the width of its identifier on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Keyed<T> {
    identifier_width: VarIntWidth,
    setting: T,
}

impl<T: KeyedSetting> Keyed<T> {
    /// `setting` with its identifier in the shortest encoding.
    pub fn new(setting: T) -> Self {
        Self {
            identifier_width: VarIntWidth::shortest(T::IDENTIFIER),
            setting,
        }
    }

    /// `setting` with its identifier at `identifier_width`.
    ///
    /// # Errors
    ///
    /// [`VarIntWidthError`] if the width cannot hold the identifier.
    pub fn with_identifier_width(
        setting: T,
        identifier_width: VarIntWidth,
    ) -> Result<Self, VarIntWidthError> {
        VarIntField::new(T::IDENTIFIER, identifier_width)?;
        Ok(Self {
            identifier_width,
            setting,
        })
    }

    /// The setting `identifier` was read with: `identifier` holds
    /// [`KeyedSetting::IDENTIFIER`].
    pub(crate) fn read(identifier: VarIntField<VarInt>, setting: T) -> Self {
        debug_assert_eq!(identifier.get(), T::IDENTIFIER);
        Self {
            identifier_width: identifier.width(),
            setting,
        }
    }

    /// The identifier as it is on the wire.
    pub fn identifier(&self) -> VarIntField<VarInt> {
        // invariant: the width was checked to hold the identifier when the
        // value was built.
        VarIntField::new(T::IDENTIFIER, self.identifier_width)
            .expect("the width holds the identifier")
    }

    /// The width of the identifier.
    pub const fn identifier_width(&self) -> VarIntWidth {
        self.identifier_width
    }

    /// The setting.
    pub const fn setting(&self) -> &T {
        &self.setting
    }

    /// Takes the setting.
    pub fn into_setting(self) -> T {
        self.setting
    }
}

/// A setting as a list of setting types reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Setting<T> {
    /// A setting whose identifier a type of the list claims: a `Coproduct`
    /// of the [`Keyed`] types of the list.
    Known(T),
    /// A setting whose identifier no type of the list claims.
    Unknown(UnknownSetting),
}

/// A setting whose identifier no type of a list claims: its identifier and
/// value as they are on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownSetting {
    identifier: VarIntField<VarInt>,
    value: VarIntField<VarInt>,
}

impl UnknownSetting {
    /// The setting with `identifier` and `value`.
    ///
    /// Whether a list of setting types claims the identifier is checked
    /// where the setting is put in a frame
    /// ([`SettingsPayload::new`](codec::SettingsPayload::new)).
    ///
    /// # Errors
    ///
    /// [`Http2SettingIdentifierError`] if the identifier is one that HTTP/2
    /// left behind, which must not be sent.
    pub fn new(
        identifier: VarIntField<VarInt>,
        value: VarIntField<VarInt>,
    ) -> Result<Self, Http2SettingIdentifierError> {
        match Http2SettingIdentifier::of(identifier.get()) {
            Some(identifier) => Err(Http2SettingIdentifierError { identifier }),
            None => Ok(Self { identifier, value }),
        }
    }

    /// The identifier.
    pub const fn identifier(&self) -> VarIntField<VarInt> {
        self.identifier
    }

    /// The value.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// The setting identifiers HTTP/2 defines without a counterpart in HTTP/3:
/// they must not be sent, and receiving one is a connection error of type
/// H3_SETTINGS_ERROR ([RFC 9114 §7.2.4.1]).
///
/// The registry also reserves 0x00 ([RFC 9114 §11.2.2]), which HTTP/2 does
/// not define; no setting type claims it, and it is read as an unknown
/// setting.
///
/// [RFC 9114 §7.2.4.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
/// [RFC 9114 §11.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-11.2.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http2SettingIdentifier {
    /// SETTINGS_ENABLE_PUSH (0x02).
    EnablePush,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x03).
    MaxConcurrentStreams,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x04).
    InitialWindowSize,
    /// SETTINGS_MAX_FRAME_SIZE (0x05).
    MaxFrameSize,
}

impl Http2SettingIdentifier {
    /// The identifier on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::EnablePush => 0x02,
            Self::MaxConcurrentStreams => 0x03,
            Self::InitialWindowSize => 0x04,
            Self::MaxFrameSize => 0x05,
        })
    }

    /// The identifier `value`, if it is one HTTP/2 left behind.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x02 => Some(Self::EnablePush),
            0x03 => Some(Self::MaxConcurrentStreams),
            0x04 => Some(Self::InitialWindowSize),
            0x05 => Some(Self::MaxFrameSize),
            _ => None,
        }
    }
}

/// A setting identifier that HTTP/2 defines without a counterpart in
/// HTTP/3, which must not be sent and is a connection error of type
/// H3_SETTINGS_ERROR when received ([RFC 9114 §7.2.4.1]).
///
/// [RFC 9114 §7.2.4.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("setting identifier {identifier:?} is one that HTTP/2 left behind"))]
pub struct Http2SettingIdentifierError {
    identifier: Http2SettingIdentifier,
}

impl Http2SettingIdentifierError {
    /// The error for `identifier`.
    pub const fn new(identifier: Http2SettingIdentifier) -> Self {
        Self { identifier }
    }

    /// The identifier.
    pub const fn identifier(&self) -> Http2SettingIdentifier {
        self.identifier
    }
}

/// The identifiers the registry reserves outside the 0x1f × N + 0x21 form:
/// 0x00 and those of [`Http2SettingIdentifier`]. No setting type claims
/// them.
pub(crate) static RESERVED_SETTING_IDENTIFIERS: ClaimedValues = ClaimedValues::new(&[
    VarInt::from_u32(0x00)..=VarInt::from_u32(0x00),
    VarInt::from_u32(0x02)..=VarInt::from_u32(0x05),
]);

/// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): the largest field section the
/// sender accepts; unlimited when absent ([RFC 9114 §4.2.2]). Every value is
/// valid.
///
/// [RFC 9114 §4.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MaxFieldSectionSize {
    value: VarIntField<VarInt>,
}

impl MaxFieldSectionSize {
    /// The setting with `value`.
    pub const fn new(value: VarIntField<VarInt>) -> Self {
        Self { value }
    }

    /// The value.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

impl KeyedSetting for MaxFieldSectionSize {
    type ValueError = Infallible;
    const IDENTIFIER: VarInt = VarInt::from_u32(0x06);

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, Infallible> {
        Ok(Self::new(value))
    }

    fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// QPACK's setting, which the part of RFC 9114 takes in. Every value is
/// valid.
impl KeyedSetting for QpackMaxTableCapacity {
    type ValueError = Infallible;
    const IDENTIFIER: VarInt = QpackMaxTableCapacity::IDENTIFIER;

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, Infallible> {
        Ok(Self::new(value))
    }

    fn value(&self) -> VarIntField<VarInt> {
        QpackMaxTableCapacity::value(self)
    }
}

/// QPACK's setting, which the part of RFC 9114 takes in. Every value is
/// valid.
impl KeyedSetting for QpackBlockedStreams {
    type ValueError = Infallible;
    const IDENTIFIER: VarInt = QpackBlockedStreams::IDENTIFIER;

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, Infallible> {
        Ok(Self::new(value))
    }

    fn value(&self) -> VarIntField<VarInt> {
        QpackBlockedStreams::value(self)
    }
}
