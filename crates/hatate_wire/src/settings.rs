//! SETTINGS ([RFC 9114 §7.2.4]).
//!
//! The payload of a SETTINGS frame is a sequence of settings, each an
//! identifier and a value. The identifiers of a connection are those of a
//! list of parts ([`set`]); [`codec::read_setting`] reads one setting at a
//! time from the payload, lets the part that claims its identifier check
//! the value, and hands an identifier no part claims to the caller as
//! [`Setting::Unknown`], to be ignored ([RFC 9114 §9]). Whether a setting
//! repeats an earlier one is for a [`codec::DuplicateSettingPolicy`] to
//! decide; [`RejectKnownDuplicates`](crate::defaults::RejectKnownDuplicates)
//! is the default.
//!
//! [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::registry::ClaimedValues;
use hatate_wire_qpack::QpackSettingIdentifier;
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;
pub mod set;

/// A setting as a list of parts reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Setting<T> {
    /// A setting whose identifier a part of the list claims, in the form of
    /// that part.
    Known(T),
    /// A setting whose identifier no part of the list claims.
    Unknown(UnknownSetting),
}

/// A setting whose identifier no part of a list claims: its identifier and
/// value as they are on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct UnknownSetting {
    identifier: VarIntField<VarInt>,
    value: VarIntField<VarInt>,
}

impl UnknownSetting {
    /// The setting with `identifier` and `value`.
    ///
    /// `None` if the identifier is one that HTTP/2 left behind
    /// ([`Http2SettingIdentifier`]), which must not be sent.
    pub fn new(identifier: VarIntField<VarInt>, value: VarIntField<VarInt>) -> Option<Self> {
        match Http2SettingIdentifier::of(identifier.get()) {
            Some(_) => None,
            None => Some(Self { identifier, value }),
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
/// not define; no part claims it, and it is read as an unknown setting.
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

/// The identifiers the registry reserves outside the 0x1f × N + 0x21 form:
/// 0x00 and those of [`Http2SettingIdentifier`]. No part claims them.
pub(crate) static RESERVED_SETTING_IDENTIFIERS: ClaimedValues = ClaimedValues::new(&[
    VarInt::from_u32(0x00)..=VarInt::from_u32(0x00),
    VarInt::from_u32(0x02)..=VarInt::from_u32(0x05),
]);

/// A setting identifier that the HTTP/3 part takes: RFC 9114's own and
/// QPACK's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http3SettingIdentifier {
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (0x06): the largest field section
    /// the sender accepts; unlimited by default ([RFC 9114 §4.2.2]).
    ///
    /// [RFC 9114 §4.2.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.2.2
    MaxFieldSectionSize,
    /// A setting of QPACK.
    Qpack(QpackSettingIdentifier),
}

impl Http3SettingIdentifier {
    /// The three identifiers.
    pub const ALL: [Self; 3] = [
        Self::Qpack(QpackSettingIdentifier::MaxTableCapacity),
        Self::MaxFieldSectionSize,
        Self::Qpack(QpackSettingIdentifier::BlockedStreams),
    ];

    /// The identifier on the wire.
    pub const fn value(self) -> VarInt {
        match self {
            Self::MaxFieldSectionSize => VarInt::from_u32(0x06),
            Self::Qpack(identifier) => identifier.value(),
        }
    }

    /// The identifier `value`, if the HTTP/3 part takes it.
    pub const fn of(value: VarInt) -> Option<Self> {
        if value.get() == 0x06 {
            return Some(Self::MaxFieldSectionSize);
        }
        match QpackSettingIdentifier::of(value) {
            Some(identifier) => Some(Self::Qpack(identifier)),
            None => None,
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Qpack(QpackSettingIdentifier::MaxTableCapacity) => 0,
            Self::MaxFieldSectionSize => 1,
            Self::Qpack(QpackSettingIdentifier::BlockedStreams) => 2,
        }
    }
}

/// A setting of the HTTP/3 part. Every value is valid for each of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Http3Setting {
    identifier: Http3SettingIdentifier,
    identifier_width: VarIntWidth,
    value: VarIntField<VarInt>,
}

impl Http3Setting {
    /// The setting `identifier` with `value`, the identifier in its
    /// shortest encoding.
    pub const fn new(identifier: Http3SettingIdentifier, value: VarIntField<VarInt>) -> Self {
        Self::with_identifier_width(identifier, VarIntWidth::One, value)
    }

    /// The setting `identifier` with `value`, the identifier at
    /// `identifier_width`. Every width holds these identifiers.
    pub const fn with_identifier_width(
        identifier: Http3SettingIdentifier,
        identifier_width: VarIntWidth,
        value: VarIntField<VarInt>,
    ) -> Self {
        Self {
            identifier,
            identifier_width,
            value,
        }
    }

    /// The identifier.
    pub const fn identifier(&self) -> Http3SettingIdentifier {
        self.identifier
    }

    /// The width of the identifier.
    pub const fn identifier_width(&self) -> VarIntWidth {
        self.identifier_width
    }

    /// The value.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}
