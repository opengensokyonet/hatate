//! Reading the parameters of a SETTINGS frame one at a time, and writing a
//! SETTINGS frame.
use super::{
    Http2SettingIdentifier, Http2SettingIdentifierError, Setting, UnknownSetting,
    set::{SettingList, Settings},
};
use crate::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{Frame, SettingsFrameType, codec::payload_integer_error_code},
    parts::PartsError,
};
use alloc::vec::Vec;
use core::fmt;
use nitori_call::AsAccess;
use nitori_codec::{DecodeFrom, EncodeInto, EncodedLen};
use nitori_io::{Combine, Read, Write, calls::ReadValue};
use sakuya_var_int::{
    VarInt, VarIntField,
    stream::{ReadVarIntError, WriteVarIntError},
};
use snafu::{ResultExt, Snafu};

/// A setting repeats an identifier that occurred earlier in its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("setting identifier {} occurs more than once", identifier.get()))]
pub struct DuplicateSettingError {
    identifier: VarInt,
}

impl DuplicateSettingError {
    /// The error for the repeated `identifier`.
    pub(crate) const fn new(identifier: VarInt) -> Self {
        Self { identifier }
    }

    /// The repeated identifier.
    pub const fn identifier(&self) -> VarInt {
        self.identifier
    }
}

/// A parameter of a SETTINGS frame as read ([RFC 9114 §7.2.4.1]): the
/// identifier and the value, each with the metadata `M` of its bytes, before
/// the list of setting types interprets them ([`Settings::insert`]).
///
/// Read the parameters of a SETTINGS frame one at a time with
/// [`FramePayload::decode`](crate::frame::payload::FramePayload::decode)
/// until nothing of the payload is left, and insert each into a new
/// [`Settings`] for the frame. A parameter of an identifier of HTTP/2 is
/// rejected as it is read.
///
/// [RFC 9114 §7.2.4.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SettingParameter<M = ()> {
    /// The identifier.
    pub identifier: ReadValue<VarIntField<VarInt>, M>,
    /// The value.
    pub value: ReadValue<VarIntField<VarInt>, M>,
}

impl<S, M> DecodeFrom<S> for SettingParameter<M>
where
    S: AsAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    type Error = DecodeSettingParameterError<<S::Family as Read>::Error>;

    async fn decode_from(mut source: S) -> Result<Self, Self::Error> {
        let identifier = ReadValue::<VarIntField<VarInt>, M>::decode_from(source.access())
            .await
            .context(decode_setting_parameter_error::IdentifierSnafu)?;
        if let Some(identifier) = Http2SettingIdentifier::of(identifier.value.get()) {
            return Err(DecodeSettingParameterError::Http2Identifier {
                source: Http2SettingIdentifierError::new(identifier),
            });
        }
        let value = ReadValue::<VarIntField<VarInt>, M>::decode_from(source.access())
            .await
            .context(decode_setting_parameter_error::ValueSnafu)?;
        Ok(Self { identifier, value })
    }
}

/// Failures of reading a [`SettingParameter`] from a source whose failures
/// are `E`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum DecodeSettingParameterError<E> {
    /// The identifier could not be read.
    #[snafu(display("could not read setting identifier"))]
    Identifier {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The identifier is one HTTP/2 left behind.
    #[snafu(display("received a setting identifier of HTTP/2"))]
    Http2Identifier {
        /// The identifier received.
        source: Http2SettingIdentifierError,
    },
    /// The value could not be read.
    #[snafu(display("could not read setting value"))]
    Value {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
}

/// H3_FRAME_ERROR when the payload ends inside the parameter ([RFC 9114
/// §7.1]), H3_SETTINGS_ERROR for an identifier of HTTP/2 ([RFC 9114
/// §7.2.4.1]); otherwise the code of the source's failure, such as
/// H3_FRAME_ERROR when the stream ended inside a frame read through a
/// [`FramePayload`](crate::frame::payload::FramePayload). `None` when the
/// stream failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
/// [RFC 9114 §7.2.4.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodeSettingParameterError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Identifier { source } | Self::Value { source } => {
                payload_integer_error_code(source)
            }
            Self::Http2Identifier { .. } => Some(ErrorCode::H3_SETTINGS_ERROR),
        }
    }
}

impl<L: SettingList> Settings<L> {
    /// Interprets `parameter`, read from the SETTINGS frame these settings
    /// are for, with the list of setting types.
    ///
    /// A parameter whose identifier a type of the list claims is checked by
    /// that type, put into its slot, and returned as [`Setting::Known`]; its
    /// identifier may occur once in a frame. One that no type claims is
    /// [`Setting::Unknown`]: it is returned and not kept, and may repeat.
    /// The metadata of the parameter is not kept.
    ///
    /// # Errors
    ///
    /// [`InsertSettingError`]; its [`ErrorCodeOf::error_code`] gives the
    /// connection error it calls for.
    pub fn insert<M>(
        &mut self,
        parameter: SettingParameter<M>,
    ) -> Result<Setting<L::Setting>, InsertSettingError<L::ValueErrors>> {
        let identifier = parameter.identifier.value;
        let value = parameter.value.value;
        let Some(setting) = L::setting_of(identifier, value) else {
            return Ok(Setting::Unknown(UnknownSetting { identifier, value }));
        };
        if L::is_taken(self.slots(), identifier.get()) {
            return Err(DuplicateSettingError::new(identifier.get()).into());
        }
        let setting = setting
            .map_err(PartsError::new)
            .context(insert_setting_error::RejectedSnafu)?;
        L::insert(self.slots_mut(), &setting);
        Ok(Setting::Known(setting))
    }
}

/// Failures of [`Settings::insert`]. `V` is the sum of the value failures of
/// the setting types.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum InsertSettingError<V> {
    /// The setting type that claims the identifier rejects the value.
    #[snafu(display("invalid setting value"))]
    Rejected {
        /// The failure of the type.
        source: PartsError<V>,
    },
    /// The identifier of a setting type occurs again in the frame.
    #[snafu(transparent)]
    Duplicate {
        /// The repeated identifier.
        source: DuplicateSettingError,
    },
}

/// H3_SETTINGS_ERROR ([RFC 9114 §7.2.4]).
///
/// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
impl<V> ErrorCodeOf<ErrorCode> for InsertSettingError<V> {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(ErrorCode::H3_SETTINGS_ERROR)
    }
}

/// A SETTINGS frame ([RFC 9114 §7.2.4]): the frame type SETTINGS with a
/// [`SettingsPayload`]. Build it with [`Frame::new`], which gives the Type
/// and Length their shortest widths, and write it with
/// [`EncodeInto`].
///
/// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
pub type SettingsFrame<L, M = ()> = Frame<SettingsFrameType, SettingsPayload<L>, M>;

/// The payload of a SETTINGS frame to write for the list of setting types
/// `L`: its settings in order, none repeating an identifier.
pub struct SettingsPayload<L: SettingList> {
    settings: Vec<Setting<L::Setting>>,
}

impl<L: SettingList> SettingsPayload<L> {
    /// The payload of `settings`.
    ///
    /// # Errors
    ///
    /// [`SettingsPayloadError`] if an identifier occurs twice, or an unknown
    /// setting has an identifier that a type of `L` claims.
    pub fn new(settings: Vec<Setting<L::Setting>>) -> Result<Self, SettingsPayloadError> {
        const {
            assert!(
                L::CLAIMS_VALID,
                "two setting types of the list claim the same identifier, or one claims a reserved one"
            );
        }
        for (index, setting) in settings.iter().enumerate() {
            let (identifier, _) = fields::<L>(setting);
            if matches!(setting, Setting::Unknown(_)) && L::IDENTIFIERS.contains(identifier.get()) {
                return Err(SettingsPayloadError::ClaimedIdentifier {
                    identifier: identifier.get(),
                });
            }
            if settings[..index]
                .iter()
                .any(|earlier| fields::<L>(earlier).0.get() == identifier.get())
            {
                return Err(SettingsPayloadError::Duplicate {
                    source: DuplicateSettingError::new(identifier.get()),
                });
            }
        }
        Ok(Self { settings })
    }

    /// The settings, in order.
    pub fn settings(&self) -> &[Setting<L::Setting>] {
        &self.settings
    }
}

impl<L: SettingList> Clone for SettingsPayload<L>
where
    L::Setting: Clone,
{
    fn clone(&self) -> Self {
        Self {
            settings: self.settings.clone(),
        }
    }
}

impl<L: SettingList> fmt::Debug for SettingsPayload<L>
where
    L::Setting: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettingsPayload")
            .field("settings", &self.settings)
            .finish()
    }
}

impl<L: SettingList> PartialEq for SettingsPayload<L>
where
    L::Setting: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.settings == other.settings
    }
}

impl<L: SettingList> Eq for SettingsPayload<L> where L::Setting: Eq {}

fn fields<L: SettingList>(
    setting: &Setting<L::Setting>,
) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
    match setting {
        Setting::Known(setting) => L::fields(setting),
        Setting::Unknown(setting) => (setting.identifier, setting.value),
    }
}

/// A [`SettingsPayload`] cannot be built.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SettingsPayloadError {
    /// An identifier occurs twice.
    #[snafu(transparent)]
    Duplicate {
        /// The repeated identifier.
        source: DuplicateSettingError,
    },
    /// An unknown setting has an identifier that a type of the list claims,
    /// whose value that type would check; read back, it is a known setting.
    #[snafu(display("unknown setting has the claimed identifier {}", identifier.get()))]
    ClaimedIdentifier {
        /// The identifier.
        identifier: VarInt,
    },
}

/// The length of the identifiers and values of the settings.
impl<L: SettingList> EncodedLen for SettingsPayload<L> {
    type LengthError = !;

    async fn encoded_len(&mut self) -> Result<u64, !> {
        let mut length = 0u64;
        for setting in &self.settings {
            let (identifier, value) = fields::<L>(setting);
            length += (identifier.encoded_len() + value.encoded_len()) as u64;
        }
        Ok(length)
    }
}

/// Writes the identifier and then the value of each setting, in order, and
/// gives the merged report of everything it wrote.
impl<S, L> EncodeInto<S> for SettingsPayload<L>
where
    S: AsAccess<Family: Write<Report: Combine>>,
    L: SettingList,
{
    type Output = <S::Family as Write>::Report;
    type Error = EncodeSettingsError<<S::Family as Write>::Error>;

    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        let mut report = <S::Family as Write>::Report::default();
        for (index, setting) in self.settings.iter().enumerate() {
            let (identifier, value) = fields::<L>(setting);
            let identifier = identifier
                .encode_into(sink.access())
                .await
                .context(encode_settings_error::IdentifierSnafu { index })?;
            let value = value
                .encode_into(sink.access())
                .await
                .context(encode_settings_error::ValueSnafu { index })?;
            report = report.combine(identifier).combine(value);
        }
        Ok(report)
    }
}

/// Failures of writing a [`SettingsPayload`] into a sink whose failures are
/// `W`; bytes accepted before the failure stay written.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodeSettingsError<W> {
    /// The identifier of a setting could not be written.
    #[snafu(display("could not write the identifier of setting {index}"))]
    Identifier {
        /// The position of the setting in the frame.
        index: usize,
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
    /// The value of a setting could not be written.
    #[snafu(display("could not write the value of setting {index}"))]
    Value {
        /// The position of the setting in the frame.
        index: usize,
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
}
