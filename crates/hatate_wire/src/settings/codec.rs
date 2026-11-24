//! Reading settings one at a time, and writing a SETTINGS frame.
use super::{
    Http2SettingIdentifier, Http2SettingIdentifierError, Setting, UnknownSetting,
    set::{SettingList, Settings},
};
use crate::{
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        FrameWidths, Http3FrameType,
        codec::{
            FrameLengthError, WriteFrameHeadError, WriteFrameHeadExt as _, length_field,
            payload_integer_error_code,
        },
    },
    parts::PartsError,
};
use alloc::vec::Vec;
use core::{fmt, future::poll_fn, task::Poll};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
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

/// Reads the next setting from the payload of a SETTINGS frame into
/// `settings`, whose list of setting types it reads with.
///
/// `io` is the payload, such as a [`FramePayload`](crate::frame::payload::FramePayload)
/// composed onto the control stream. Returns `None` at its end. A setting
/// whose identifier a type of the list claims is checked by that type, put
/// into its slot of `settings`, and returned as [`Setting::Known`]; its
/// identifier may occur once in a frame. One that no type claims is
/// [`Setting::Unknown`]: it is returned and not kept, and may repeat.
///
/// Use a new [`Settings`] for each frame.
///
/// # Errors
///
/// [`ReadSettingError`]; its [`ErrorCodeOf::error_code`] gives the
/// connection error it calls for.
#[call(sync)]
pub async fn read_setting<L: SettingList, F: Read + ExactLen, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    settings: &mut Settings<L>,
) -> Result<Option<Setting<L::Setting>>, ReadSettingError<F::Error, L::ValueErrors>>
where
    <F as ExactLen>::Length: TryInto<u64>,
{
    let remaining =
        poll_fn(|cx| io.poll_access(cx, |mut view, _| Poll::Ready(view.remaining_len()))).await;
    if matches!(remaining.try_into(), Ok(0u64)) {
        return Ok(None);
    }
    let identifier = io
        .read_var_int_field::<VarInt>()
        .await
        .context(read_setting_error::IdentifierSnafu)?;
    if let Some(identifier) = Http2SettingIdentifier::of(identifier.get()) {
        return Err(ReadSettingError::Http2Identifier {
            source: Http2SettingIdentifierError::new(identifier),
        });
    }
    let value = io
        .read_var_int_field::<VarInt>()
        .await
        .context(read_setting_error::ValueSnafu)?;
    let Some(setting) = L::setting_of(identifier, value) else {
        // invariant: HTTP/2 identifiers were rejected above.
        return Ok(Some(Setting::Unknown(UnknownSetting { identifier, value })));
    };
    if L::is_taken(settings.slots(), identifier.get()) {
        return Err(DuplicateSettingError::new(identifier.get()).into());
    }
    let setting = setting
        .map_err(PartsError::new)
        .context(read_setting_error::RejectedSnafu)?;
    L::insert(settings.slots_mut(), &setting);
    Ok(Some(Setting::Known(setting)))
}

/// Failures of [`read_setting`]. `V` is the sum of the value failures of
/// the setting types.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReadSettingError<E, V> {
    /// The identifier could not be read.
    #[snafu(display("could not read setting identifier"))]
    Identifier {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The value could not be read.
    #[snafu(display("could not read setting value"))]
    Value {
        /// The failure of reading the integer.
        source: ReadVarIntError<E>,
    },
    /// The identifier is one HTTP/2 left behind.
    #[snafu(display("received a setting identifier of HTTP/2"))]
    Http2Identifier {
        /// The identifier received.
        source: Http2SettingIdentifierError,
    },
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

/// H3_FRAME_ERROR when the payload ends inside a setting ([RFC 9114 §7.1]),
/// H3_SETTINGS_ERROR for a setting that is not valid ([RFC 9114 §7.2.4]);
/// otherwise the code of the source's failure, such as H3_FRAME_ERROR when
/// the stream ended inside a frame read through a
/// [`FramePayload`](crate::frame::payload::FramePayload). `None` when the
/// stream failed.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
/// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
impl<E: ErrorCodeOf<ErrorCode>, V> ErrorCodeOf<ErrorCode> for ReadSettingError<E, V> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Identifier { source } | Self::Value { source } => {
                payload_integer_error_code(source)
            }
            Self::Http2Identifier { .. } | Self::Rejected { .. } | Self::Duplicate { .. } => {
                Some(ErrorCode::H3_SETTINGS_ERROR)
            }
        }
    }
}

/// A SETTINGS frame to write for the list of setting types `L`: its
/// settings in order, none repeating an identifier, and the widths of its
/// Type and Length.
pub struct SettingsFrame<L: SettingList> {
    widths: FrameWidths,
    length: VarIntField<VarInt>,
    settings: Vec<Setting<L::Setting>>,
}

impl<L: SettingList> SettingsFrame<L> {
    /// The frame of `settings`, with `widths`.
    ///
    /// # Errors
    ///
    /// [`SettingsFrameError`] if an identifier occurs twice, an unknown
    /// setting has an identifier that a type of `L` claims, or the Length
    /// cannot be written at its width.
    pub fn new(
        settings: Vec<Setting<L::Setting>>,
        widths: FrameWidths,
    ) -> Result<Self, SettingsFrameError> {
        const {
            assert!(
                L::CLAIMS_VALID,
                "two setting types of the list claim the same identifier, or one claims a reserved one"
            );
        }
        let mut length = 0u64;
        for (index, setting) in settings.iter().enumerate() {
            let (identifier, value) = fields::<L>(setting);
            if matches!(setting, Setting::Unknown(_)) && L::IDENTIFIERS.contains(identifier.get()) {
                return Err(SettingsFrameError::ClaimedIdentifier {
                    identifier: identifier.get(),
                });
            }
            if settings[..index]
                .iter()
                .any(|earlier| fields::<L>(earlier).0.get() == identifier.get())
            {
                return Err(SettingsFrameError::Duplicate {
                    source: DuplicateSettingError::new(identifier.get()),
                });
            }
            length += (identifier.encoded_len() + value.encoded_len()) as u64;
        }
        let length = length_field(length, 0, widths.length_width())
            .context(settings_frame_error::LengthSnafu)?;
        Ok(Self {
            widths,
            length,
            settings,
        })
    }

    /// The settings, in order.
    pub fn settings(&self) -> &[Setting<L::Setting>] {
        &self.settings
    }

    /// The widths of the Type and Length.
    pub const fn widths(&self) -> FrameWidths {
        self.widths
    }

    /// The length of the payload.
    pub const fn payload_len(&self) -> u64 {
        self.length.get().get()
    }
}

impl<L: SettingList> Clone for SettingsFrame<L>
where
    L::Setting: Clone,
{
    fn clone(&self) -> Self {
        Self {
            widths: self.widths,
            length: self.length,
            settings: self.settings.clone(),
        }
    }
}

impl<L: SettingList> fmt::Debug for SettingsFrame<L>
where
    L::Setting: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SettingsFrame")
            .field("widths", &self.widths)
            .field("length", &self.length)
            .field("settings", &self.settings)
            .finish()
    }
}

impl<L: SettingList> PartialEq for SettingsFrame<L>
where
    L::Setting: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.widths == other.widths
            && self.length == other.length
            && self.settings == other.settings
    }
}

impl<L: SettingList> Eq for SettingsFrame<L> where L::Setting: Eq {}

fn fields<L: SettingList>(
    setting: &Setting<L::Setting>,
) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
    match setting {
        Setting::Known(setting) => L::fields(setting),
        Setting::Unknown(setting) => (setting.identifier, setting.value),
    }
}

/// A SETTINGS frame cannot be built.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum SettingsFrameError {
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
    /// The Length cannot state the payload.
    #[snafu(display("could not encode SETTINGS length"))]
    Length {
        /// Why the Length cannot be written.
        source: FrameLengthError,
    },
}

/// Writes `frame`.
///
/// # Errors
///
/// [`WriteSettingsFrameError`]; bytes accepted before the failure stay
/// written.
#[call(sync)]
pub async fn write_settings_frame<L: SettingList, F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame: &SettingsFrame<L>,
) -> Result<(), WriteSettingsFrameError<F::Error>> {
    let type_field = VarIntField::new(Http3FrameType::Settings.value(), frame.widths.type_width())
        .expect("every width holds the frame type 0x04");
    io.write_frame_head(type_field, frame.length)
        .await
        .context(write_settings_frame_error::HeadSnafu)?;
    for (index, setting) in frame.settings.iter().enumerate() {
        let (identifier, value) = fields::<L>(setting);
        io.write_var_int_field(identifier)
            .await
            .context(write_settings_frame_error::IdentifierSnafu { index })?;
        io.write_var_int_field(value)
            .await
            .context(write_settings_frame_error::ValueSnafu { index })?;
    }
    Ok(())
}

/// Failures of [`write_settings_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum WriteSettingsFrameError<E> {
    /// The head could not be written.
    #[snafu(display("could not write SETTINGS head"))]
    Head {
        /// The failure of writing the head.
        source: WriteFrameHeadError<E>,
    },
    /// The identifier of a setting could not be written.
    #[snafu(display("could not write the identifier of setting {index}"))]
    Identifier {
        /// The position of the setting in the frame.
        index: usize,
        /// The failure of writing the integer.
        source: WriteVarIntError<E>,
    },
    /// The value of a setting could not be written.
    #[snafu(display("could not write the value of setting {index}"))]
    Value {
        /// The position of the setting in the frame.
        index: usize,
        /// The failure of writing the integer.
        source: WriteVarIntError<E>,
    },
}
