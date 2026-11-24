//! Reading settings one at a time, and writing a SETTINGS frame.
use super::{
    Http2SettingIdentifier, Http2SettingIdentifierError, Setting, UnknownSetting, set::SettingsSet,
};
use crate::{
    error_code::ErrorCode,
    frame::{
        FrameWidths, Http3FrameType,
        codec::{
            FrameLengthError, WriteFrameHeadError, WriteFrameHeadExt as _, length_field,
            payload_integer_error_code,
        },
        payload::PayloadError,
    },
    parts::PartsError,
};
use alloc::vec::Vec;
use core::{future::poll_fn, task::Poll};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{ExactLen, prelude::*};
use sakuya_var_int::{
    VarInt, VarIntField,
    call::{ReadVarIntError, ReadVarIntFieldExt as _, WriteVarIntError, WriteVarIntFieldExt as _},
};
use snafu::{ResultExt, Snafu};

/// Decides whether a setting may follow those before it in one SETTINGS
/// frame. RFC 9114 forbids sending an identifier twice and lets a receiver
/// treat a repeat as a connection error of type H3_SETTINGS_ERROR, or not
/// ([RFC 9114 §7.2.4]).
///
/// Use a new policy value for each frame. The default is
/// [`RejectKnownDuplicates`](crate::defaults::RejectKnownDuplicates).
///
/// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
pub trait DuplicateSettingPolicy {
    /// The list of parts whose settings it checks.
    type Parts: SettingsSet;

    /// Checks `setting`, which follows the settings checked before it.
    ///
    /// # Errors
    ///
    /// [`DuplicateSettingError`] to reject the frame.
    fn check(
        &mut self,
        setting: &Setting<<Self::Parts as SettingsSet>::Setting>,
    ) -> Result<(), DuplicateSettingError>;
}

/// A setting repeats an identifier that occurred earlier in its frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("setting identifier {} occurs more than once", identifier.get()))]
pub struct DuplicateSettingError {
    identifier: VarInt,
}

impl DuplicateSettingError {
    /// The error for the repeated `identifier`.
    pub const fn new(identifier: VarInt) -> Self {
        Self { identifier }
    }

    /// The repeated identifier.
    pub const fn identifier(&self) -> VarInt {
        self.identifier
    }
}

/// Reads the next setting from the payload of a SETTINGS frame, of the list
/// of parts that `policy` checks.
///
/// `io` is the payload, such as a [`FramePayload`](crate::frame::payload::FramePayload)
/// composed onto the control stream. Returns `None` at its end. A setting
/// whose identifier a part claims is checked by that part; one that no part
/// claims is [`Setting::Unknown`]. Then `policy` checks it against the
/// settings before it.
///
/// # Errors
///
/// [`ReadSettingError`]; [`ReadSettingError::error_code`] gives the
/// connection error it calls for.
#[call(sync)]
pub async fn read_setting<
    P: DuplicateSettingPolicy,
    F: Read + ExactLen,
    A: ReceiverAccess<Family = F>,
>(
    io: &mut A,
    policy: &mut P,
) -> Result<
    Option<Setting<<P::Parts as SettingsSet>::Setting>>,
    ReadSettingError<F::Error, <P::Parts as SettingsSet>::ValueError>,
>
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
    let setting = match <P::Parts as SettingsSet>::identifier_of(identifier.get()) {
        Some(known) => Setting::Known(
            <P::Parts as SettingsSet>::setting_of(known, identifier.width(), value)
                .map_err(PartsError::new)
                .context(read_setting_error::RejectedSnafu)?,
        ),
        // invariant: HTTP/2 identifiers were rejected above.
        None => Setting::Unknown(UnknownSetting { identifier, value }),
    };
    policy.check(&setting)?;
    Ok(Some(setting))
}

/// Failures of [`read_setting`]. `V` is the sum of the parts' value
/// failures.
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
    /// The part that claims the identifier rejects the value.
    #[snafu(display("invalid setting value"))]
    Rejected {
        /// The part's failure.
        source: PartsError<V>,
    },
    /// The policy rejects a repeated identifier.
    #[snafu(transparent)]
    Duplicate {
        /// The repeated identifier.
        source: DuplicateSettingError,
    },
}

impl<E, V> ReadSettingError<PayloadError<E>, V> {
    /// The connection error this failure calls for, when the payload was
    /// read through a [`FramePayload`](crate::frame::payload::FramePayload):
    /// H3_FRAME_ERROR when the payload or the stream ends inside a setting
    /// ([RFC 9114 §7.1]), H3_SETTINGS_ERROR for a setting that is not valid
    /// ([RFC 9114 §7.2.4]). `None` when the stream failed.
    ///
    /// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
    /// [RFC 9114 §7.2.4]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4
    pub fn error_code(&self) -> Option<ErrorCode> {
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

/// A SETTINGS frame to write: its settings in order, none repeating an
/// identifier, and the widths of its Type and Length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettingsFrame<T> {
    widths: FrameWidths,
    length: VarIntField<VarInt>,
    settings: Vec<Setting<T>>,
}

impl<T> SettingsFrame<T> {
    /// The frame of `settings` of the list of parts `S`, with `widths`.
    ///
    /// # Errors
    ///
    /// [`SettingsFrameError`] if an identifier occurs twice, an unknown
    /// setting has an identifier that a part of `S` claims, or the Length
    /// cannot be written at its width.
    pub fn new<S: SettingsSet<Setting = T>>(
        settings: Vec<Setting<T>>,
        widths: FrameWidths,
    ) -> Result<Self, SettingsFrameError> {
        let mut length = 0u64;
        for (index, setting) in settings.iter().enumerate() {
            let (identifier, value) = fields::<S>(setting);
            if matches!(setting, Setting::Unknown(_))
                && S::identifier_of(identifier.get()).is_some()
            {
                return Err(SettingsFrameError::ClaimedIdentifier {
                    identifier: identifier.get(),
                });
            }
            if settings[..index]
                .iter()
                .any(|earlier| fields::<S>(earlier).0.get() == identifier.get())
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
    pub fn settings(&self) -> &[Setting<T>] {
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

fn fields<S: SettingsSet>(
    setting: &Setting<S::Setting>,
) -> (VarIntField<VarInt>, VarIntField<VarInt>) {
    match setting {
        Setting::Known(setting) => S::fields(setting),
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
    /// An unknown setting has an identifier that a part of the list claims,
    /// whose value that part would check; read back, it is a known setting.
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

/// Writes a SETTINGS frame of the list of parts `S`, which `parts` names.
///
/// # Errors
///
/// [`WriteSettingsFrameError`]; bytes accepted before the failure stay
/// written.
#[call(sync)]
pub async fn write_settings_frame<S: SettingsSet, F: Write, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    frame: &SettingsFrame<S::Setting>,
    parts: core::marker::PhantomData<S>,
) -> Result<(), WriteSettingsFrameError<F::Error>> {
    let _ = parts;
    let type_field = VarIntField::new(Http3FrameType::Settings.value(), frame.widths.type_width())
        .expect("every width holds the frame type 0x04");
    io.write_frame_head(type_field, frame.length)
        .await
        .context(write_settings_frame_error::HeadSnafu)?;
    for (index, setting) in frame.settings.iter().enumerate() {
        let (identifier, value) = fields::<S>(setting);
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
