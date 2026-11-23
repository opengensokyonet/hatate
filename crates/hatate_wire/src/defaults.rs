//! The default choices where RFC 9114 leaves one to the implementation.
use crate::settings::{
    Setting,
    codec::{DuplicateSettingError, DuplicateSettingPolicy},
    set::SettingsSet,
};
use core::{fmt, marker::PhantomData};

/// The default [`DuplicateSettingPolicy`]: a setting whose identifier a
/// part claims may occur once in a frame, and a second occurrence is a
/// connection error of type H3_SETTINGS_ERROR. Unknown identifiers are not
/// checked: no part interprets them, so a repeat changes nothing.
pub struct RejectKnownDuplicates<S: SettingsSet> {
    occurrences: S::Occurrences,
    parts: PhantomData<fn() -> S>,
}

impl<S: SettingsSet> RejectKnownDuplicates<S> {
    /// The policy for one frame, before any setting.
    pub fn new() -> Self {
        Self {
            occurrences: S::Occurrences::default(),
            parts: PhantomData,
        }
    }
}

impl<S: SettingsSet> Default for RejectKnownDuplicates<S> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S: SettingsSet> fmt::Debug for RejectKnownDuplicates<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RejectKnownDuplicates")
            .finish_non_exhaustive()
    }
}

impl<S: SettingsSet> DuplicateSettingPolicy for RejectKnownDuplicates<S> {
    type Parts = S;

    fn check(&mut self, setting: &Setting<S::Setting>) -> Result<(), DuplicateSettingError> {
        match setting {
            Setting::Known(setting) => {
                if S::record(&mut self.occurrences, S::identifier(setting)) {
                    Ok(())
                } else {
                    Err(DuplicateSettingError::new(S::fields(setting).0.get()))
                }
            }
            Setting::Unknown(_) => Ok(()),
        }
    }
}
