//! HTTP/3 on the wire: frames, settings and unidirectional stream types
//! ([RFC 9114]), composed of parts.
//!
//! Each of these is an extension point of HTTP/3 ([RFC 9114 §9]). RFC 9114
//! together with QPACK is one part, [`Part`]; each extension is another, in
//! its own package. A connection's wire format is the list of the parts it
//! uses, such as `HList![hatate_wire::Part, hatate_wire_datagram::Part]`:
//! [`frame::set::FrameSet`], [`settings::set::SettingsSet`] and
//! [`stream_type::StreamTypeSet`] are implemented for such lists, and what
//! a list reads is a `Coproduct` of what its parts read. A value that no part
//! of the list claims is handed to the caller as unknown rather than
//! rejected, as HTTP/3 requires.
//!
//! The parts of a list must claim disjoint values, none of them reserved.
//! [`assert_claims_valid!`] checks a list at compile time; reading with a
//! list that fails the check does not build either.
//!
//! Reading follows the shape of every object on a byte stream: start (read
//! the head and look it up), advance (consume the content through a
//! composed source), finish (check that the content ended where it should).
//! Every variable-length integer keeps the width it had on the wire.
//!
//! [RFC 9114]: https://www.rfc-editor.org/rfc/rfc9114.html
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
#![no_std]
#![feature(impl_trait_in_assoc_type)]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

pub mod defaults;
pub mod error_code;
pub mod frame;
mod part;
pub mod parts;
pub mod registry;
pub mod settings;
pub mod stream_type;

pub use part::Part;

/// The role of an endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// The endpoint that opens the connection and sends requests.
    Client,
    /// The endpoint that accepts the connection and sends responses.
    Server,
}

/// Asserts at compile time that the parts of a list claim disjoint frame
/// types, setting identifiers and stream types, none of them reserved.
///
/// ```
/// use frunk_core::HList;
/// hatate_wire::assert_claims_valid!(HList![hatate_wire::Part]);
/// ```
///
/// Parts that claim a value twice, or a reserved one, do not pass. The parts
/// below each claim one frame type (the setup is hidden); two that claim the
/// same type fail to build:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues, settings::set::SettingsPart,
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
/// # /// A part that claims the frame type `FRAME` and nothing else.
/// # struct Frame<const FRAME: u32>;
/// # impl<const FRAME: u32> FramePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # impl<const FRAME: u32> SettingsPart for Frame<FRAME> {
/// #     type Identifier = CNil;
/// #     type Setting = CNil;
/// #     type ValueError = Infallible;
/// #     type Occurrences = ();
/// #     const SETTING_IDENTIFIERS: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn identifier_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn setting_of(
/// #         identifier: CNil,
/// #         _identifier_width: VarIntWidth,
/// #         _value: VarIntField<VarInt>,
/// #     ) -> Result<CNil, Infallible> { match identifier {} }
/// #     fn identifier(setting: &CNil) -> CNil { match *setting {} }
/// #     fn fields(setting: &CNil) -> (VarIntField<VarInt>, VarIntField<VarInt>) { match *setting {} }
/// #     fn record(_occurrences: &mut (), identifier: CNil) -> bool { match identifier {} }
/// # }
/// # impl<const FRAME: u32> StreamTypePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Frame<0x0a>, Frame<0x0a>]);
/// ```
///
/// and so does a part that claims 0x21, a value of the form 0x1f × N + 0x21
/// that the registry reserves:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues, settings::set::SettingsPart,
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
/// # /// A part that claims the frame type `FRAME` and nothing else.
/// # struct Frame<const FRAME: u32>;
/// # impl<const FRAME: u32> FramePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # impl<const FRAME: u32> SettingsPart for Frame<FRAME> {
/// #     type Identifier = CNil;
/// #     type Setting = CNil;
/// #     type ValueError = Infallible;
/// #     type Occurrences = ();
/// #     const SETTING_IDENTIFIERS: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn identifier_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn setting_of(
/// #         identifier: CNil,
/// #         _identifier_width: VarIntWidth,
/// #         _value: VarIntField<VarInt>,
/// #     ) -> Result<CNil, Infallible> { match identifier {} }
/// #     fn identifier(setting: &CNil) -> CNil { match *setting {} }
/// #     fn fields(setting: &CNil) -> (VarIntField<VarInt>, VarIntField<VarInt>) { match *setting {} }
/// #     fn record(_occurrences: &mut (), identifier: CNil) -> bool { match identifier {} }
/// # }
/// # impl<const FRAME: u32> StreamTypePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Frame<0x21>]);
/// ```
///
/// The same parts pass when their claims are disjoint and unreserved:
///
/// ```
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues, settings::set::SettingsPart,
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
/// # /// A part that claims the frame type `FRAME` and nothing else.
/// # struct Frame<const FRAME: u32>;
/// # impl<const FRAME: u32> FramePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # impl<const FRAME: u32> SettingsPart for Frame<FRAME> {
/// #     type Identifier = CNil;
/// #     type Setting = CNil;
/// #     type ValueError = Infallible;
/// #     type Occurrences = ();
/// #     const SETTING_IDENTIFIERS: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn identifier_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn setting_of(
/// #         identifier: CNil,
/// #         _identifier_width: VarIntWidth,
/// #         _value: VarIntField<VarInt>,
/// #     ) -> Result<CNil, Infallible> { match identifier {} }
/// #     fn identifier(setting: &CNil) -> CNil { match *setting {} }
/// #     fn fields(setting: &CNil) -> (VarIntField<VarInt>, VarIntField<VarInt>) { match *setting {} }
/// #     fn record(_occurrences: &mut (), identifier: CNil) -> bool { match identifier {} }
/// # }
/// # impl<const FRAME: u32> StreamTypePart for Frame<FRAME> {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Frame<0x0a>, Frame<0x0b>]);
/// ```
#[macro_export]
macro_rules! assert_claims_valid {
    ($parts:ty) => {
        const _: () = ::core::assert!(
            <$parts as $crate::frame::set::FrameSet>::CLAIMS_VALID
                && <$parts as $crate::settings::set::SettingsSet>::CLAIMS_VALID
                && <$parts as $crate::stream_type::StreamTypeSet>::CLAIMS_VALID,
            "the parts claim overlapping or reserved values"
        );
    };
}
