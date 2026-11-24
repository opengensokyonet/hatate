//! HTTP/3 on the wire: frames, settings and unidirectional stream types
//! ([RFC 9114]), composed of parts.
//!
//! Each of these is an extension point of HTTP/3 ([RFC 9114 §9]). RFC 9114
//! together with QPACK is one part, [`Part`]; each extension is another, in
//! its own package. A connection's wire format is the list of the parts it
//! uses, such as `HList![hatate_wire::Part, hatate_wire_datagram::Part]`:
//! [`frame::set::FrameSet`], [`settings::set::SettingsOf`] and
//! [`stream_type::StreamTypeSet`] are implemented for such lists, and what
//! a list reads is a `Coproduct` of what its parts read. A value that no part
//! of the list claims is handed to the caller as unknown rather than
//! rejected, as HTTP/3 requires.
//!
//! The parts of a list must claim disjoint values, none of them reserved.
//! [`assert_claims_valid!`] checks a list at compile time, in `cargo check`
//! as well. Reading with a list that fails the check does not build either,
//! but that check is evaluated only when the reading code is generated for
//! the list, so `cargo build` reports it and `cargo check` does not; write
//! [`assert_claims_valid!`] where a list is defined.
//!
//! A list of two parts that claim the same frame type does not read, without
//! `assert_claims_valid!`: looking up a type in it fails to build.
//!
//! ```compile_fail,E0080
//! # use frunk_core::{HList, coproduct::CNil};
//! # use hatate_wire::{frame::set::{FramePart, FrameSet}, registry::ClaimedValues};
//! # use sakuya_var_int::VarInt;
//! # /// A part that claims the frame type `FRAME`.
//! # struct Claims<const FRAME: u32>;
//! # impl<const FRAME: u32> FramePart for Claims<FRAME> {
//! #     type Kind = CNil;
//! #     type TypeValue = CNil;
//! #     const FRAME_TYPES: &'static ClaimedValues =
//! #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
//! #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
//! #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
//! #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
//! # }
//! type Parts = HList![Claims<0x0a>, Claims<0x0a>];
//! let _ = <Parts as FrameSet>::type_value_of(VarInt::from_u32(0x0a));
//! ```
//!
//! Reading follows the shape of every object on a byte stream: start (read
//! the head and look it up), advance (consume the content through a
//! composed source), finish (check that the content ended where it should).
//! Every variable-length integer keeps the width it had on the wire.
//!
//! A read that is dropped before it completes keeps nothing of what it
//! read: the bytes the stream handed over stay consumed, and a
//! [`FramePayload`](frame::payload::FramePayload) counts them, but the
//! integer or setting they began is lost. Reading cannot resume from there;
//! the stream is inside the object.
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
/// Parts that claim a value twice, or a reserved one, do not pass. The part
/// below claims one frame type, one setting identifier and one stream type
/// (the setup is hidden). Two that claim the same frame type fail to build:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x0a, 0x0a, 0x0a>, Claims<0x0a, 0x0b, 0x0b>]);
/// ```
///
/// A frame type of the form 0x1f × N + 0x21, which the registry reserves, does not pass:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x21, 0x0a, 0x0a>]);
/// ```
///
/// Nor does a frame type of HTTP/2 that HTTP/3 left behind (0x02):
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x02, 0x0a, 0x0a>]);
/// ```
///
/// Setting identifiers have reserved values too: 0x00,
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x0a, 0x00, 0x0a>]);
/// ```
///
/// the identifiers of HTTP/2 (0x02 to 0x05),
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x0a, 0x04, 0x0a>]);
/// ```
///
/// and an identifier that another part claims, such as SETTINGS_QPACK_BLOCKED_STREAMS (0x07) of [`Part`]:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![hatate_wire::Part, Claims<0x0a, 0x07, 0x0a>]);
/// ```
///
/// A stream type that another part claims, such as the QPACK encoder stream (0x02) of [`Part`], does not pass:
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![hatate_wire::Part, Claims<0x0a, 0x0a, 0x02>]);
/// ```
///
/// Nor does a reserved stream type (0x21):
///
/// ```compile_fail,E0080
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![Claims<0x0a, 0x0a, 0x21>]);
/// ```
///
/// The same parts pass when their claims are disjoint and unreserved:
///
/// ```
/// # use core::convert::Infallible;
/// # use frunk_core::{HList, coproduct::CNil};
/// # use hatate_wire::{
/// #     frame::set::FramePart, registry::ClaimedValues,
/// #     settings::{KeyedSetting, set::SettingsPart},
/// #     stream_type::StreamTypePart,
/// # };
/// # use sakuya_var_int::{VarInt, VarIntField};
/// # /// A part that claims the frame type `FRAME`, the setting identifier
/// # /// `SETTING` and the stream type `STREAM`, and nothing else.
/// # struct Claims<const FRAME: u32, const SETTING: u32, const STREAM: u32>;
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> FramePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const FRAME_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(FRAME)..=VarInt::from_u32(FRAME)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// # #[derive(Clone, Copy)]
/// # struct Claimed<const SETTING: u32>;
/// # impl<const SETTING: u32> KeyedSetting for Claimed<SETTING> {
/// #     type ValueError = Infallible;
/// #     const IDENTIFIER: VarInt = VarInt::from_u32(SETTING);
/// #     fn from_value(_value: VarIntField<VarInt>) -> Result<Self, Infallible> { Ok(Self) }
/// #     fn value(&self) -> VarIntField<VarInt> { VarIntField::shortest(VarInt::ZERO) }
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> SettingsPart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Settings = HList![Claimed<SETTING>];
/// # }
/// # impl<const FRAME: u32, const SETTING: u32, const STREAM: u32> StreamTypePart
/// #     for Claims<FRAME, SETTING, STREAM>
/// # {
/// #     type Kind = CNil;
/// #     type TypeValue = CNil;
/// #     const STREAM_TYPES: &'static ClaimedValues =
/// #         &ClaimedValues::new(&[VarInt::from_u32(STREAM)..=VarInt::from_u32(STREAM)]);
/// #     fn type_value_of(_value: VarInt) -> Option<CNil> { None }
/// #     fn value_of(type_value: CNil) -> VarInt { match type_value {} }
/// #     fn kind_of(type_value: CNil) -> CNil { match type_value {} }
/// # }
/// hatate_wire::assert_claims_valid!(HList![hatate_wire::Part, Claims<0x0a, 0x0a, 0x0a>, Claims<0x0b, 0x0b, 0x0b>]);
/// ```
#[macro_export]
macro_rules! assert_claims_valid {
    ($parts:ty) => {
        const _: () = ::core::assert!(
            <$parts as $crate::frame::set::FrameSet>::CLAIMS_VALID
                && <<$parts as $crate::settings::set::SettingsOf>::Settings as $crate::settings::set::SettingList>::CLAIMS_VALID
                && <$parts as $crate::stream_type::StreamTypeSet>::CLAIMS_VALID,
            "the parts claim overlapping or reserved values"
        );
    };
}
