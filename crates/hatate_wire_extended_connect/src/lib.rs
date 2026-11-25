//! Extended CONNECT on HTTP/3 ([RFC 9220]): the wire part.
//!
//! The extension adds one setting, SETTINGS_ENABLE_CONNECT_PROTOCOL
//! (0x08), with which a server lets the client send Extended CONNECT
//! requests ([RFC 8441 §3]). Put [`Part`] in a connection's list of parts to
//! read it; without it, the setting is unknown and ignored.
//!
//! [RFC 9220]: https://www.rfc-editor.org/rfc/rfc9220.html
//! [RFC 8441 §3]: https://www.rfc-editor.org/rfc/rfc8441.html#section-3
#![no_std]
#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

use frunk_core::{HList, coproduct::CNil};
use hatate_wire::{
    frame::set::{FramePart, FramePartOn},
    registry::ClaimedValues,
    settings::{KeyedSetting, set::SettingsPart},
    stream::{
        class::StreamClass,
        kind::StreamKind,
        part::{StreamPart, StreamVerdict},
    },
    stream_type::StreamTypePart,
};
use nitori_call::ReceiverAccess;
use nitori_io::Read;
use sakuya_var_int::{VarInt, VarIntField};
use snafu::Snafu;

/// The part of Extended CONNECT: one setting, no frame types or stream
/// types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Part;

/// SETTINGS_ENABLE_CONNECT_PROTOCOL (0x08): 0 or 1. 1 lets the client use
/// Extended CONNECT; a server's own setting has no effect
/// ([RFC 8441 §3]).
///
/// [RFC 8441 §3]: https://www.rfc-editor.org/rfc/rfc8441.html#section-3
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EnableConnectProtocol {
    value: VarIntField<VarInt>,
}

impl EnableConnectProtocol {
    /// The setting with value 1 if `enabled`, else 0, in its shortest
    /// encoding.
    pub fn new(enabled: bool) -> Self {
        Self {
            value: VarIntField::shortest(VarInt::from_u32(u32::from(enabled))),
        }
    }

    /// Whether the value is 1.
    pub fn enabled(&self) -> bool {
        self.value.get().get() == 1
    }

    /// The value as it is on the wire.
    pub const fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

impl KeyedSetting for EnableConnectProtocol {
    type ValueError = EnableConnectProtocolValueError;
    const IDENTIFIER: VarInt = VarInt::from_u32(0x08);

    fn from_value(value: VarIntField<VarInt>) -> Result<Self, EnableConnectProtocolValueError> {
        if value.get().get() > 1 {
            return Err(EnableConnectProtocolValueError { value: value.get() });
        }
        Ok(Self { value })
    }

    fn value(&self) -> VarIntField<VarInt> {
        self.value
    }
}

/// A SETTINGS_ENABLE_CONNECT_PROTOCOL value other than 0 or 1.
///
/// [RFC 8441 §3] requires the value to be 0 or 1 and says nothing of a
/// receiver that gets another; this crate rejects it as a connection error
/// of type H3_SETTINGS_ERROR, which RFC 9114 defines for a SETTINGS frame
/// whose contents are invalid ([RFC 9114 §8.1]).
///
/// [RFC 8441 §3]: https://www.rfc-editor.org/rfc/rfc8441.html#section-3
/// [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("SETTINGS_ENABLE_CONNECT_PROTOCOL is {} rather than 0 or 1", value.get()))]
pub struct EnableConnectProtocolValueError {
    value: VarInt,
}

impl EnableConnectProtocolValueError {
    /// The value received.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

impl SettingsPart for Part {
    type Settings = HList![EnableConnectProtocol];
}

impl FramePart for Part {
    const FRAME_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
}

/// No frame types, on any kind of stream.
impl<K: StreamKind> FramePartOn<K> for Part {
    type FrameType = CNil;
}

impl StreamTypePart for Part {
    const STREAM_TYPES: &'static ClaimedValues = &ClaimedValues::NONE;
}

/// No streams of its own, in any class.
impl<C: StreamClass, L> StreamPart<C, L> for Part {
    type Claimed = CNil;
    type Rejection = CNil;
    type Stream<I> = CNil;
    type ReadError<E> = CNil;

    fn judge(_value: VarInt, _skipped: bool) -> StreamVerdict<CNil, CNil> {
        StreamVerdict::NotClaimed
    }

    async fn read<I: ReceiverAccess<Family: Read<Metadata = ()>>>(
        claimed: CNil,
        _field: VarIntField<VarInt>,
        _io: I,
    ) -> Result<CNil, CNil> {
        match claimed {}
    }
}
