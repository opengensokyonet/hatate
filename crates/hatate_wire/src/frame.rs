//! HTTP/3 frames ([RFC 9114 §7]).
//!
//! A frame is a Type, a Length and a payload of Length bytes, on a stream
//! where its bytes may arrive in pieces. Reading one has three steps, as for
//! every object on a byte stream: [`codec::read_frame_head`] reads the Type
//! and Length and finds the part that claims the type; the caller then
//! consumes the payload through a [`payload::FramePayload`] composed onto
//! the stream, either itself or with the reader of that frame type; and
//! [`payload::FramePayload::finish`] checks that the payload was consumed
//! to its end before the next frame starts.
//!
//! The types of a connection are those of a list of parts ([`set`]). A
//! type no part claims, including the reserved types and those of
//! extensions the list leaves out, is [`FrameType::Unknown`] and handed to
//! the caller, who normally discards it ([RFC 9114 §9]).
//!
//! Each variable-length integer keeps the width it was read with, and is
//! written at the width its value holds, so that writing a value read from
//! the wire gives back the same bytes.
//!
//! [RFC 9114 §7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::{Role, registry::ClaimedValues};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
use set::{FrameKind, StreamKind};
use snafu::Snafu;

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;
pub mod control;
pub mod payload;
pub mod set;

/// A frame type that RFC 9114 defines ([RFC 9114 §7.2]).
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http3FrameType {
    /// DATA (0x00): bytes of the content of a message.
    Data,
    /// HEADERS (0x01): an encoded field section.
    Headers,
    /// CANCEL_PUSH (0x03): a push is cancelled.
    CancelPush,
    /// SETTINGS (0x04): the sender's settings.
    Settings,
    /// PUSH_PROMISE (0x05): a server push is promised on a request stream.
    PushPromise,
    /// GOAWAY (0x07): the sender begins to shut the connection down.
    Goaway,
    /// MAX_PUSH_ID (0x0d): the largest push ID the client permits.
    MaxPushId,
}

impl Http3FrameType {
    /// The seven frame types.
    pub const ALL: [Self; 7] = [
        Self::Data,
        Self::Headers,
        Self::CancelPush,
        Self::Settings,
        Self::PushPromise,
        Self::Goaway,
        Self::MaxPushId,
    ];

    /// The frame type on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::Data => 0x00,
            Self::Headers => 0x01,
            Self::CancelPush => 0x03,
            Self::Settings => 0x04,
            Self::PushPromise => 0x05,
            Self::Goaway => 0x07,
            Self::MaxPushId => 0x0d,
        })
    }

    /// The frame type `value`, if RFC 9114 defines it.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x00 => Some(Self::Data),
            0x01 => Some(Self::Headers),
            0x03 => Some(Self::CancelPush),
            0x04 => Some(Self::Settings),
            0x05 => Some(Self::PushPromise),
            0x07 => Some(Self::Goaway),
            0x0d => Some(Self::MaxPushId),
            _ => None,
        }
    }
}

/// The placement and role rules of [RFC 9114 §7.2].
///
/// [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
impl FrameKind for Http3FrameType {
    fn allowed_on(self, stream: StreamKind) -> bool {
        match self {
            Self::Data | Self::Headers => {
                matches!(stream, StreamKind::Request | StreamKind::Push)
            }
            Self::PushPromise => stream == StreamKind::Request,
            Self::CancelPush | Self::Settings | Self::Goaway | Self::MaxPushId => {
                stream == StreamKind::Control
            }
        }
    }

    fn receivable_by(self, role: Role) -> bool {
        match self {
            // Only a server pushes (§7.2.5), and only a client permits
            // pushes (§7.2.7).
            Self::PushPromise => role == Role::Client,
            Self::MaxPushId => role == Role::Server,
            _ => true,
        }
    }
}

/// The frame types HTTP/2 defines and HTTP/3 does not: receiving one is a
/// connection error of type H3_FRAME_UNEXPECTED ([RFC 9114 §7.2.8]).
///
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Http2FrameType {
    /// PRIORITY (0x02).
    Priority,
    /// PING (0x06).
    Ping,
    /// WINDOW_UPDATE (0x08).
    WindowUpdate,
    /// CONTINUATION (0x09).
    Continuation,
}

impl Http2FrameType {
    /// The frame type on the wire.
    pub const fn value(self) -> VarInt {
        VarInt::from_u32(match self {
            Self::Priority => 0x02,
            Self::Ping => 0x06,
            Self::WindowUpdate => 0x08,
            Self::Continuation => 0x09,
        })
    }

    /// The frame type `value`, if it is one HTTP/2 left behind.
    pub const fn of(value: VarInt) -> Option<Self> {
        match value.get() {
            0x02 => Some(Self::Priority),
            0x06 => Some(Self::Ping),
            0x08 => Some(Self::WindowUpdate),
            0x09 => Some(Self::Continuation),
            _ => None,
        }
    }
}

/// A frame type that HTTP/2 defines and HTTP/3 does not, which must not be
/// sent and is a connection error of type H3_FRAME_UNEXPECTED when
/// received ([RFC 9114 §7.2.8]).
///
/// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("frame type {frame_type:?} is one that HTTP/2 left behind"))]
pub struct Http2FrameTypeError {
    frame_type: Http2FrameType,
}

impl Http2FrameTypeError {
    /// The error for `frame_type`.
    pub const fn new(frame_type: Http2FrameType) -> Self {
        Self { frame_type }
    }

    /// The frame type.
    pub const fn frame_type(&self) -> Http2FrameType {
        self.frame_type
    }
}

/// The values of [`Http2FrameType`]: no part claims them.
pub(crate) static HTTP2_FRAME_TYPES: ClaimedValues = ClaimedValues::new(&[
    VarInt::from_u32(0x02)..=VarInt::from_u32(0x02),
    VarInt::from_u32(0x06)..=VarInt::from_u32(0x06),
    VarInt::from_u32(0x08)..=VarInt::from_u32(0x09),
]);

/// A push ID ([RFC 9114 §4.6]): any variable-length integer. Whether it is
/// within the permitted range is a question for the connection.
///
/// [RFC 9114 §4.6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-4.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PushId(VarInt);

impl PushId {
    /// The push ID `value`.
    pub const fn new(value: VarInt) -> Self {
        Self(value)
    }

    /// The value.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for PushId {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<PushId> for VarInt {
    fn from(id: PushId) -> Self {
        id.0
    }
}

/// The widths of the Type and Length of a frame whose Length the payload
/// determines. Every width holds the Type of a frame of RFC 9114 and the
/// Length of a CANCEL_PUSH, GOAWAY or MAX_PUSH_ID; the Length of a SETTINGS
/// or PUSH_PROMISE frame may not fit, which building or writing the frame
/// reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameWidths {
    type_width: VarIntWidth,
    length_width: VarIntWidth,
}

impl FrameWidths {
    /// One byte each: the shortest encodings.
    pub const SHORTEST: Self = Self::new(VarIntWidth::One, VarIntWidth::One);

    /// The widths `type_width` and `length_width`.
    pub const fn new(type_width: VarIntWidth, length_width: VarIntWidth) -> Self {
        Self {
            type_width,
            length_width,
        }
    }

    /// The width of the Type.
    pub const fn type_width(self) -> VarIntWidth {
        self.type_width
    }

    /// The width of the Length.
    pub const fn length_width(self) -> VarIntWidth {
        self.length_width
    }
}

/// The type of a frame as a list of parts reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameType<T> {
    /// A type that a part of the list claims, in the form of that part.
    Known(T),
    /// A type no part of the list claims. The caller normally discards the
    /// payload ([RFC 9114 §9]); a part that is not in the list could read it.
    ///
    /// [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
    Unknown(VarInt),
}

/// The Type and Length of a frame, as read from a stream.
///
/// `T` is the frame type value of the list of parts that read it
/// ([`set::FrameSet::TypeValue`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FrameHead<T> {
    frame_type: FrameType<T>,
    type_field: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
}

impl<T: Copy> FrameHead<T> {
    /// The frame type, as the list of parts reads it.
    pub const fn frame_type(&self) -> FrameType<T> {
        self.frame_type
    }

    /// The Type field.
    pub const fn type_field(&self) -> VarIntField<VarInt> {
        self.type_field
    }

    /// The Length field: the length of the payload in bytes.
    pub const fn length(&self) -> VarIntField<VarInt> {
        self.length
    }

    /// The widths of the Type and Length.
    pub const fn widths(&self) -> FrameWidths {
        FrameWidths::new(self.type_field.width(), self.length.width())
    }

    /// The state that delimits the payload, to compose onto the stream the
    /// head was read from.
    pub fn payload(&self) -> payload::FramePayload {
        payload::FramePayload::new(self.length.get().get())
    }
}
