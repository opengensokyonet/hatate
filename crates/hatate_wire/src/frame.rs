//! HTTP/3 frames ([RFC 9114 §7]).
//!
//! A frame is a Type, a Length and a payload of Length bytes, on a stream
//! where its bytes may arrive in pieces. Frames are read on a stream that
//! carries them, a [`FrameStream`](crate::stream::FrameStream), which holds
//! the current frame: [`frame`](crate::stream::FrameStream::frame) gives it,
//! with its payload, the stream composed with a [`payload::FramePayload`],
//! for the caller to consume itself or with the reader of that frame type;
//! [`next_frame`](crate::stream::FrameStream::next_frame) skips what is left
//! of the payload and reads the next frame.
//!
//! The types of a connection are those of a list of parts ([`set`]), and
//! each kind of stream has its own ([`set::FrameSetOn`]). A reserved type is
//! [`FrameType::Reserved`]; one no part claims, including those of
//! extensions the list leaves out, is [`FrameType::Unknown`]. Both are
//! skipped ([RFC 9114 §9]).
//!
//! Each variable-length integer keeps the width it was read with, and is
//! written at the width its value holds, so that writing a value read from
//! the wire gives back the same bytes.
//!
//! [RFC 9114 §7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::{
    Role,
    registry::{ClaimedValue, ClaimedValues, UnclaimedValueError, is_reserved},
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
use set::FrameKind;
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

impl ClaimedValue for Http3FrameType {
    fn value(self) -> VarInt {
        Self::value(self)
    }

    fn of(value: VarInt) -> Option<Self> {
        Self::of(value)
    }
}

impl From<Http3FrameType> for VarInt {
    fn from(frame_type: Http3FrameType) -> Self {
        frame_type.value()
    }
}

impl TryFrom<VarInt> for Http3FrameType {
    type Error = UnclaimedValueError;

    fn try_from(value: VarInt) -> Result<Self, UnclaimedValueError> {
        Self::of(value).ok_or(UnclaimedValueError::new(value))
    }
}

/// The role rules of [RFC 9114 §7.2.5, §7.2.7]: only a server pushes, and
/// only a client permits pushes.
///
/// [RFC 9114 §7.2.5, §7.2.7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.5
const fn http3_receivable_by(frame_type: Http3FrameType, role: Role) -> bool {
    match frame_type {
        Http3FrameType::PushPromise => matches!(role, Role::Client),
        Http3FrameType::MaxPushId => matches!(role, Role::Server),
        _ => true,
    }
}

macro_rules! frame_types_on {
    ($(#[$meta:meta])* $name:ident { $($(#[$variant_meta:meta])* $variant:ident),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $($(#[$variant_meta])* $variant,)+
        }

        impl $name {
            /// The frame type as RFC 9114 names it.
            pub const fn frame_type(self) -> Http3FrameType {
                match self {
                    $(Self::$variant => Http3FrameType::$variant,)+
                }
            }

            /// The frame type `frame_type`, if it appears on this kind of stream.
            pub const fn of_frame_type(frame_type: Http3FrameType) -> Option<Self> {
                match frame_type {
                    $(Http3FrameType::$variant => Some(Self::$variant),)+
                    #[allow(unreachable_patterns)]
                    _ => None,
                }
            }
        }

        impl From<$name> for Http3FrameType {
            fn from(frame_type: $name) -> Self {
                frame_type.frame_type()
            }
        }

        impl ClaimedValue for $name {
            fn value(self) -> VarInt {
                self.frame_type().value()
            }

            fn of(value: VarInt) -> Option<Self> {
                match Http3FrameType::of(value) {
                    Some(frame_type) => Self::of_frame_type(frame_type),
                    None => None,
                }
            }
        }

        impl FrameKind for $name {
            fn receivable_by(self, role: Role) -> bool {
                http3_receivable_by(self.frame_type(), role)
            }
        }
    };
}

frame_types_on!(
    /// A frame type of RFC 9114 that appears on a request stream
    /// ([RFC 9114 §7.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2)).
    RequestFrameType {
        /// DATA (0x00).
        Data,
        /// HEADERS (0x01).
        Headers,
        /// PUSH_PROMISE (0x05), which only a client receives.
        PushPromise,
    }
);

frame_types_on!(
    /// A frame type of RFC 9114 that appears on a control stream
    /// ([RFC 9114 §7.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2)).
    ControlFrameType {
        /// CANCEL_PUSH (0x03).
        CancelPush,
        /// SETTINGS (0x04).
        Settings,
        /// GOAWAY (0x07).
        Goaway,
        /// MAX_PUSH_ID (0x0d), which only a server receives.
        MaxPushId,
    }
);

frame_types_on!(
    /// A frame type of RFC 9114 that appears on a push stream
    /// ([RFC 9114 §7.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2)).
    PushFrameType {
        /// DATA (0x00).
        Data,
        /// HEADERS (0x01).
        Headers,
    }
);

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

/// The ID of a GOAWAY frame ([RFC 9114 §7.2.6]): from a server, a
/// client-initiated bidirectional stream ID; from a client, a push ID. Which
/// one it is, and whether it is valid, is a question for the connection,
/// which knows who sent the frame.
///
/// [RFC 9114 §7.2.6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.6
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GoawayId(VarInt);

impl GoawayId {
    /// The ID `value`.
    pub const fn new(value: VarInt) -> Self {
        Self(value)
    }

    /// The value.
    pub const fn get(self) -> VarInt {
        self.0
    }
}

impl From<VarInt> for GoawayId {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<GoawayId> for VarInt {
    fn from(id: GoawayId) -> Self {
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

/// The type of a frame on a stream of some kind, as the list of parts of
/// the stream reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FrameType<T> {
    /// A type that a part of the list has on this kind of stream, in the form
    /// of that part.
    Known(T),
    /// A reserved type ([RFC 9114 §7.2.8]), which belongs to no part and has
    /// no meaning; its payload is skipped.
    ///
    /// [RFC 9114 §7.2.8]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.8
    Reserved(VarInt),
    /// A type that no part of the list claims. Its payload is skipped
    /// ([RFC 9114 §9]); a part that is not in the list could read it.
    ///
    /// [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
    Unknown(VarInt),
}

impl<T: ClaimedValue> FrameType<T> {
    /// The type on the wire.
    pub fn value(self) -> VarInt {
        match self {
            Self::Known(frame_type) => frame_type.value(),
            Self::Reserved(value) | Self::Unknown(value) => value,
        }
    }
}

/// The type `value` as the list reads it: a type it has on this kind of
/// stream, else reserved, else unknown. A type the list claims for other
/// kinds of stream, or one of HTTP/2, is unknown here; reading a frame
/// rejects it before it becomes a `FrameType`.
impl<T: ClaimedValue> From<VarInt> for FrameType<T> {
    fn from(value: VarInt) -> Self {
        match T::of(value) {
            Some(frame_type) => Self::Known(frame_type),
            None if is_reserved(value) => Self::Reserved(value),
            None => Self::Unknown(value),
        }
    }
}

impl<T: ClaimedValue> From<FrameType<T>> for VarInt {
    fn from(frame_type: FrameType<T>) -> Self {
        frame_type.value()
    }
}

/// A frame ([RFC 9114 §7.1]): its Type, its Length, and its payload `P`.
///
/// `T` is the type of the Type field, which keeps the width it had on the
/// wire: the frame types of a kind of stream as its list of parts reads them,
/// [`FrameType`], for a frame read from a
/// [`FrameStream`](crate::stream::FrameStream), or any type that gives its
/// value on the wire, such as [`Http3FrameType`] or a raw `VarInt`, for a
/// frame to write. A frame read from a stream is written back as the bytes
/// it was read from.
///
/// Read from a stream, the payload is the stream composed with what is left
/// of the payload ([`FramePayload`](payload::FramePayload)), which ends at
/// the end of the payload. To write a frame, the payload is a source of its
/// bytes ([`codec::write_frame`]).
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frame<T, P> {
    r#type: VarIntField<T>,
    length: VarIntField<VarInt>,
    payload: P,
}

impl<T, P> Frame<T, P> {
    /// The frame with the Type `r#type`, the Length `length` and the
    /// payload `payload`. Whether the payload has that length is checked
    /// where it is written.
    pub const fn new(r#type: VarIntField<T>, length: VarIntField<VarInt>, payload: P) -> Self {
        Self {
            r#type,
            length,
            payload,
        }
    }

    /// The Length field: the length of the payload in bytes.
    pub const fn length(&self) -> VarIntField<VarInt> {
        self.length
    }

    /// The payload.
    pub fn payload(&mut self) -> &mut P {
        &mut self.payload
    }

    /// The payload, giving up the rest of the frame.
    pub fn into_payload(self) -> P {
        self.payload
    }
}

impl<T: Copy, P> Frame<T, P> {
    /// The Type field.
    pub const fn r#type(&self) -> VarIntField<T> {
        self.r#type
    }

    /// The type.
    pub const fn frame_type(&self) -> T {
        self.r#type.get()
    }

    /// The widths of the Type and Length.
    pub const fn widths(&self) -> FrameWidths {
        FrameWidths::new(self.r#type.width(), self.length.width())
    }
}
