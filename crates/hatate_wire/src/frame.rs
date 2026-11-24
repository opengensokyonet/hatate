//! HTTP/3 frames ([RFC 9114 §7]).
//!
//! A frame is a Type, a Length and a payload of Length bytes, on a stream
//! where its bytes may arrive in pieces. Reading one has three steps, as for
//! every object on a byte stream: [`codec::read_received_frame`] reads the
//! Type and Length from a stream that carries frames, finds the part that
//! claims the type and checks that the frame may arrive there; the caller
//! then consumes the payload, the stream composed with a
//! [`payload::FramePayload`], either itself or with the reader of that
//! frame type; and [`ReceivedFrame::finish`] skips what is left of the
//! payload and gives the stream back at the next frame, or
//! [`ReceivedFrame::next`] also reads that frame. [`codec::read_frame`]
//! reads a [`Frame`] from any source, without the type and placement
//! checks.
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
use crate::stream_type::Http3StreamType;
use crate::{Role, registry::ClaimedValues};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth};
use set::{FrameKind, FrameStreamKind};
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
    fn allowed_on(self, stream: FrameStreamKind) -> bool {
        let unidirectional = match stream {
            FrameStreamKind::Request => None,
            FrameStreamKind::Unidirectional(value) => Some(Http3StreamType::of(value)),
        };
        match self {
            Self::Data | Self::Headers => {
                matches!(unidirectional, None | Some(Some(Http3StreamType::Push)))
            }
            Self::PushPromise => unidirectional.is_none(),
            Self::CancelPush | Self::Settings | Self::Goaway | Self::MaxPushId => {
                unidirectional == Some(Some(Http3StreamType::Control))
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

/// A frame ([RFC 9114 §7.1]): its Type, its Length, and its payload `P`.
///
/// Read from a stream with [`codec::read_frame`], the payload is the
/// stream composed with a [`FramePayload`](payload::FramePayload), which
/// ends at the end of the payload; [`finish`](Self::finish) skips what is
/// left of it and gives the stream back, at the next frame, and
/// [`next`](Self::next) reads that frame too. To write a frame, the
/// payload is a source of its bytes ([`codec::write_frame`]).
///
/// The stream stays inside a frame that is dropped before it is finished,
/// and so does it when the call reading the frame is dropped: no frame can be
/// read from it any more, and the stream is abandoned, with STOP_SENDING or
/// by closing the connection, as HTTP/3 does with a stream it stops reading.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
#[must_use = "a stream stays inside a frame that is not finished"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frame<P> {
    r#type: VarIntField<VarInt>,
    length: VarIntField<VarInt>,
    payload: P,
}

impl<P> Frame<P> {
    /// The frame with the Type `r#type`, the Length `length` and the
    /// payload `payload`. Whether the payload has that length is checked
    /// where it is written.
    pub const fn new(r#type: VarIntField<VarInt>, length: VarIntField<VarInt>, payload: P) -> Self {
        Self {
            r#type,
            length,
            payload,
        }
    }

    /// The Type field.
    pub const fn r#type(&self) -> VarIntField<VarInt> {
        self.r#type
    }

    /// The Length field: the length of the payload in bytes.
    pub const fn length(&self) -> VarIntField<VarInt> {
        self.length
    }

    /// The widths of the Type and Length.
    pub const fn widths(&self) -> FrameWidths {
        FrameWidths::new(self.r#type.width(), self.length.width())
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

/// A frame read from a stream that carries frames, with its type as the
/// list of parts of the stream reads it.
///
/// [`codec::read_received_frame`] reads it from a stream composed with a
/// [`FrameStream`](crate::stream::FrameStream), and checks that a frame of
/// its type may arrive there. `T` is the frame type value of the list of
/// parts ([`set::FrameSet::TypeValue`]). As with [`Frame`], the stream
/// stays inside a frame that is dropped before it is finished.
#[must_use = "a stream stays inside a frame that is not finished"]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ReceivedFrame<T, P> {
    frame_type: FrameType<T>,
    frame: Frame<P>,
}

impl<T: Copy, P> ReceivedFrame<T, P> {
    /// The frame of type `frame_type`, which its stream allows.
    pub(crate) const fn new(frame_type: FrameType<T>, frame: Frame<P>) -> Self {
        Self { frame_type, frame }
    }

    /// The frame type, as the list of parts reads it.
    pub const fn frame_type(&self) -> FrameType<T> {
        self.frame_type
    }

    /// The frame.
    pub const fn frame(&self) -> &Frame<P> {
        &self.frame
    }

    /// The payload of the frame.
    pub fn payload(&mut self) -> &mut P {
        self.frame.payload()
    }

    /// The frame, without its type as the parts read it.
    pub fn into_frame(self) -> Frame<P> {
        self.frame
    }
}
