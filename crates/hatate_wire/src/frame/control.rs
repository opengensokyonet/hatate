//! The frames whose payload is one integer: CANCEL_PUSH, GOAWAY and
//! MAX_PUSH_ID, all on the control stream ([RFC 9114 §7.2.3, §7.2.6,
//! §7.2.7]).
//!
//! Each is a [`Frame`] of its frame type whose payload is the integer with the
//! metadata of its bytes. Read one whole from a source (`DecodeFrom`), or read
//! the payload of a frame of a [`FrameStream`](crate::stream::FrameStream)
//! with [`FramePayload::decode_to_end`](super::payload::FramePayload::decode_to_end);
//! either fails when the payload is longer or shorter than the integer. Build
//! one to write with [`Frame::new`], whose Length is the width of the integer.
//!
//! [RFC 9114 §7.2.3, §7.2.6, §7.2.7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.3
use super::{CancelPushFrameType, Frame, GoawayFrameType, GoawayId, MaxPushIdFrameType, PushId};
use nitori_io::calls::ReadValue;
use sakuya_var_int::VarIntField;

/// A CANCEL_PUSH frame (type 0x03, [RFC 9114 §7.2.3]): the push with this ID
/// is cancelled.
///
/// [RFC 9114 §7.2.3]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.3
pub type CancelPushFrame<M = ()> = Frame<CancelPushFrameType, ReadValue<VarIntField<PushId>, M>, M>;

/// A GOAWAY frame (type 0x07, [RFC 9114 §7.2.6]): the sender begins to shut
/// the connection down, up to the [`GoawayId`].
///
/// [RFC 9114 §7.2.6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.6
pub type GoawayFrame<M = ()> = Frame<GoawayFrameType, ReadValue<VarIntField<GoawayId>, M>, M>;

/// A MAX_PUSH_ID frame (type 0x0d, [RFC 9114 §7.2.7]): the largest push ID
/// the client permits.
///
/// [RFC 9114 §7.2.7]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.7
pub type MaxPushIdFrame<M = ()> = Frame<MaxPushIdFrameType, ReadValue<VarIntField<PushId>, M>, M>;
