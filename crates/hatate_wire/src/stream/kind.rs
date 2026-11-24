//! The kinds of stream that carry frames.
//!
//! A kind of stream is derived within a class of QUIC stream
//! ([`class`](super::class)) by the part that defines it: RFC 9114 defines
//! request, control and push streams. Each kind is a marker type, which a
//! [`FrameStream`](super::FrameStream) takes as a parameter, and each part
//! says which of its frame types appear on it
//! ([`FramePartOn`](crate::frame::set::FramePartOn)).

/// A kind of stream that carries frames, as a marker type.
pub trait StreamKind {}

/// Request streams ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)),
/// client-initiated bidirectional streams.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct RequestStreamKind;

impl StreamKind for RequestStreamKind {}

/// Control streams ([RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)),
/// unidirectional streams of type 0x00 that each endpoint opens.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ControlStreamKind;

impl StreamKind for ControlStreamKind {}

/// Push streams ([RFC 9114 §6.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2)),
/// server-initiated unidirectional streams of type 0x01.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PushStreamKind;

impl StreamKind for PushStreamKind {}
