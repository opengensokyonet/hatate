//! HTTP/3 error codes ([RFC 9114 §8.1]).
//!
//! An error code is carried in the application error code of QUIC
//! RESET_STREAM, STOP_SENDING and CONNECTION_CLOSE frames. Unknown codes,
//! including those of extensions this connection does not use, have no
//! special meaning ([RFC 9114 §9]).
//!
//! [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
//! [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
use crate::registry;
use core::fmt;
use hatate_wire_qpack::QpackErrorCode;
use sakuya_var_int::VarInt;

/// An HTTP/3 error code: any variable-length integer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ErrorCode(VarInt);

macro_rules! codes {
    ($($(#[$doc:meta])* $name:ident = $value:literal;)+) => {
        impl ErrorCode {
            $($(#[$doc])* pub const $name: Self = Self(VarInt::from_u32($value));)+
        }
    };
}

codes! {
    /// No error (0x0100).
    H3_NO_ERROR = 0x0100;
    /// General protocol error (0x0101).
    H3_GENERAL_PROTOCOL_ERROR = 0x0101;
    /// Internal error (0x0102).
    H3_INTERNAL_ERROR = 0x0102;
    /// Stream creation error (0x0103).
    H3_STREAM_CREATION_ERROR = 0x0103;
    /// A critical stream was closed (0x0104).
    H3_CLOSED_CRITICAL_STREAM = 0x0104;
    /// A frame was not permitted where it arrived (0x0105).
    H3_FRAME_UNEXPECTED = 0x0105;
    /// A frame violated its layout or size rules (0x0106).
    H3_FRAME_ERROR = 0x0106;
    /// The peer is generating excessive load (0x0107).
    H3_EXCESSIVE_LOAD = 0x0107;
    /// A stream ID or push ID was used incorrectly (0x0108).
    H3_ID_ERROR = 0x0108;
    /// An error in the payload of a SETTINGS frame (0x0109).
    H3_SETTINGS_ERROR = 0x0109;
    /// No SETTINGS frame at the beginning of the control stream (0x010a).
    H3_MISSING_SETTINGS = 0x010a;
    /// A request was rejected before any processing (0x010b).
    H3_REQUEST_REJECTED = 0x010b;
    /// The request or its response is cancelled (0x010c).
    H3_REQUEST_CANCELLED = 0x010c;
    /// The stream terminated without a complete request (0x010d).
    H3_REQUEST_INCOMPLETE = 0x010d;
    /// An HTTP message was malformed (0x010e).
    H3_MESSAGE_ERROR = 0x010e;
    /// The connection of a CONNECT request was reset or closed (0x010f).
    H3_CONNECT_ERROR = 0x010f;
    /// The request should be retried over HTTP/1.1 (0x0110).
    H3_VERSION_FALLBACK = 0x0110;
}

impl ErrorCode {
    /// The error code `value`.
    pub const fn new(value: VarInt) -> Self {
        Self(value)
    }

    /// The value on the wire.
    pub const fn value(self) -> VarInt {
        self.0
    }

    /// Whether the code is one of the reserved values 0x1f × N + 0x21, which
    /// have no meaning ([RFC 9114 §8.1]).
    ///
    /// [RFC 9114 §8.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-8.1
    pub const fn is_reserved(self) -> bool {
        registry::is_reserved(self.0)
    }
}

impl From<QpackErrorCode> for ErrorCode {
    fn from(code: QpackErrorCode) -> Self {
        Self(code.value())
    }
}

impl From<VarInt> for ErrorCode {
    fn from(value: VarInt) -> Self {
        Self(value)
    }
}

impl From<ErrorCode> for VarInt {
    fn from(code: ErrorCode) -> Self {
        code.0
    }
}

/// Formats the value in hexadecimal, as the RFCs write error codes.
impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#06x}", self.0.get())
    }
}
