//! The four classes of QUIC stream ([RFC 9000 §2.1]): bidirectional or
//! unidirectional, opened by the client or by the server.
//!
//! Every stream of HTTP/3 is of one of them, and the kinds of stream that
//! HTTP/3 and its extensions define, such as request, control and push
//! streams, are told apart within a class: a part says, for each class,
//! which values at the start of a stream of that class open a stream of its
//! own ([`StreamPart`](super::part::StreamPart)). A client-initiated push
//! stream is no stream of any part.
//!
//! [RFC 9000 §2.1]: https://www.rfc-editor.org/rfc/rfc9000.html#section-2.1
use crate::Role;

mod sealed {
    pub trait Sealed {}
}

/// One of the four classes of QUIC stream, as a marker type.
pub trait StreamClass: sealed::Sealed + Copy {
    /// The role of the endpoint that opens a stream of this class.
    const INITIATOR: Role;

    /// The role of the endpoint that receives a stream of this class: the
    /// peer of the one that opens it.
    const RECEIVER: Role = match Self::INITIATOR {
        Role::Client => Role::Server,
        Role::Server => Role::Client,
    };
}

/// A class of bidirectional streams.
pub trait BidirectionalClass: StreamClass {}

/// A class of unidirectional streams.
pub trait UnidirectionalClass: StreamClass {}

macro_rules! stream_class {
    ($(#[$meta:meta])* $name:ident, $initiator:ident, $direction:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
        pub struct $name;

        impl sealed::Sealed for $name {}

        impl StreamClass for $name {
            const INITIATOR: Role = Role::$initiator;
        }

        impl $direction for $name {}
    };
}

stream_class!(
    /// Client-initiated, bidirectional streams: request streams, and the
    /// bidirectional streams of extensions.
    ClientInitiatedBidirectional,
    Client,
    BidirectionalClass
);
stream_class!(
    /// Server-initiated, bidirectional streams, which HTTP/3 itself does not
    /// use ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)).
    ServerInitiatedBidirectional,
    Server,
    BidirectionalClass
);
stream_class!(
    /// Client-initiated, unidirectional streams.
    ClientInitiatedUnidirectional,
    Client,
    UnidirectionalClass
);
stream_class!(
    /// Server-initiated, unidirectional streams, among them push streams.
    ServerInitiatedUnidirectional,
    Server,
    UnidirectionalClass
);
