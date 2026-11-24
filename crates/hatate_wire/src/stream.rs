//! HTTP/3 streams that carry frames ([RFC 9114 §6]).
//!
//! A request stream, a control stream and a push stream each carry frames,
//! which only certain streams may carry and only one role may receive
//! ([RFC 9114 §7.2]). [`FrameStream`] is composition state that tells a
//! stream which one it is: its kind, the role of this endpoint, and the
//! list of parts `L` of the connection. Composed onto a stream, it passes
//! reading, skipping and writing through and adds the [`FrameStreamInfo`]
//! capability, which [`read_received_frame`](crate::frame::codec::read_received_frame)
//! needs to check where a frame arrived.
//!
//! It composes either way: on an access in a call, `io.compose(stream)`
//! or `Composed::new(io, stream)`, or on a receiver it stays with,
//! `ComposedReceiver::new(receiver, stream)`. A request stream is
//! [`FrameStream::request`]; a unidirectional stream starts with its type,
//! which [`codec::read_unidirectional_stream`] reads.
//!
//! [RFC 9114 §6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6
//! [RFC 9114 §7.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2
use crate::{
    Role,
    frame::{PushId, set::FrameStreamKind},
    stream_type::StreamTypeHead,
};
use bytes::{Buf, BufMut};
use core::{
    fmt,
    hash::{Hash, Hasher},
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use nitori_call::{Compose, Composed, Lent, ReceiverFamily};
use nitori_io::{ExactLen, Min, Read, ReadChunk, Skip, Write};
use sakuya_var_int::VarIntField;

#[allow(missing_docs)] // The call macro also generates operation and extension trait items.
pub mod codec;

/// Composition state for a stream that carries frames: its kind, the role
/// of this endpoint, and the list of parts `L` whose frames it reads.
///
/// The parts are a type parameter; name them where the state is made, as in
/// `FrameStream::<Parts>::request(Role::Server)`.
pub struct FrameStream<L> {
    kind: FrameStreamKind,
    role: Role,
    parts: PhantomData<fn() -> L>,
}

impl<L> FrameStream<L> {
    /// The stream of kind `kind` at an endpoint of role `role`.
    pub const fn new(kind: FrameStreamKind, role: Role) -> Self {
        Self {
            kind,
            role,
            parts: PhantomData,
        }
    }

    /// A request stream at an endpoint of role `role`
    /// ([RFC 9114 §6.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.1)).
    pub const fn request(role: Role) -> Self {
        Self::new(FrameStreamKind::Request, role)
    }

    /// The kind of the stream.
    pub const fn kind(&self) -> FrameStreamKind {
        self.kind
    }

    /// The role of this endpoint, which receives the frames.
    pub const fn role(&self) -> Role {
        self.role
    }
}

impl<L> Clone for FrameStream<L> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<L> Copy for FrameStream<L> {}

impl<L> PartialEq for FrameStream<L> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.role == other.role
    }
}

impl<L> Eq for FrameStream<L> {}

impl<L> Hash for FrameStream<L> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.role.hash(state);
    }
}

impl<L> fmt::Debug for FrameStream<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameStream")
            .field("kind", &self.kind)
            .field("role", &self.role)
            .finish()
    }
}

/// Tells which stream that carries frames a source is: the capability that
/// [`FrameStream`] adds to the stream it is composed onto.
#[nitori_call::capability]
pub trait FrameStreamInfo: ReceiverFamily {
    /// The list of parts whose frames the stream carries.
    type Parts;
    /// The stream: its kind and the role of this endpoint.
    fn frame_stream<'visit>(host: Pin<&mut Self::ReceiverView<'visit>>) -> FrameStream<Self::Parts>
    where
        Self: 'visit;
}

/// The family of a view of `F` composed with a [`FrameStream`] of the
/// parts `L`. It passes on [`Read`], [`ReadChunk`], [`ExactLen`],
/// [`Skip`] and [`Write`] where `F` has them, and adds
/// [`FrameStreamInfo`].
pub struct Framed<F, L>(PhantomData<fn(F) -> F>, PhantomData<fn() -> L>);

pin_project_lite::pin_project! {
    /// The view of a [`Framed`] family: the parent view, held by value, and
    /// the stream.
    pub struct FramedView<'v, F, L>
    where
        F: ReceiverFamily,
        F: 'v,
    {
        #[pin]
        parent: F::ReceiverView<'v>,
        stream: FrameStream<L>,
    }
}

impl<F: ReceiverFamily, L> fmt::Debug for FramedView<'_, F, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FramedView")
            .field("stream", &self.stream)
            .finish_non_exhaustive()
    }
}

impl<F: ReceiverFamily, L> ReceiverFamily for Framed<F, L> {
    type ReceiverView<'v>
        = FramedView<'v, F, L>
    where
        Self: 'v;
}

impl<F: ReceiverFamily, L> Compose<F> for FrameStream<L> {
    type Family = Framed<F, L>;
    fn compose<'v>(self: Pin<&'v mut Self>, parent: F::ReceiverView<'v>) -> FramedView<'v, F, L>
    where
        F: 'v,
        Self::Family: 'v,
    {
        FramedView {
            parent,
            stream: *self,
        }
    }
}

impl<F: ReceiverFamily, L> FrameStreamInfo for Framed<F, L> {
    type Parts = L;
    fn frame_stream<'v>(host: Pin<&mut Self::ReceiverView<'v>>) -> FrameStream<L>
    where
        Self: 'v,
    {
        *host.project().stream
    }
}

/// The stream of the lent view, so that state composed on an access of a
/// stream that carries frames keeps the capability.
impl<F: FrameStreamInfo> FrameStreamInfo for Lent<F> {
    type Parts = F::Parts;
    fn frame_stream<'v>(host: Pin<&mut Self::ReceiverView<'v>>) -> FrameStream<F::Parts>
    where
        Self: 'v,
    {
        host.get_mut()
            .with(|parent| F::frame_stream(parent.into_pin()))
    }
}

impl<F: Read, L> Read for Framed<F, L> {
    type Error = F::Error;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        F::poll_read(host.project().parent, cx, destination)
    }
}

impl<F: ReadChunk, L> ReadChunk for Framed<F, L> {
    type Chunk = F::Chunk;
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<F::Chunk>, Self::Error>>
    where
        Self: 'v,
    {
        F::poll_read_chunk(host.project().parent, cx, maximum)
    }
}

impl<F: Skip, L> Skip for Framed<F, L> {
    type Count = F::Count;
    fn poll_skip<'v, M: Min<F::Count, Output = F::Count> + Clone>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<F::Count>, Self::Error>>
    where
        Self: 'v,
    {
        F::poll_skip(host.project().parent, cx, maximum)
    }
}

impl<F: ExactLen, L> ExactLen for Framed<F, L> {
    type Length = F::Length;
    fn remaining_len<'v>(host: Pin<&mut Self::ReceiverView<'v>>) -> F::Length
    where
        Self: 'v,
    {
        F::remaining_len(host.project().parent)
    }
}

impl<F: Write, L> Write for Framed<F, L> {
    type Error = F::Error;
    fn poll_write<'v, I: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        input: &mut I,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        F::poll_write(host.project().parent, cx, input)
    }
}

/// A unidirectional stream whose type has been read
/// ([RFC 9114 §6.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2)):
/// the access `I` it was read from, composed with its [`FrameStream`]
/// where the stream carries frames.
///
/// Take the stream apart with [`Composed::into_parts`] to keep the
/// [`FrameStream`] with a receiver instead.
#[derive(Debug)]
pub enum UnidirectionalStream<I, L: crate::stream_type::StreamTypeSet> {
    /// A control stream (0x00,
    /// [RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1)):
    /// frames follow the type.
    Control(Composed<I, FrameStream<L>>),
    /// A push stream (0x01,
    /// [RFC 9114 §6.2.2](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.2)):
    /// its Push ID followed the type, and frames follow.
    Push {
        /// The Push ID, at the width it had on the wire. Whether it is
        /// within the permitted range is a question for the connection.
        push_id: VarIntField<PushId>,
        /// The stream, at its first frame.
        stream: Composed<I, FrameStream<L>>,
    },
    /// A stream that carries no frames of RFC 9114: a QPACK stream, the
    /// stream of an extension, or a type no part claims, which the receiver
    /// discards or stops reading ([RFC 9114 §9](https://www.rfc-editor.org/rfc/rfc9114.html#section-9)).
    Other(ReceivedStream<L::TypeValue, I>),
}

/// The type at the start of a unidirectional stream, and the access `I`
/// it was read from, at the byte after the type.
///
/// The stream of an extension that carries frames becomes one again with a
/// [`FrameStream`] of its kind, `FrameStream::new(FrameStreamKind::of_stream_type(&stream.head()), role)`.
#[derive(Debug)]
pub struct ReceivedStream<T, I> {
    head: StreamTypeHead<T>,
    io: I,
}

impl<T: Copy, I> ReceivedStream<T, I> {
    /// The type of the stream, as read.
    pub const fn head(&self) -> StreamTypeHead<T> {
        self.head
    }

    /// The access the type was read from.
    pub fn io(&mut self) -> &mut I {
        &mut self.io
    }

    /// The type and the access.
    pub fn into_parts(self) -> (StreamTypeHead<T>, I) {
        (self.head, self.io)
    }
}
