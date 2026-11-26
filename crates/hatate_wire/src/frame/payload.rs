//! The payload of a frame and the stream it is read from.
//!
//! [`FramePayload`] holds the stream and what is left of the payload, and
//! lends the stream limited to that rest ([`AsAccess`]): reads end at the end
//! of the payload, so whoever consumes the payload cannot read the next frame.
//! The lent access is a [`Composed`], whose
//! `parent_mut` and `state_mut` reach past the limit: reading the stream
//! through them, or changing the state, breaks the payload and the frame
//! stream it belongs to. Read through the access itself.
//! The limited stream passes on [`Read`] and [`ReadChunk`], and [`Skip`] where
//! the stream skips, and reports its exact remaining length ([`ExactLen`]). A
//! stream that ends inside the payload is a truncated frame
//! ([`PayloadError::Truncated`]), not an early EOF.
//!
//! [`FramePayload::finish`] skips what is left and gives the stream back at
//! the frame boundary. A payload dropped without it leaves the stream inside
//! the payload; to read frame after frame, read them on a
//! [`FrameStream`](crate::stream::FrameStream), which skips for itself.
use super::codec::DecodeToEndError;
use crate::error_code::{ErrorCode, ErrorCodeOf};
use bytes::{Buf, BufMut};
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{AsAccess, Compose, Composed, Lent, ReceiverFamily};
use nitori_codec::DecodeFrom;
use nitori_io::{
    ChunkSegment, ExactLen, Infinite, Min, Read, ReadChunk, ReadSegment, Skip, prelude::*,
};
use snafu::Snafu;

/// The payload of a frame ([RFC 9114 §7.1]): the stream `S` it is read
/// from, at a point inside the payload, and what is left of the payload.
///
/// It lends `S` limited to the rest of the payload ([`AsAccess`]), as an
/// owned value and as `&mut`. [`finish`](Self::finish) skips what is left
/// and gives `S` back at the frame boundary; [`into_source`](Self::into_source)
/// gives it back when nothing is left. Dropped without either, it leaves the
/// stream inside the payload.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
#[must_use = "a payload not finished leaves its stream inside the payload"]
#[derive(Debug)]
pub struct FramePayload<S> {
    /// The stream composed with what is left of the payload.
    pub(crate) stream: Composed<S, PayloadLimit>,
}

impl<S> FramePayload<S> {
    /// The payload of `length` bytes that `source` is at the start of.
    pub(crate) const fn new(source: S, length: u64) -> Self {
        Self {
            stream: Composed::new(source, PayloadLimit::new(length)),
        }
    }

    /// The bytes of the payload not yet consumed.
    pub const fn remaining(&self) -> u64 {
        self.stream.state().remaining
    }

    /// The stream, at the frame boundary, if nothing of the payload is left
    /// and reading it has not failed; otherwise the payload itself.
    ///
    /// # Errors
    ///
    /// The payload, when bytes of it are left or reading it failed.
    pub fn into_source(self) -> Result<S, Self> {
        let limit = self.stream.state();
        if limit.remaining == 0 && limit.state != PayloadState::Failed {
            Ok(self.stream.into_parts().0)
        } else {
            Err(self)
        }
    }
}

impl<S: AsAccess> FramePayload<S>
where
    S::Family: Skip<Count: Clone + Min<u64, Output = u64>>,
    u64: Min<<S::Family as Skip>::Count, Output = <S::Family as Skip>::Count>,
    Infinite: Min<<S::Family as Skip>::Count, Output = <S::Family as Skip>::Count>,
{
    /// Skips what is left of the payload and gives the stream back at the
    /// frame boundary.
    ///
    /// A call dropped before it completes resumes where it stopped: the
    /// payload counts what it skipped.
    ///
    /// # Errors
    ///
    /// [`PayloadError`] when the stream fails or ends inside the payload,
    /// or reading it had already failed; the stream is then inside the
    /// payload and is not given back.
    pub async fn finish(mut self) -> Result<S, PayloadError<<S::Family as Read>::Error>> {
        self.access().skip_to_end().await?;
        Ok(self.stream.into_parts().0)
    }
}

impl<S: AsAccess> FramePayload<S> {
    /// Reads a value of the payload, such as a field of a frame.
    ///
    /// A call dropped before it completes is detected: if it read nothing,
    /// the next value starts over; if it read some of the bytes of the value,
    /// the payload is interrupted, and later reads of it fail with
    /// [`PayloadError::Interrupted`], which the value's error carries. What is
    /// left can still be skipped ([`finish`](Self::finish),
    /// [`FrameStream::next_frame`](crate::stream::FrameStream::next_frame)).
    /// Decoding `V` from the payload directly does not detect it.
    ///
    /// One value is followed at a time. A value read through `decode` reads
    /// its own fields with their `decode_from` on the payload, not with
    /// `decode`: a call of `decode` inside another ends the following of
    /// the outer value, which, dropped between two of its fields, would then
    /// go undetected.
    ///
    /// # Errors
    ///
    /// The value's error.
    pub async fn decode<V, E>(&mut self) -> Result<V, E>
    where
        V: for<'a> DecodeFrom<&'a mut Self, Error = E>,
    {
        self.stream.state_mut().begin_value();
        let value = V::decode_from(&mut *self).await;
        self.stream.state_mut().end_value();
        value
    }

    /// Reads a value of the payload as [`decode`](Self::decode) does, which
    /// must take all of what is left of it, such as the integer of a GOAWAY.
    ///
    /// # Errors
    ///
    /// [`DecodeToEndError`]: the value's error, or bytes of the payload
    /// left after it.
    pub async fn decode_to_end<V, E>(&mut self) -> Result<V, DecodeToEndError<E>>
    where
        V: for<'a> DecodeFrom<&'a mut Self, Error = E>,
    {
        let value = self
            .decode::<V, E>()
            .await
            .map_err(|source| DecodeToEndError::Value { source })?;
        match NonZeroU64::new(self.stream.state().remaining) {
            None => Ok(value),
            Some(left) => Err(DecodeToEndError::Unread { left }),
        }
    }
}

/// The stream limited to the rest of the payload.
impl<S: AsAccess> AsAccess for FramePayload<S> {
    type Family = PayloadSource<Lent<S::Family>>;
    type Access = Composed<S, PayloadLimit>;
    fn access(&mut self) -> &mut Self::Access {
        &mut self.stream
    }
}

/// The stream limited to the rest of the payload, for a payload borrowed
/// from a frame.
impl<S: AsAccess> AsAccess for &mut FramePayload<S> {
    type Family = PayloadSource<Lent<S::Family>>;
    type Access = Composed<S, PayloadLimit>;
    fn access(&mut self) -> &mut Self::Access {
        &mut self.stream
    }
}

/// What is left of the payload of a frame, as composition state on the
/// stream: it limits reads to the rest of the payload. A [`FramePayload`]
/// keeps it; its stream, composed with it, is the payload source
/// ([`PayloadSource`]).
#[derive(Debug, PartialEq, Eq)]
pub struct PayloadLimit {
    remaining: u64,
    state: PayloadState,
}

/// Where reading a payload is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PayloadState {
    /// No value is being read: reads and skips go on.
    Open,
    /// A value is being read through [`FramePayload::decode`], which began
    /// when `start` bytes were left.
    Value {
        /// The bytes left when the value began.
        start: u64,
    },
    /// A value was dropped after it had read some of its bytes: what it left
    /// unread cannot be read as anything else, so reads fail and skips go on.
    Interrupted,
    /// Reading failed: neither reads nor skips go on.
    Failed,
}

impl PayloadLimit {
    /// A payload of `length` bytes.
    pub(crate) const fn new(length: u64) -> Self {
        Self {
            remaining: length,
            state: PayloadState::Open,
        }
    }

    /// Whether a read may go on: not after a failure, nor after a value was
    /// interrupted.
    fn check_read<E>(&self) -> Result<(), PayloadError<E>> {
        match self.state {
            PayloadState::Open | PayloadState::Value { .. } => Ok(()),
            PayloadState::Interrupted => Err(PayloadError::Interrupted),
            PayloadState::Failed => Err(PayloadError::Failed),
        }
    }

    /// A value begins. One begun before and dropped before it finished
    /// either read nothing, and this one starts over, or read some of its
    /// bytes, and the payload is interrupted.
    fn begin_value(&mut self) {
        match self.state {
            PayloadState::Value { start } if start != self.remaining => {
                self.state = PayloadState::Interrupted;
            }
            PayloadState::Open | PayloadState::Value { .. } => {
                self.state = PayloadState::Value {
                    start: self.remaining,
                };
            }
            PayloadState::Interrupted | PayloadState::Failed => {}
        }
    }

    /// The value begun last finished, whether it was read or failed.
    fn end_value(&mut self) {
        if let PayloadState::Value { .. } = self.state {
            self.state = PayloadState::Open;
        }
    }

    /// Takes `count` consumed bytes off the remaining length.
    fn consume(&mut self, count: usize) {
        // invariant: the parent's contract in `nitori_io` bounds a read by
        // the room of the destination and a chunk by the requested maximum,
        // and both were limited to the remaining length.
        self.remaining = u64::try_from(count)
            .ok()
            .and_then(|count| self.remaining.checked_sub(count))
            .expect("the parent delivered at most the remaining length");
    }

    fn poll<'v, F: Read + 'v, O: BufMut + ?Sized>(
        &mut self,
        parent: Pin<&mut F::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> PayloadPoll<F> {
        if let Err(error) = self.check_read() {
            return Poll::Ready(Err(error));
        }
        let Some(missing) = NonZeroU64::new(self.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let empty = destination.remaining_mut() == 0;
        let allowed = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let result = ready!(F::poll_read(parent, cx, &mut destination.limit(allowed)));
        match result {
            Ok(None) if !empty => {
                self.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Ok(None) => Poll::Ready(Ok(None)),
            Ok(Some(segment)) => {
                self.consume(segment.count.get());
                Poll::Ready(Ok(Some(segment)))
            }
            Err(source) => {
                self.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Host { source }))
            }
        }
    }
}

type PayloadPoll<F> =
    Poll<Result<Option<ReadSegment<<F as Read>::Metadata>>, PayloadError<<F as Read>::Error>>>;

/// Failures reading a payload through [`FramePayload`].
#[derive(Debug, Snafu)]
pub enum PayloadError<E> {
    /// The stream ended inside the payload. On a stream that ended cleanly
    /// this is a connection error of type H3_FRAME_ERROR ([RFC 9114 §7.1]).
    ///
    /// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
    #[snafu(display("frame payload ended with {missing} bytes missing"))]
    Truncated {
        /// Bytes of the payload that did not arrive.
        missing: NonZeroU64,
    },
    /// The stream failed.
    #[snafu(display("could not read frame payload"))]
    Host {
        /// The stream's error.
        source: E,
    },
    /// Reading this payload has already failed.
    #[snafu(display("frame payload has already failed"))]
    Failed,
    /// A value read from this payload was dropped after it had read some of
    /// its bytes ([`FramePayload::decode`]): the rest of the payload can only
    /// be skipped.
    #[snafu(display("frame payload was left inside a value"))]
    Interrupted,
}

/// H3_FRAME_ERROR when the stream ended inside the payload
/// ([RFC 9114 §7.1]); the code of the stream's own failure, such as
/// H3_CLOSED_CRITICAL_STREAM on a critical stream. `None` for a read after a
/// failure, whose first failure was already reported.
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for PayloadError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Truncated { .. } => Some(ErrorCode::H3_FRAME_ERROR),
            Self::Host { source } => source.error_code(),
            Self::Failed | Self::Interrupted => None,
        }
    }
}

/// The receiver family of a stream limited to a frame payload by a
/// [`PayloadLimit`].
pub struct PayloadSource<F>(PhantomData<fn(F) -> F>);

pin_project_lite::pin_project! {
    /// The view of a [`PayloadSource`]: the parent view, held by value, and
    /// the payload state.
    pub struct PayloadView<'v, F>
    where
        F: ReceiverFamily,
        F: 'v,
    {
        #[pin]
        parent: F::ReceiverView<'v>,
        state: &'v mut PayloadLimit,
    }
}

impl<F: ReceiverFamily> ReceiverFamily for PayloadSource<F> {
    type ReceiverView<'v>
        = PayloadView<'v, F>
    where
        Self: 'v;
}

impl<F: ReceiverFamily> Compose<F> for PayloadLimit {
    type Family = PayloadSource<F>;
    fn compose<'v>(self: Pin<&'v mut Self>, parent: F::ReceiverView<'v>) -> PayloadView<'v, F>
    where
        F: 'v,
        Self::Family: 'v,
    {
        PayloadView {
            parent,
            state: self.get_mut(),
        }
    }
}

// A short parent is a truncation error, so reading succeeds to EOF exactly
// when the rest of the payload has been read, even on a live stream.
impl<F: ReceiverFamily> ExactLen for PayloadSource<F> {
    type Length = u64;
    type LengthError = !;
    fn poll_remaining_len<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
    ) -> Poll<Result<u64, !>>
    where
        Self: 'v,
    {
        Poll::Ready(Ok(view.project().state.remaining))
    }
}

impl<F: Read> Read for PayloadSource<F> {
    type Error = PayloadError<F::Error>;
    type Metadata = F::Metadata;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<Option<ReadSegment<F::Metadata>>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.project();
        view.state.poll::<F, O>(view.parent, cx, destination)
    }
}

impl<F: ReadChunk> ReadChunk for PayloadSource<F> {
    type Chunk = F::Chunk;
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<ChunkSegment<F::Chunk, <F as Read>::Metadata>>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.project();
        let state = view.state;
        if let Err(error) = state.check_read() {
            return Poll::Ready(Err(error));
        }
        let Some(missing) = NonZeroU64::new(state.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let allowed = usize::try_from(state.remaining)
            .ok()
            .and_then(NonZeroUsize::new)
            .map_or(maximum, |remaining| remaining.min(maximum));
        let result = ready!(F::poll_read_chunk(view.parent, cx, allowed));
        match result {
            Ok(Some(chunk)) => {
                state.consume(chunk.chunk.remaining());
                Poll::Ready(Ok(Some(chunk)))
            }
            Ok(None) => {
                state.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Err(source) => {
                state.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Host { source }))
            }
        }
    }
}

/// The smaller of a caller's maximum and the rest of the payload, as one
/// maximum for the parent.
#[derive(Clone)]
struct PayloadMaximum<M>(M, u64);

impl<C, M: Min<C, Output = C>> Min<C> for PayloadMaximum<M>
where
    u64: Min<C, Output = C>,
{
    type Output = C;
    fn min(self, rhs: C) -> C {
        Min::min(self.0, Min::min(self.1, rhs))
    }
}

/// Skips within the payload, answering EOF at its end without polling the
/// stream, as reads do; a stream that ends inside the payload is a
/// truncated frame. Each skip is bounded by the rest of the payload, so the
/// count, in the stream's own `Count`, fits it.
impl<F: Skip> Skip for PayloadSource<F>
where
    F::Count: Clone + Min<u64, Output = u64>,
    u64: Min<F::Count, Output = F::Count>,
{
    type Count = F::Count;
    fn poll_skip<'v, M: Min<F::Count, Output = F::Count> + Clone>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<F::Count>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.project();
        let state = view.state;
        if state.state == PayloadState::Failed {
            return Poll::Ready(Err(PayloadError::Failed));
        }
        let Some(missing) = NonZeroU64::new(state.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let result = ready!(F::poll_skip(
            view.parent,
            cx,
            PayloadMaximum(maximum, state.remaining)
        ));
        match result {
            Ok(Some(count)) => {
                // invariant: the stream skipped at most the rest of the
                // payload, so the minimum is the count itself. Reading
                // panics on a source that reports more than it was given;
                // here the minimum would hide it.
                debug_assert!(
                    Min::min(count.clone(), u64::MAX) <= state.remaining,
                    "the stream skipped more than the rest of the payload"
                );
                state.remaining -= Min::min(count.clone(), state.remaining);
                Poll::Ready(Ok(Some(count)))
            }
            Ok(None) => {
                state.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Err(source) => {
                state.state = PayloadState::Failed;
                Poll::Ready(Err(PayloadError::Host { source }))
            }
        }
    }
}
