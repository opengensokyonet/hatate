//! The payload of a frame, composed onto the stream it is on.
//!
//! [`FramePayload`] delimits a payload of a known length:
//! `io.compose(&mut payload)` reads at most the rest of it from `io`, then
//! answers EOF, so whoever consumes the payload cannot read the next frame.
//! It passes on [`Read`] and [`ReadChunk`], and [`Skip`] where the stream
//! skips, and reports its exact remaining length ([`ExactLen`]). A stream that ends inside the payload is a
//! truncated frame ([`PayloadError::Truncated`]), not an early EOF.
use crate::error_code::{ErrorCode, ErrorCodeOf};
use bytes::{Buf, BufMut};
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, ReceiverFamily};
use nitori_io::{ChunkSegment, ExactLen, Min, Read, ReadChunk, ReadSegment, Skip};
use snafu::Snafu;

/// The part of a frame's payload not yet consumed, composed onto the stream
/// the frame is on. A frame read from a stream holds it
/// ([`Frame`](super::Frame)); finishing the frame skips what is left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramePayload {
    remaining: u64,
    failed: bool,
}

impl FramePayload {
    /// A payload of `length` bytes.
    pub const fn new(length: u64) -> Self {
        Self {
            remaining: length,
            failed: false,
        }
    }

    /// The bytes of the payload not yet consumed.
    pub const fn remaining(&self) -> u64 {
        self.remaining
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
        if self.failed {
            return Poll::Ready(Err(PayloadError::Failed));
        }
        let Some(missing) = NonZeroU64::new(self.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let empty = destination.remaining_mut() == 0;
        let allowed = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let result = ready!(F::poll_read(parent, cx, &mut destination.limit(allowed)));
        match result {
            Ok(None) if !empty => {
                self.failed = true;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Ok(None) => Poll::Ready(Ok(None)),
            Ok(Some(segment)) => {
                self.consume(segment.count.get());
                Poll::Ready(Ok(Some(segment)))
            }
            Err(source) => {
                self.failed = true;
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
            Self::Failed => None,
        }
    }
}

/// The receiver family of a [`FramePayload`] composed onto a parent stream.
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
        state: &'v mut FramePayload,
    }
}

impl<F: ReceiverFamily> ReceiverFamily for PayloadSource<F> {
    type ReceiverView<'v>
        = PayloadView<'v, F>
    where
        Self: 'v;
}

impl<F: ReceiverFamily> Compose<F> for FramePayload {
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
        if state.failed {
            return Poll::Ready(Err(PayloadError::Failed));
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
                state.failed = true;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Err(source) => {
                state.failed = true;
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
        if state.failed {
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
                state.failed = true;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Err(source) => {
                state.failed = true;
                Poll::Ready(Err(PayloadError::Host { source }))
            }
        }
    }
}
