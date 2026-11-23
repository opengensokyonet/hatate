//! The payload of a frame, composed onto the stream it is on.
//!
//! [`FramePayload`] delimits a payload of a known length:
//! `io.compose(&mut payload)` reads at most the rest of it from `io`, then
//! answers EOF, so whoever consumes the payload cannot read the next frame.
//! It passes on [`Read`] and [`ReadChunk`] and reports its exact remaining
//! length ([`ExactLen`]). A stream that ends inside the payload is a
//! truncated frame ([`PayloadError::Truncated`]), not an early EOF.
use bytes::{Buf, BufMut};
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, ReceiverAccess, ReceiverFamily, ViewLoan, call};
use nitori_io::{ExactLen, Read, ReadChunk, prelude::*};
use snafu::Snafu;

/// The part of a frame's payload not yet consumed. Compose it onto the
/// stream the frame head was read from, and [`finish`](Self::finish) it
/// before reading the next frame.
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

    /// Checks that the payload was consumed to its end, so that the stream
    /// is at the next frame.
    ///
    /// # Errors
    ///
    /// [`UnfinishedPayloadError`] if bytes remain or reading the payload
    /// failed; the stream is then inside this frame.
    pub fn finish(&self) -> Result<(), UnfinishedPayloadError> {
        match (self.failed, NonZeroU64::new(self.remaining)) {
            (false, None) => Ok(()),
            (failed, remaining) => Err(UnfinishedPayloadError { remaining, failed }),
        }
    }

    fn poll<'v, F: Read + 'v, O: BufMut + ?Sized>(
        &mut self,
        parent: &mut ViewLoan<'v, F>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, PayloadError<F::Error>>> {
        if self.failed {
            return Poll::Ready(Err(PayloadError::Failed));
        }
        let Some(missing) = NonZeroU64::new(self.remaining) else {
            return Poll::Ready(Ok(0));
        };
        let empty = destination.remaining_mut() == 0;
        let allowed = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let result = ready!(parent.with(|view| F::poll_read(
            view.into_pin(),
            cx,
            &mut destination.limit(allowed)
        )));
        match result {
            Ok(0) if !empty => {
                self.failed = true;
                Poll::Ready(Err(PayloadError::Truncated { missing }))
            }
            Ok(count) => {
                // invariant: the parent filled at most the limited destination.
                self.remaining -= count as u64;
                Poll::Ready(Ok(count))
            }
            Err(source) => {
                self.failed = true;
                Poll::Ready(Err(PayloadError::Host { source }))
            }
        }
    }
}

/// The payload was left before its end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Snafu)]
#[snafu(display("frame payload left unfinished"))]
pub struct UnfinishedPayloadError {
    remaining: Option<NonZeroU64>,
    failed: bool,
}

impl UnfinishedPayloadError {
    /// The bytes of the payload not consumed, if any.
    pub const fn remaining(&self) -> Option<NonZeroU64> {
        self.remaining
    }

    /// Whether reading the payload failed.
    pub const fn failed(&self) -> bool {
        self.failed
    }
}

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

/// The receiver family of a [`FramePayload`] composed onto a parent stream.
pub struct PayloadSource<F>(PhantomData<fn(F) -> F>);

/// The parent view and the payload state lent for one poll.
pub struct PayloadView<'v, F: ReceiverFamily> {
    parent: ViewLoan<'v, F>,
    state: &'v mut FramePayload,
}

impl<F: ReceiverFamily> ReceiverFamily for PayloadSource<F> {
    type ReceiverView<'v>
        = PayloadView<'v, F>
    where
        Self: 'v;
}

impl<F: ReceiverFamily> Compose<F> for FramePayload {
    type Family = PayloadSource<F>;
    fn compose<'v, 'p>(
        self: Pin<&'v mut Self>,
        parent: Pin<&'v mut F::ReceiverView<'p>>,
    ) -> PayloadView<'v, F>
    where
        F: 'p,
        'p: 'v,
        Self::Family: 'v,
    {
        PayloadView {
            parent: ViewLoan::new(parent),
            state: self.get_mut(),
        }
    }
}

// A short parent is a truncation error, so reading succeeds to EOF exactly
// when the rest of the payload has been read, even on a live stream.
impl<F: ReceiverFamily> ExactLen for PayloadSource<F> {
    type Length = u64;
    fn remaining_len<'v>(view: Pin<&mut Self::ReceiverView<'v>>) -> u64
    where
        Self: 'v,
    {
        view.state.remaining
    }
}

impl<F: Read> Read for PayloadSource<F> {
    type Error = PayloadError<F::Error>;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.get_mut();
        view.state.poll(&mut view.parent, cx, destination)
    }
}

impl<F: ReadChunk> ReadChunk for PayloadSource<F> {
    type Chunk = F::Chunk;
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<F::Chunk>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.get_mut();
        let state = &mut view.state;
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
        let result = ready!(view.parent.with(|parent| F::poll_read_chunk(
            parent.into_pin(),
            cx,
            allowed
        )));
        match result {
            Ok(Some(chunk)) => {
                // invariant: a chunk holds at most the requested maximum.
                state.remaining -= chunk.remaining() as u64;
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

/// Reads and discards the rest of a source, such as the payload of a frame
/// of an unknown type, and returns how many bytes it discarded.
///
/// # Errors
///
/// The source's error; the bytes read before it stay consumed.
#[call(sync)]
pub async fn discard<F: Read, A: ReceiverAccess<Family = F>>(io: &mut A) -> Result<u64, F::Error> {
    let mut buffer = [0; 256];
    let mut discarded = 0u64;
    loop {
        let count = io.read(&mut &mut buffer[..]).await?;
        if count == 0 {
            return Ok(discarded);
        }
        discarded += count as u64;
    }
}
