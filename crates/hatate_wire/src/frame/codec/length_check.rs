//! Holding the payload of a frame being written to its Length.
use bytes::Buf;
use core::{
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, ReceiverFamily};
use nitori_io::{LentBuffer, LentOutcome, Write, WriteLent, WriteLentResult, WriteResult};
use snafu::Snafu;

/// What a frame being written has left of its Length, as composition state
/// on the sink its payload is written to.
///
/// The sink accepts at most what is left of the Length: once it is used
/// up, it accepts nothing (`Ok(None)`), so a payload that writes more fails
/// with its own error, such as a copy's no-progress error, and nothing
/// beyond the Length reaches the stream. A payload that ends before the
/// Length fails the frame ([`Frame`](crate::frame::Frame)'s encoding,
/// [`ShortPayloadError`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadWriteLimit {
    length: u64,
    remaining: u64,
}

impl PayloadWriteLimit {
    /// The limit of a payload of `length` bytes.
    pub(crate) const fn new(length: u64) -> Self {
        Self {
            length,
            remaining: length,
        }
    }

    /// Whether the payload wrote all of its Length.
    pub(crate) fn finish(&self) -> Result<(), ShortPayloadError> {
        match NonZeroU64::new(self.remaining) {
            None => Ok(()),
            Some(missing) => Err(ShortPayloadError {
                length: self.length,
                missing,
            }),
        }
    }

    /// What is left of the Length, as much of it as a write can offer.
    fn left(&self) -> usize {
        usize::try_from(self.remaining).unwrap_or(usize::MAX)
    }

    /// Takes `count` written bytes off what is left.
    fn take(&mut self, count: usize) {
        // invariant: the sink below accepts at most what it is offered, and
        // it is offered at most what is left.
        self.remaining -= count as u64;
    }
}

/// The payload of a frame ended before its Length: it wrote fewer bytes
/// than it reported. Its measurements can only be obtained from a payload
/// that ended short.
#[derive(Debug, PartialEq, Eq, Snafu)]
#[snafu(display("frame payload ended {missing} bytes before its Length {length}"))]
pub struct ShortPayloadError {
    length: u64,
    missing: NonZeroU64,
}

impl ShortPayloadError {
    /// The Length of the frame.
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// The bytes of the Length the payload did not write.
    pub const fn missing(&self) -> NonZeroU64 {
        self.missing
    }
}

/// The receiver family of a sink composed with a [`PayloadWriteLimit`].
pub struct PayloadSink<F>(PhantomData<fn(F) -> F>);

pin_project_lite::pin_project! {
    /// The view of a [`PayloadSink`]: the parent view, held by value, and
    /// the limit.
    pub struct PayloadSinkView<'v, F>
    where
        F: ReceiverFamily,
        F: 'v,
    {
        #[pin]
        parent: F::ReceiverView<'v>,
        state: &'v mut PayloadWriteLimit,
    }
}

impl<F: ReceiverFamily> ReceiverFamily for PayloadSink<F> {
    type ReceiverView<'v>
        = PayloadSinkView<'v, F>
    where
        Self: 'v;
}

impl<F: ReceiverFamily> Compose<F> for PayloadWriteLimit {
    type Family = PayloadSink<F>;
    fn compose<'v>(self: Pin<&'v mut Self>, parent: F::ReceiverView<'v>) -> PayloadSinkView<'v, F>
    where
        F: 'v,
        Self::Family: 'v,
    {
        PayloadSinkView {
            parent,
            state: self.get_mut(),
        }
    }
}

/// Passes writes on, held to what is left of the Length. Once it is used
/// up, it accepts nothing (`Ok(None)`) without asking the sink below.
impl<F: Write> Write for PayloadSink<F> {
    type Error = F::Error;
    type Report = F::Report;
    fn poll_write<'v, I: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        input: &mut I,
    ) -> Poll<WriteResult<Self>>
    where
        Self: 'v,
    {
        let view = host.project();
        let left = view.state.left();
        if left == 0 {
            return Poll::Ready(Ok(None));
        }
        let segment = ready!(F::poll_write(
            view.parent,
            cx,
            &mut (&mut *input).take(left)
        ))?;
        if let Some(segment) = &segment {
            view.state.take(segment.count.get());
        }
        Poll::Ready(Ok(segment))
    }
}

/// Lends at most what is left of the Length. Once it is used up, it accepts
/// nothing (`Ok(None)`) without asking the sink below, as
/// `nitori_io::adapters::WriteLimit` does at its boundary: a copy then probes
/// whether its source ended, and a full sink below cannot hold up a frame
/// that is already whole.
impl<F: WriteLent> WriteLent for PayloadSink<F> {
    type Buffer<'l> = F::Buffer<'l>;
    fn poll_write_lent<'v, T, A, Fill>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        wanted: NonZeroUsize,
        fill: Fill,
    ) -> Poll<WriteLentResult<Self, T, A>>
    where
        Self: 'v,
        Fill: for<'l> FnOnce(&mut LentBuffer<Self::Buffer<'l>>) -> Result<T, A>,
    {
        let view = host.project();
        let Some(left) = NonZeroUsize::new(view.state.left()) else {
            return Poll::Ready(Ok(None));
        };
        let allowed = left.min(wanted);
        let result = ready!(F::poll_write_lent(view.parent, cx, allowed, fill))?;
        if let Some(LentOutcome::Kept(segment)) = &result {
            view.state.take(segment.count.get());
        }
        Poll::Ready(Ok(result))
    }
}
