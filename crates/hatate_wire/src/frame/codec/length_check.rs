//! Holding the payload of a frame being written to its Length.
use bytes::Buf;
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, ReceiverFamily};
use nitori_io::{LentBuffer, LentOutcome, Write, WriteLent, WriteLentResult, WriteResult};

/// What a frame being written has left of its Length, as composition state
/// on the sink its payload is written to.
///
/// A payload that writes more than the Length, or ends before it, panics
/// ([`Frame`](crate::frame::Frame)'s encoding): the Length came from the
/// payload, so the two disagree only when the payload, or the source it
/// writes out, does not keep the length it reported. One case fails
/// instead: a payload that fills storage the sink lends ([`WriteLent`]),
/// such as `nitori_codec::Fill`, is refused any loan once the Length is
/// used up, so a source longer than the Length ends its copy with the
/// copy's no-progress error.
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

    /// Panics unless the payload wrote all of its Length.
    pub(crate) fn finish(&self) {
        assert!(
            self.remaining == 0,
            "the payload of a frame ended {} bytes before its Length {}",
            self.remaining,
            self.length
        );
    }

    /// Takes `count` written bytes off what is left, panicking past the Length.
    fn take(&mut self, count: usize) {
        let taken = u64::try_from(count)
            .ok()
            .and_then(|count| self.remaining.checked_sub(count));
        let Some(remaining) = taken else {
            panic!(
                "the payload of a frame wrote more than its Length {}",
                self.length
            );
        };
        self.remaining = remaining;
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

/// Passes writes on, panicking when one offers more than is left of the
/// Length.
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
        assert!(
            u64::try_from(input.remaining()).is_ok_and(|offered| offered <= view.state.remaining),
            "the payload of a frame wrote more than its Length {}",
            view.state.length
        );
        let segment = ready!(F::poll_write(view.parent, cx, input))?;
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
        let Some(left) =
            NonZeroUsize::new(usize::try_from(view.state.remaining).unwrap_or(usize::MAX))
        else {
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
