//! The QPACK encoder and decoder streams as HTTP/3 has them
//! ([RFC 9204 §4.2]): unidirectional streams of type 0x02 and 0x03, each
//! critical, read instruction by instruction.
//!
//! A critical stream may not end. [`CriticalStream`] is composition state
//! that makes the end of a stream a failure of the stream itself,
//! [`CriticalStreamError::Closed`], wherever it comes: at an instruction or
//! frame boundary, or inside one, where the bytes are read through a borrowed
//! source. The readers above pass the failure of the stream through, so its
//! code, H3_CLOSED_CRITICAL_STREAM, is that of every read that meets the end.
//! [`QpackEncoderStream`] and [`QpackDecoderStream`] hold the instruction
//! streams of `hatate_qpack` on a stream composed with it; the control stream
//! of `hatate_wire` uses it as well.
//!
//! [RFC 9204 §4.2]: https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2
use bytes::BufMut;
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, ready},
};
use hatate_qpack::{
    decoder_instruction::{DecoderInstruction, DecoderStream, codec::ReadError},
    encoder_instruction::{EncoderStream, Started, codec::StartError},
};
use nitori_call::{Compose, Composed, ReceiverAccess, ReceiverFamily};
use nitori_io::{Min, Read, ReadChunk, Skip};
use snafu::Snafu;

/// Composition state for a critical stream: the end of the stream is a
/// failure, [`CriticalStreamError::Closed`], rather than an end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct CriticalStream;

/// The failures of a critical stream: it ended, or it failed. `E` is the
/// failure of the stream.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum CriticalStreamError<E> {
    /// The stream ended, which a critical stream may not
    /// ([RFC 9114 §6.2.1](https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2.1),
    /// [RFC 9204 §4.2](https://www.rfc-editor.org/rfc/rfc9204.html#section-4.2)).
    #[snafu(display("a critical stream was closed"))]
    Closed,
    /// The stream failed.
    #[snafu(display("a critical stream failed"))]
    Host {
        /// The stream's error.
        source: E,
    },
}

/// The receiver family of a [`CriticalStream`] composed onto a parent
/// stream. It passes on [`Read`], [`ReadChunk`] and [`Skip`] where the
/// parent has them, with the end of the stream as a failure.
pub struct CriticalSource<F>(PhantomData<fn(F) -> F>);

pin_project_lite::pin_project! {
    /// The view of a [`CriticalSource`] family: the parent view, held by value.
    pub struct CriticalView<'v, F>
    where
        F: ReceiverFamily,
        F: 'v,
    {
        #[pin]
        parent: F::ReceiverView<'v>,
    }
}

impl<F: ReceiverFamily> core::fmt::Debug for CriticalView<'_, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CriticalView").finish_non_exhaustive()
    }
}

impl<F: ReceiverFamily> ReceiverFamily for CriticalSource<F> {
    type ReceiverView<'v>
        = CriticalView<'v, F>
    where
        Self: 'v;
}

impl<F: ReceiverFamily> Compose<F> for CriticalStream {
    type Family = CriticalSource<F>;
    fn compose<'v>(self: Pin<&'v mut Self>, parent: F::ReceiverView<'v>) -> CriticalView<'v, F>
    where
        F: 'v,
        Self::Family: 'v,
    {
        CriticalView { parent }
    }
}

impl<F: Read> Read for CriticalSource<F> {
    type Error = CriticalStreamError<F::Error>;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        let empty = destination.remaining_mut() == 0;
        Poll::Ready(
            match ready!(F::poll_read(host.project().parent, cx, destination)) {
                Ok(0) if !empty => Err(CriticalStreamError::Closed),
                Ok(count) => Ok(count),
                Err(source) => Err(CriticalStreamError::Host { source }),
            },
        )
    }
}

impl<F: ReadChunk> ReadChunk for CriticalSource<F> {
    type Chunk = F::Chunk;
    fn poll_read_chunk<'v>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: NonZeroUsize,
    ) -> Poll<Result<Option<F::Chunk>, Self::Error>>
    where
        Self: 'v,
    {
        Poll::Ready(
            match ready!(F::poll_read_chunk(host.project().parent, cx, maximum)) {
                Ok(Some(chunk)) => Ok(Some(chunk)),
                Ok(None) => Err(CriticalStreamError::Closed),
                Err(source) => Err(CriticalStreamError::Host { source }),
            },
        )
    }
}

impl<F: Skip> Skip for CriticalSource<F> {
    type Count = F::Count;
    fn poll_skip<'v, M: Min<F::Count, Output = F::Count> + Clone>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<F::Count>, Self::Error>>
    where
        Self: 'v,
    {
        Poll::Ready(
            match ready!(F::poll_skip(host.project().parent, cx, maximum)) {
                Ok(Some(count)) => Ok(Some(count)),
                Ok(None) => Err(CriticalStreamError::Closed),
                Err(source) => Err(CriticalStreamError::Host { source }),
            },
        )
    }
}

/// The QPACK encoder stream of the peer (stream type 0x02), on the stream
/// `A` composed with [`CriticalStream`].
#[derive(Debug)]
pub struct QpackEncoderStream<A> {
    stream: EncoderStream<Composed<A, CriticalStream>>,
}

impl<A: ReceiverAccess> QpackEncoderStream<A>
where
    Composed<A, CriticalStream>: ReceiverAccess<Family: Read>,
{
    /// The stream on `io`, right after its type. Nothing is read.
    pub fn new(io: A) -> Self {
        Self {
            stream: EncoderStream::new(Composed::new(io, CriticalStream)),
        }
    }

    /// Reads the start of the next instruction, as
    /// [`EncoderStream::next_instruction`] does. The stream never ends: its
    /// end, at the boundary or inside the instruction, is
    /// [`CriticalStreamError::Closed`] as the failure of the stream.
    ///
    /// # Errors
    ///
    /// [`StartError`], whose failures of the stream are
    /// [`CriticalStreamError`].
    pub async fn next_instruction(
        &mut self,
        max_wire_len: usize,
        max_decoded_len: usize,
    ) -> Result<
        Started<'_, Composed<A, CriticalStream>>,
        StartError<<<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error>,
    > {
        let started = self
            .stream
            .next_instruction(max_wire_len, max_decoded_len)
            .await?;
        // invariant: a critical stream reports its end as a failure, so the
        // instruction stream never sees it end at a boundary.
        Ok(started.expect("a critical stream does not end"))
    }
}

impl<A: ReceiverAccess> QpackEncoderStream<A> {
    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.stream.into_io().into_parts().0
    }
}

/// The QPACK decoder stream of the peer (stream type 0x03), on the stream
/// `A` composed with [`CriticalStream`].
#[derive(Debug)]
pub struct QpackDecoderStream<A> {
    stream: DecoderStream<Composed<A, CriticalStream>>,
}

impl<A: ReceiverAccess> QpackDecoderStream<A>
where
    Composed<A, CriticalStream>: ReceiverAccess<Family: Read>,
{
    /// The stream on `io`, right after its type. Nothing is read.
    pub fn new(io: A) -> Self {
        Self {
            stream: DecoderStream::new(Composed::new(io, CriticalStream)),
        }
    }

    /// Reads the next instruction, as [`DecoderStream::next_instruction`]
    /// does. The stream never ends: its end is [`CriticalStreamError::Closed`]
    /// as the failure of the stream.
    ///
    /// # Errors
    ///
    /// [`ReadError`], whose failures of the stream are
    /// [`CriticalStreamError`].
    pub async fn next_instruction(
        &mut self,
        max_wire_len: usize,
    ) -> Result<
        DecoderInstruction,
        ReadError<<<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error>,
    > {
        let instruction = self.stream.next_instruction(max_wire_len).await?;
        // invariant: as for the encoder stream.
        Ok(instruction.expect("a critical stream does not end"))
    }
}

impl<A: ReceiverAccess> QpackDecoderStream<A> {
    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.stream.into_io().into_parts().0
    }
}
