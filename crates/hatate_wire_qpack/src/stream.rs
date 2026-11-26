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
//! of `hatate_wire` uses it as well. The instructions this endpoint writes go
//! to the streams of `hatate_qpack` directly.
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
    decoder_instruction::{
        DecodeDecoderInstructionError, DecoderInstruction, DecoderStream, DecoderStreamLimits,
    },
    encoder_instruction::{
        DecodeEncoderInstructionError, EncoderInstruction, EncoderStream, EncoderStreamLimits,
    },
};
use nitori_call::{Compose, Composed, ReceiverAccess, ReceiverFamily};
use nitori_codec::DecodeFrom;
use nitori_io::{ChunkSegment, Combine, Min, Read, ReadChunk, ReadSegment, Skip, calls::ReadValue};
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
    type Metadata = F::Metadata;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<Option<ReadSegment<F::Metadata>>, Self::Error>>
    where
        Self: 'v,
    {
        let empty = destination.remaining_mut() == 0;
        Poll::Ready(
            match ready!(F::poll_read(host.project().parent, cx, destination)) {
                Ok(None) if !empty => Err(CriticalStreamError::Closed),
                Ok(segment) => Ok(segment),
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
    ) -> Poll<Result<Option<ChunkSegment<F::Chunk, <F as Read>::Metadata>>, Self::Error>>
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
///
/// The next instruction is decoded from it as a
/// `ReadValue<EncoderInstruction<S, H>, M>`, `M` being the metadata of the
/// stream's bytes, as from an [`EncoderStream`] with two differences. The
/// stream never ends: its end, at the boundary or inside the instruction, is
/// [`CriticalStreamError::Closed`] as the failure of the stream, so there is
/// no `None`. Its limits are always those of the dynamic table capacity this
/// endpoint allows ([`EncoderStreamLimits::for_table_capacity`]), so an
/// instruction beyond them is one the peer's encoder may not send, and
/// [`DecodeQpackEncoderInstructionError`] says so.
#[derive(Debug)]
pub struct QpackEncoderStream<A> {
    stream: EncoderStream<Composed<A, CriticalStream>>,
}

impl<A> QpackEncoderStream<A> {
    /// The stream on `io`, right after its type, reading instructions
    /// within the limits of a dynamic table of capacity 0, which the peer's
    /// encoder may not exceed until the SETTINGS this endpoint sent say
    /// otherwise. Nothing is read.
    ///
    /// The connection sets the SETTINGS_QPACK_MAX_TABLE_CAPACITY it sent
    /// with [`set_max_table_capacity`](Self::set_max_table_capacity).
    pub fn new(io: A) -> Self {
        Self {
            stream: EncoderStream::new(Composed::new(io, CriticalStream), Default::default()),
        }
    }

    /// The limits the next instruction is read within.
    pub const fn limits(&self) -> EncoderStreamLimits {
        self.stream.limits()
    }

    /// Reads the instructions after this call within the limits of a
    /// dynamic table of at most `capacity` octets, the
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY this endpoint sent
    /// ([`EncoderStreamLimits::for_table_capacity`]). An instruction begun
    /// before keeps the limits it began with.
    pub fn set_max_table_capacity(&mut self, capacity: u64) {
        self.stream
            .set_limits(EncoderStreamLimits::for_table_capacity(capacity));
    }
}

/// Reads the next instruction whole, as [`EncoderStream`] does.
///
/// # Errors
///
/// [`DecodeQpackEncoderInstructionError`], whose failures of the stream are
/// [`CriticalStreamError`].
impl<'s, A, S, H, M> DecodeFrom<&'s mut QpackEncoderStream<A>>
    for ReadValue<EncoderInstruction<S, H>, M>
where
    A: ReceiverAccess,
    Composed<A, CriticalStream>: ReceiverAccess<Family: ReadChunk<Metadata = M>>,
    S: Default
        + Extend<<<Composed<A, CriticalStream> as ReceiverAccess>::Family as ReadChunk>::Chunk>,
    H: Default + Extend<u8>,
    M: Combine + Unpin,
{
    type Error = DecodeQpackEncoderInstructionError<
        <<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error,
    >;

    async fn decode_from(stream: &'s mut QpackEncoderStream<A>) -> Result<Self, Self::Error> {
        let instruction =
            Option::<ReadValue<EncoderInstruction<S, H>, M>>::decode_from(&mut stream.stream)
                .await
                .map_err(|source| DecodeQpackEncoderInstructionError { source })?;
        // invariant: a critical stream reports its end as a failure, so the
        // instruction stream never sees it end at a boundary.
        Ok(instruction.expect("a critical stream does not end"))
    }
}

impl<A: ReceiverAccess> QpackEncoderStream<A> {
    /// The access, giving up the stream.
    pub fn into_io(self) -> A {
        self.stream.into_io().into_parts().0
    }
}

/// An instruction of the peer's QPACK encoder stream
/// ([`QpackEncoderStream`]) could not be read; `E` is the failure of the
/// stream.
///
/// The limits the instruction was read within are those of the dynamic table
/// capacity this endpoint allows. An insertion beyond them, by its decoded
/// literals or by its octets on the wire, or by the least of them that the
/// octets read so far allow, cannot fit in the table, which the peer's
/// encoder may not ask for (RFC 9204 §3.2.2): such a failure is the peer's,
/// unlike the same failure of an [`EncoderStream`] read within limits of the
/// caller's choice.
#[derive(Debug, Snafu)]
#[snafu(display("could not read an instruction of the QPACK encoder stream"))]
pub struct DecodeQpackEncoderInstructionError<E> {
    source: DecodeEncoderInstructionError<E>,
}

impl<E> DecodeQpackEncoderInstructionError<E> {
    /// The failure of reading the instruction.
    pub const fn instruction_error(&self) -> &DecodeEncoderInstructionError<E> {
        &self.source
    }

    /// The failure of reading the instruction, taken out.
    pub fn into_instruction_error(self) -> DecodeEncoderInstructionError<E> {
        self.source
    }

    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        self.source.host_error()
    }
}

/// The QPACK decoder stream of the peer (stream type 0x03), on the stream
/// `A` composed with [`CriticalStream`].
///
/// The next instruction is decoded from it as a
/// `ReadValue<DecoderInstruction, M>`, `M` being the metadata of the stream's
/// bytes, as from a [`DecoderStream`] with the difference that the stream
/// never ends: its end is [`CriticalStreamError::Closed`] as the failure of
/// the stream, so there is no `None`.
#[derive(Debug)]
pub struct QpackDecoderStream<A> {
    stream: DecoderStream<Composed<A, CriticalStream>>,
}

impl<A> QpackDecoderStream<A> {
    /// The stream on `io`, right after its type, reading instructions
    /// within the default [`DecoderStreamLimits`]. Nothing is read.
    ///
    /// The connection may set another limit with
    /// [`set_limits`](Self::set_limits).
    pub fn new(io: A) -> Self {
        Self {
            stream: DecoderStream::new(Composed::new(io, CriticalStream), Default::default()),
        }
    }

    /// The limit the next instruction is read within.
    pub const fn limits(&self) -> DecoderStreamLimits {
        self.stream.limits()
    }

    /// Reads the instructions after this call within `limits`.
    pub fn set_limits(&mut self, limits: DecoderStreamLimits) {
        self.stream.set_limits(limits);
    }
}

/// Reads the next instruction, as [`DecoderStream`] does.
///
/// # Errors
///
/// [`DecodeDecoderInstructionError`], whose failures of the stream are
/// [`CriticalStreamError`].
impl<'s, A, M> DecodeFrom<&'s mut QpackDecoderStream<A>> for ReadValue<DecoderInstruction, M>
where
    A: ReceiverAccess,
    Composed<A, CriticalStream>: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    type Error = DecodeDecoderInstructionError<
        <<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error,
    >;

    async fn decode_from(stream: &'s mut QpackDecoderStream<A>) -> Result<Self, Self::Error> {
        let instruction =
            Option::<ReadValue<DecoderInstruction, M>>::decode_from(&mut stream.stream).await?;
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
