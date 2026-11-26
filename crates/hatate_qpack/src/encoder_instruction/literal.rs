//! Sources for individual length-delimited instruction literals.
use bytes::{Buf, BufMut};
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, Composed, ReceiverAccess, ReceiverFamily};
use nitori_io::{ChunkSegment, Combine, Read, ReadChunk, ReadSegment};
use snafu::Snafu;

use crate::huffman::{self, SymbolDecoder};

/// Access to the current literal. Raw chunks retain the host's chunk type.
/// A Huffman read decodes into storage supplied by the consumer.
pub enum LiteralSource<'a, A: ReceiverAccess<Family: Read>> {
    /// A bounded source providing the parent's read capabilities.
    Raw(Composed<&'a mut A, &'a mut RawLiteral>),
    /// A bounded, decoded source implementing [`Read`].
    Huffman(Composed<&'a mut A, &'a mut HuffmanLiteral<<A::Family as Read>::Metadata>>),
}

/// Receiver family for a literal composed onto its parent stream.
pub struct Source<S, F>(PhantomData<fn() -> (S, F)>);

pin_project_lite::pin_project! {
    /// The parent view, held by value, and the literal state.
    pub struct SourceView<'v, S, F>
    where
        F: ReceiverFamily,
        F: 'v,
    {
        #[pin]
        parent: F::ReceiverView<'v>,
        state: &'v mut S,
    }
}

impl<S, F: ReceiverFamily> ReceiverFamily for Source<S, F> {
    type ReceiverView<'v>
        = SourceView<'v, S, F>
    where
        Self: 'v;
}

macro_rules! compose_literal {
    ($state:ty) => {
        impl<F: ReceiverFamily> Compose<F> for $state {
            type Family = Source<Self, F>;
            fn compose<'v>(
                self: Pin<&'v mut Self>,
                parent: F::ReceiverView<'v>,
            ) -> SourceView<'v, Self, F>
            where
                F: 'v,
                Self::Family: 'v,
            {
                SourceView {
                    parent,
                    state: self.get_mut(),
                }
            }
        }
    };
}
compose_literal!(RawLiteral);

impl<M: Unpin, F: ReceiverFamily> Compose<F> for HuffmanLiteral<M> {
    type Family = Source<Self, F>;
    fn compose<'v>(self: Pin<&'v mut Self>, parent: F::ReceiverView<'v>) -> SourceView<'v, Self, F>
    where
        F: 'v,
        Self::Family: 'v,
    {
        SourceView {
            parent,
            state: self.get_mut(),
        }
    }
}

/// The original stream could not supply the literal's declared payload.
#[derive(Debug, Snafu)]
pub enum InputError<E> {
    /// The stream ended inside this literal.
    #[snafu(display("literal payload ended with {missing} octets missing"))]
    Truncated {
        /// Declared bytes that have not arrived.
        missing: NonZeroUsize,
    },
    /// The underlying stream failed.
    #[snafu(display("could not read literal input"))]
    Host {
        /// Original stream error.
        source: E,
    },
    /// Processing has already failed for this literal.
    #[snafu(display("literal input has already failed"))]
    Failed,
}

type RawPoll<F> =
    Poll<Result<Option<ReadSegment<<F as Read>::Metadata>>, InputError<<F as Read>::Error>>>;
type HuffmanPoll<F> =
    Poll<Result<Option<ReadSegment<<F as Read>::Metadata>>, HuffmanReadError<<F as Read>::Error>>>;

/// Composition state for raw input, excluding all following fields.
pub struct RawLiteral {
    remaining: usize,
    failed: bool,
}

impl RawLiteral {
    pub(crate) fn new(length: usize) -> Self {
        Self {
            remaining: length,
            failed: false,
        }
    }

    fn poll<'v, F: Read + 'v, O: BufMut + ?Sized>(
        &mut self,
        parent: Pin<&mut F::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> RawPoll<F> {
        if self.failed {
            return Poll::Ready(Err(InputError::Failed));
        }
        let Some(missing) = NonZeroUsize::new(self.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let empty = destination.remaining_mut() == 0;
        let result = ready!(F::poll_read(
            parent,
            cx,
            &mut destination.limit(self.remaining)
        ));
        match result {
            Ok(None) if !empty => {
                self.failed = true;
                Poll::Ready(Err(InputError::Truncated { missing }))
            }
            Ok(None) => Poll::Ready(Ok(None)),
            Ok(Some(segment)) => {
                self.remaining -= segment.count.get();
                Poll::Ready(Ok(Some(segment)))
            }
            Err(source) => {
                self.failed = true;
                Poll::Ready(Err(InputError::Host { source }))
            }
        }
    }
}

// A short parent is a truncation error. A successful end of this layer is
// therefore exactly the remaining declared payload, even for a live stream.
impl<F: ReceiverFamily> nitori_io::ExactLen for Source<RawLiteral, F> {
    type Length = usize;
    type LengthError = !;
    fn poll_remaining_len<'v>(
        view: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
    ) -> Poll<Result<usize, !>>
    where
        Self: 'v,
    {
        Poll::Ready(Ok(view.project().state.remaining))
    }
}

impl<F: Read> Read for Source<RawLiteral, F> {
    type Error = InputError<F::Error>;
    type Metadata = F::Metadata;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> Poll<Result<Option<ReadSegment<F::Metadata>>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.project();
        view.state.poll::<F, O>(view.parent, cx, dst)
    }
}

impl<F: ReadChunk> ReadChunk for Source<RawLiteral, F> {
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
            return Poll::Ready(Err(InputError::Failed));
        }
        let Some(missing) = NonZeroUsize::new(state.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let result = ready!(F::poll_read_chunk(view.parent, cx, maximum.min(missing)));
        match result {
            Ok(Some(chunk)) => {
                state.remaining -= chunk.chunk.remaining();
                Poll::Ready(Ok(Some(chunk)))
            }
            Ok(None) => {
                state.failed = true;
                Poll::Ready(Err(InputError::Truncated { missing }))
            }
            Err(source) => {
                state.failed = true;
                Poll::Ready(Err(InputError::Host { source }))
            }
        }
    }
}

/// Failure pulling decoded Huffman octets from an instruction literal.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum HuffmanReadError<E> {
    /// The underlying bounded source failed.
    #[snafu(display("could not read Huffman input"))]
    Input {
        /// Input failure.
        source: InputError<E>,
    },
    /// A coding rule or the decoded instruction budget was violated.
    #[snafu(display("invalid Huffman literal"))]
    Coding {
        /// Decoder failure.
        source: huffman::DecodeError,
    },
    /// This literal already reported a terminal error.
    #[snafu(display("Huffman literal has already failed"))]
    Failed,
}

enum Decoding {
    Active(SymbolDecoder),
    Deferred(huffman::DecodeError),
    Done(usize),
    Failed,
}

/// Pull-based decoding state. A bounded encoded input window survives
/// suspension. Decoded bytes go directly into the consumer's buffer.
///
/// `M` is the metadata of the parent's segments. A segment of decoded bytes
/// carries the merged metadata of the encoded input it was decoded from,
/// and of the input window the segment before it ended in, whose bits can
/// begin its first byte.
pub struct HuffmanLiteral<M = ()> {
    input: RawLiteral,
    decoding: Decoding,
    encoded: [u8; 64],
    pos: usize,
    end: usize,
    used_bits: u8,
    /// The metadata of the segment of the parent in the input window.
    window: M,
    /// The metadata of the input read since the last segment of decoded
    /// bytes, and of the window that segment ended in.
    unreported: M,
}

impl<M: Default> HuffmanLiteral<M> {
    pub(crate) fn new(encoded_len: usize, limit: usize) -> Self {
        Self {
            input: RawLiteral::new(encoded_len),
            decoding: if encoded_len == 0 {
                Decoding::Done(0)
            } else {
                Decoding::Active(SymbolDecoder::new(limit))
            },
            encoded: [0; 64],
            pos: 0,
            end: 0,
            used_bits: 0,
            window: M::default(),
            unreported: M::default(),
        }
    }
}

impl<M: Combine + Clone> HuffmanLiteral<M> {
    /// The segment of `written` decoded bytes, if any, with the metadata of
    /// the input they came from. The window stays unreported, since its
    /// bits can go on into the next segment.
    fn segment(&mut self, written: usize) -> Option<ReadSegment<M>> {
        let count = NonZeroUsize::new(written)?;
        let metadata = core::mem::replace(&mut self.unreported, self.window.clone());
        Some(ReadSegment { count, metadata })
    }

    fn poll<'v, F: Read<Metadata = M> + 'v, O: BufMut + ?Sized>(
        &mut self,
        mut parent: Pin<&mut F::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> HuffmanPoll<F> {
        let mut written = 0;
        loop {
            let decoder = match &mut self.decoding {
                Decoding::Active(decoder) => decoder,
                Decoding::Done(_) => return Poll::Ready(Ok(self.segment(written))),
                Decoding::Failed => return Poll::Ready(Err(HuffmanReadError::Failed)),
                Decoding::Deferred(_) => {
                    if written > 0 {
                        return Poll::Ready(Ok(self.segment(written)));
                    }
                    let Decoding::Deferred(source) =
                        core::mem::replace(&mut self.decoding, Decoding::Failed)
                    else {
                        unreachable!()
                    };
                    return Poll::Ready(Err(HuffmanReadError::Coding { source }));
                }
            };
            if self.pos == self.end && self.input.remaining == 0 {
                self.decoding = match decoder.finish() {
                    Ok(n) => Decoding::Done(n),
                    Err(e) => Decoding::Deferred(e),
                };
                continue;
            }
            let capacity = dst.remaining_mut();
            if capacity == 0 {
                return Poll::Ready(Ok(self.segment(written)));
            }
            if self.pos == self.end {
                // Never report Pending or a host failure after emitting bytes.
                if written > 0 {
                    return Poll::Ready(Ok(self.segment(written)));
                }
                let request = capacity
                    .saturating_mul(30)
                    .div_ceil(8)
                    .min(self.encoded.len());
                let mut buffer = &mut self.encoded[..request];
                self.end = match ready!(self.input.poll::<F, _>(parent.as_mut(), cx, &mut buffer)) {
                    // The request is nonempty, so the literal reports a segment
                    // or an error; `None` would only be an empty request.
                    Ok(None) => 0,
                    Ok(Some(segment)) => {
                        self.window = segment.metadata.clone();
                        let unreported = core::mem::take(&mut self.unreported);
                        self.unreported = unreported.combine(segment.metadata);
                        segment.count.get()
                    }
                    Err(source) => {
                        self.decoding = Decoding::Failed;
                        return Poll::Ready(Err(HuffmanReadError::Input { source }));
                    }
                };
                self.pos = 0;
            }
            let bit = (self.encoded[self.pos] >> (7 - self.used_bits)) & 1;
            self.used_bits += 1;
            if self.used_bits == 8 {
                self.pos += 1;
                self.used_bits = 0;
            }
            match decoder.bit(bit) {
                Ok(Some(byte)) => {
                    dst.put_u8(byte);
                    written += 1;
                }
                Ok(None) => {}
                Err(e) => self.decoding = Decoding::Deferred(e),
            }
        }
    }
}

/// The decoded bytes, each segment with the merged metadata of the encoded
/// input it came from ([`HuffmanLiteral`]).
impl<F: Read> Read for Source<HuffmanLiteral<F::Metadata>, F>
where
    F::Metadata: Combine + Clone,
{
    type Error = HuffmanReadError<F::Error>;
    type Metadata = F::Metadata;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> Poll<Result<Option<ReadSegment<F::Metadata>>, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.project();
        view.state.poll::<F, O>(view.parent, cx, dst)
    }
}

pub(crate) enum Literal<M = ()> {
    Raw { state: RawLiteral, length: usize },
    Huffman(HuffmanLiteral<M>),
}
impl Literal {
    pub(super) fn new(coded: bool, length: usize, limit: usize) -> Self {
        if coded {
            Self::Huffman(HuffmanLiteral::new(length, limit))
        } else {
            Self::Raw {
                state: RawLiteral::new(length),
                length,
            }
        }
    }
    /// The literal, read from a source whose segments have metadata `M`.
    /// Nothing of it has been read yet.
    pub(super) fn with_metadata<M: Default>(self) -> Literal<M> {
        match self {
            Self::Raw { state, length } => Literal::Raw { state, length },
            Self::Huffman(state) => Literal::Huffman(HuffmanLiteral {
                input: state.input,
                decoding: state.decoding,
                encoded: state.encoded,
                pos: state.pos,
                end: state.end,
                used_bits: state.used_bits,
                window: M::default(),
                unreported: M::default(),
            }),
        }
    }
}
impl<M> Literal<M> {
    pub(super) fn source<'a, A: ReceiverAccess<Family: Read<Metadata = M>>>(
        &'a mut self,
        io: &'a mut A,
    ) -> LiteralSource<'a, A>
    where
        M: Unpin,
    {
        match self {
            Self::Raw { state, .. } => LiteralSource::Raw(io.compose(state)),
            Self::Huffman(state) => LiteralSource::Huffman(io.compose(state)),
        }
    }
    pub(super) fn finish(self) -> Result<usize, FinishError> {
        match self {
            Self::Raw { state, length } if !state.failed && state.remaining == 0 => Ok(length),
            Self::Raw { state, .. } if state.failed => Err(FinishError::Failed),
            Self::Raw { .. } => Err(FinishError::Unread),
            Self::Huffman(state) => match state.decoding {
                Decoding::Done(n) => Ok(n),
                Decoding::Failed => Err(FinishError::Failed),
                Decoding::Deferred(source) => Err(FinishError::Coding { source }),
                Decoding::Active(mut decoder) => {
                    if state.input.remaining != 0 {
                        return Err(FinishError::Unread);
                    }
                    // If the last read exactly filled its destination, the
                    // final padding may still be in the local input window.
                    for index in state.pos..state.end {
                        let used = if index == state.pos {
                            state.used_bits
                        } else {
                            0
                        };
                        for shift in (0..8 - used).rev() {
                            if decoder
                                .bit((state.encoded[index] >> shift) & 1)
                                .map_err(|source| FinishError::Coding { source })?
                                .is_some()
                            {
                                return Err(FinishError::Unread);
                            }
                        }
                    }
                    decoder
                        .finish()
                        .map_err(|source| FinishError::Coding { source })
                }
            },
        }
    }
}

/// A literal cannot transition to its successor. No input is skipped.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum FinishError {
    /// Input or decoded data remains unconsumed.
    #[snafu(display("literal has unread data"))]
    Unread,
    /// A prior read terminated with an error.
    #[snafu(display("literal already failed"))]
    Failed,
    /// Buffered bits violate the Huffman rules, including the final padding.
    #[snafu(display("invalid Huffman literal ending"))]
    Coding {
        /// Decoder failure.
        source: huffman::DecodeError,
    },
}

impl<E> InputError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Host { source } => Some(source),
            Self::Truncated { .. } | Self::Failed => None,
        }
    }
}

impl<E> HuffmanReadError<E> {
    /// The error of the stream itself, if the failure came from the stream.
    pub fn host_error(&self) -> Option<&E> {
        match self {
            Self::Input { source } => source.host_error(),
            Self::Coding { .. } | Self::Failed => None,
        }
    }
}
