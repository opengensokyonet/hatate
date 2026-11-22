//! Sources for individual length-delimited instruction literals.
use bytes::{Buf, BufMut};
use core::{
    marker::PhantomData,
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll, ready},
};
use nitori_call::{Compose, Composed, ReceiverAccess, ReceiverFamily, ViewLoan};
use nitori_io::{Read, ReadChunk};
use snafu::Snafu;

use crate::huffman::{self, SymbolDecoder};

/// Access to the current literal. Raw chunks retain the host's chunk type.
/// A Huffman read decodes into storage supplied by the consumer.
pub enum LiteralSource<'a, A: ReceiverAccess> {
    /// A bounded source providing the parent's read capabilities.
    Raw(Composed<'a, A, &'a mut RawLiteral>),
    /// A bounded, decoded source implementing [`Read`].
    Huffman(Composed<'a, A, &'a mut HuffmanLiteral>),
}

/// Receiver family for a literal composed onto its parent stream.
pub struct Source<S, F>(PhantomData<fn() -> (S, F)>);

/// The parent view and literal state lent for one poll.
pub struct SourceView<'v, S, F: ReceiverFamily> {
    parent: ViewLoan<'v, F>,
    state: &'v mut S,
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
            fn compose<'v, 'p>(
                self: Pin<&'v mut Self>,
                parent: Pin<&'v mut F::ReceiverView<'p>>,
            ) -> SourceView<'v, Self, F>
            where
                F: 'p,
                'p: 'v,
                Self::Family: 'v,
            {
                SourceView {
                    parent: ViewLoan::new(parent),
                    state: self.get_mut(),
                }
            }
        }
    };
}
compose_literal!(RawLiteral);
compose_literal!(HuffmanLiteral);

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
        parent: &mut ViewLoan<'v, F>,
        cx: &mut Context<'_>,
        destination: &mut O,
    ) -> Poll<Result<usize, InputError<F::Error>>> {
        if self.failed {
            return Poll::Ready(Err(InputError::Failed));
        }
        let Some(missing) = NonZeroUsize::new(self.remaining) else {
            return Poll::Ready(Ok(0));
        };
        let empty = destination.remaining_mut() == 0;
        let result = ready!(parent.with(|view| F::poll_read(
            view.into_pin(),
            cx,
            &mut destination.limit(self.remaining)
        )));
        match result {
            Ok(0) if !empty => {
                self.failed = true;
                Poll::Ready(Err(InputError::Truncated { missing }))
            }
            Ok(n) => {
                self.remaining -= n;
                Poll::Ready(Ok(n))
            }
            Err(source) => {
                self.failed = true;
                Poll::Ready(Err(InputError::Host { source }))
            }
        }
    }
}

impl<F: Read> Read for Source<RawLiteral, F> {
    type Error = InputError<F::Error>;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.get_mut();
        view.state.poll(&mut view.parent, cx, dst)
    }
}

impl<F: ReadChunk> ReadChunk for Source<RawLiteral, F> {
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
            return Poll::Ready(Err(InputError::Failed));
        }
        let Some(missing) = NonZeroUsize::new(state.remaining) else {
            return Poll::Ready(Ok(None));
        };
        let result = ready!(view.parent.with(|parent| F::poll_read_chunk(
            parent.into_pin(),
            cx,
            maximum.min(missing)
        )));
        match result {
            Ok(Some(chunk)) => {
                state.remaining -= chunk.remaining();
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
pub struct HuffmanLiteral {
    input: RawLiteral,
    decoding: Decoding,
    encoded: [u8; 64],
    pos: usize,
    end: usize,
    used_bits: u8,
}

impl HuffmanLiteral {
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
        }
    }
    fn poll<'v, F: Read + 'v, O: BufMut + ?Sized>(
        &mut self,
        parent: &mut ViewLoan<'v, F>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> Poll<Result<usize, HuffmanReadError<F::Error>>> {
        let mut written = 0;
        loop {
            let decoder = match &mut self.decoding {
                Decoding::Active(decoder) => decoder,
                Decoding::Done(_) => return Poll::Ready(Ok(written)),
                Decoding::Failed => return Poll::Ready(Err(HuffmanReadError::Failed)),
                Decoding::Deferred(_) => {
                    if written > 0 {
                        return Poll::Ready(Ok(written));
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
                return Poll::Ready(Ok(written));
            }
            if self.pos == self.end {
                // Never report Pending or a host failure after emitting bytes.
                if written > 0 {
                    return Poll::Ready(Ok(written));
                }
                let request = capacity
                    .saturating_mul(30)
                    .div_ceil(8)
                    .min(self.encoded.len());
                let mut buffer = &mut self.encoded[..request];
                self.end = match ready!(self.input.poll(parent, cx, &mut buffer)) {
                    Ok(n) => n,
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

impl<F: Read> Read for Source<HuffmanLiteral, F> {
    type Error = HuffmanReadError<F::Error>;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut Context<'_>,
        dst: &mut O,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'v,
    {
        let view = host.get_mut();
        view.state.poll(&mut view.parent, cx, dst)
    }
}

pub(crate) enum Literal {
    Raw { state: RawLiteral, length: usize },
    Huffman(HuffmanLiteral),
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
    pub(super) fn source<'a, A: ReceiverAccess>(
        &'a mut self,
        io: &'a mut A,
    ) -> LiteralSource<'a, A> {
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
