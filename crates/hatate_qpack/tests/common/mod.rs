//! The helpers the encoder-instruction tests share.
#![allow(dead_code)]
use bytes::Buf;
use hatate_qpack::encoder_instruction::{
    DecodeEncoderInstructionError, EncoderInstruction, EncoderStream, EncoderStreamLimits,
};
use nitori_call::ReceiverAccess;
use nitori_codec::DecodeFrom;
use nitori_io::{calls::ReadValue, prelude::*};

/// The octets of a raw literal, copied from chunks of any type.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Collected(pub Vec<u8>);

impl<C: Buf> Extend<C> for Collected {
    fn extend<I: IntoIterator<Item = C>>(&mut self, chunks: I) {
        for mut chunk in chunks {
            while chunk.has_remaining() {
                let count = chunk.chunk().len();
                self.0.extend_from_slice(chunk.chunk());
                chunk.advance(count);
            }
        }
    }
}

impl AsRef<[u8]> for Collected {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An instruction as these tests read it.
pub type Read = EncoderInstruction<Collected, Vec<u8>>;

/// Limits `reader` to `wire` and `decoded` octets and reads its next
/// instruction, whose bytes have no metadata.
pub async fn next_encoder<A: ReceiverAccess<Family: ReadChunk<Metadata = ()>>>(
    reader: &mut EncoderStream<A>,
    wire: usize,
    decoded: usize,
) -> Result<Option<Read>, DecodeEncoderInstructionError<<A::Family as nitori_io::Read>::Error>> {
    reader.set_limits(EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    });
    let next = Option::<ReadValue<Read, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

pub fn encoder_stream<A>(io: A) -> EncoderStream<A> {
    EncoderStream::new(io, EncoderStreamLimits::default())
}

/// The decoded octets of a literal.
pub fn octets<S: AsRef<[u8]>, H: AsRef<[u8]>>(
    literal: &hatate_qpack::string_literal::StringLiteral<S, H>,
) -> &[u8] {
    literal.as_ref()
}

/// A source that waits before each octet, read or chunk.
pub struct Trickle<'a> {
    pub rest: &'a [u8],
    pub waiting: bool,
}
nitori_call::family_receiver!(impl ['a] for Trickle<'a>);

impl Trickle<'_> {
    /// Waits once before each octet: `None` while waiting, then the octet.
    fn next(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<()> {
        if !self.waiting {
            self.waiting = true;
            cx.waker().wake_by_ref();
            return core::task::Poll::Pending;
        }
        self.waiting = false;
        core::task::Poll::Ready(())
    }
}

impl nitori_io::Read for Trickle<'_> {
    type Error = core::convert::Infallible;
    type Metadata = ();
    fn poll_read<'v, B: bytes::BufMut + ?Sized>(
        host: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        dst: &mut B,
    ) -> core::task::Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::{Poll, ready};
        let this = host.get_pin_mut().get_mut();
        ready!(this.next(cx));
        if !dst.has_remaining_mut() {
            return Poll::Ready(Ok(None));
        }
        let Some((&b, rest)) = this.rest.split_first() else {
            return Poll::Ready(Ok(None));
        };
        this.rest = rest;
        dst.put_u8(b);
        Poll::Ready(Ok(Some(nitori_io::ReadSegment {
            count: core::num::NonZeroUsize::MIN,
            metadata: (),
        })))
    }
}

impl<'a> ReadChunk for Trickle<'a> {
    type Chunk = &'a [u8];
    fn poll_read_chunk<'v>(
        host: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        _: core::num::NonZeroUsize,
    ) -> core::task::Poll<Result<Option<nitori_io::ChunkSegment<&'a [u8], ()>>, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::{Poll, ready};
        let this = host.get_pin_mut().get_mut();
        ready!(this.next(cx));
        if this.rest.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let (chunk, rest) = this.rest.split_at(1);
        this.rest = rest;
        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
            chunk,
            metadata: (),
        })))
    }
}

/// A sink that waits before it accepts each octet.
#[derive(Default)]
pub struct PausingSink {
    pub wire: Vec<u8>,
    pub waiting: bool,
}
nitori_call::family_receiver!(impl [] for PausingSink);

impl nitori_io::Write for PausingSink {
    type Error = !;
    type Report = ();
    fn poll_write<'v, B: Buf + ?Sized>(
        view: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        cx: &mut core::task::Context<'_>,
        src: &mut B,
    ) -> core::task::Poll<Result<Option<nitori_io::WriteSegment<()>>, Self::Error>>
    where
        Self: 'v,
    {
        use core::task::Poll;
        let sink = view.get_pin_mut().get_mut();
        if !sink.waiting {
            sink.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        sink.waiting = false;
        if !src.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        sink.wire.push(src.get_u8());
        Poll::Ready(Ok(Some(nitori_io::WriteSegment {
            count: core::num::NonZeroUsize::MIN,
            report: (),
        })))
    }
}
