//! The helpers the encoder-instruction tests share.
#![allow(dead_code)]
use hatate_qpack::encoder_instruction::{
    EncoderStream, EncoderStreamLimits, Started, codec::StartError,
};
use nitori_call::ReceiverAccess;
use nitori_codec::DecodeFrom;
use nitori_io::{calls::ReadValue, prelude::*};

pub async fn next_encoder<'a, F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &'a mut EncoderStream<A>,
    wire: usize,
    decoded: usize,
) -> Result<Option<Started<'a, A>>, StartError<F::Error>> {
    reader.set_limits(EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    });
    let next = Option::<ReadValue<Started<'a, A>, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

pub fn encoder_stream<A>(io: A) -> EncoderStream<A> {
    EncoderStream::new(io, EncoderStreamLimits::default())
}
pub struct Trickle<'a> {
    pub rest: &'a [u8],
    pub waiting: bool,
}
nitori_call::family_receiver!(impl ['a] for Trickle<'a>);
impl Read for Trickle<'_> {
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
        use core::task::Poll;
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
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

impl ExactLen for Trickle<'_> {
    type Length = usize;
    type LengthError = !;
    fn poll_remaining_len<'v>(
        view: core::pin::Pin<&mut Self::ReceiverView<'v>>,
        _: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<usize, !>>
    where
        Self: 'v,
    {
        core::task::Poll::Ready(Ok(view.get_pin_mut().rest.len()))
    }
}
