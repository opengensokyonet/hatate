//! Hosts shared by the integration tests.
#![allow(dead_code)]

#[macro_use]
pub mod receiver_layer;

use bytes::{Buf, BufMut};
use core::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};
use hatate_qpack::{
    decoder_instruction::{
        DecodeDecoderInstructionError, DecoderInstruction, DecoderStream, DecoderStreamLimits,
    },
    encoder_instruction::{
        DecodeEncoderInstructionError, EncoderInstruction, EncoderStream, EncoderStreamLimits,
    },
};
use hatate_wire::{
    frame::{FrameType, Http3FrameType},
    registry::ClaimedValue,
};
use hatate_wire_qpack::stream::{
    CriticalStream, DecodeQpackEncoderInstructionError, QpackDecoderStream, QpackEncoderStream,
};
use nitori_call::{AsAccess, Composed, ReceiverAccess};
use nitori_codec::DecodeFrom;
use nitori_io::{Read, ReadChunk, calls::ReadValue, prelude::*};

/// A stream that gives at most `chunk` bytes per read and answers
/// `Pending` once before every read, so that every state a reader keeps
/// across a suspension is exercised.
pub struct Dribble<'a> {
    input: &'a [u8],
    chunk: usize,
    waiting: bool,
}

impl<'a> Dribble<'a> {
    pub fn new(input: &'a [u8], chunk: usize) -> Self {
        assert!(chunk > 0);
        Self {
            input,
            chunk,
            waiting: false,
        }
    }

    /// The bytes not yet read.
    pub fn rest(&self) -> &'a [u8] {
        self.input
    }
}

nitori_call::family_receiver!(impl ['a] for Dribble<'a>);

impl nitori_io::Read for Dribble<'_> {
    type Error = Infallible;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        let count = this.chunk.min(this.input.len()).min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(core::num::NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

/// Hands out chunks like it reads: at most `chunk` bytes, after one
/// `Pending`.
impl<'a> nitori_io::ReadChunk for Dribble<'a> {
    type Chunk = &'a [u8];
    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: core::num::NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<&'a [u8], ()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        if this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = this.chunk.min(this.input.len()).min(maximum.get());
        let (chunk, tail) = this.input.split_at(count);
        this.input = tail;
        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
            chunk,
            metadata: (),
        })))
    }
}

/// Skips like it reads: at most `chunk` bytes, after one `Pending`.
impl nitori_io::Skip for Dribble<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        let allowed = nitori_io::Min::min(maximum, this.chunk);
        if allowed != 0 && this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = allowed.min(this.input.len());
        this.input = &this.input[count..];
        Poll::Ready(Ok(Some(count)))
    }
}

/// Polls `future` to completion, returning how many times it was pending.
pub fn run<T>(future: impl Future<Output = T>) -> (T, usize) {
    let mut future = pin!(future);
    let mut cx = Context::from_waker(Waker::noop());
    let mut pending = 0;
    loop {
        match future.as_mut().poll(&mut cx) {
            Poll::Ready(value) => return (value, pending),
            Poll::Pending => {
                pending += 1;
                assert!(pending < 100_000, "the future never completes");
            }
        }
    }
}
/// A source that reports `claimed` bytes remaining but holds only `data`.
pub struct Liar<'a> {
    data: &'a [u8],
    claimed: usize,
}

impl<'a> Liar<'a> {
    pub fn new(data: &'a [u8], claimed: usize) -> Self {
        Self { data, claimed }
    }
}

nitori_call::family_receiver!(impl ['a] for Liar<'a>);

impl nitori_io::Read for Liar<'_> {
    type Error = Infallible;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        let count = this.data.len().min(dst.remaining_mut());
        let (head, tail) = this.data.split_at(count);
        dst.put_slice(head);
        this.data = tail;
        Poll::Ready(Ok(core::num::NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

impl nitori_io::ExactLen for Liar<'_> {
    type Length = usize;
    type LengthError = !;
    fn poll_remaining_len<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _: &mut Context<'_>,
    ) -> Poll<Result<usize, !>>
    where
        Self: 'visit,
    {
        Poll::Ready(Ok(host.get_pin_mut().get_mut().claimed))
    }
}

/// The error of a [`Broken`] stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Boom;

impl hatate_wire::error_code::ErrorCodeOf<hatate_wire::error_code::ErrorCode> for Boom {
    fn error_code(&self) -> Option<hatate_wire::error_code::ErrorCode> {
        None
    }
}

/// A stream whose every read fails.
pub struct Broken;

nitori_call::family_receiver!(impl [] for Broken);

impl nitori_io::Read for Broken {
    type Error = Boom;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Boom))
    }
}

impl nitori_io::ReadChunk for Broken {
    type Chunk = bytes::Bytes;
    fn poll_read_chunk<'visit>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _maximum: core::num::NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<bytes::Bytes, ()>>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Boom))
    }
}

impl nitori_io::Skip for Broken {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Err(Boom))
    }
}

/// A stream that gives its bytes and then fails every read and skip.
pub struct Failing<'a> {
    input: &'a [u8],
}

impl<'a> Failing<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }
}

nitori_call::family_receiver!(impl ['a] for Failing<'a>);

impl nitori_io::Read for Failing<'_> {
    type Error = Boom;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.input.is_empty() {
            return Poll::Ready(Err(Boom));
        }
        let count = this.input.len().min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(core::num::NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

impl nitori_io::Skip for Failing<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.input.is_empty() {
            return Poll::Ready(Err(Boom));
        }
        let count = nitori_io::Min::min(maximum, this.input.len());
        this.input = &this.input[count..];
        Poll::Ready(Ok(Some(count)))
    }
}

/// A stream that can only read, by bytes or by chunks, never skip: at most
/// `chunk` bytes per read, after one `Pending`.
pub struct ReadOnly<'a> {
    input: &'a [u8],
    chunk: usize,
    waiting: bool,
}

impl<'a> ReadOnly<'a> {
    pub fn new(input: &'a [u8], chunk: usize) -> Self {
        assert!(chunk > 0);
        Self {
            input,
            chunk,
            waiting: false,
        }
    }

    /// The bytes not yet read.
    pub fn rest(&self) -> &'a [u8] {
        self.input
    }

    /// Answers `Pending` once before each read.
    fn pause(&mut self, cx: &mut Context<'_>) -> bool {
        if self.waiting {
            self.waiting = false;
            return false;
        }
        self.waiting = true;
        cx.waker().wake_by_ref();
        true
    }
}

nitori_call::family_receiver!(impl ['a] for ReadOnly<'a>);

impl nitori_io::Read for ReadOnly<'_> {
    type Error = Infallible;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.pause(cx) {
            return Poll::Pending;
        }
        let count = this.chunk.min(this.input.len()).min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(core::num::NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

impl nitori_io::ReadChunk for ReadOnly<'_> {
    type Chunk = bytes::Bytes;
    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: core::num::NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<bytes::Bytes, ()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if this.pause(cx) {
            return Poll::Pending;
        }
        if this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = this.chunk.min(this.input.len()).min(maximum.get());
        let (head, tail) = this.input.split_at(count);
        this.input = tail;
        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
            chunk: bytes::Bytes::copy_from_slice(head),
            metadata: (),
        })))
    }
}

/// A stream that gives its bytes, and whose skips report one byte more than
/// they were allowed.
pub struct Overskip<'a> {
    input: &'a [u8],
}

impl<'a> Overskip<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self { input }
    }
}

nitori_call::family_receiver!(impl ['a] for Overskip<'a>);

impl nitori_io::Read for Overskip<'_> {
    type Error = Infallible;
    type Metadata = ();
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        let count = this.input.len().min(dst.remaining_mut());
        let (head, tail) = this.input.split_at(count);
        dst.put_slice(head);
        this.input = tail;
        Poll::Ready(Ok(core::num::NonZeroUsize::new(count).map(|count| {
            nitori_io::ReadSegment {
                count,
                metadata: (),
            }
        })))
    }
}

impl nitori_io::Skip for Overskip<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Ok(Some(nitori_io::Min::min(maximum, 8) + 1)))
    }
}
/// The type of a frame as the tests compare it: its value on the wire, and
/// whether a part has it on the stream, it is reserved, or it is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ty {
    Known(u64),
    Reserved(u64),
    Unknown(u64),
}

/// The SETTINGS_QPACK_MAX_TABLE_CAPACITY of `octets`, in its shortest
/// encoding.
pub fn table_capacity(octets: u64) -> hatate_wire_qpack::QpackMaxTableCapacity {
    use sakuya_var_int::{VarInt, VarIntField};
    hatate_wire_qpack::QpackMaxTableCapacity::new(VarIntField::shortest(
        VarInt::new(octets).expect("a capacity within the varint range"),
    ))
}

pub fn ty<C: ClaimedValue>(frame_type: FrameType<C>) -> Ty {
    match frame_type {
        FrameType::Known(known) => Ty::Known(known.value().get()),
        FrameType::Reserved(value) => Ty::Reserved(value.get()),
        FrameType::Unknown(value) => Ty::Unknown(value.get()),
    }
}

/// The type of a frame of RFC 9114 that a part has on the stream.
pub const fn known(frame_type: Http3FrameType) -> Ty {
    Ty::Known(frame_type.value().get())
}

/// The bytes of a field, at its width.
pub fn field_bytes<T: Copy + Into<sakuya_var_int::VarInt> + TryFrom<sakuya_var_int::VarInt>>(
    field: sakuya_var_int::VarIntField<T>,
) -> Vec<u8> {
    let (bytes, length) = field.to_encoding();
    bytes[..length].to_vec()
}

/// The bytes of a frame of the type `frame_type` with the payload `payload`:
/// the Type and the Length at `widths`, then the payload.
pub fn frame_bytes(
    frame_type: sakuya_var_int::VarInt,
    widths: hatate_wire::frame::FrameWidths,
    payload: &[u8],
) -> Vec<u8> {
    use sakuya_var_int::{VarInt, VarIntField};
    let mut bytes = field_bytes(VarIntField::new(frame_type, widths.type_width()).unwrap());
    let length = VarInt::new(u64::try_from(payload.len()).unwrap()).unwrap();
    bytes.extend(field_bytes(
        VarIntField::new(length, widths.length_width()).unwrap(),
    ));
    bytes.extend_from_slice(payload);
    bytes
}

/// Reads at most `take` bytes from `io`, stopping at EOF.
pub async fn read_some<A: AsAccess<Family: Read<Metadata = ()>>>(
    io: &mut A,
    take: usize,
) -> Result<Vec<u8>, <A::Family as Read>::Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 7];
    while bytes.len() < take {
        let want = (take - bytes.len()).min(buffer.len());
        let count = io
            .access()
            .read(&mut &mut buffer[..want])
            .await?
            .map_or(0, |segment| segment.count.get());
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    Ok(bytes)
}

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

/// An encoder instruction as these tests read it.
pub type Instruction = EncoderInstruction<Collected, Vec<u8>>;

/// Limits `reader` to `wire` and `decoded` octets and reads its next
/// instruction, whose bytes have no metadata.
pub async fn next_encoder<A: ReceiverAccess<Family: ReadChunk<Metadata = ()>>>(
    reader: &mut EncoderStream<A>,
    wire: usize,
    decoded: usize,
) -> Result<Option<Instruction>, DecodeEncoderInstructionError<<A::Family as Read>::Error>> {
    reader.set_limits(EncoderStreamLimits {
        max_wire_len: wire,
        max_decoded_len: decoded,
    });
    let next = Option::<ReadValue<Instruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

/// Reads the next instruction of the critical encoder stream within the
/// limits of a table of `capacity` octets.
pub async fn next_critical_encoder<A: ReceiverAccess>(
    reader: &mut QpackEncoderStream<A>,
    capacity: u64,
) -> Result<
    Instruction,
    DecodeQpackEncoderInstructionError<
        <<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error,
    >,
>
where
    Composed<A, CriticalStream>: ReceiverAccess<Family: ReadChunk<Metadata = ()>>,
{
    reader.set_max_table_capacity(table_capacity(capacity));
    let next = ReadValue::<Instruction, ()>::decode_from(reader).await?;
    Ok(next.value)
}

/// Limits `reader` to `wire` octets and reads its next instruction.
pub async fn next_decoder<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    reader: &mut DecoderStream<A>,
    wire: usize,
) -> Result<Option<DecoderInstruction>, DecodeDecoderInstructionError<F::Error>> {
    reader.set_limits(DecoderStreamLimits { max_wire_len: wire });
    let next = Option::<ReadValue<DecoderInstruction, ()>>::decode_from(reader).await?;
    Ok(next.map(|read| read.value))
}

/// As [`next_decoder`], on the critical decoder stream.
pub async fn next_critical_decoder<A: ReceiverAccess>(
    reader: &mut QpackDecoderStream<A>,
    wire: usize,
) -> Result<
    DecoderInstruction,
    DecodeDecoderInstructionError<
        <<Composed<A, CriticalStream> as ReceiverAccess>::Family as Read>::Error,
    >,
>
where
    Composed<A, CriticalStream>: ReceiverAccess<Family: Read<Metadata = ()>>,
{
    reader.set_limits(DecoderStreamLimits { max_wire_len: wire });
    let next = ReadValue::<DecoderInstruction, ()>::decode_from(reader).await?;
    Ok(next.value)
}

/// A sink that takes `quota` bytes in all, by writes or by lending its
/// storage, and answers `Pending` once it is full, as a QUIC stream does when
/// its flow-control credit is used up.
pub struct Quota {
    written: bytes::BytesMut,
    quota: usize,
}

impl Quota {
    pub fn new(quota: usize) -> Self {
        Self {
            written: bytes::BytesMut::new(),
            quota,
        }
    }

    /// The bytes taken so far.
    pub fn written(&self) -> &[u8] {
        &self.written
    }

    fn room(&self) -> usize {
        self.quota - self.written.len()
    }
}

nitori_call::family_receiver!(impl [] for Quota);

impl nitori_io::Write for Quota {
    type Error = !;
    type Report = ();
    fn poll_write<'visit, I: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        input: &mut I,
    ) -> Poll<nitori_io::WriteResult<Self>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        if !input.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        let count = this.room().min(input.remaining());
        let Some(count) = core::num::NonZeroUsize::new(count) else {
            return Poll::Pending;
        };
        this.written.put(input.take(count.get()));
        Poll::Ready(Ok(Some(nitori_io::WriteSegment { count, report: () })))
    }
}

impl nitori_io::WriteLent for Quota {
    type Buffer<'l> = &'l mut bytes::BytesMut;
    fn poll_write_lent<'visit, T, A, Fill>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        wanted: core::num::NonZeroUsize,
        fill: Fill,
    ) -> Poll<nitori_io::WriteLentResult<Self, T, A>>
    where
        Self: 'visit,
        Fill: for<'l> FnOnce(&mut nitori_io::LentBuffer<&'l mut bytes::BytesMut>) -> Result<T, A>,
    {
        use nitori_io::{LentOutcome, LentSegment};
        let this = host.get_pin_mut().get_mut();
        let Some(granted) = core::num::NonZeroUsize::new(wanted.get().min(this.room())) else {
            return Poll::Pending;
        };
        // What is lent is the empty tail split off the written bytes.
        this.written.reserve(granted.get());
        let mut spare = this.written.split_off(this.written.len());
        let mut lent =
            nitori_io::LentBuffer::new(&mut spare, granted).expect("the grant fits the room");
        let result = fill(&mut lent);
        let kept = core::num::NonZeroUsize::new(spare.len()).filter(|count| *count <= granted);
        let outcome = match (result, kept) {
            (Ok(value), Some(count)) => LentOutcome::Kept(LentSegment {
                count,
                report: (),
                value,
            }),
            (Ok(value), None) => LentOutcome::NotKept(value),
            (Err(abandoned), _) => LentOutcome::GaveUp(abandoned),
        };
        if !matches!(outcome, LentOutcome::Kept(_)) {
            spare.clear();
        }
        this.written.unsplit(spare);
        Poll::Ready(Ok(Some(outcome)))
    }
}
