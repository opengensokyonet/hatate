//! HTTP/3 streams ([RFC 9114 §6]): telling them apart at their start, and
//! reading the frames of those that carry frames.
//!
//! Each stream belongs to one of the four classes of QUIC stream
//! ([`class`]). A stream the peer opened starts with a variable-length
//! integer: the type of a unidirectional stream
//! ([`codec::read_unidirectional_stream`]), or the type of the first frame of
//! a bidirectional one after any reserved frames
//! ([`codec::read_bidirectional_stream`]). The parts of the connection give
//! their verdicts on it ([`part`]), and the part that claims it reads the
//! stream up to where it can be used: a stream that carries frames comes back
//! as a [`FrameStream`] at its first frame, a push stream with its Push ID.
//! A stream no part claims comes back as an [`UnknownStream`], to be
//! discarded.
//!
//! The kinds of stream that carry frames ([`kind`]) are derived within the
//! classes by the parts that define them. A [`FrameStream`] holds the stream
//! and its current frame: [`FrameStream::frame`] gives the frame, whose
//! payload is the [`FramePayload`] of the stream limited to what is left of it, and
//! [`FrameStream::next_frame`] skips what is left and reads the next frame.
//!
//! [RFC 9114 §6]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6
use crate::{
    Role,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::{
        Frame, FrameType,
        codec::{ReadFrameHeadError, check_frame_type, read_length, read_type},
        payload::{FramePayload, PayloadError, PayloadLimit},
        set::FrameSetOn,
    },
};
use core::marker::PhantomData;
use frunk_core::coproduct::{CNil, Coproduct};
use kind::StreamKind;
use nitori_call::{AsAccess, Composed, ReceiverAccess};
use nitori_io::{
    Combine, Infinite, Min, Read, Skip, adapters::ReadLimit, calls::ReadValue, prelude::*,
};
use sakuya_var_int::{VarInt, VarIntField, VarIntWidth, VarIntWidthError};
use snafu::Snafu;

pub mod class;
pub mod codec;
pub mod http3;
pub mod kind;
pub mod part;

/// A stream that carries frames, of kind `K` in a connection whose list of
/// parts is `L`, and its current frame.
///
/// It holds the head of the current frame and its payload, a
/// [`FramePayload`] that holds the access `I` to the stream. It is made at its first frame
/// ([`read`](Self::read)) and always has a current frame: after the stream
/// ends at a frame boundary it keeps the last one, whose payload is then
/// empty.
///
/// The frame [`frame`](Self::frame) gives borrows the payload, so it is read
/// before the next frame is: [`next_frame`](Self::next_frame) skips
/// what is left of it. Skipping resumes where it stopped if the call is
/// dropped, and so does a call dropped or failing before it read any byte of
/// the next head. A stream whose next head was begun but not read whole,
/// because the call was dropped, failed or the head was rejected, is
/// interrupted and is abandoned. [`into_io`](Self::into_io) gives the access back.
pub struct FrameStream<L: FrameSetOn<K>, K: StreamKind, I, M = ()> {
    role: Role,
    r#type: ReadValue<VarIntField<FrameType<L::FrameType>>, M>,
    length: ReadValue<VarIntField<VarInt>, M>,
    payload: FramePayload<I>,
    /// What may still be read of the next head: unlimited, and unchanged
    /// until a byte of it is read.
    head: ReadLimit<u64>,
    state: FrameStreamState,
    marker: PhantomData<fn() -> (L, K)>,
}

/// Where a [`FrameStream`] is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameStreamState {
    /// Inside the current frame.
    InFrame,
    /// At the boundary after the current frame, reading the head of the
    /// next one: nothing of it is read while `head` is unchanged.
    AtHead,
    /// The stream ended at the boundary after the current frame.
    Ended,
    /// Skipping the payload failed, or the head of the next frame was begun
    /// and not read whole.
    Interrupted,
}

/// The head of a frame that a [`FrameStream`] of `L` on `K` reads, with
/// the metadata `M` of its bytes.
type Head<L, K, M> = (
    ReadValue<VarIntField<FrameType<<L as FrameSetOn<K>>::FrameType>>, M>,
    ReadValue<VarIntField<VarInt>, M>,
);

/// Reads the Length of the frame whose Type `r#type` was read, after
/// checking the type, or `None` at the end of the stream.
async fn read_after_type<
    L: FrameSetOn<K>,
    K: StreamKind,
    I: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
>(
    io: &mut I,
    role: Role,
    r#type: ReadValue<VarIntField<VarInt>, M>,
) -> Result<Head<L, K, M>, ReadFrameHeadError<<I::Family as Read>::Error>> {
    let frame_type = check_frame_type::<L, K>(r#type.value.get(), role)
        .map_err(|source| ReadFrameHeadError::Unexpected { source })?;
    let length = read_length(&mut *io)
        .await
        .map_err(|source| ReadFrameHeadError::Frame { source })?;
    // invariant: the frame type is the value that was read at this width.
    let value =
        VarIntField::new(frame_type, r#type.value.width()).expect("the width held the value");
    Ok((
        ReadValue {
            value,
            metadata: r#type.metadata,
        },
        length,
    ))
}

/// Reads and checks the head of the next frame, or `None` at the end of the
/// stream.
async fn read_head<
    L: FrameSetOn<K>,
    K: StreamKind,
    I: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
>(
    io: &mut I,
    role: Role,
) -> Result<Option<Head<L, K, M>>, ReadFrameHeadError<<I::Family as Read>::Error>> {
    let Some(r#type) = read_type(&mut *io)
        .await
        .map_err(|source| ReadFrameHeadError::Frame { source })?
    else {
        return Ok(None);
    };
    read_after_type::<L, K, I, M>(io, role, r#type)
        .await
        .map(Some)
}

impl<L: FrameSetOn<K>, K: StreamKind, I, M> FrameStream<L, K, I, M>
where
    I: ReceiverAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
{
    /// Reads the first frame of the stream `io` at an endpoint of role
    /// `role`, which receives the frames, and gives the stream at it.
    ///
    /// Returns `None` if the stream ends before the first byte.
    ///
    /// # Errors
    ///
    /// [`ReadFrameHeadError`]; its [`ErrorCodeOf::error_code`] gives the
    /// connection error the failure calls for, if any.
    pub async fn read(
        mut io: I,
        role: Role,
    ) -> Result<Option<Self>, ReadFrameHeadError<<I::Family as Read>::Error>> {
        let Some((r#type, length)) = read_head::<L, K, I, M>(&mut io, role).await? else {
            return Ok(None);
        };
        Ok(Some(Self::at(io, role, r#type, length)))
    }

    /// The stream `io` whose first frame has the Type `r#type`, already
    /// read: checks the type and reads the Length.
    pub(crate) async fn with_type(
        mut io: I,
        role: Role,
        r#type: ReadValue<VarIntField<VarInt>, M>,
    ) -> Result<Self, ReadFrameHeadError<<I::Family as Read>::Error>> {
        let (r#type, length) = read_after_type::<L, K, I, M>(&mut io, role, r#type).await?;
        Ok(Self::at(io, role, r#type, length))
    }

    fn at(
        io: I,
        role: Role,
        r#type: ReadValue<VarIntField<FrameType<L::FrameType>>, M>,
        length: ReadValue<VarIntField<VarInt>, M>,
    ) -> Self {
        Self {
            role,
            r#type,
            payload: FramePayload::new(io, length.value.get().get()),
            length,
            head: ReadLimit(u64::MAX),
            state: FrameStreamState::InFrame,
            marker: PhantomData,
        }
    }
}

impl<L: FrameSetOn<K>, K: StreamKind, I, M: Clone> FrameStream<L, K, I, M> {
    /// The current frame, with the metadata of the bytes of its head. Its
    /// payload lends the stream limited to what is left of the payload,
    /// which ends at the end of the payload.
    pub fn frame(&mut self) -> Frame<FrameType<L::FrameType>, &mut FramePayload<I>, M> {
        Frame::from_parts(self.r#type.clone(), self.length.clone(), &mut self.payload)
    }
}

impl<L: FrameSetOn<K>, K: StreamKind, I, M> FrameStream<L, K, I, M> {
    /// The role of this endpoint, which receives the frames.
    pub const fn role(&self) -> Role {
        self.role
    }

    /// The access, giving up the stream, wherever it is.
    pub fn into_io(self) -> I {
        self.payload.stream.into_parts().0
    }
}

impl<L: FrameSetOn<K>, K: StreamKind, I, M> FrameStream<L, K, I, M>
where
    I: ReceiverAccess<Family: Skip<Count: Clone + Min<u64, Output = u64>, Metadata = M>>,
    M: Combine + Unpin + Clone,
    u64: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    /// Skips what is left of the current frame and reads the next frame,
    /// which becomes the current one.
    ///
    /// Returns `None` if the stream ends at the frame boundary; the stream
    /// keeps the last frame, and every later call returns `None` too.
    ///
    /// The payload is skipped on the stream, which therefore skips
    /// ([`Skip`]); compose [`ReadSkip`](nitori_io::adapters::ReadSkip) or
    /// [`ReadChunkSkip`](nitori_io::adapters::ReadChunkSkip) onto a stream
    /// that only reads.
    ///
    /// # Errors
    ///
    /// [`NextFrameError`]; its [`ErrorCodeOf::error_code`] gives the
    /// connection error the failure calls for, if any.
    pub async fn next_frame(
        &mut self,
    ) -> Result<
        Option<Frame<FrameType<L::FrameType>, &mut FramePayload<I>, M>>,
        NextFrameError<<I::Family as Read>::Error>,
    > {
        Ok(if self.advance().await? {
            Some(self.frame())
        } else {
            None
        })
    }

    /// Reads frames as [`next_frame`](Self::next_frame) does until one of a
    /// type a part has on this kind of stream, skipping the reserved and
    /// unknown ones ([RFC 9114 §9]).
    ///
    /// # Errors
    ///
    /// [`NextFrameError`], as for [`next_frame`](Self::next_frame).
    ///
    /// [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
    pub async fn next_known_frame(
        &mut self,
    ) -> Result<
        Option<Frame<FrameType<L::FrameType>, &mut FramePayload<I>, M>>,
        NextFrameError<<I::Family as Read>::Error>,
    > {
        loop {
            if !self.advance().await? {
                return Ok(None);
            }
            if let FrameType::Known(_) = self.r#type.value.get() {
                return Ok(Some(self.frame()));
            }
        }
    }

    /// Moves to the next frame; `false` at the end of the stream.
    async fn advance(&mut self) -> Result<bool, NextFrameError<<I::Family as Read>::Error>> {
        match self.state {
            FrameStreamState::InFrame => {
                // A dropped skip resumes: the payload counts what it skipped.
                if let Err(source) = self.payload.access().skip_to_end().await {
                    self.state = FrameStreamState::Interrupted;
                    return Err(NextFrameError::Skip { source });
                }
                self.head = ReadLimit(u64::MAX);
                self.state = FrameStreamState::AtHead;
            }
            // A dropped read of the head that read nothing of it starts over.
            FrameStreamState::AtHead if self.head.0 == u64::MAX => {}
            FrameStreamState::AtHead | FrameStreamState::Interrupted => {
                self.state = FrameStreamState::Interrupted;
                return Err(NextFrameError::Interrupted);
            }
            FrameStreamState::Ended => return Ok(false),
        }
        let mut head = Composed::new(self.payload.stream.parent_mut(), &mut self.head);
        match read_head::<L, K, _, M>(&mut head, self.role).await {
            Ok(Some((r#type, length))) => {
                *self.payload.stream.state_mut() = PayloadLimit::new(length.value.get().get());
                self.r#type = r#type;
                self.length = length;
                self.state = FrameStreamState::InFrame;
                Ok(true)
            }
            Ok(None) => {
                self.state = FrameStreamState::Ended;
                Ok(false)
            }
            Err(source) => {
                // A failure before the first byte of the head read nothing
                // of it: the stream stays at the boundary.
                if self.head.0 != u64::MAX {
                    self.state = FrameStreamState::Interrupted;
                }
                Err(NextFrameError::Head { source })
            }
        }
    }
}

impl<L: FrameSetOn<K>, K: StreamKind, I, M: core::fmt::Debug> core::fmt::Debug
    for FrameStream<L, K, I, M>
where
    L::FrameType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("FrameStream")
            .field("role", &self.role)
            .field("type", &self.r#type)
            .field("length", &self.length)
            .field("payload", self.payload.stream.state())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Failures of [`FrameStream::next_frame`].
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum NextFrameError<E> {
    /// What was left of the current frame could not be skipped; the stream is
    /// inside it.
    #[snafu(display("could not skip the rest of the frame"))]
    Skip {
        /// The failure of skipping the payload.
        source: PayloadError<E>,
    },
    /// The head of the next frame could not be read, or was rejected.
    #[snafu(display("could not read the next frame"))]
    Head {
        /// The failure of reading the head.
        source: ReadFrameHeadError<E>,
    },
    /// An earlier call began reading a head and did not complete it, or
    /// failed after it began: the stream is inside a frame head and is
    /// abandoned.
    #[snafu(display("frame stream is inside a frame head"))]
    Interrupted,
}

/// The code of the failure of skipping or reading; `None` for an
/// interrupted stream, whose failure was reported before.
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for NextFrameError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Skip { source } => source.error_code(),
            Self::Head { source } => source.error_code(),
            Self::Interrupted => None,
        }
    }
}

/// A stream that gives its type on the wire, as the start of a
/// unidirectional stream ([`UnidirectionalStream`]).
pub trait TypedStream {
    /// The type of the stream on the wire.
    fn stream_type(&self) -> VarInt;
}

impl TypedStream for CNil {
    fn stream_type(&self) -> VarInt {
        match *self {}
    }
}

impl<H: TypedStream, T: TypedStream> TypedStream for Coproduct<H, T> {
    fn stream_type(&self) -> VarInt {
        match self {
            Coproduct::Inl(stream) => stream.stream_type(),
            Coproduct::Inr(stream) => stream.stream_type(),
        }
    }
}

/// A stream as the parts of a connection read its start: one a part claims,
/// `S`, in the form of that part, or one no part claims, `U`.
#[derive(Debug)]
pub enum ReceivedStream<S, U> {
    /// A stream a part claims.
    Known(S),
    /// A stream no part claims.
    Unknown(U),
}

impl<S: TypedStream, U: TypedStream> TypedStream for ReceivedStream<S, U> {
    fn stream_type(&self) -> VarInt {
        match self {
            Self::Known(stream) => stream.stream_type(),
            Self::Unknown(stream) => stream.stream_type(),
        }
    }
}

/// A stream that no part of the connection claims, at the byte after the
/// value it started with ([RFC 9114 §9]).
///
/// The receiver discards it or stops reading it; [`discard`](Self::discard)
/// reads it to its end. Dropping it drops the access, with what that means
/// for the stream at the interface to QUIC.
///
/// [RFC 9114 §9]: https://www.rfc-editor.org/rfc/rfc9114.html#section-9
#[must_use = "a stream no part claims is discarded or stopped"]
#[derive(Debug)]
pub struct UnknownStream<I> {
    value: VarInt,
    io: I,
}

impl<I> UnknownStream<I> {
    pub(crate) const fn new(value: VarInt, io: I) -> Self {
        Self { value, io }
    }

    /// The value the stream started with: its type, on a unidirectional
    /// stream, or the type of its first frame that is not reserved, on a
    /// bidirectional one.
    pub const fn value(&self) -> VarInt {
        self.value
    }
}

impl<I: ReceiverAccess<Family: Skip>> UnknownStream<I>
where
    Infinite: Min<<I::Family as Skip>::Count, Output = <I::Family as Skip>::Count>,
{
    /// Reads the stream to its end, discarding what it carries.
    ///
    /// # Errors
    ///
    /// The stream's failure.
    pub async fn discard(self) -> Result<(), <I::Family as Read>::Error> {
        let mut io = self.io;
        io.skip_to_end().await
    }
}

impl<I> TypedStream for UnknownStream<I> {
    fn stream_type(&self) -> VarInt {
        self.value
    }
}

/// A unidirectional stream ([RFC 9114 §6.2]) whose type has been read: the
/// stream `S`, which gives its type, the width of the Stream Type field, so
/// that it is written back in as many bytes as it was read in, and the
/// metadata `M` of the bytes of the field.
///
/// Read from the wire, `S` is a [`ReceivedStream`] of the streams of the
/// parts; its `transpose` methods move the width and the metadata onto each
/// kind of stream.
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
#[derive(Debug)]
pub struct UnidirectionalStream<S, M = ()> {
    width: VarIntWidth,
    type_metadata: M,
    stream: S,
}

impl<S: TypedStream> UnidirectionalStream<S> {
    /// The stream `stream`, whose type is written at `width`.
    ///
    /// # Errors
    ///
    /// [`VarIntWidthError`] if the type does not fit `width`.
    pub fn new(stream: S, width: VarIntWidth) -> Result<Self, VarIntWidthError> {
        VarIntField::new(stream.stream_type(), width)?;
        Ok(Self {
            width,
            type_metadata: (),
            stream,
        })
    }
}

impl<S: TypedStream, M> UnidirectionalStream<S, M> {
    /// The Stream Type field.
    pub fn type_field(&self) -> VarIntField<VarInt> {
        // invariant: the width was checked to hold the type when it was made.
        VarIntField::new(self.stream.stream_type(), self.width)
            .expect("the width holds the stream type")
    }
}

impl<S, M> UnidirectionalStream<S, M> {
    /// The stream whose type was read at `width`, with the metadata of the
    /// bytes of the type.
    pub(crate) const fn read(stream: S, width: VarIntWidth, type_metadata: M) -> Self {
        Self {
            width,
            type_metadata,
            stream,
        }
    }

    /// The width of the Stream Type field.
    pub const fn width(&self) -> VarIntWidth {
        self.width
    }

    /// The metadata of the bytes of the Stream Type field.
    pub const fn type_metadata(&self) -> &M {
        &self.type_metadata
    }

    /// The stream.
    pub const fn stream(&self) -> &S {
        &self.stream
    }

    /// The stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// The stream, giving up the width of its type and the metadata of its
    /// bytes.
    pub fn into_stream(self) -> S {
        self.stream
    }

    /// The stream and the metadata of the bytes of its type, giving up the
    /// width.
    pub(crate) fn into_parts(self) -> (S, M) {
        (self.stream, self.type_metadata)
    }
}

impl<S, U, M> UnidirectionalStream<ReceivedStream<S, U>, M> {
    /// The stream, with the width of its type and the metadata of its bytes,
    /// as one a part claims or one no part claims.
    pub fn transpose(
        self,
    ) -> ReceivedStream<UnidirectionalStream<S, M>, UnidirectionalStream<U, M>> {
        let Self {
            width,
            type_metadata,
            stream,
        } = self;
        match stream {
            ReceivedStream::Known(stream) => {
                ReceivedStream::Known(UnidirectionalStream::read(stream, width, type_metadata))
            }
            ReceivedStream::Unknown(stream) => {
                ReceivedStream::Unknown(UnidirectionalStream::read(stream, width, type_metadata))
            }
        }
    }
}

impl<H, T, M> UnidirectionalStream<Coproduct<H, T>, M> {
    /// The stream, with the width of its type and the metadata of its bytes,
    /// as the stream of the part that claims it.
    pub fn transpose(self) -> Coproduct<UnidirectionalStream<H, M>, UnidirectionalStream<T, M>> {
        let Self {
            width,
            type_metadata,
            stream,
        } = self;
        match stream {
            Coproduct::Inl(stream) => {
                Coproduct::Inl(UnidirectionalStream::read(stream, width, type_metadata))
            }
            Coproduct::Inr(stream) => {
                Coproduct::Inr(UnidirectionalStream::read(stream, width, type_metadata))
            }
        }
    }
}
