//! Hosts shared by the integration tests.
#![allow(dead_code)]

use bytes::BufMut;
use core::{
    convert::Infallible,
    future::Future,
    pin::{Pin, pin},
    task::{Context, Poll, Waker},
};

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
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
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
        Poll::Ready(Ok(count))
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
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        let this = host.get_pin_mut().get_mut();
        let count = this.data.len().min(dst.remaining_mut());
        let (head, tail) = this.data.split_at(count);
        dst.put_slice(head);
        this.data = tail;
        Poll::Ready(Ok(count))
    }
}

impl nitori_io::ExactLen for Liar<'_> {
    type Length = usize;
    fn remaining_len<'visit>(host: Pin<&mut Self::ReceiverView<'visit>>) -> usize
    where
        Self: 'visit,
    {
        host.get_pin_mut().get_mut().claimed
    }
}

/// The error of a [`Broken`] stream.
#[derive(Debug, PartialEq, Eq)]
pub struct Boom;

/// A stream whose every read fails.
pub struct Broken;

nitori_call::family_receiver!(impl [] for Broken);

impl nitori_io::Read for Broken {
    type Error = Boom;
    fn poll_read<'visit, B: BufMut + ?Sized>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
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
    fn poll_read<'visit, B: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
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
        Poll::Ready(Ok(count))
    }
}

impl nitori_io::ReadChunk for ReadOnly<'_> {
    type Chunk = bytes::Bytes;
    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut Context<'_>,
        maximum: core::num::NonZeroUsize,
    ) -> Poll<Result<Option<bytes::Bytes>, Self::Error>>
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
        Poll::Ready(Ok(Some(bytes::Bytes::copy_from_slice(head))))
    }
}

/// A stream whose skips report one byte more than they were allowed.
pub struct Overskip;

nitori_call::family_receiver!(impl [] for Overskip);

impl nitori_io::Read for Overskip {
    type Error = Infallible;
    fn poll_read<'visit, B: BufMut + ?Sized>(
        _host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        _dst: &mut B,
    ) -> Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        Poll::Ready(Ok(0))
    }
}

impl nitori_io::Skip for Overskip {
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
