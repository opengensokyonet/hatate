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
