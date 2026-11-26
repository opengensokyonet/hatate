//! Constructors for literals whose lengths are known without waiting.
#![allow(dead_code)]
use bytes::Buf;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use hatate_qpack::string_literal::StringLiteral;
use nitori_codec::EncodedLen;

/// Run a future that completes without waiting.
pub fn now<F: Future>(future: F) -> F::Output {
    match pin!(future).poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("the future waited"),
    }
}

/// A raw literal with the shortest length prefix.
pub fn raw<S: EncodedLen<LengthError = !>, H>(bytes: S) -> StringLiteral<S, H> {
    now(StringLiteral::raw(bytes)).expect("a test literal has a length")
}

/// A Huffman literal with the shortest length prefix.
pub fn huffman<S, H: Buf + Clone>(decoded: H) -> StringLiteral<S, H> {
    StringLiteral::huffman(decoded).expect("a test literal has a length")
}
