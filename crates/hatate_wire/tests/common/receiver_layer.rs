//! The receiver the receiver-layer tests hold by pin, and the script runner
//! they share: the same script on the call layer and on every way of holding
//! a receiver.
use core::{
    fmt::Debug,
    marker::PhantomPinned,
    pin::Pin,
    task::{Context, Poll},
};
use hatate_wire::error_code::{ErrorCode, ErrorCodeOf};
use nitori_io::{Read, ReadChunk, Skip};

/// A receiver that is not Unpin: at most three bytes per read or skip.
pub struct Fixed<'a> {
    input: &'a [u8],
    _pinned: PhantomPinned,
}

impl<'a> Fixed<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            _pinned: PhantomPinned,
        }
    }
    pub fn rest(&self) -> &'a [u8] {
        self.input
    }
}

nitori_call::family_receiver!(impl ['a] for Fixed<'a>);

impl Read for Fixed<'_> {
    type Error = !;
    type Metadata = ();
    fn poll_read<'visit, B: bytes::BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        dst: &mut B,
    ) -> Poll<Result<Option<nitori_io::ReadSegment<()>>, Self::Error>>
    where
        Self: 'visit,
    {
        // SAFETY: nothing is moved out of the pinned receiver.
        let this = unsafe { host.get_pin_mut().get_unchecked_mut() };
        let count = 3.min(this.input.len()).min(dst.remaining_mut());
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

/// Hands out chunks like it reads: at most three bytes.
impl<'a> ReadChunk for Fixed<'a> {
    type Chunk = &'a [u8];
    fn poll_read_chunk<'visit>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        maximum: core::num::NonZeroUsize,
    ) -> Poll<Result<Option<nitori_io::ChunkSegment<&'a [u8], ()>>, Self::Error>>
    where
        Self: 'visit,
    {
        // SAFETY: as above.
        let this = unsafe { host.get_pin_mut().get_unchecked_mut() };
        if this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = 3.min(this.input.len()).min(maximum.get());
        let (chunk, tail) = this.input.split_at(count);
        this.input = tail;
        Poll::Ready(Ok(Some(nitori_io::ChunkSegment {
            chunk,
            metadata: (),
        })))
    }
}

impl Skip for Fixed<'_> {
    type Count = usize;
    fn poll_skip<'visit, M: nitori_io::Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'visit>>,
        _cx: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, Self::Error>>
    where
        Self: 'visit,
    {
        // SAFETY: as above.
        let this = unsafe { host.get_pin_mut().get_unchecked_mut() };
        let allowed = nitori_io::Min::min(maximum, 3usize);
        if allowed != 0 && this.input.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = allowed.min(this.input.len());
        this.input = &this.input[count..];
        Poll::Ready(Ok(Some(count)))
    }
}

pub type Outcome = (Vec<String>, Option<Vec<u8>>);

/// Runs a script on every layer and every way of holding a receiver, and
/// checks that all agree with the call layer on a slice. The call-layer
/// function ends with the bytes the access has left (if the stream was
/// given back); the receiver-layer function gives the access back.
#[allow(unused_macros)]
macro_rules! agree {
    ($sync:ident, $suspended:ident, $recv:ident, $input:expr $(, $arg:expr)*) => {{
        let input: &[u8] = $input;
        let mut slice = input;
        let expected: $crate::common::receiver_layer::Outcome = slice.$sync($($arg),*);
        let mut host = $crate::common::Dribble::new(input, 1);
        let (dribbled, _) = $crate::common::run(host.$suspended($($arg),*));
        assert_eq!(dribbled, expected, "call layer, suspended");
        let check = |way: &str, got: $crate::common::receiver_layer::Outcome| {
            assert_eq!(got.0, expected.0, "{way}");
            if expected.1.is_some() {
                assert_eq!(got.1, expected.1, "{way}");
            }
        };
        let (log, io) = $recv(::nitori_call::ConstructedAccess::new($crate::common::Dribble::new(input, 1)) $(, $arg)*);
        check("by value", (log, io.map(|io| io.into_inner().rest().to_vec())));
        let (log, io) = $recv(::nitori_call::ConstructedAccess::new(input) $(, $arg)*);
        check("a slice by value", (log, io.map(|io| io.into_inner().to_vec())));
        let mut borrowed = input;
        let (log, _) = $recv(::nitori_call::ConstructedAccess::new(&mut borrowed) $(, $arg)*);

        check("borrowed", (log, Some(borrowed.to_vec())));
        let (log, io) = $recv(::nitori_call::ConstructedAccess::new(Box::pin($crate::common::receiver_layer::Fixed::new(input))) $(, $arg)*);
        check("pinned in a box", (log, io.map(|io| io.into_inner().rest().to_vec())));
        let mut pinned = ::core::pin::pin!($crate::common::receiver_layer::Fixed::new(input));
        let (log, _) = $recv(::nitori_call::ConstructedAccess::new(pinned.as_mut()) $(, $arg)*);

        check("pinned on the stack", (log, Some(pinned.rest().to_vec())));
        expected
    }};
}

#[allow(unused_macros)]
macro_rules! aw {
    ($step:expr) => {
        $step.await
    };
}
#[allow(unused_macros)]
macro_rules! ru {
    ($step:expr) => {
        $crate::common::run($step).0
    };
}

/// Whether a step ended the stream (end or failure), and how, as text.
pub fn step_text<T, E: ErrorCodeOf<ErrorCode> + Debug>(
    result: Result<Option<T>, E>,
) -> (bool, String) {
    match result {
        Ok(Some(_)) => (false, "frame".to_string()),
        Ok(None) => (true, "end".to_string()),
        Err(error) => (true, format!("error {:?} {error:?}", error.error_code())),
    }
}

/// From the current frame of `$stream`: its type and at most `$take` payload
/// bytes, then the next frame (`$known` skips reserved and unknown), until
/// `$stop` frames were seen or the stream ended or failed; the step after
/// that is logged once more.
#[allow(unused_macros)]
macro_rules! walk_stream {
    ($w:ident, $stream:ident, $log:ident, $take:expr, $known:expr, $stop:expr) => {{
        let mut seen = 0usize;
        loop {
            {
                let mut frame = $stream.frame();
                let payload = $w!($crate::common::read_some(frame.payload(), $take))
                    .map_err(|error| format!("payload error {:?}", error.error_code()));
                $log.push(format!(
                    "{:?} {:?}",
                    $crate::common::ty(frame.frame_type()),
                    payload
                ));
            }
            seen += 1;
            if seen >= $stop {
                break;
            }
            let (over, text) = if $known {
                $crate::common::receiver_layer::step_text($w!($stream.next_known_frame()))
            } else {
                $crate::common::receiver_layer::step_text($w!($stream.next_frame()))
            };
            if over {
                $log.push(text);
                let (_, again) =
                    $crate::common::receiver_layer::step_text($w!($stream.next_frame()));
                $log.push(format!("again: {again}"));
                break;
            }
        }
    }};
}
