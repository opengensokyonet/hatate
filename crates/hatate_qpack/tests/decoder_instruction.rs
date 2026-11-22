use core::num::NonZeroU64;
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, StreamId,
        codec::{
            ReadDecoderInstructionHostExt, ReadError, WriteDecoderInstructionHostExt, WriteError,
        },
    },
    instruction::{NumberError, OctetError},
};
use nitori_io::calls::ReadArrayError;

#[test]
fn successive_decoder_instructions_keep_the_next_opcode() {
    // RFC 9204 Appendix B.2 (ack stream 4), B.3 (increment), B.4 (cancel stream 8).
    let cases = [
        (
            D::SectionAcknowledgment(StreamId::try_from(4).unwrap()),
            0x84,
        ),
        (D::InsertCountIncrement(NonZeroU64::MIN), 1),
        (D::StreamCancellation(StreamId::try_from(8).unwrap()), 0x48),
    ];
    let mut wire = Vec::new();
    for &(op, byte) in &cases {
        wire.sync_write_decoder_instruction_unpin(op, 1).unwrap();
        assert_eq!(wire.last(), Some(&byte));
    }
    let mut input = wire.as_slice();
    for &(op, _) in &cases {
        assert_eq!(input.sync_read_decoder_instruction_unpin(1).unwrap(), op);
    }
    assert!(matches!(
        input.sync_read_decoder_instruction_unpin(1),
        Err(ReadError::Prefix {
            source: OctetError::Read {
                source: ReadArrayError::Incomplete { .. }
            }
        })
    ));
}

#[test]
fn zero_increment_and_unrepresentable_stream_ids_are_distinct() {
    assert!(matches!(
        (&[0][..]).sync_read_decoder_instruction_unpin(1),
        Err(ReadError::ZeroIncrement)
    ));
    assert_eq!(StreamId::try_from(1 << 62).unwrap_err().value(), 1 << 62);
    for acknowledgment in [true, false] {
        let mut wire = Vec::new();
        if acknowledgment {
            hatate_qpack::integer::write::<7>(&mut wire, 0x80, 1 << 62).unwrap();
        } else {
            hatate_qpack::integer::write::<6>(&mut wire, 0x40, 1 << 62).unwrap();
        }
        let result = wire
            .as_slice()
            .sync_read_decoder_instruction_unpin(wire.len());
        assert!(matches!(
            (acknowledgment, result),
            (true, Err(ReadError::AcknowledgmentStream { .. }))
                | (false, Err(ReadError::CancellationStream { .. }))
        ));
    }
}

#[test]
fn wire_budget_applies_before_reading_or_writing_the_next_octet() {
    let mut rest = &[0x3f, 0, 0x84][..];
    assert!(matches!(
        rest.sync_read_decoder_instruction_unpin(0),
        Err(ReadError::Prefix {
            source: OctetError::WireLimit { .. }
        })
    ));
    assert_eq!(rest, &[0x3f, 0, 0x84]);
    assert!(matches!(rest.sync_read_decoder_instruction_unpin(1),
        Err(ReadError::IncrementNumber {source:NumberError::Continuation {source:OctetError::WireLimit {source}}})
            if source.required()==2 && source.limit()==1));
    assert_eq!(rest, &[0, 0x84]);
    let mut dst = Vec::from(b"prefix");
    assert!(
        matches!(dst.sync_write_decoder_instruction_unpin(D::InsertCountIncrement(NonZeroU64::new(63).unwrap()),1),
        Err(WriteError::WireLimit {source}) if source.required()==2 && source.limit()==1)
    );
    assert_eq!(dst, b"prefix");
}

#[test]
fn continuation_truncation_and_nonminimal_length() {
    assert!(matches!(
        (&[0xff][..]).sync_read_decoder_instruction_unpin(11),
        Err(ReadError::AcknowledgmentNumber {
            source: NumberError::Continuation {
                source: OctetError::Read {
                    source: ReadArrayError::Incomplete { .. }
                }
            }
        })
    ));
    let mut input = &[0xff, 0x80, 0, 0x48][..];
    assert_eq!(
        input.sync_read_decoder_instruction_unpin(3).unwrap(),
        D::SectionAcknowledgment(StreamId::try_from(127).unwrap())
    );
    assert_eq!(input, [0x48]);
}

struct Fragmented<'a> {
    input: &'a [u8],
    waiting: bool,
}
nitori_call::family_receiver!(impl ['a] for Fragmented<'a>);

impl nitori_io::Read for Fragmented<'_> {
    type Error = core::convert::Infallible;
    fn poll_read<'visit, B: bytes::BufMut + ?Sized>(
        host: core::pin::Pin<&mut Self::ReceiverView<'visit>>,
        cx: &mut core::task::Context<'_>,
        dst: &mut B,
    ) -> core::task::Poll<Result<usize, Self::Error>>
    where
        Self: 'visit,
    {
        use core::task::Poll;
        let this = host.get_pin_mut().get_mut();
        if !this.waiting {
            this.waiting = true;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        this.waiting = false;
        let Some((&byte, rest)) = this.input.split_first() else {
            return Poll::Ready(Ok(0));
        };
        dst.put_u8(byte);
        this.input = rest;
        Poll::Ready(Ok(1))
    }
}

#[test]
fn integer_state_and_budget_survive_pending_between_every_octet() {
    use core::{
        future::Future,
        pin::{Pin, pin},
        task::{Context, Poll, Waker},
    };
    use hatate_qpack::decoder_instruction::codec::ReadDecoderInstruction;
    use nitori_call::CallExecutor;

    let mut host = Fragmented {
        input: &[0xff, 0x80, 0, 0x48],
        waiting: false,
    };
    {
        let mut call = pin!(CallExecutor::execute(
            Pin::new(&mut host),
            ReadDecoderInstruction::new(3)
        ));
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            assert!(call.as_mut().poll(&mut cx).is_pending());
        }
        assert!(
            matches!(call.as_mut().poll(&mut cx),Poll::Ready(Ok(D::SectionAcknowledgment(id))) if id.get()==127)
        );
    }
    assert_eq!(host.input, [0x48]);
}

#[test]
fn host_write_failure_preserves_the_accepted_prefix() {
    let mut buffer = [0u8; 1];
    let error = buffer
        .as_mut_slice()
        .sync_write_decoder_instruction_unpin(
            D::InsertCountIncrement(NonZeroU64::new(63).unwrap()),
            2,
        )
        .unwrap_err();
    assert!(matches!(error, WriteError::Send { source } if source.completed()==1));
    assert_eq!(buffer, [0x3f]);
}
