//! Check opcode dispatch, wire budget and cursor movement against in-memory
//! decoding; write each instruction read back and compare it with the
//! octets it was read from, and check the wire limit before writing.
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use core::num::NonZeroU64;
use hatate_qpack::{
    decoder_instruction::{
        DecodeDecoderInstructionError, DecoderInstruction as D, DecoderStream, DecoderStreamLimits,
        Increment, StreamId,
    },
    integer::{self, PrefixedField},
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_codec::{DecodeFrom, EncodeInto};
use nitori_io::{Read, Write, calls::ReadValue};

/// One instruction from a fresh stream; after a failure the same stream must
/// report the interruption.
#[call(sync)]
async fn read_one<F: Read<Metadata = ()>, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    max_wire_len: usize,
) -> Result<Option<D>, ()> {
    let mut stream = DecoderStream::new(io, DecoderStreamLimits { max_wire_len });
    match Option::<ReadValue<D, ()>>::decode_from(&mut stream).await {
        Ok(instruction) => Ok(instruction.map(|read| read.value)),
        Err(_) => {
            assert!(matches!(
                Option::<ReadValue<D, ()>>::decode_from(&mut stream).await,
                Err(DecodeDecoderInstructionError::Interrupted)
            ));
            Err(())
        }
    }
}

/// Writes one instruction to a fresh stream within `max_wire_len`.
#[call(sync)]
async fn write_one<G: Write<Report = ()>, A: ReceiverAccess<Family = G>>(
    io: &mut A,
    instruction: D,
    max_wire_len: usize,
) -> bool {
    let mut stream = DecoderStream::new(io, DecoderStreamLimits { max_wire_len });
    instruction.encode_into(&mut stream).await.is_ok()
}

fn reference(first: u8, rest: &mut &[u8]) -> Option<D> {
    match first {
        0x80..=0xff => {
            let field = integer::read::<7>(first, rest).ok()?;
            let id = StreamId::try_from(field.value().get()).ok()?;
            Some(D::SectionAcknowledgment {
                stream_id: PrefixedField::new::<7>(id, field.padding()).unwrap(),
            })
        }
        0x40..=0x7f => {
            let field = integer::read::<6>(first, rest).ok()?;
            let id = StreamId::try_from(field.value().get()).ok()?;
            Some(D::StreamCancellation {
                stream_id: PrefixedField::new::<6>(id, field.padding()).unwrap(),
            })
        }
        _ => {
            let field = integer::read::<6>(first, rest).ok()?;
            let increment = Increment::new(NonZeroU64::new(field.value().get())?);
            Some(D::InsertCountIncrement {
                increment: PrefixedField::new::<6>(increment, field.padding()).unwrap(),
            })
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&budget, mut stream)) = data.split_first() else {
        return;
    };
    let budget = usize::from(budget);
    while !stream.is_empty() {
        let available = stream.len().min(budget);
        let mut bounded = &stream[..available];
        let before = stream;
        let expected = bounded.split_first().and_then(|(&first, tail)| {
            bounded = tail;
            reference(first, &mut bounded)
        });
        let actual = stream.sync_read_one_unpin(budget);
        // The stream is not empty, so it cannot end at the boundary.
        assert_eq!(actual, expected.map(Some).ok_or(()));
        let consumed = before.len() - stream.len();
        assert_eq!(consumed, available - bounded.len());
        let Ok(Some(instruction)) = actual else {
            return;
        };
        assert_eq!(instruction.wire_len() as usize, consumed);
        // Written back, the instruction is the octets it was read from.
        let mut encoded = Vec::new();
        assert!(encoded.sync_write_one_unpin(instruction, budget));
        assert_eq!(encoded, &before[..consumed]);
        let mut replay = encoded.as_slice();
        assert_eq!(replay.sync_read_one_unpin(budget), Ok(Some(instruction)));
        // The end after the instruction is at the boundary.
        assert_eq!(replay.sync_read_one_unpin(budget), Ok(None));
        assert!(replay.is_empty());
        // A limit below its length writes nothing.
        let mut short = vec![0xa5];
        assert!(!short.sync_write_one_unpin(instruction, consumed - 1));
        assert_eq!(short, [0xa5]);
    }
    if budget > 0 {
        assert_eq!((&[][..]).sync_read_one_unpin(budget), Ok(None));
    }
});
