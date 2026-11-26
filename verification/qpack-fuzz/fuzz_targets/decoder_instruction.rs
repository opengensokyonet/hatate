//! Check opcode dispatch, wire budget, cursor movement and canonical writing.
#![no_main]
#![feature(impl_trait_in_assoc_type)]
use core::num::NonZeroU64;
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, DecoderStream, DecoderStreamLimits, StreamId,
        codec::{ReadError, WriteDecoderInstructionHostExt},
    },
    integer,
};
use libfuzzer_sys::fuzz_target;
use nitori_call::{ReceiverAccess, call};
use nitori_codec::DecodeFrom;
use nitori_io::{Read, calls::ReadValue};

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
                Err(ReadError::Interrupted)
            ));
            Err(())
        }
    }
}

fn reference(first: u8, rest: &mut &[u8]) -> Option<D> {
    match first {
        0x80..=0xff => Some(D::SectionAcknowledgment(
            StreamId::try_from(integer::read::<7>(first, rest).ok()?).ok()?,
        )),
        0x40..=0x7f => Some(D::StreamCancellation(
            StreamId::try_from(integer::read::<6>(first, rest).ok()?).ok()?,
        )),
        _ => Some(D::InsertCountIncrement(NonZeroU64::new(
            integer::read::<6>(first, rest).ok()?,
        )?)),
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
        assert_eq!(stream.len(), before.len() - (available - bounded.len()));
        let Ok(Some(instruction)) = actual else {
            return;
        };
        let mut encoded = Vec::new();
        encoded
            .sync_write_decoder_instruction_unpin(instruction, budget)
            .unwrap();
        let mut replay = encoded.as_slice();
        assert_eq!(replay.sync_read_one_unpin(budget), Ok(Some(instruction)));
        // The end after the instruction is at the boundary.
        assert_eq!(replay.sync_read_one_unpin(budget), Ok(None));
        assert!(replay.is_empty());
        let mut short = vec![0xa5];
        assert!(
            short
                .sync_write_decoder_instruction_unpin(instruction, encoded.len() - 1)
                .is_err()
        );
        assert_eq!(short, [0xa5]);
    }
    if budget > 0 {
        assert_eq!((&[][..]).sync_read_one_unpin(budget), Ok(None));
    }
});
