//! Check opcode dispatch, wire budget, cursor movement and canonical writing.
#![no_main]
use core::num::NonZeroU64;
use hatate_qpack::{
    decoder_instruction::{
        DecoderInstruction as D, StreamId,
        codec::{ReadDecoderInstructionHostExt, WriteDecoderInstructionHostExt},
    },
    integer,
};
use libfuzzer_sys::fuzz_target;

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
        let actual = stream.sync_read_decoder_instruction_unpin(budget).ok();
        assert_eq!(actual, expected);
        assert_eq!(stream.len(), before.len() - (available - bounded.len()));
        let Some(instruction) = actual else { break };
        let mut encoded = Vec::new();
        encoded
            .sync_write_decoder_instruction_unpin(instruction, budget)
            .unwrap();
        let mut replay = encoded.as_slice();
        assert_eq!(
            replay.sync_read_decoder_instruction_unpin(budget).unwrap(),
            instruction
        );
        assert!(replay.is_empty());
        let mut short = vec![0xa5];
        assert!(
            short
                .sync_write_decoder_instruction_unpin(instruction, encoded.len() - 1)
                .is_err()
        );
        assert_eq!(short, [0xa5]);
    }
});
