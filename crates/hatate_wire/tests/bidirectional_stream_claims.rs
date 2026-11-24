#![feature(impl_trait_in_assoc_type)]
//! A part that has a frame type of its own on bidirectional streams, as
//! WebTransport has 0x41: HTTP/3's verdict on a client's stream that starts
//! with it gives way to the part's claim, and stands if no part claims it.
use core::convert::Infallible;
use frunk_core::{
    HList,
    coproduct::{CNil, Coproduct},
};
use hatate_wire::{
    Part,
    error_code::{ErrorCode, ErrorCodeOf as _},
    frame::{
        codec::UnexpectedFrameTypeError,
        set::{FramePart, FramePartOn},
    },
    registry::ClaimedValues,
    stream::{
        ReceivedStream,
        class::{ClientInitiatedBidirectional, ServerInitiatedBidirectional},
        codec::{ReadBidirectionalStreamError, read_bidirectional_stream},
        kind::StreamKind,
        part::{StreamPart, StreamVerdict},
    },
};
use nitori_call::{ReceiverAccess, call};
use nitori_io::{Read, Skip};
use sakuya_var_int::{VarInt, VarIntField};

const TYPE: u32 = 0x41;
static TYPES: ClaimedValues =
    ClaimedValues::new(&[VarInt::from_u32(TYPE)..=VarInt::from_u32(TYPE)]);

/// Has 0x41 as a frame type, and claims the client's bidirectional streams
/// that start with it.
#[derive(Clone, Copy)]
struct Claiming;

/// Has 0x41 as a frame type, but takes no bidirectional stream.
#[derive(Clone, Copy)]
struct Listing;

#[derive(Debug, PartialEq, Eq)]
struct Taken;

macro_rules! parts {
    ($part:ty, $claims:expr) => {
        impl FramePart for $part {
            const FRAME_TYPES: &'static ClaimedValues = &TYPES;
        }

        impl<K: StreamKind> FramePartOn<K> for $part {
            type FrameType = CNil;
        }

        impl<L> StreamPart<ClientInitiatedBidirectional, L> for $part {
            type Claimed = ();
            type Rejection = CNil;
            type Stream<I> = Taken;
            type ReadError<E> = CNil;

            fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<(), CNil> {
                if $claims && value.get() == u64::from(TYPE) {
                    StreamVerdict::Claimed(())
                } else {
                    StreamVerdict::NotClaimed
                }
            }

            async fn read<I: ReceiverAccess<Family: Read>>(
                _claimed: (),
                _field: VarIntField<VarInt>,
                _io: I,
            ) -> Result<Taken, CNil> {
                Ok(Taken)
            }
        }

        impl<L> StreamPart<ServerInitiatedBidirectional, L> for $part {
            type Claimed = ();
            type Rejection = CNil;
            type Stream<I> = Taken;
            type ReadError<E> = CNil;

            fn judge(_value: VarInt, _skipped: bool) -> StreamVerdict<(), CNil> {
                StreamVerdict::NotClaimed
            }

            async fn read<I: ReceiverAccess<Family: Read>>(
                _claimed: (),
                _field: VarIntField<VarInt>,
                _io: I,
            ) -> Result<Taken, CNil> {
                Ok(Taken)
            }
        }
    };
}

parts!(Claiming, true);
parts!(Listing, false);

/// Whose stream the first value gave.
#[derive(Debug, PartialEq, Eq)]
enum Whose {
    Http3,
    Claiming,
    Unknown(u64),
    Rejected(u64, ErrorCode, Rule),
}

/// Which rule of the frame types rejected the value.
#[derive(Debug, PartialEq, Eq)]
enum Rule {
    Http2Type,
    NotAllowedOnStream,
    NotReceivableByRole,
}

fn rule(error: &UnexpectedFrameTypeError) -> Rule {
    match error {
        UnexpectedFrameTypeError::Http2Type { .. } => Rule::Http2Type,
        UnexpectedFrameTypeError::NotAllowedOnStream { .. } => Rule::NotAllowedOnStream,
        UnexpectedFrameTypeError::NotReceivableByRole { .. } => Rule::NotReceivableByRole,
    }
}

macro_rules! start {
    ($name:ident, $list:ty, |$known:ident| $whose:expr) => {
        #[call(sync)]
        async fn $name<
            F: Read<Error = Infallible> + Skip<Count = usize>,
            A: ReceiverAccess<Family = F>,
        >(
            io: &mut A,
        ) -> Whose {
            match read_bidirectional_stream::<$list, ClientInitiatedBidirectional, _>(&mut *io)
                .await
            {
                Ok(Some(ReceivedStream::Known($known))) => $whose,
                Ok(Some(ReceivedStream::Unknown(unknown))) => Whose::Unknown(unknown.value().get()),
                Ok(None) => panic!("the stream is empty"),
                Err(ReadBidirectionalStreamError::Rejected { value, source }) => {
                    let code: Option<ErrorCode> = source.error_code();
                    let code = code.expect("a rejection has a code");
                    // HTTP/3's part is the first of every list here.
                    let Coproduct::Inl(reason) = source.get() else {
                        panic!("another part rejected")
                    };
                    Whose::Rejected(value.get(), code, rule(reason))
                }
                Err(_) => panic!("another failure"),
            }
        }
    };
}

start!(
    read_with_claiming,
    HList![Part, Claiming],
    |known| match known {
        Coproduct::Inl(_) => Whose::Http3,
        Coproduct::Inr(Coproduct::Inl(Taken)) => Whose::Claiming,
        Coproduct::Inr(Coproduct::Inr(none)) => match none {},
    }
);
start!(
    read_with_listing,
    HList![Part, Listing],
    |known| match known {
        Coproduct::Inl(_) => Whose::Http3,
        Coproduct::Inr(Coproduct::Inl(Taken)) => Whose::Claiming,
        Coproduct::Inr(Coproduct::Inr(none)) => match none {},
    }
);
start!(read_alone, HList![Part], |known| match known {
    Coproduct::Inl(_) => Whose::Http3,
    Coproduct::Inr(none) => match none {},
});

/// The stream starts with the value 0x41 in two bytes, then a Length.
const WIRE: [u8; 4] = [0x40, 0x41, 0x00, 0xaa];

#[test]
fn a_stream_that_starts_with_a_frame_of_another_part_is_its_stream_if_it_claims_it() {
    let mut input = &WIRE[..];
    assert_eq!(input.sync_read_with_claiming_unpin(), Whose::Claiming);
    // Only the value was read.
    assert_eq!(input.len(), 2);
    // A frame of another stream of HTTP/3 is no one's: still the error.
    for value in [0x03, 0x04, 0x07, 0x0d] {
        let mut input = &[value, 0x00][..];
        assert_eq!(
            input.sync_read_with_claiming_unpin(),
            Whose::Rejected(
                u64::from(value),
                ErrorCode::H3_FRAME_UNEXPECTED,
                Rule::NotAllowedOnStream
            )
        );
    }
}

#[test]
fn a_frame_type_a_part_has_but_no_part_claims_is_h3_frame_unexpected() {
    let mut input = &WIRE[..];
    assert_eq!(
        input.sync_read_with_listing_unpin(),
        Whose::Rejected(
            0x41,
            ErrorCode::H3_FRAME_UNEXPECTED,
            Rule::NotAllowedOnStream
        )
    );
    // Only the value was read.
    assert_eq!(input.len(), 2);
}

#[test]
fn the_frames_of_http3_and_of_http2_keep_their_verdicts_beside_a_claiming_part() {
    for value in [0x00, 0x01] {
        let mut input = &[value, 0x00][..];
        assert_eq!(input.sync_read_with_claiming_unpin(), Whose::Http3);
    }
    // HTTP/2's types, and a type nothing has.
    for value in [0x02, 0x06, 0x08, 0x09] {
        let mut input = &[value, 0x00][..];
        assert_eq!(
            input.sync_read_with_claiming_unpin(),
            Whose::Rejected(
                u64::from(value),
                ErrorCode::H3_FRAME_UNEXPECTED,
                Rule::Http2Type
            )
        );
    }
    let mut input = &[0x33, 0x00][..];
    assert_eq!(input.sync_read_with_claiming_unpin(), Whose::Unknown(0x33));
    // Without the part, 0x41 is a frame no part has.
    let mut input = &WIRE[..];
    assert_eq!(input.sync_read_alone_unpin(), Whose::Unknown(0x41));
}
