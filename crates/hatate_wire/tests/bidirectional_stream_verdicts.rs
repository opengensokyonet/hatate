//! What the parts of a list make of the first value of a stream: how the
//! verdicts of the parts combine, and what the parts of HTTP/3 judge in each
//! class of stream, with the reasons they give for rejecting it.
use frunk_core::{
    HList,
    coproduct::{CNil, Coproduct},
};
use hatate_wire::{
    Part,
    error_code::{ErrorCode, ErrorCodeOf},
    frame::codec::UnexpectedFrameTypeError,
    stream::{
        class::{
            ClientInitiatedBidirectional, ClientInitiatedUnidirectional,
            ServerInitiatedBidirectional, ServerInitiatedUnidirectional, StreamClass,
        },
        http3::{ClientPushStreamError, ServerBidirectionalStreamError},
        part::{StreamPart, StreamSet, StreamVerdict},
    },
};
use nitori_call::ReceiverAccess;
use nitori_io::{Combine, Read, calls::ReadValue};
use sakuya_var_int::{VarInt, VarIntField};

type Plain = HList![Part];

/// Why a part of these tests rejects a stream: with this code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reason(ErrorCode);

impl core::fmt::Display for Reason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "rejected with {:?}", self.0)
    }
}

impl core::error::Error for Reason {}

impl ErrorCodeOf<ErrorCode> for Reason {
    fn error_code(&self) -> Option<ErrorCode> {
        Some(self.0)
    }
}

/// A part that gives one fixed verdict on one value, in any class.
struct Says<const VALUE: u32, const VERDICT: u8>;

const FIRST: Reason = Reason(ErrorCode::new(VarInt::from_u32(0x2001)));
const WEAK: Reason = Reason(ErrorCode::new(VarInt::from_u32(0x2002)));

impl<const VALUE: u32, const VERDICT: u8, C: StreamClass, L> StreamPart<C, L>
    for Says<VALUE, VERDICT>
{
    type Claimed = ();
    type Rejection = Reason;
    type Stream<I, M> = ();
    type ReadError<E> = CNil;

    fn judge(value: VarInt, _skipped: bool) -> StreamVerdict<(), Reason> {
        if value.get() != u64::from(VALUE) {
            return StreamVerdict::NotClaimed;
        }
        match VERDICT {
            0 => StreamVerdict::Claimed(()),
            1 => StreamVerdict::Error(FIRST),
            _ => StreamVerdict::ErrorUnlessClaimed(WEAK),
        }
    }

    async fn read<I: ReceiverAccess<Family: Read<Metadata = M>>, M: Combine + Unpin + Clone>(
        (): (),
        _field: ReadValue<VarIntField<VarInt>, M>,
        _io: I,
    ) -> Result<(), CNil> {
        Ok(())
    }
}

type Claimed<const VALUE: u32> = Says<VALUE, 0>;
type Errors<const VALUE: u32> = Says<VALUE, 1>;
type Weak<const VALUE: u32> = Says<VALUE, 2>;

fn judge<C: StreamClass, L: StreamSet<C, L>>(value: u32) -> StreamVerdict<L::Claimed, L::Rejection>
where
    L::Claimed: core::fmt::Debug,
    L::Rejection: core::fmt::Debug,
{
    L::judge(VarInt::from_u32(value), false)
}

#[test]
fn the_verdicts_of_the_parts_of_a_list_combine_by_the_rules_of_the_set() {
    use StreamVerdict::{Claimed as Yes, Error, ErrorUnlessClaimed, NotClaimed};
    // A rejection is the injection of the rejecting part, as a claim is.
    use Coproduct::{Inl, Inr};
    type Uni = ClientInitiatedUnidirectional;
    // The list's own verdict on a value no part has an opinion on.
    assert_eq!(judge::<Uni, HList![]>(7), NotClaimed);
    assert_eq!(
        judge::<Uni, HList![Claimed<1>, Errors<2>, Weak<3>]>(9),
        NotClaimed
    );

    // One part's verdict is the list's, wherever it is in the list, and
    // a claim is given as the injection of the claiming part.
    type A = HList![Claimed<1>, Errors<2>, Weak<3>];
    assert_eq!(judge::<Uni, A>(1), Yes(Inl(())));
    assert_eq!(judge::<Uni, A>(2), Error(Inr(Inl(FIRST))));
    assert_eq!(judge::<Uni, A>(3), ErrorUnlessClaimed(Inr(Inr(Inl(WEAK)))));
    type B = HList![Weak<3>, Errors<2>, Claimed<1>];
    assert_eq!(judge::<Uni, B>(1), Yes(Inr(Inr(Inl(())))));
    assert_eq!(judge::<Uni, B>(2), Error(Inr(Inl(FIRST))));
    assert_eq!(judge::<Uni, B>(3), ErrorUnlessClaimed(Inl(WEAK)));

    // A weak error gives way to a claim by another part, in either order,
    // and an error is stronger than a weak error.
    type C1 = HList![Weak<5>, Claimed<5>];
    type C2 = HList![Claimed<5>, Weak<5>];
    assert_eq!(judge::<Uni, C1>(5), Yes(Inr(Inl(()))));
    assert_eq!(judge::<Uni, C2>(5), Yes(Inl(())));
    type D1 = HList![Weak<6>, Errors<6>];
    type D2 = HList![Errors<6>, Weak<6>];
    assert_eq!(judge::<Uni, D1>(6), Error(Inr(Inl(FIRST))));
    assert_eq!(judge::<Uni, D2>(6), Error(Inl(FIRST)));
    // Two weak errors are still one weak error: the first part's.
    assert_eq!(
        judge::<Uni, HList![Weak<6>, Weak<6>]>(6),
        ErrorUnlessClaimed(Inl(WEAK))
    );

    // The same in the other three classes.
    assert_eq!(judge::<ServerInitiatedUnidirectional, C2>(5), Yes(Inl(())));
    assert_eq!(
        judge::<ClientInitiatedBidirectional, D1>(6),
        Error(Inr(Inl(FIRST)))
    );
    assert_eq!(
        judge::<ServerInitiatedBidirectional, HList![Weak<6>]>(6),
        ErrorUnlessClaimed(Inl(WEAK))
    );
}

#[test]
fn the_parts_of_http3_judge_each_class_by_its_own_rules() {
    use Coproduct::Inl;
    use StreamVerdict::{Claimed as Yes, Error, ErrorUnlessClaimed, NotClaimed};
    type L = Plain;
    // Unidirectional, a client opens: everything but push, which is a
    // client's push stream.
    for value in [0, 2, 3] {
        assert!(matches!(
            judge::<ClientInitiatedUnidirectional, L>(value),
            Yes(_)
        ));
    }
    let verdict = judge::<ClientInitiatedUnidirectional, L>(1);
    assert_eq!(verdict, Error(Inl(ClientPushStreamError)));
    let Error(Inl(rejection)) = verdict else {
        unreachable!()
    };
    assert_eq!(
        rejection.error_code(),
        Some(ErrorCode::H3_STREAM_CREATION_ERROR)
    );
    // A server opens: all four.
    for value in 0..4 {
        assert!(matches!(
            judge::<ServerInitiatedUnidirectional, L>(value),
            Yes(_)
        ));
    }
    for value in [4, 0x21, 0x40, 0x3fff] {
        assert_eq!(judge::<ClientInitiatedUnidirectional, L>(value), NotClaimed);
        assert_eq!(judge::<ServerInitiatedUnidirectional, L>(value), NotClaimed);
    }
    // A client opens a bidirectional stream: a frame type of the request
    // stream is a request stream, and no more.
    for value in [0, 1] {
        assert!(matches!(
            judge::<ClientInitiatedBidirectional, L>(value),
            Yes(_)
        ));
    }
    // The types of HTTP/2, PUSH_PROMISE, which a server does not receive,
    // and the frames of HTTP/3 for other streams are errors, each of the
    // rule it breaks.
    for value in [2, 3, 4, 5, 6, 7, 8, 9, 0x0d] {
        let Error(Inl(rejection)) = judge::<ClientInitiatedBidirectional, L>(value) else {
            panic!("{value} is not an error");
        };
        assert_eq!(
            rejection.error_code(),
            Some(ErrorCode::H3_FRAME_UNEXPECTED),
            "{value}"
        );
        match value {
            2 | 6 | 8 | 9 => assert!(
                matches!(rejection, UnexpectedFrameTypeError::Http2Type { .. }),
                "{value}"
            ),
            5 => assert!(
                matches!(
                    rejection,
                    UnexpectedFrameTypeError::NotReceivableByRole { .. }
                ),
                "{value}"
            ),
            _ => assert!(
                matches!(
                    rejection,
                    UnexpectedFrameTypeError::NotAllowedOnStream { .. }
                ),
                "{value}"
            ),
        }
    }
    for value in [0x0a, 0x0b, 0x0c, 0x0e, 0x20, 0x33] {
        assert_eq!(judge::<ClientInitiatedBidirectional, L>(value), NotClaimed);
    }
    // A server opens one: HTTP/3 leaves it to an extension.
    for value in [0, 1, 0x33, 0x41] {
        assert_eq!(
            judge::<ServerInitiatedBidirectional, L>(value),
            ErrorUnlessClaimed(Inl(ServerBidirectionalStreamError))
        );
    }
    assert_eq!(
        ServerBidirectionalStreamError.error_code(),
        Some(ErrorCode::H3_STREAM_CREATION_ERROR)
    );
}
