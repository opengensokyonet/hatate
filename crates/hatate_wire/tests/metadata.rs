//! The metadata of the bytes a frame, a stream type and a Push ID are read
//! from: a source whose first bytes arrived early (as in 0-RTT) marks the
//! fields made of them, and the payload's own reads report theirs.
use bytes::{Buf, BufMut};
use core::{
    num::NonZeroUsize,
    pin::Pin,
    task::{Context, Poll},
};
use frunk_core::{HList, coproduct::Coproduct};
use hatate_wire::{
    Part, Role,
    frame::{
        Frame, FrameWidths, GoawayFrameType, Http3FrameType, control::GoawayFrame,
        payload::FramePayload,
    },
    settings::{
        Setting, UnknownSetting,
        codec::{SettingParameter, SettingsFrame, WriteSettingsFrameHostExt as _},
        set::{Settings, SettingsOf},
    },
    stream::{
        FrameStream, ReceivedStream, class::ServerInitiatedUnidirectional,
        codec::read_unidirectional_stream, http3::Http3UnidirectionalStream,
        kind::RequestStreamKind,
    },
};
use nitori_call::{AsAccess, ConstructedAccess, family_receiver};
use nitori_codec::DecodeFrom as _;
use nitori_io::{Combine, Min, Read, ReadSegment, Skip, Write, WriteSegment, prelude::*};
use sakuya_var_int::{VarInt, VarIntField};

type Parts = HList![Part];

/// Whether any of the bytes arrived early.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Early(bool);

impl Combine for Early {
    fn combine(self, next: Self) -> Self {
        Self(self.0 || next.0)
    }
}

/// A stream that hands out one byte at a time; its first `early` bytes
/// arrived early.
struct Arrival<'a> {
    data: &'a [u8],
    early: usize,
}

impl<'a> Arrival<'a> {
    fn access(data: &'a [u8], early: usize) -> ConstructedAccess<Self> {
        ConstructedAccess::new(Self { data, early })
    }

    fn take(&mut self, count: usize) -> Early {
        let early = self.early > 0;
        self.early = self.early.saturating_sub(count);
        self.data = &self.data[count..];
        Early(early)
    }
}

family_receiver!(impl ['a] for Arrival<'a>);

impl Read for Arrival<'_> {
    type Error = !;
    type Metadata = Early;
    fn poll_read<'v, O: BufMut + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        out: &mut O,
    ) -> Poll<Result<Option<ReadSegment<Early>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let Some(&byte) = this.data.first().filter(|_| out.has_remaining_mut()) else {
            return Poll::Ready(Ok(None));
        };
        out.put_u8(byte);
        let metadata = this.take(1);
        Poll::Ready(Ok(Some(ReadSegment {
            count: NonZeroUsize::MIN,
            metadata,
        })))
    }
}

impl Skip for Arrival<'_> {
    type Count = usize;
    fn poll_skip<'v, M: Min<usize, Output = usize> + Clone>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        maximum: M,
    ) -> Poll<Result<Option<usize>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        let allowed = Min::min(maximum, 1);
        if allowed != 0 && this.data.is_empty() {
            return Poll::Ready(Ok(None));
        }
        let count = Ord::min(allowed, this.data.len());
        this.take(count);
        Poll::Ready(Ok(Some(count)))
    }
}

fn run<T>(future: impl core::future::Future<Output = T>) -> T {
    nitori_call::__private::run_sync(future)
}

#[test]
fn a_frame_stream_keeps_the_metadata_of_each_head() {
    // DATA "ab", HEADERS "c"; the first byte arrived early.
    let wire = [0x00, 0x02, b'a', b'b', 0x01, 0x01, b'c'];
    let mut io = Arrival::access(&wire, 1);
    let mut stream = run(FrameStream::<Parts, RequestStreamKind, _, Early>::read(
        &mut io,
        Role::Server,
    ))
    .unwrap()
    .unwrap();
    let mut frame = stream.frame();
    assert_eq!(frame.type_metadata(), &Early(true));
    assert_eq!(frame.length_metadata(), &Early(false));
    let both = run(frame.payload().access().read_array::<2>()).unwrap();
    assert_eq!(both.value, *b"ab");
    assert_eq!(both.metadata, Early(false));
    // The next head arrived after it.
    let frame = run(stream.next_frame()).unwrap().unwrap();
    assert_eq!(frame.type_metadata(), &Early(false));
    assert_eq!(frame.length_metadata(), &Early(false));
}

#[test]
fn the_metadata_of_a_payload_read_is_that_of_its_bytes() {
    // The whole first frame arrived early but its last byte.
    let wire = [0x00, 0x02, b'a', b'b', 0x01, 0x00];
    let mut io = Arrival::access(&wire, 3);
    let mut stream = run(FrameStream::<Parts, RequestStreamKind, _, Early>::read(
        &mut io,
        Role::Server,
    ))
    .unwrap()
    .unwrap();
    let mut frame = stream.frame();
    assert_eq!(frame.type_metadata(), &Early(true));
    assert_eq!(frame.length_metadata(), &Early(true));
    let first = run(frame.payload().access().read_array::<1>()).unwrap();
    assert_eq!(first.metadata, Early(true));
    let second = run(frame.payload().access().read_array::<1>()).unwrap();
    assert_eq!(second.metadata, Early(false));
    // Both, as one read.
    let mut io = Arrival::access(&wire, 3);
    let mut stream = run(FrameStream::<Parts, RequestStreamKind, _, Early>::read(
        &mut io,
        Role::Server,
    ))
    .unwrap()
    .unwrap();
    let both = run(stream.frame().payload().access().read_array::<2>()).unwrap();
    assert_eq!((both.value, both.metadata), (*b"ab", Early(true)));
}

#[test]
fn a_whole_frame_keeps_the_metadata_of_its_fields() {
    // GOAWAY 4 in two bytes; only its Type arrived early.
    let wire = [0x07, 0x02, 0x40, 0x04];
    let mut io = Arrival::access(&wire, 1);
    let mut frame = run(GoawayFrame::<Early>::decode_from(&mut io)).unwrap();
    assert_eq!(frame.type_metadata(), &Early(true));
    assert_eq!(frame.length_metadata(), &Early(false));
    let id = frame.payload();
    assert_eq!(id.value.get().get().get(), 4);
    assert_eq!(id.metadata, Early(false));
    // In stages, the head only.
    let mut io = Arrival::access(&wire, 2);
    let frame =
        run(Frame::<GoawayFrameType, FramePayload<_>, Early>::decode_from(&mut io)).unwrap();
    assert_eq!(frame.type_metadata(), &Early(true));
    assert_eq!(frame.length_metadata(), &Early(true));
    assert_eq!(frame.length().get().get(), 2);
}

#[test]
fn a_setting_parameter_keeps_the_metadata_of_its_fields() {
    // Identifier 0x21, value 1; only the identifier arrived early.
    let wire = [0x21, 0x01];
    let mut io = Arrival::access(&wire, 1);
    let parameter = run(SettingParameter::<Early>::decode_from(&mut io)).unwrap();
    assert_eq!(parameter.identifier.metadata, Early(true));
    assert_eq!(parameter.value.metadata, Early(false));
    let mut settings = Settings::<<Parts as SettingsOf>::Settings>::new();
    let Ok(Setting::Unknown(unknown)) = settings.insert(parameter) else {
        panic!("an unknown setting");
    };
    assert_eq!(unknown.identifier().get().get(), 0x21);
    assert_eq!(unknown.value().get().get(), 1);
}

#[test]
fn a_unidirectional_stream_keeps_the_metadata_of_its_type_and_first_frame() {
    // A control stream: its type byte, then SETTINGS without settings; the
    // type and the Type of the frame arrived early.
    let wire = [0x00, 0x04, 0x00];
    let mut io = Arrival::access(&wire, 2);
    let stream = run(read_unidirectional_stream::<
        Parts,
        ServerInitiatedUnidirectional,
        _,
        Early,
    >(&mut io))
    .unwrap()
    .unwrap();
    assert_eq!(stream.type_metadata(), &Early(true));
    let ReceivedStream::Known(known) = stream.transpose() else {
        panic!("a stream of a part");
    };
    assert_eq!(known.type_metadata(), &Early(true));
    let Coproduct::Inl(http3) = known.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Control(control) = http3.transpose() else {
        panic!("a control stream");
    };
    assert_eq!(control.type_metadata(), &Early(true));
    let mut control = control.into_stream();
    let frame = control.frame();
    assert_eq!(frame.frame_type().value(), Http3FrameType::Settings.value());
    assert_eq!(frame.type_metadata(), &Early(true));
    assert_eq!(frame.length_metadata(), &Early(false));
}

#[test]
fn a_push_stream_keeps_the_metadata_of_its_push_id() {
    // A push stream: its type, the Push ID 7 in two bytes, a DATA frame; the
    // type and the Push ID arrived early, the frame after them.
    let wire = [0x01, 0x40, 0x07, 0x00, 0x01, b'x'];
    let mut io = Arrival::access(&wire, 3);
    let stream = run(read_unidirectional_stream::<
        Parts,
        ServerInitiatedUnidirectional,
        _,
        Early,
    >(&mut io))
    .unwrap()
    .unwrap();
    let ReceivedStream::Known(known) = stream.transpose() else {
        panic!("a stream of a part");
    };
    let Coproduct::Inl(http3) = known.transpose() else {
        unreachable!("one part");
    };
    let Http3UnidirectionalStream::Push(push) = http3.transpose() else {
        panic!("a push stream");
    };
    assert_eq!(push.type_metadata(), &Early(true));
    let mut push = push.into_stream();
    assert_eq!(push.push_id().get().get().get(), 7);
    assert_eq!(push.push_id_metadata(), &Early(true));
    let frame = push.frames().frame();
    assert_eq!(frame.type_metadata(), &Early(false));
    let (push_id, mut frames) = push.into_parts();
    assert_eq!(push_id.metadata, Early(true));
    assert_eq!(frames.frame().length().get().get(), 1);
}

/// What the sink counts of the writes it accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Writes(u32);

impl Combine for Writes {
    fn combine(self, next: Self) -> Self {
        Self(self.0 + next.0)
    }
}

/// A sink that accepts one byte at a time and reports one write for each.
#[derive(Default)]
struct Tally {
    bytes: Vec<u8>,
}

family_receiver!(impl [] for Tally);

impl Write for Tally {
    type Error = !;
    type Report = Writes;
    fn poll_write<'v, B: Buf + ?Sized>(
        host: Pin<&mut Self::ReceiverView<'v>>,
        _: &mut Context<'_>,
        input: &mut B,
    ) -> Poll<Result<Option<WriteSegment<Writes>>, !>>
    where
        Self: 'v,
    {
        let this = host.get_pin_mut().get_mut();
        if !input.has_remaining() {
            return Poll::Ready(Ok(None));
        }
        this.bytes.push(input.get_u8());
        Poll::Ready(Ok(Some(WriteSegment {
            count: NonZeroUsize::MIN,
            report: Writes(1),
        })))
    }
}

#[test]
fn a_written_settings_frame_reports_what_all_of_it_took() {
    let setting = Setting::Unknown(
        UnknownSetting::new(
            VarIntField::shortest(VarInt::from_u32(0x21)),
            VarIntField::shortest(VarInt::from_u32(1)),
        )
        .unwrap(),
    );
    let frame =
        SettingsFrame::<<Parts as SettingsOf>::Settings>::new(vec![setting], FrameWidths::SHORTEST)
            .unwrap();
    let mut sink = Tally::default();
    let report = sink.sync_write_settings_frame_unpin(&frame).unwrap();
    // Type, Length, identifier and value: four bytes, a write each.
    assert_eq!(sink.bytes, [0x04, 0x02, 0x21, 0x01]);
    assert_eq!(report, Writes(4));
}
