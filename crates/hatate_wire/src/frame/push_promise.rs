//! PUSH_PROMISE frames ([RFC 9114 §7.2.5]): a Push ID and an encoded field
//! section, on a request stream.
//!
//! [RFC 9114 §7.2.5]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.5
use super::{Frame, PushId, PushPromiseFrameType, payload::FramePayload};
use crate::error_code::{ErrorCode, ErrorCodeOf};
use nitori_call::AsAccess;
use nitori_codec::{DecodeFrom, EncodeInto, EncodedLen};
use nitori_io::{Combine, Read, Write, calls::ReadValue};
use sakuya_var_int::{VarIntField, stream::WriteVarIntError};
use snafu::{ResultExt, Snafu};

/// A PUSH_PROMISE frame: the frame type PUSH_PROMISE with a
/// [`PushPromisePayload`].
pub type PushPromiseFrame<P, M = ()> = Frame<PushPromiseFrameType, PushPromisePayload<P, M>, M>;

/// The payload of a PUSH_PROMISE frame ([RFC 9114 §7.2.5]): the Push ID,
/// with the metadata `M` of its bytes, and the encoded field section `P`,
/// which takes the rest of the payload.
///
/// Read, the section is the payload of the frame
/// (`&mut` [`FramePayload`]) after the Push ID, for the caller to read to
/// its end. Written, it is a value that encodes the section, such as a
/// [`Chunks`](nitori_codec::payload::Chunks) of a source of its bytes.
///
/// [RFC 9114 §7.2.5]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.5
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PushPromisePayload<P, M = ()> {
    /// The Push ID.
    pub push_id: ReadValue<VarIntField<PushId>, M>,
    /// The encoded field section.
    pub section: P,
}

/// Reads the Push ID through [`FramePayload::decode`], which detects a read
/// dropped inside it, and gives the rest of the payload as the section.
impl<'a, S, M, E> DecodeFrom<&'a mut FramePayload<S>>
    for PushPromisePayload<&'a mut FramePayload<S>, M>
where
    S: AsAccess<Family: Read<Metadata = M>>,
    M: Combine + Unpin,
    ReadValue<VarIntField<PushId>, M>: for<'b> DecodeFrom<&'b mut FramePayload<S>, Error = E>,
{
    type Error = DecodePushPromisePayloadError<E>;

    async fn decode_from(source: &'a mut FramePayload<S>) -> Result<Self, Self::Error> {
        let push_id = source
            .decode::<ReadValue<VarIntField<PushId>, M>, E>()
            .await
            .context(DecodePushPromisePayloadSnafu)?;
        Ok(Self {
            push_id,
            section: source,
        })
    }
}

/// A [`PushPromisePayload`] could not be decoded, failing with `E`: the
/// payload ended before its Push ID, or the stream failed.
#[derive(Debug, Snafu)]
#[snafu(display("could not decode the PUSH_PROMISE payload"))]
pub struct DecodePushPromisePayloadError<E> {
    source: E,
}

impl<E> DecodePushPromisePayloadError<E> {
    /// The failure of reading the integer.
    pub const fn read_error(&self) -> &E {
        &self.source
    }
}

/// The code of the failure of reading the integer: H3_FRAME_ERROR when the
/// payload is shorter than the Push ID ([RFC 9114 §7.1]).
///
/// [RFC 9114 §7.1]: https://www.rfc-editor.org/rfc/rfc9114.html#section-7.1
impl<E: ErrorCodeOf<ErrorCode>> ErrorCodeOf<ErrorCode> for DecodePushPromisePayloadError<E> {
    fn error_code(&self) -> Option<ErrorCode> {
        self.source.error_code()
    }
}

/// The length of the Push ID and of the section.
impl<P: EncodedLen, M> EncodedLen for PushPromisePayload<P, M> {
    type LengthError = P::LengthError;

    async fn encoded_len(&mut self) -> Result<u64, P::LengthError> {
        let Ok(push_id) = self.push_id.encoded_len().await;
        // A sum past u64::MAX is past 2^62 - 1 too, which building the frame
        // reports.
        Ok(push_id.saturating_add(self.section.encoded_len().await?))
    }
}

/// Writes the Push ID and then the section.
impl<S, P, M> EncodeInto<S> for PushPromisePayload<P, M>
where
    S: AsAccess<Family: Write<Report: Combine>>,
    P: EncodeInto<S>,
{
    type Output = PushPromiseOutput<<S::Family as Write>::Report, P::Output>;
    type Error = EncodePushPromiseError<<S::Family as Write>::Error, P::Error>;

    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        let push_id = self
            .push_id
            .encode_into(sink.access())
            .await
            .context(encode_push_promise_error::PushIdSnafu)?;
        let section = self
            .section
            .encode_into(sink)
            .await
            .context(encode_push_promise_error::SectionSnafu)?;
        Ok(PushPromiseOutput { push_id, section })
    }
}

/// What writing a [`PushPromisePayload`] produced: the report `R` of writing
/// the Push ID and the output `O` of the section.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PushPromiseOutput<R, O> {
    /// The report of writing the Push ID.
    pub push_id: R,
    /// What encoding the section produced.
    pub section: O,
}

/// Failures of writing a [`PushPromisePayload`] into a sink whose failures
/// are `W`, with a section whose failures are `P`.
#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum EncodePushPromiseError<W, P> {
    /// The Push ID could not be written.
    #[snafu(display("could not write push ID"))]
    PushId {
        /// The failure of writing the integer.
        source: WriteVarIntError<W>,
    },
    /// The field section could not be written.
    #[snafu(display("could not write PUSH_PROMISE field section"))]
    Section {
        /// The section's failure.
        source: P,
    },
}
