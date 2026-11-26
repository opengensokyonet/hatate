//! Containers that collect a raw literal from a chunked source and write it
//! back, in memory as a [`Buf`] or to a stream with `nitori_codec`.

use bytes::{Buf, Bytes, BytesMut};
use nitori_call::AsAccess;
use nitori_codec::{EncodeInto, EncodedLen};
use nitori_io::{
    Combine, Write,
    calls::{WriteAllError, WriteAllExt as _},
};

/// Octets collected from [`Bytes`] chunks without copying the first one.
///
/// A literal that arrives in a single chunk keeps sharing that chunk's
/// storage; from the second nonempty chunk on, the chunks are copied into
/// one contiguous buffer. Equality compares the octets.
#[derive(Clone, Debug, Default)]
pub struct JoinedBytes(Joined);

#[derive(Clone, Debug)]
enum Joined {
    Shared(Bytes),
    Copied(BytesMut),
}

impl Default for Joined {
    fn default() -> Self {
        Self::Shared(Bytes::new())
    }
}

impl JoinedBytes {
    /// The octets as `Bytes`, still shared if they arrived in one chunk.
    pub fn into_bytes(self) -> Bytes {
        match self.0 {
            Joined::Shared(bytes) => bytes,
            Joined::Copied(bytes) => bytes.freeze(),
        }
    }
}

impl Extend<Bytes> for JoinedBytes {
    fn extend<I: IntoIterator<Item = Bytes>>(&mut self, chunks: I) {
        for chunk in chunks {
            if chunk.is_empty() {
                continue;
            }
            match &mut self.0 {
                Joined::Shared(first) if first.is_empty() => *first = chunk,
                Joined::Shared(first) => {
                    let mut joined = BytesMut::with_capacity(first.len() + chunk.len());
                    joined.extend_from_slice(first);
                    joined.extend_from_slice(&chunk);
                    self.0 = Joined::Copied(joined);
                }
                Joined::Copied(joined) => joined.extend_from_slice(&chunk),
            }
        }
    }
}

impl AsRef<[u8]> for JoinedBytes {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            Joined::Shared(bytes) => bytes,
            Joined::Copied(bytes) => bytes,
        }
    }
}

impl PartialEq for JoinedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for JoinedBytes {}

impl Buf for JoinedBytes {
    fn remaining(&self) -> usize {
        self.as_ref().len()
    }

    fn chunk(&self) -> &[u8] {
        self.as_ref()
    }

    fn advance(&mut self, count: usize) {
        match &mut self.0 {
            Joined::Shared(bytes) => bytes.advance(count),
            Joined::Copied(bytes) => bytes.advance(count),
        }
    }
}

impl EncodedLen for JoinedBytes {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(self.remaining() as u64)
    }
}

/// Writes the octets whole and returns the merged report.
impl<S> EncodeInto<S> for JoinedBytes
where
    S: AsAccess<Family: Write<Report: Combine>>,
{
    type Output = <S::Family as Write>::Report;
    type Error = WriteAllError<<S::Family as Write>::Error>;
    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        sink.access().write_all(self).await
    }
}

/// Octets copied from borrowed chunks into one contiguous buffer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CopiedBytes(BytesMut);

impl CopiedBytes {
    /// The octets as `Bytes`.
    pub fn into_bytes(self) -> Bytes {
        self.0.freeze()
    }
}

impl<'a> Extend<&'a [u8]> for CopiedBytes {
    fn extend<I: IntoIterator<Item = &'a [u8]>>(&mut self, chunks: I) {
        for chunk in chunks {
            self.0.extend_from_slice(chunk);
        }
    }
}

impl AsRef<[u8]> for CopiedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Buf for CopiedBytes {
    fn remaining(&self) -> usize {
        self.0.len()
    }

    fn chunk(&self) -> &[u8] {
        &self.0
    }

    fn advance(&mut self, count: usize) {
        self.0.advance(count);
    }
}

impl EncodedLen for CopiedBytes {
    type LengthError = !;
    async fn encoded_len(&mut self) -> Result<u64, !> {
        Ok(self.remaining() as u64)
    }
}

/// Writes the octets whole and returns the merged report.
impl<S> EncodeInto<S> for CopiedBytes
where
    S: AsAccess<Family: Write<Report: Combine>>,
{
    type Output = <S::Family as Write>::Report;
    type Error = WriteAllError<<S::Family as Write>::Error>;
    async fn encode_into(self, mut sink: S) -> Result<Self::Output, Self::Error> {
        sink.access().write_all(self).await
    }
}
