//! Reading the type of a unidirectional stream.
use super::{StreamType, StreamTypeHead, StreamTypeSet};
use core::marker::PhantomData;
use nitori_call::{ReceiverAccess, call};
use nitori_io::Read;
use sakuya_var_int::{
    VarInt,
    call::{ReadVarIntError, ReadVarIntFieldExt as _},
};

/// Reads the type at the start of a unidirectional stream and looks it up
/// in the list of parts `S`, which `parts` names.
///
/// Returns `None` if the stream ends before the first byte; a receiver
/// tolerates a stream closed before its type ([RFC 9114 §6.2]).
///
/// # Errors
///
/// The failure of reading the integer, including a stream that ends inside
/// it, which a receiver also tolerates.
///
/// [RFC 9114 §6.2]: https://www.rfc-editor.org/rfc/rfc9114.html#section-6.2
#[call(sync)]
pub async fn read_stream_type<S: StreamTypeSet, F: Read, A: ReceiverAccess<Family = F>>(
    io: &mut A,
    parts: PhantomData<S>,
) -> Result<Option<StreamTypeHead<S::TypeValue>>, ReadVarIntError<F::Error>> {
    let _ = parts;
    let field = match io.read_var_int_field::<VarInt>().await {
        Ok(field) => field,
        Err(error) if error.is_incomplete() && error.completed() == 0 => return Ok(None),
        Err(error) => return Err(error),
    };
    let value = field.get();
    let stream_type = S::type_value_of(value).map_or(StreamType::Unknown(value), StreamType::Known);
    Ok(Some(StreamTypeHead { stream_type, field }))
}
