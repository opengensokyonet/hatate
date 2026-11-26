//! Exercise arbitrary codewords and octets, canonical padding, and bounds.
#![no_main]
use bytes::{Buf, BytesMut};
use hatate_qpack::huffman::{self, DecodeError};
use libfuzzer_sys::fuzz_target;

fn decode(src: impl Buf, limit: usize) -> Result<Vec<u8>, DecodeError> {
    huffman::decode(src, limit)
}

fuzz_target!(|data: &[u8]| {
    let Some((&control, payload)) = data.split_first() else {
        return;
    };
    let split = usize::from(control).min(payload.len());
    let segmented = (&payload[..split]).chain(&payload[split..]);
    let decoded = decode(payload, usize::MAX);
    assert_eq!(decode(segmented, usize::MAX), decoded);
    let into_bytes_mut = huffman::decode::<BytesMut>(payload, usize::MAX);
    assert_eq!(into_bytes_mut.as_deref().ok(), decoded.as_deref().ok());
    if let Ok(plain) = decoded {
        // The encoding of the decoded octets is unique: re-encoding gives
        // back the original payload.
        let mut canonical = Vec::new();
        huffman::encode(&mut canonical, &plain[..]).unwrap();
        assert_eq!(canonical, payload);
        if plain.len() > usize::from(control) {
            assert_eq!(
                decode(payload, usize::from(control)),
                Err(DecodeError::OutputTooLong {
                    limit: usize::from(control)
                })
            );
        }
    }

    let mut encoded = Vec::new();
    huffman::encode(&mut encoded, payload).unwrap();
    assert_eq!(decode(&encoded[..], payload.len()).unwrap(), payload);
    let mut from_segments = Vec::new();
    huffman::encode(
        &mut from_segments,
        (&payload[..split]).chain(&payload[split..]),
    )
    .unwrap();
    assert_eq!(from_segments, encoded);
    if !encoded.is_empty() {
        let capacity = usize::from(control) % encoded.len();
        let mut storage = vec![0x5a; capacity];
        let mut dst = storage.as_mut_slice();
        let error = huffman::encode(&mut dst, payload).unwrap_err();
        assert_eq!(error.required(), encoded.len() as u128);
        assert_eq!(error.available(), capacity);
        assert_eq!(dst.len(), capacity);
        assert!(storage.iter().all(|&byte| byte == 0x5a));
    }
    // An exact destination below the 30-bit bound takes the measured path.
    let mut exact = vec![0; encoded.len()];
    huffman::encode(&mut exact.as_mut_slice(), payload).unwrap();
    assert_eq!(exact, encoded);
});
