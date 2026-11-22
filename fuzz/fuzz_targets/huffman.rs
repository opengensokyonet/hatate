//! Exercise arbitrary codewords and octets, canonical padding, and bounds.
#![no_main]
use bytes::Buf;
use hatate_qpack::huffman::{self, DecodeError};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&control, payload)) = data.split_first() else {
        return;
    };
    let split = usize::from(control).min(payload.len());
    let segmented = (&payload[..split]).chain(&payload[split..]);
    let decoded = huffman::decode(payload, usize::MAX);
    assert_eq!(huffman::decode(segmented, usize::MAX), decoded);
    if let Ok(plain) = decoded {
        let mut canonical = Vec::new();
        huffman::encode(&mut canonical, &plain).unwrap();
        assert_eq!(canonical, payload);
        if plain.len() > usize::from(control) {
            assert_eq!(
                huffman::decode(payload, usize::from(control)),
                Err(DecodeError::OutputTooLong {
                    limit: usize::from(control)
                })
            );
        }
    }

    let mut encoded = Vec::new();
    huffman::encode(&mut encoded, payload).unwrap();
    assert_eq!(
        huffman::decode(&encoded[..], payload.len())
            .unwrap()
            .as_ref(),
        payload
    );
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
});
