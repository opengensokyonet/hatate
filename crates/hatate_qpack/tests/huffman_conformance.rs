//! Independent canonical-code model of RFC 7541 Appendix B, using only
//! its symbol lengths. See LICENSE-RFC7541 for the table's license.
use hatate_qpack::huffman;

// In each width group the RFC assigns consecutive codes in symbol order.
const WIDTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

struct Codebook {
    first_code: [u32; 31],
    groups: [Vec<u16>; 31],
    code: [u32; 257],
}

impl Codebook {
    fn new() -> Self {
        let mut groups: [Vec<u16>; 31] = core::array::from_fn(|_| Vec::new());
        for (symbol, &width) in WIDTHS.iter().enumerate() {
            groups[usize::from(width)].push(symbol as u16);
        }
        let mut first_code = [0; 31];
        let mut code = [0; 257];
        let mut next = 0;
        for (width, symbols) in groups.iter().enumerate() {
            next <<= 1;
            first_code[width] = next;
            for &symbol in symbols {
                code[usize::from(symbol)] = next;
                next += 1;
            }
        }
        Self {
            first_code,
            groups,
            code,
        }
    }

    // Match the numeric interval for the current code length, rather than
    // following the production decoder's tree.
    fn decode(&self, wire: &[u8]) -> Option<Vec<u8>> {
        let mut plain = Vec::new();
        let mut bits = 0;
        let mut code = 0u32;
        for &octet in wire {
            for shift in (0..8).rev() {
                bits += 1;
                code = (code << 1) | u32::from((octet >> shift) & 1);
                let offset = code.checked_sub(self.first_code[bits])?;
                if let Some(&symbol) = self.groups[bits].get(offset as usize) {
                    plain.push(u8::try_from(symbol).ok()?);
                    bits = 0;
                    code = 0;
                }
            }
        }
        (bits <= 7 && code == (1 << bits) - 1).then_some(plain)
    }

    // Pack the RFC symbols from left to right into a bit stream. Accepting
    // the reserved EOS as a test input lets us exercise its rejection.
    fn wire(&self, symbols: impl IntoIterator<Item = u16>) -> Vec<u8> {
        let mut bits = Vec::new();
        for symbol in symbols {
            let at = usize::from(symbol);
            for shift in (0..WIDTHS[at]).rev() {
                bits.push((self.code[at] >> shift) as u8 & 1);
            }
        }
        bits.resize(bits.len().next_multiple_of(8), 1);
        bits.as_chunks::<8>()
            .0
            .iter()
            .map(|chunk| chunk.iter().fold(0, |byte, bit| byte * 2 + bit))
            .collect()
    }
}

#[test]
fn every_one_and_two_octet_payload_matches_the_canonical_codebook() {
    let book = Codebook::new();
    let check = |wire: &[u8]| {
        let expected = book.decode(wire);
        let decoded = huffman::decode::<Vec<u8>>(wire, usize::MAX);
        assert_eq!(decoded.ok().as_deref(), expected.as_deref(), "{wire:02x?}");
    };
    for byte in 0..=u8::MAX {
        check(&[byte]);
    }
    for word in 0..=u16::MAX {
        check(&word.to_be_bytes());
    }
}

#[test]
fn every_symbol_starts_at_every_bit_offset() {
    let book = Codebook::new();
    // '0' uses five bits, coprime to eight. Between zero and seven copies
    // place the next symbol at each bit offset exactly once.
    for count in 0..8 {
        for byte in 0..=u8::MAX {
            let mut plain = vec![b'0'; count];
            plain.push(byte);
            let expected = book.wire(plain.iter().copied().map(u16::from));
            let mut actual = Vec::new();
            huffman::encode(&mut actual, &plain[..]).unwrap();
            assert_eq!(actual, expected);
            assert_eq!(
                huffman::decode::<Vec<u8>>(&expected[..], plain.len()).unwrap(),
                plain
            );
        }
        let eos = book.wire(core::iter::repeat_n(u16::from(b'0'), count).chain([256]));
        assert_eq!(
            huffman::decode::<Vec<u8>>(eos.as_slice(), usize::MAX),
            Err(huffman::DecodeError::EndOfString)
        );
    }
}
