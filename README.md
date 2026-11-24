# hatate

hatate implements HTTP/3 for Open Gensokyo Network. The [QPACK package](crates/hatate_qpack) reads and writes single field line representations from an in-memory payload. It supports the RFC 9204 static table and the RFC 7541 Huffman code. Dynamic references retain their wire index for a field section decoder to resolve. The `integer` and `huffman` modules expose the same codecs for use outside a field line.

For a connection with zero maximum dynamic table capacity, `static_section` also reads and writes complete field section payloads. Its iterator resolves static references and checks both per-literal and aggregate decoded size limits. Its writer preserves the caller’s representations and checks the whole section before writing.

A raw literal borrows or shares its input storage. Huffman literals return decoded bytes. The caller supplies the maximum decoded size of each literal in octets. The packages work with `no_std` and an allocator.

On an encoder stream, `encoder_instruction::EncoderStream` identifies each instruction and lends out successive literal sources; it reads nothing until asked, gives `None` where the stream ends at an instruction boundary, and is abandoned once an instruction is left unfinished. A raw literal can be consumed in the host's own chunks. A Huffman literal decodes incrementally into a caller-selected buffer. Finishing the value validates the end of an insertion and allows the next instruction to start. The writer accepts the name before the value source is available. Use `write::Payload::Raw` for uncompressed bytes and `write::Payload::Huffman` for already encoded bytes. Each source supplies its remaining wire length through `ExactLen`. The writer checks the Huffman codes, padding and shared decoded-size limit as it transfers the bytes. Retain the same writer between instructions and abandon a stream left inside an unfinished insertion. The three decoder-stream instructions are read whole from a `decoder_instruction::DecoderStream` and written with the `write_decoder_instruction` call.

[`hatate_wire`](crates/hatate_wire) reads and writes HTTP/3 frames, settings and unidirectional stream types on a byte stream. Each of these registries is extended by parts: `hatate_wire::Part` holds RFC 9114 together with the registrations of QPACK, which live in [`hatate_wire_qpack`](crates/hatate_wire_qpack), and [`hatate_wire_datagram`](crates/hatate_wire_datagram) and [`hatate_wire_extended_connect`](crates/hatate_wire_extended_connect) are the parts of HTTP Datagrams (RFC 9297) and Extended CONNECT (RFC 9220). A connection lists the parts it uses, such as `HList![hatate_wire::Part, hatate_wire_datagram::Part]`. A frame type, setting or stream type that no listed part claims is returned as unknown for the caller to ignore. The parts' claims are checked at compile time to be disjoint and not reserved.

A stream the peer opens is told apart at its start. `read_unidirectional_stream` reads the type of a unidirectional stream and `read_bidirectional_stream` the first frame type of a bidirectional one, after any reserved frames; each part of the list gives its verdict for the class of the stream, and the part that claims the value reads the stream up to where it can be used. The RFC 9114 part gives a control or push stream at its first frame, a push stream with its Push ID, the QPACK encoder and decoder streams of `hatate_wire_qpack`, and a request stream at its first frame. A stream no part claims comes back to be discarded. A stream that carries frames is a `FrameStream` of its kind, which holds the stream and its current frame: `frame` gives the frame, whose payload is the stream composed with a `FramePayload`, and `next_frame` skips what is left of the payload and reads the next frame, checked against the frame types the list has on that kind of stream and the role of this endpoint. A reserved or unknown frame type is skipped. A stream whose next frame head was not read whole is abandoned. Control, QPACK encoder and decoder streams are critical: their end is an error. `write_frame` writes a frame whose payload comes from a source; a frame read from a stream is written back as it was read. SETTINGS are read one at a time into a `Settings`, which holds one slot for each setting type of the listed parts; a repeated identifier of such a type is an error, and a setting that no type claims is returned without being kept. Every variable-length integer keeps the width it was read with, so writing a frame that was read gives back its bytes. `hatate_wire_datagram` also reads and writes the HTTP/3 datagram format in memory.

## Development

Run the following commands from the repository root with rustup. The toolchain file selects the compiler and the bare-metal target.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo build --locked -p hatate_qpack -p hatate_wire -p hatate_wire_qpack -p hatate_wire_datagram -p hatate_wire_extended_connect --target x86_64-unknown-none
for package in hatate_qpack hatate_wire hatate_wire_qpack hatate_wire_datagram hatate_wire_extended_connect; do cargo clippy --locked -p "$package" --no-default-features --target x86_64-unknown-none -- -D warnings; done
```

## Fuzzing

The separate [verification/qpack-fuzz](verification/qpack-fuzz) workspace exercises the public QPACK APIs with cargo-fuzz and libFuzzer. The `integer` target compares decoding and byte consumption with a 128-bit reference calculation. The `huffman` target checks accepted wire encodings, segmented input and output bounds. The `field_line` target reads arbitrary wire sequences and constructs valid field lines to exercise the writer. The `static_section` target compares complete field sections against single-line decoding and independent size accounting. The `decoder_instruction` target checks decoder-stream dispatch, cursor movement, and wire limits. The `encoder_instruction` target compares staged reads and writes with in-memory decoding and independently framed payloads under wire and decoded limits. The `wire_frames` target walks a `FrameStream` of a request, control or push stream over segmented input and checks that every frame it reads completely is written back to the same bytes, including DATA, HEADERS, unknown frames, SETTINGS and PUSH_PROMISE. The `wire_received_frames` target walks the same streams with `next_frame` or `next_known_frame`, on a host that skips and on one that only reads, and checks the frames, the failure and its code against an independent reading of the stream, and that every frame written back whole with `write_frame` gives its original bytes. The `wire_streams` target reads the start of unidirectional and bidirectional streams with the two constructors from segmented input, and HTTP/3 datagrams, and checks both against an independent decoding of the first integer (and of the reserved frames and the first frame head after it) and against their written-back bytes. The regular test suite also exhausts one- and two-octet Huffman payloads against an independent canonical-code decoder.

Cargo generates the verification workspace’s lockfile locally. With cargo-fuzz installed, run from the repository root. Use a writable corpus directory first so the checked-in seeds remain available for repeat runs.

```sh
fuzz_dir=verification/qpack-fuzz
for target in integer huffman field_line static_section decoder_instruction encoder_instruction wire_frames wire_received_frames wire_streams; do
    mkdir -p "$fuzz_dir/corpus/$target"
    cargo fuzz run --fuzz-dir "$fuzz_dir" "$target" "$fuzz_dir/corpus/$target" "$fuzz_dir/seeds/$target" -- -max_total_time=60
done
```

To replay a saved input, pass its file path after the target, for example `cargo fuzz run --fuzz-dir verification/qpack-fuzz huffman verification/qpack-fuzz/seeds/huffman/rfc-host`.

## License

The software and code examples are available under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT). The QPACK static table and Huffman code table carry the IETF notices for [RFC 9204](crates/hatate_qpack/LICENSE-RFC9204) and [RFC 7541](crates/hatate_qpack/LICENSE-RFC7541). Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY).
