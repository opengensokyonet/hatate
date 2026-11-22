# hatate

hatate implements HTTP/3 for Open Gensokyo Network. The [QPACK package](crates/hatate_qpack) reads and writes single field line representations from an in-memory payload. It supports the RFC 9204 static table and the RFC 7541 Huffman code. Dynamic references retain their wire index for a field section decoder to resolve. The `integer` and `huffman` modules expose the same codecs for use outside a field line.

For a connection with zero maximum dynamic table capacity, `static_section` also reads and writes complete field section payloads. Its iterator resolves static references and checks both per-literal and aggregate decoded size limits. Its writer preserves the caller’s representations and checks the whole section before writing.

A raw literal borrows or shares its input storage. Huffman literals return decoded bytes. The caller supplies the maximum decoded size of each literal in octets. The package works with `no_std` and an allocator.

On an encoder stream, `encoder_instruction::Reader` identifies an instruction and lends out successive literal sources. A raw literal can be consumed in the host's own chunks. A Huffman literal decodes incrementally into a caller-selected buffer. Finishing the value validates the end of an insertion and allows the next instruction to start. The three decoder-stream instructions use the `read_decoder_instruction` and `write_decoder_instruction` calls.

## Development

Run the following commands from the repository root with rustup. The toolchain file selects the compiler and the bare-metal target.

```sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-targets
cargo test --locked --workspace --all-targets --all-features
cargo test --locked --workspace --doc
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
cargo build --locked -p hatate_qpack --target x86_64-unknown-none
```

## Fuzzing

The separate [verification/qpack-fuzz](verification/qpack-fuzz) workspace exercises the public QPACK APIs with cargo-fuzz and libFuzzer. The `integer` target compares decoding and byte consumption with a 128-bit reference calculation. The `huffman` target checks accepted wire encodings, segmented input and output bounds. The `field_line` target reads arbitrary wire sequences and constructs valid field lines to exercise the writer. The `static_section` target compares complete field sections against single-line decoding and independent size accounting. The `decoder_instruction` target checks decoder-stream dispatch, cursor movement, and wire limits. The `encoder_instruction` target compares staged literal reads with in-memory decoding under independent wire and decoded limits. The regular test suite also exhausts one- and two-octet Huffman payloads against an independent canonical-code decoder.

Cargo generates the verification workspace’s lockfile locally. With cargo-fuzz installed, run from the repository root. Use a writable corpus directory first so the checked-in seeds remain available for repeat runs.

```sh
fuzz_dir=verification/qpack-fuzz
for target in integer huffman field_line static_section decoder_instruction encoder_instruction; do
    mkdir -p "$fuzz_dir/corpus/$target"
    cargo fuzz run --fuzz-dir "$fuzz_dir" "$target" "$fuzz_dir/corpus/$target" "$fuzz_dir/seeds/$target" -- -max_total_time=60
done
```

To replay a saved input, pass its file path after the target, for example `cargo fuzz run --fuzz-dir verification/qpack-fuzz huffman verification/qpack-fuzz/seeds/huffman/rfc-host`.

## License

The software and code examples are available under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT). The QPACK static table and Huffman code table carry the IETF notices for [RFC 9204](crates/hatate_qpack/LICENSE-RFC9204) and [RFC 7541](crates/hatate_qpack/LICENSE-RFC7541). Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY).
