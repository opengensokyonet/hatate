# hatate

hatate implements HTTP/3 for Open Gensokyo Network. The [QPACK package](crates/hatate_qpack) reads and writes single field line representations from an in-memory payload. It supports the RFC 9204 static table and the RFC 7541 Huffman code. Dynamic references retain their wire index for a field section decoder to resolve.

A raw literal borrows or shares its input storage. Huffman literals return decoded bytes. The caller supplies the maximum decoded size of each literal in octets. The package works with `no_std` and an allocator.

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

## License

The software and code examples are available under either [Apache-2.0](LICENSE-APACHE) or [MIT](LICENSE-MIT). The QPACK static table and Huffman code table carry the IETF notices for [RFC 9204](crates/hatate_qpack/LICENSE-RFC9204) and [RFC 7541](crates/hatate_qpack/LICENSE-RFC7541). Explanatory documentation is licensed under [CC BY 4.0](LICENSE-CC-BY).
