# Transaction activity proof

`transactionActivityProof.json` contains a SHA-256 MMR proof generated from
Exoware branch `update-commonware-v2026.10.0` with Commonware revision
`7c2cf9a8cf81164b2d1da7e18030910fdcea4301`. The log contains five fixed keyless
append operations whose 32-byte values are filled with `0x01` through `0x05`.
The proof covers locations 1 and 3 at tip 4. `proof` is the hexadecimal protobuf
`HistoricalMultiProof`; `operations` gives the expected digest at each location.
The root uses Commonware's domain-separated Merkle root semantics.

To regenerate, create a temporary `qmdb/rs/wasm/examples/generate_digest_fixture.rs`
in that Exoware checkout and run
`cargo run -p exoware-qmdb-wasm --example generate_digest_fixture`.
The generator imports `../src/proto.rs`, encodes the five native keyless
`Operation::Append` values using `FixedEncoding<Digest>`, and adds them to
`merkle::mem::Mem<mmr::Family, Digest>` with `qmdb::hasher::<Sha256>()`.
It calls `batch.merkleize(&merkle, &hasher)`, applies the batch, obtains
`merkle.root(&hasher, 0)`, and calls `merkle::verification::multi_proof` at
locations 1 and 3. Serialize the proof, encoded operations, and root into
Exoware's `HistoricalMultiProof`, then replace the fixture's root and proof
with their hex encodings. The expected digests are the 32-byte append values;
the encoded operations also contain a tag and padding. Remove the temporary
example afterward.
