<!-- License and provenance notices for the packaged cargo-vet helper and curated audit data. -->
# Third-party notices

## cargo-vet

Supply Chain Guard packages `cargo-vet` 0.10.2 from:

- repository: <https://github.com/mozilla/cargo-vet>
- source commit: `e496a28a2cde71db0d98ef631cf4586f89a7fed6`
- crates.io package checksum: `dd93790018205cbbfa161f078ca4631afa8ed57fc8f32482268bcfdf0c0d7499`
- licenses: MIT or Apache-2.0

The complete corresponding source is the pinned Git submodule under `third-party/cargo-vet`. Its license texts are `third-party/cargo-vet/LICENSE-MIT` and `third-party/cargo-vet/LICENSE-APACHE`.

## Curated audit data

The default live imports and embedded recovery records are filtered from public cargo-vet audit repositories maintained by Google, Mozilla, Bytecode Alliance, Zcash, and ISRG. Runtime source URLs are shown by `cargo supply-chain-guard cargo-vet sources`. Embedded source repositories, immutable commits, source digests, and retained counts are recorded in [curation/sources.toml](curation/sources.toml) and [curation/generated/provenance.toml](curation/generated/provenance.toml). Individual records retain their original `who`, notes, and `aggregated-from` attribution fields.

Audit records express reviewer conclusions and are provided without a guarantee from Supply Chain Guard or cargo-vet.
