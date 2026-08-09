<!-- SPDX-License-Identifier: Elastic-2.0 -->

# Third-party dependencies

The exact resolved graph is pinned by `rust/Cargo.lock`. Every Cargo package
below is sourced from the crates.io registry identified in the lockfile as
`registry+https://github.com/rust-lang/crates.io-index`.

| Package | Version | Relationship | Declared licence | Source |
|---|---:|---|---|---|
| `ahash` | 0.8.12 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `bitflags` | 2.13.1 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `cc` | 1.4.0 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `cfg-if` | 1.0.4 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `errno` | 0.3.14 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `fallible-iterator` | 0.3.0 | transitive | `MIT/Apache-2.0` | crates.io registry |
| `fallible-streaming-iterator` | 0.1.9 | transitive | `MIT/Apache-2.0` | crates.io registry |
| `fastrand` | 2.5.0 | transitive | `Apache-2.0 OR MIT` | crates.io registry |
| `find-msvc-tools` | 0.1.9 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `getrandom` | 0.3.4 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `hashbrown` | 0.14.5 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `hashlink` | 0.9.1 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `itoa` | 1.0.18 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `libc` | 0.2.189 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `libsqlite3-sys` | 0.30.1 | transitive | `MIT` | crates.io registry |
| `linux-raw-sys` | 0.12.1 | transitive | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | crates.io registry |
| `memchr` | 2.8.3 | transitive | `Unlicense OR MIT` | crates.io registry |
| `once_cell` | 1.21.4 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `pkg-config` | 0.3.33 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `proc-macro2` | 1.0.107 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `quote` | 1.0.47 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `r-efi` | 5.3.0 | transitive | `MIT OR Apache-2.0 OR LGPL-2.1-or-later` | crates.io registry |
| `rusqlite` | 0.32.1 | direct runtime, `bundled` | `MIT` | crates.io registry |
| `rustix` | 1.1.4 | transitive | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | crates.io registry |
| `serde` | 1.0.229 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `serde_core` | 1.0.229 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `serde_derive` | 1.0.229 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `serde_json` | 1.0.149 | direct runtime | `MIT OR Apache-2.0` | crates.io registry |
| `shlex` | 2.0.1 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `smallvec` | 1.15.2 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `syn` | 2.0.119 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `syn` | 3.0.3 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `tempfile` | 3.24.0 | direct development | `MIT OR Apache-2.0` | crates.io registry |
| `unicode-ident` | 1.0.24 | transitive | `(MIT OR Apache-2.0) AND Unicode-3.0` | crates.io registry |
| `vcpkg` | 0.2.15 | transitive | `MIT/Apache-2.0` | crates.io registry |
| `version_check` | 0.9.5 | transitive | `MIT/Apache-2.0` | crates.io registry |
| `wasip2` | 1.0.4+wasi-0.2.12 | transitive | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | crates.io registry |
| `windows-link` | 0.2.1 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `windows-sys` | 0.61.2 | transitive | `MIT OR Apache-2.0` | crates.io registry |
| `wit-bindgen` | 0.57.1 | transitive | `Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT` | crates.io registry |
| `zerocopy` | 0.8.54 | transitive | `BSD-2-Clause OR Apache-2.0 OR MIT` | crates.io registry |
| `zerocopy-derive` | 0.8.54 | transitive | `BSD-2-Clause OR Apache-2.0 OR MIT` | crates.io registry |
| `zmij` | 1.0.23 | transitive | `MIT` | crates.io registry |

The `bundled` feature compiles SQLite 3.46.0 from the amalgamation carried by
`libsqlite3-sys`; upstream SQLite dedicates that amalgamation to the public
domain. No Git, path, or unpinned registry dependency is present.
