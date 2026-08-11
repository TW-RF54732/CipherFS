# Vendored WinFsp binding provenance

CipherFS patches `winfsp-sys` to `vendor/winfsp-sys` so source builds reuse the
crate's checked-in generated bindings instead of requiring libclang/bindgen.
Delay-load linking is enabled separately by the repository root `build.rs`, so
non-mount commands start without the WinFsp runtime installed.

- Crate: `winfsp-sys 0.12.1+winfsp-2.1`
- crates.io archive SHA-256:
  `D42ACC30C105F8D33507F556398237C738B681271C775A3B94EEFD29D2B8C77E`
- Binding project: <https://github.com/SnowflakePowered/winfsp-rs>
- WinFsp runtime/API version: 2.1
- Upstream WinFsp: <https://github.com/winfsp/winfsp/releases/tag/v2.1>
- Local modification: `build.rs` copies `src/bindings.rs` instead of invoking
  bindgen; unused bindgen build dependencies are removed. Generated bindings,
  headers and import libraries are otherwise retained from the crate archive.
- `Cargo.toml.orig` SHA-256:
  `D65D1FBED1C2CABA9601373C472720D4ACE92DC9A7ADA60E6C0F9C6590B7CCDA`
- `src/bindings.rs` SHA-256:
  `0424D1FF68349A2189C223F29D05CCF7E9B905A84E0AED984071D04549A76108`
- x64 import library SHA-256:
  `41EE9DB17DA0196AED067605CAA719443142F74C0FA8E7800D2ACB3FABF78354`

Before changing this directory, compare it with the matching crates.io source,
record the upstream archive SHA-256 in the pull request, run `cargo deny check`,
and repeat the Windows missing-runtime and installed-runtime tests.
