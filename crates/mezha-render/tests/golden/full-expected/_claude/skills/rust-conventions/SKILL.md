---
name: "rust-conventions"
description: "Error handling and test conventions for this Rust workspace. Use when writing or reviewing Rust code."
user-invocable: false
disable-model-invocation: false
paths:
  - "**/*.rs"
  - "Cargo.toml"
---

Use `thiserror` for library errors and `anyhow` in binaries.

---

Tests live next to the code they test.
