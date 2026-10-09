---
name: "release"
description: "Cut a release: checks, version bump, tag."
when_to_use: "When the user asks to release or tag a version."
user-invocable: true
disable-model-invocation: true
allowed-tools:
  - "Bash(cargo test *)"
  - "Bash(git tag *)"
arguments:
  - "version"
---

Release version $version:

1. Run the tests.
2. Tag `v$version`.
