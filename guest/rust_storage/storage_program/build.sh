#!/usr/bin/env bash
set -e
RUSTFLAGS="-Zexport-executable-symbols" cargo build --target x86_64-unknown-linux-musl --release
