#!/usr/bin/env bash
set -e
RUSTFLAGS="-Ctarget-feature=+crt-static -Zexport-executable-symbols" cargo build --release
#RUSTFLAGS="-Zexport-executable-symbols" cargo build --target x86_64-unknown-linux-musl --release
