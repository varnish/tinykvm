#!/usr/bin/env bash
set -e
gcc-12 -static -O2 -Wl,-Ttext-segment=0x44000000 storage.c -o storage
objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* storage storage.syms

RUSTFLAGS="-C target-feature=+crt-static -Zexport-executable-symbols -C link_arg=-Wl,--just-symbols=storage.syms" cargo build --target x86_64-unknown-linux-gnu --release
