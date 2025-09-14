#!/usr/bin/env bash
set -e
pushd storage_program
./build.sh
popd
storage_binary=./storage_program/target/x86_64-unknown-linux-musl/release/demo
objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* $storage_binary storage.syms
gcc-12 -static -O2 symbol_offset.c -o symbol_offset
./symbol_offset storage.syms 0x44000000

RUSTFLAGS="-Ctarget-feature=+crt-static -Zexport-executable-symbols -C link_arg=-Wl,--just-symbols=storage.syms" cargo build --target x86_64-unknown-linux-gnu --release
