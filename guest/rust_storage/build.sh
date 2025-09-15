#!/usr/bin/env bash
set -e
pushd storage_program
./build.sh
popd
storage_binary=./storage_program/target/release/demo
objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* $storage_binary storage.syms
gcc-12 -static -O2 symbol_offset.c -o symbol_offset
./symbol_offset storage.syms 0x44000000

rm -rf target/
RUSTFLAGS="-Zexport-executable-symbols -C link_arg=-Wl,--undefined=do_calculation,--just-symbols=$PWD/storage.syms" cargo build --release
