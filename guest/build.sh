#!/usr/bin/env bash
WARN="-Wall -Wextra"
CUSTOM="-static -ffreestanding -nostdlib -fno-exceptions -fno-rtti"
COMMON="-O2 -ggdb3 -march=native -fno-omit-frame-pointer $CUSTOM"
FILES="src/guest.cpp src/crc32c.cpp src/start.cpp"
SYMS="-Wl,--defsym=syscall_entry=0x2000"

g++ $WARN $COMMON -Ttext=201000 $SYMS $FILES -o guest.elf
