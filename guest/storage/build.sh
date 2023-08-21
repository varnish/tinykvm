set -v
# C
gcc-12 -static -O2 -Wl,-Ttext-segment=0x44000000 storage.c -o storage

objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* storage storage.syms
gcc-12 -static -O2 -Wl,--just-symbols=storage.syms main.c -o main

# C++
$CXX -static -O2 -Wl,-Ttext-segment=0x44000000 storage.cpp -o cpp_storage

objcopy -w --extract-symbol --strip-symbol=!*remote* --strip-symbol=* cpp_storage cpp_storage.syms
$CXX -static -O2 -Wl,--just-symbols=cpp_storage.syms main.cpp -o cpp_main
