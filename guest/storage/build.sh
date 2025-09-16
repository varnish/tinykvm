set -v
clang++-20 -static -O2 -std=c++20 -Wl,-Ttext-segment=0x44000000 storage.cpp -o storage

objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* storage storage.syms
clang++-20 -static -O2 -std=c++20 -Wl,--just-symbols=storage.syms main.cpp -o main
