set -v
#clang++-20 -static -O2 -std=c++20 -Wl,-Ttext-segment=0x44000000 storage.cpp -o storage
#
#objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=!_Z*remote* --strip-symbol=* storage storage.syms
#clang++-20 -static -O2 -std=c++20 -Wl,--just-symbols=storage.syms main.cpp -o main

mkdir -p .build
pushd .build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j8
popd

ln -fs .build/main main
ln -fs .build/storage storage
