NIM_LIBS=`whereis nim`
NIM_LIBS="${NIM_LIBS##*: }"
NIM_LIBS="${NIM_LIBS/bin*/lib}"
echo ">>> Nim libs: $NIM_LIBS"

WARN="-Wno-discarded-qualifiers"

set -ev
rm -rf $PWD/storage_nimcache
rm -rf $PWD/main_nimcache

nim c --nimcache:$PWD/storage_nimcache --colors:on --os:linux --mm:arc --noMain --app:lib -d:release -c storage.nim
gcc-12 -static -O2 -Wl,-Ttext-segment=0x44000000 $WARN -I$NIM_LIBS main.c storage_nimcache/*.c -o storage

objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* storage storage.syms

nim c --nimcache:$PWD/main_nimcache --colors:on --os:linux --mm:arc --noMain --app:lib -d:release -c main.nim
gcc-12 -static -O2 -Wl,--just-symbols=storage.syms $WARN -I$NIM_LIBS main.c main_nimcache/*.c -o main
