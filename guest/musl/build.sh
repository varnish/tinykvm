musl-gcc -static -O2 -g musl.c -o musl
musl-gcc -static -O2 -g simple.c -o simple
gcc -static -O2 -g musl.c -o glibc
