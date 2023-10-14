musl-gcc -static -O2 -ggdb3 musl.c -o musl
musl-gcc -static -O2 -ggdb3 simple.c -o simple
gcc -static -O2 -ggdb3 musl.c -o glibc
