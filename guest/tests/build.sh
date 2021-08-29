musl-gcc -static -O0 -ggdb3 test.c -o musl_test
gcc -static -O0 -ggdb3 test.c -o glibc_test
#g++ -static -O2 cxx_test.cpp -o cxx_test
