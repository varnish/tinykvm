musl-gcc -static -O2 test.c -o musl_test
gcc -static -O2 test.c -o glibc_test
#g++ -static -O2 cxx_test.cpp -o cxx_test
