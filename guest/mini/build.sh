nasm -f elf64 mini.asm -o mini.o
gcc -static -Wall -nostartfiles -Ttext=0x200000 -Wl,-utest mini.o -o mini
