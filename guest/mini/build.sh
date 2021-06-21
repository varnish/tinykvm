nasm -f elf64 mini.asm -o mini.o
gcc -static -Wall -nostartfiles mini.o -o mini
