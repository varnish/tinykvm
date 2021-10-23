nasm -f bin -o interrupts interrupts.asm
xxd -i interrupts > kernel_assembly.h
