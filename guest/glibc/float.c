#include <stdio.h>

__attribute__((noinline))
static void call_other_function()
{
}

__attribute__((noinline))
static void takes_float(float f)
{
    call_other_function();
    printf("Float has value: %f\n", f);
}

int main()
{
    takes_float(111.0f);
}
