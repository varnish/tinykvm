#include <stdio.h>

__attribute__((noinline))
static void takes_float(float f)
{
    printf("Float has value: %f\n", f);
}

int main()
{
    takes_float(111.0f);
}
