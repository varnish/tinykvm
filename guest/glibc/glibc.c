#include <malloc.h>
#include <stdio.h>
#include <string.h>

int main()
{
	char* test = (char *)malloc(14);
	strcpy(test, "Hello World!\n");
	printf("%.*s", 13, test);

	return 0;
}
