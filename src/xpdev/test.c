#include <stdbool.h>
#include <stdio.h>

int main(int argc, char **argv)
{
	bool x = false;
	char y = 0xff;

	*(char *)&x = 0xff;
	printf("Hello, world %d!\n", x);
	printf("Is it true? %s\n", x == true ? "Yes!" : "No!");
	printf("Hello, world %d!\n", (bool)y);
	printf("Is it true? %s\n", ((bool)y) == true ? "Yes!" : "No!");
}
