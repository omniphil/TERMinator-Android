#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#define STBUF_FLAG_DYNAMIC (1U << 0)
struct stbuf {
	size_t sz;
	size_t len;
	uint32_t flags;
	char buf[];
};

int main(int argc, char** argv)
{
	struct stbuf buf = (struct stbuf)(char[offsetof(struct stbuf, buf) + 10]);

	printf("Size: %zu\n", sizeof(buf));
}
