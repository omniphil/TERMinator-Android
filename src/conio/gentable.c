#include <inttypes.h>
#include <stdio.h>

struct YCoCg_data {
	unsigned Y;
	signed Co;
	signed Cg;
};

static void
RGB_to_YCoCg(const uint32_t RGB, struct YCoCg_data *YCoCg)
{
	signed R, G, B, tmp;

	R = (RGB >> 16) & 0xFF;
	G = (RGB >> 8) & 0xFF;
	B = (RGB) & 0xFF;

	YCoCg->Co = R - B;
	tmp = B + (YCoCg->Co >> 1);
	YCoCg->Cg = G - tmp;
	YCoCg->Y = tmp + (YCoCg->Cg >> 1);
}

uint32_t c[] = {
	UINT32_C(0),
	UINT32_C(0x0000A8),
	UINT32_C(0x00A800),
	UINT32_C(0x00A8A8),
	UINT32_C(0xA80000),
	UINT32_C(0xA800A8),
	UINT32_C(0xA85400),
	UINT32_C(0xA8A8A8),
	UINT32_C(0x545454),
	UINT32_C(0x5454FF),
	UINT32_C(0x54FF54),
	UINT32_C(0x54FFFF),
	UINT32_C(0xFF5454),
	UINT32_C(0xFF54FF),
	UINT32_C(0xFFFF54),
	UINT32_C(0xFFFFFF),
};

int main(int argc, char **argv)
{
	for (int i = 0; i < 16; i++) {
		struct YCoCg_data ycc;
		RGB_to_YCoCg(c[i], &ycc);
		printf("	{%u, %d, %d}\n", ycc.Y, ycc.Co, ycc.Cg);
	}
	return 0;
}
