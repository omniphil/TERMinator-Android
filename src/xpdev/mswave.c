#include <inttypes.h>

struct hacky_wave_header {
	uint8_t riff[4];
	uint32_t csize;
	uint8_t wave[4];
	uint8_t fmt[4];
	uint32_t scsz;
	uint16_t afmt;
	uint16_t nchan;
	uint32_t srate;
	uint32_t brate;
	uint16_t balign;
	uint16_t bps;
	uint8_t data[4];
	uint32_t sc2sz;
};

void *
convert_wavefile(const char *path, size_t *sz)
{
	struct hacky_wave_header hdr;
	FILE *wf = NULL;
	void *ret = NULL;
	unsigned i, j;

	wf = fopen(path, "rb");
	if (wf == NULL)
		goto fail;
	if (fread(&hdr, sizeof(hdr), 1, wf) != 1)
		goto fail;
	if (hdr->riff[0] != 'R')
		goto fail;
	if (hdr->riff[1] != 'I')
		goto fail;
	if (hdr->riff[2] != 'F')
		goto fail;
	if (hdr->riff[3] != 'F')
		goto fail;
	if (hdr->csize < 44)
		goto fail;
	if (hdr->wave[0] != 'W')
		goto fail;
	if (hdr->wave[1] != 'A')
		goto fail;
	if (hdr->wave[2] != 'V')
		goto fail;
	if (hdr->wave[3] != 'E')
		goto fail;
	if (hdr->fmt[0] != 'f')
		goto fail;
	if (hdr->fmt[1] != 'm')
		goto fail;
	if (hdr->fmt[2] != 't')
		goto fail;
	if (hdr->fmt[3] != ' ')
		goto fail;
	if (hdr->scsz != 16)
		goto fail;
	if (hdr->afmt != 1)
		goto fail;
	if (hdr->nchan > 2 || hdr->nchan == 0)
		goto fail;
	// TODO: Other conversions (only downsample for now)
	if (hdr->srate % 22050)
		goto fail;
	if (hdr->brate != (hdr->srate * hdr->nchan * hdr->bps / 8))
		goto fail;
	if (hdr->balign != (hdr->nchan * hdr->bps / 8))
		goto fail;
	if (hdr->bps != 8 && hdr->bps != 16)
		goto fail;
	if (hdr->data[0] != 'd')
		goto fail;
	if (hdr->data[1] != 'a')
		goto fail;
	if (hdr->data[2] != 't')
		goto fail;
	if (hdr->data[3] != 'a')
		goto fail;
	ret = malloc(hdr->sc2sz);
	if (ret == NULL)
		goto fail;
	if (fread(ret, hdr->sc2sz, 1, wf) != 1)
		goto fail;

	if (hdr->bps == 16) {
		int16_t *ibuf = ret;
		uint8_t *obuf = ret;

		for (i = 0; i < (hdr->sc2sz / (hdr->nchan * 2)); i++) {
			int32_t samp = ibuf[i];
			samp += 32767;
			out[i] = samp >> 8;
		}
		hdr->sc2sz /= 2;
	}
	if (hdr->nchan == 2) {
		uint8_t *obuf = ret;

		for (i = 0; i < hdr->sc2sz; i += 2) {
			*(obuf++) = (ret[i] + ret[i + 1]) / 2;
		}
		hdr->sc2sz /= 2;
	}
	if (hdr->srate > 22050) {
		uint8_t *obuf = ret;
		unsigned mult = hdr->srate / 22050;
		for (i = 0; i < hdr->sc2sz; i += mult) {
			uint64_t sum = 0;
			for (j = 0; j < mult; j++) {
				sum += ret[i + j];
			}
			*(obuf++) = sum / mult;
		}
		hdr->sc2sz /= mult;
	}
	void *tmp = realloc(ret, hdr->sc2sz);
	if (tmp != NULL)
		ret = tmp;
	return ret;

fail:
	if (wf)
		fclose(wf);
	free(ret);
	return NULL;
}
