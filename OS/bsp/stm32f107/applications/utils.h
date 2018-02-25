#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdio.h>
#include <string.h>

/***********************************************/

#define	bswap_16(value)  \
 	((((value) & 0xff) << 8) | ((value) >> 8))

#define	bswap_32(value)	\
 	(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
 	(uint32_t)bswap_16((uint16_t)((value) >> 16)))

#define	bswap_64(value)	\
 	(((uint64_t)bswap_32((uint32_t)((value) & 0xffffffff)) \
 	    << 32) | \
 	(uint64_t)bswap_32((uint32_t)((value) >> 32)))

static __inline uint32_t swab32(uint32_t v)
{
	return bswap_32(v);
}

static __inline void swap256(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;

	dest[0] = src[7];
	dest[1] = src[6];
	dest[2] = src[5];
	dest[3] = src[4];
	dest[4] = src[3];
	dest[5] = src[2];
	dest[6] = src[1];
	dest[7] = src[0];
}

static __inline void swab256(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;

	dest[0] = swab32(src[7]);
	dest[1] = swab32(src[6]);
	dest[2] = swab32(src[5]);
	dest[3] = swab32(src[4]);
	dest[4] = swab32(src[3]);
	dest[5] = swab32(src[2]);
	dest[6] = swab32(src[1]);
	dest[7] = swab32(src[0]);
}

static __inline void flip32(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;
	int i;

	for (i = 0; i < 8; i++)
		dest[i] = swab32(src[i]);
}

static __inline void flip64(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;
	int i;

	for (i = 0; i < 16; i++)
		dest[i] = swab32(src[i]);
}

static __inline void flip80(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;
	int i;

	for (i = 0; i < 20; i++)
		dest[i] = swab32(src[i]);
}

static __inline void flip128(void *dest_p, const void *src_p)
{
	uint32_t *dest = dest_p;
	const uint32_t *src = src_p;
	int i;

	for (i = 0; i < 32; i++)
		dest[i] = swab32(src[i]);
}

/* For flipping to the correct endianness if necessary */
#if defined(__BIG_ENDIAN__) || defined(MIPSEB)
static __inline void endian_flip32(void *dest_p, const void *src_p)
{
	flip32(dest_p, src_p);
}

static __inline void endian_flip128(void *dest_p, const void *src_p)
{
	flip128(dest_p, src_p);
}
#else
static __inline void
endian_flip32(void *dest_p, const void *src_p)
{
}

static __inline void
endian_flip128(void *dest_p, const void *src_p)
{
}
#endif

#define htole32(x) (x)


/* Align a size_t to 4 byte boundaries for fussy arches */
static __inline void align_len(size_t *len)
{
	if (*len % 4)
		*len += 4 - (*len % 4);
}


////////////////////////////////////////////////////////

#endif /* __UTILS_H__ */