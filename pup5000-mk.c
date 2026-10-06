/*
 * The PlayStation PUP extractor 5000  --  package builder
 * -------------------------------------------------------
 * Writes PlayStation update packages: the inverse of pup5000.
 *
 *   SCEUF (PS Vita): 32-byte entry records at 0x80
 *                    { u32 id; u32 pad; u64 offset; u64 size; u64 type }
 *                    followed by a 64-byte-per-entry digest table, then the
 *                    segment payloads, then an optional trailing blob.
 *
 *   CFMS  (PS3):     { u32 offset; u32 size; u32 type; u32 name_size;
 *                      char name[] }  with the count at 0x0c and the table
 *                    at 0x20 -- the first layout pup5000 validates.
 *
 * This produces structurally valid containers.  It does NOT sign anything: a
 * Vita will not install a package whose digest table and trailing signature
 * blob are wrong, and no amount of correct layout changes that.
 *
 * Build: cc -O2 -Wall -Wextra -o pup5000-mk pup5000-mk.c
 */

#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PROG "pup5000-mk"
#define MAX_SEG 1024

/* --- little-endian helpers ------------------------------------- */

static void wr32(unsigned char *p, uint32_t v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

static void wr64(unsigned char *p, uint64_t v)
{
	wr32(p, (uint32_t)v);
	wr32(p + 4, (uint32_t)(v >> 32));
}

static void die(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs(PROG ": ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
	exit(1);
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

/* slurp a file, return length via *len */
static unsigned char *slurp(const char *path, size_t *len)
{
	FILE *f = fopen(path, "rb");
	unsigned char *buf;
	long n;

	if (!f)
		die("cannot open %s: %s", path, strerror(errno));
	if (fseek(f, 0, SEEK_END) != 0)
		die("cannot seek %s", path);
	n = ftell(f);
	if (n < 0)
		die("cannot size %s", path);
	rewind(f);
	buf = xmalloc((size_t)n + 1);
	if (n && fread(buf, 1, (size_t)n, f) != (size_t)n)
		die("short read on %s", path);
	fclose(f);
	*len = (size_t)n;
	return buf;
}

static void spit(const char *path, const unsigned char *buf, size_t len)
{
	FILE *f = fopen(path, "wb");
	if (!f)
		die("cannot create %s: %s", path, strerror(errno));
	if (len && fwrite(buf, 1, len, f) != len)
		die("short write on %s", path);
	if (fclose(f) != 0)
		die("cannot close %s: %s", path, strerror(errno));
}

/* --- segment spec ---------------------------------------------- */

typedef struct {
	uint32_t id;          /* vita image id */
	char name[256];       /* ps3 name       */
	unsigned char *data;
	size_t len;
} seg_t;

/* --- SCEUF builder --------------------------------------------- */

static void build_vita(const char *out, seg_t *segs, size_t nseg,
		       uint32_t image_type, const char *digest_tbl,
		       const unsigned char *trailer, size_t trailer_len)
{
	const uint32_t tbl_off = 0x80;
	const uint32_t dig_stride = 0x40;
	uint32_t tbl_end, dig_end, data_start, i;
	size_t pos, out_len;
	unsigned char *o;
	seg_t *s;

	if (nseg == 0 || nseg > MAX_SEG)
		die("need 1..%d segments, got %zu", MAX_SEG, nseg);

	tbl_end = tbl_off + 32 * (uint32_t)nseg;
	dig_end = tbl_end + dig_stride * (uint32_t)nseg;
	data_start = dig_end + 0x20;      /* matches the observed prototype */

	/* lay out payloads, checking 32-bit addressability */
	pos = data_start;
	s = xmalloc(nseg * sizeof(*s));
	for (i = 0; i < nseg; i++) {
		s[i] = segs[i];
		s[i].len = segs[i].len;
		if (segs[i].len > 0xFFFFFFFFull || pos > 0xFFFFFFFFull)
			die("package would exceed the 4 GiB the format can address");
		s[i].data = (unsigned char *)(uintptr_t)pos;  /* stash offset */
		pos += segs[i].len;
	}
	out_len = pos + trailer_len;
	if (out_len > 0xFFFFFFFFull)
		die("package would exceed 4 GiB");

	o = xmalloc(out_len);
	memset(o, 0, out_len);

	/* header */
	memcpy(o, "SCEUF\0\0\x01", 8);
	wr32(o + 0x08, image_type);
	wr32(o + 0x18, (uint32_t)nseg);
	wr32(o + 0x20, data_start);          /* first payload offset */
	wr32(o + 0x28, (uint32_t)pos);       /* end of segment data  */

	/* entry table */
	for (i = 0; i < nseg; i++) {
		unsigned char *r = o + tbl_off + i * 32;
		wr32(r, s[i].id);
		wr64(r + 8, (uint64_t)(uintptr_t)s[i].data);
		wr64(r + 16, s[i].len);
		wr64(r + 24, 2);                 /* type, as observed */
	}

	/* digest table: record index in the first word, rest supplied verbatim.
 * The prototype also has a lone 32-byte value immediately after the last
 * record (at tbl_end + n*64); if the file carries it, copy it too. */
	if (digest_tbl) {
		size_t need = (size_t)nseg * dig_stride;
		size_t dl;
		unsigned char *dt = slurp(digest_tbl, &dl);
		if (dl < need)
			die("digest table %s is %zu bytes, need %zu (%u entries "
			    "x %u)", digest_tbl, dl, need, nseg, dig_stride);
		memcpy(o + tbl_end, dt, need);
		if (dl >= need + 32)
			memcpy(o + tbl_end + need, dt + need, 32);
		free(dt);
	}
	for (i = 0; i < nseg; i++)
		wr32(o + tbl_end + i * dig_stride, i);

	/* payloads */
	for (i = 0; i < nseg; i++)
		if (s[i].len)
			memcpy(o + (uintptr_t)s[i].data, segs[i].data, s[i].len);

	/* trailing blob (signature area) */
	if (trailer_len)
		memcpy(o + pos, trailer, trailer_len);

	spit(out, o, out_len);
	printf("wrote %s: %zu segment%s, %" PRIu64 " bytes, data 0x%x..0x%x\n",
	       out, nseg, nseg == 1 ? "" : "s", (uint64_t)out_len, data_start,
	       (unsigned)pos);
	free(o);
	free(s);
}

/* --- CFMS builder ---------------------------------------------- */

static void build_ps3(const char *out, seg_t *segs, size_t nseg,
		      uint32_t image_type)
{
	const uint32_t tbl_off = 0x20;
	size_t pos, out_len, i;
	unsigned char *o;
	seg_t *s;

	if (nseg == 0 || nseg > MAX_SEG)
		die("need 1..%d entries, got %zu", MAX_SEG, nseg);

	/* first pass: size the table */
	pos = tbl_off;
	for (i = 0; i < nseg; i++)
		pos += 16 + strlen(segs[i].name) + 1;

	s = xmalloc(nseg * sizeof(*s));
	for (i = 0; i < nseg; i++) {
		s[i] = segs[i];
		s[i].data = (unsigned char *)(uintptr_t)pos;
		pos += segs[i].len;
	}
	out_len = pos;
	o = xmalloc(out_len);
	memset(o, 0, out_len);

	memcpy(o, "CFMS", 4);
	wr32(o + 0x04, 1);
	wr32(o + 0x08, image_type);
	wr32(o + 0x0c, (uint32_t)nseg);        /* entry count */
	wr32(o + 0x14, (uint32_t)out_len);     /* data length */

	/* entry table, then payloads */
	pos = tbl_off;
	for (i = 0; i < nseg; i++) {
		size_t nl = strlen(s[i].name) + 1;
		unsigned char *r = o + pos;
		wr32(r, (uint32_t)(uintptr_t)s[i].data);
		wr32(r + 4, (uint32_t)s[i].len);
		wr32(r + 8, 1);                    /* file */
		wr32(r + 12, (uint32_t)nl);
		memcpy(r + 16, s[i].name, nl);
		pos += 16 + nl;
	}
	for (i = 0; i < nseg; i++)
		if (s[i].len)
			memcpy(o + (uintptr_t)s[i].data, segs[i].data, s[i].len);

	spit(out, o, out_len);
	printf("wrote %s: %zu entries, %" PRIu64 " bytes\n", out, nseg,
	       (uint64_t)out_len);
	free(o);
	free(s);
}

/* --- main ------------------------------------------------------ */

static void usage(FILE *f)
{
	fprintf(f,
"pup5000-mk - build PlayStation update packages (PS Vita / PS3)\n"
"\n"
"Usage: %s [options] <out.pup> <segment>...\n"
"\n"
"  vita segments   0xID:path/to/file        e.g. 0x0204:ro.img\n"
"  ps3  segments   name=path/to/file       e.g. EBOOT.BIN=EBOOT.BIN\n"
"\n"
"Options:\n"
"  -f, --format vita|ps3   container to write (default: vita)\n"
"  -t, --image-type N      image type field (default: 2)\n"
"  -d, --digests FILE      supply a verbatim digest table\n"
"                          (n*64 bytes; otherwise left zero)\n"
"  -T, --trailer FILE      append FILE verbatim as the trailing blob\n"
"  -v, --verbose           list what was written\n"
"  -h, --help              this text\n"
"\n"
"Notes:\n"
"  The container is written correctly; the digest table and trailing\n"
"  signature are NOT forged.  Real hardware will reject the result.\n"
"\n"
"Example:\n"
"  %s -f vita fw.PUP 0x0204:a.bin 0x0302:b.bin\n"
"  %s -f ps3  fw.PUP EBOOT.BIN=EBOOT.BIN data.img=data.img\n",
		PROG, PROG, PROG);
}

int main(int argc, char **argv)
{
	seg_t segs[MAX_SEG];
	size_t nseg = 0;
	const char *out = NULL, *digest = NULL;
	const char *fmt = "vita";
	const char *trailer_path = NULL;
	unsigned char *trailer = NULL;
	size_t trailer_len = 0;
	uint32_t image_type = 2;
	int verbose = 0, i;

	memset(segs, 0, sizeof(segs));

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];
		seg_t *s;

		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(a, "-f") || !strcmp(a, "--format")) {
			if (i + 1 >= argc)
				die("--format needs vita or ps3");
			fmt = argv[++i];
		} else if (!strcmp(a, "-t") || !strcmp(a, "--image-type")) {
			if (i + 1 >= argc)
				die("--image-type needs a number");
			image_type = (uint32_t)strtoul(argv[++i], NULL, 0);
		} else if (!strcmp(a, "-d") || !strcmp(a, "--digests")) {
			if (i + 1 >= argc)
				die("--digests needs a path");
			digest = argv[++i];
		} else if (!strcmp(a, "-T") || !strcmp(a, "--trailer")) {
			if (i + 1 >= argc)
				die("--trailer needs a path");
			trailer_path = argv[++i];
		} else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
			verbose = 1;
		} else if (a[0] == '-' && a[1]) {
			die("unknown option '%s' (try --help)", a);
		} else if (!out) {
			out = a;
		} else {
			if (nseg >= MAX_SEG)
				die("too many segments (max %d)", MAX_SEG);
			s = &segs[nseg];
			if (!strcmp(fmt, "vita")) {
				const char *colon = strchr(a, ':');
				if (!colon || colon == a)
					die("vita segment must be 0xID:file, got '%s'", a);
				{
					char idbuf[32];
					size_t n = (size_t)(colon - a);
					if (n >= sizeof(idbuf))
						die("bad segment id in '%s'", a);
					memcpy(idbuf, a, n);
					idbuf[n] = '\0';
					s->id = (uint32_t)strtoul(idbuf, NULL, 0);
				}
				s->data = slurp(colon + 1, &s->len);
			} else if (!strcmp(fmt, "ps3")) {
				const char *eq = strchr(a, '=');
				if (!eq || eq == a || !eq[1])
					die("ps3 segment must be name=file, got '%s'", a);
				if ((size_t)(eq - a) >= sizeof(s->name))
					die("name too long in '%s'", a);
				memcpy(s->name, a, (size_t)(eq - a));
				s->name[eq - a] = '\0';
				s->data = slurp(eq + 1, &s->len);
			} else {
				die("--format must be vita or ps3");
			}
			if (verbose)
				fprintf(stderr, "  seg %zu: %s (%zu bytes)\n", nseg,
					!strcmp(fmt, "ps3") ? s->name : "(vita)",
					s->len);
			nseg++;
		}
	}

	if (!out) {
		usage(stderr);
		return 2;
	}
	if (trailer_path) {
		trailer = slurp(trailer_path, &trailer_len);
		if (verbose)
			fprintf(stderr, "  trailer: %zu bytes\n", trailer_len);
	}

	if (!strcmp(fmt, "ps3"))
		build_ps3(out, segs, nseg, image_type);
	else
		build_vita(out, segs, nseg, image_type, digest, trailer,
			   trailer_len);

	for (i = 0; (size_t)i < nseg; i++)
		free(segs[i].data);
	free(trailer);
	return 0;
}
