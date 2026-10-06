/*
 * The PlayStation PUP extractor 5000  (pup5000)
 * ------------------------------------------
 * A PUP (PlayStation Update Package) unpacker for PS Vita and PS3 images.
 *
 * Supported containers:
 *   - "SCEUF" : PS Vita update package.  32-byte entry records
 *               { u32 id; u32 pad; u64 offset; u64 size; u64 type }
 *               stored at 0x80.  Names are not present in this format, so
 *               segments are named after their image id + container magic.
 *   - "CFMS"  : PS3 / PSP update package.  Variable-length entries
 *               { u32 offset; u32 size; u32 type; u32 name_size; char name[] }
 *               with real filenames.  Header field placement varies between
 *               revisions, so the table is located by validating candidates.
 *
 * Nested packages (a member that is itself a PUP) are detected by magic and
 * unpacked recursively into a subdirectory.
 *
 * Build: cc -O2 -Wall -Wextra -o pup5000 pup5000.c
 * This file is self-contained: no external dependencies.
 */

#define _FILE_OFFSET_BITS 64
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define PROG        "pup5000"
#define VERSION     "5000.1"
#define MAX_ENTRIES  4096
#define MAX_NAME     256
#define MAX_DEPTH    8

/* ------------------------------------------------------------------ */
/* tiny helpers                                                        */
/* ------------------------------------------------------------------ */

static const char *g_quiet = NULL;

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

static void warn(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fputs(PROG ": warning: ", stderr);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
}

static void *xmalloc(size_t n)
{
	void *p = malloc(n ? n : 1);
	if (!p)
		die("out of memory");
	return p;
}

/* Little-endian readers (PUP is LE everywhere). */
static uint32_t rd32(const unsigned char *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p)
{
	return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static const char *human(uint64_t n, char buf[32])
{
	static const char *unit[] = { "B", "KiB", "MiB", "GiB", "TiB" };
	double v = (double)n;
	int u = 0;

	while (v >= 1024.0 && u < 4) {
		v /= 1024.0;
		u++;
	}
	if (u == 0)
		snprintf(buf, 32, "%" PRIu64 " B", n);
	else
		snprintf(buf, 32, "%.1f %s", v, unit[u]);
	return buf;
}

/* ------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4) - for --checksum                               */
/* ------------------------------------------------------------------ */

typedef struct {
	uint32_t h[8];
	uint64_t total;
	unsigned char buf[64];
	size_t used;
} sha256_ctx;

static const uint32_t SHA_K[64] = {
	0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
	0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
	0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
	0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
	0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
	0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
	0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
	0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
	0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
	0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
	0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
	0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
	0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(sha256_ctx *c, const unsigned char *p)
{
	uint32_t w[64], a, b, cc, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) | (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}
	a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
	e = c->h[4]; f = c->h[5]; g = c->h[6]; h = c->h[7];
	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
		uint32_t ch = (e & f) ^ ((~e) & g);
		uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
		uint32_t mj = (a & b) ^ (a & cc) ^ (b & cc);
		t1 = h + S1 + ch + SHA_K[i] + w[i];
		t2 = S0 + mj;
		h = g; g = f; f = e; e = d + t1;
		d = cc; cc = b; b = a; a = t1 + t2;
	}
	c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
	c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_init(sha256_ctx *c)
{
	static const uint32_t iv[8] = {
		0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
		0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
	};
	memcpy(c->h, iv, sizeof(iv));
	c->total = 0;
	c->used = 0;
}

static void sha256_update(sha256_ctx *c, const unsigned char *p, size_t n)
{
	c->total += n;
	if (c->used) {
		size_t take = 64 - c->used;
		if (take > n)
			take = n;
		memcpy(c->buf + c->used, p, take);
		c->used += take;
		p += take;
		n -= take;
		if (c->used == 64) {
			sha256_block(c, c->buf);
			c->used = 0;
		}
	}
	while (n >= 64) {
		sha256_block(c, p);
		p += 64;
		n -= 64;
	}
	if (n) {
		memcpy(c->buf, p, n);
		c->used = n;
	}
}

static void sha256_hex(sha256_ctx *c, char out[65])
{
	uint64_t bits = c->total * 8;
	unsigned char pad[72];
	size_t padlen;
	int i;

	memset(pad, 0, sizeof(pad));
	pad[0] = 0x80;
	padlen = (c->used < 56) ? (56 - c->used) : (120 - c->used);
	for (i = 0; i < 8; i++)
		pad[(size_t)padlen + (size_t)i] =
			(unsigned char)(bits >> (56 - 8 * i));
	sha256_update(c, pad, padlen + 8);
	for (i = 0; i < 8; i++)
		snprintf(out + i * 8, 9, "%08x", c->h[i]);
	out[64] = '\0';
}

/* ------------------------------------------------------------------ */
/* in-memory view of the package                                       */
/* ------------------------------------------------------------------ */

typedef struct {
	const unsigned char *base;   /* whole file */
	uint64_t size;
} pkg_t;

typedef struct {
	uint32_t id;       /* SCEUF image id (0 for CFMS)  */
	uint64_t offset;
	uint64_t size;
	uint64_t type;     /* CFMS: 0 = dir, 1 = file      */
	char name[MAX_NAME];
} entry_t;

typedef struct {
	entry_t *v;
	size_t n;
} list_t;

typedef enum { FMT_UNKNOWN = 0, FMT_VITA, FMT_PS3 } fmt_t;

typedef struct {
	fmt_t fmt;
	uint32_t version;
	uint32_t image_type;
	uint32_t count;
	uint32_t sig_size;     /* header-reported signature/blob length */
	uint64_t sig_offset;   /* where it lives                         */
	uint32_t data_len;     /* header-reported data length            */
	uint32_t reserved;     /* undocumented header field              */
	uint32_t table_off;
	uint32_t table_end;
} hdr_t;

/* --- header detection ------------------------------------------- */

/* Overflow-safe "does [off, off+size) fit inside total?" */
static int range_ok(uint64_t off, uint64_t size, uint64_t total)
{
	return off <= total && size <= total - off;
}

static int looks_like_vita(const unsigned char *p, uint64_t n)
{
	return n >= 0x140 && memcmp(p, "SCEUF", 5) == 0;
}

static int looks_like_ps3(const unsigned char *p, uint64_t n)
{
	return n >= 0x20 && memcmp(p, "CFMS", 4) == 0;
}

/* Validate one CFMS entry table laid out at `tbl`; fill `out` on success.
 * Returns the number of entries parsed, or -1 if the layout is bogus.
 *
 * Names are only required to be NUL terminated and free of embedded NULs;
 * non-printable bytes are tolerated (they get sanitised on extraction) but
 * most names must look like text, otherwise a random offset could pass for a
 * valid table. */
static int parse_ps3_table(const pkg_t *p, uint32_t tbl, uint32_t count,
			   list_t *out)
{
	uint64_t pos = tbl, i;
	uint64_t table_end;
	size_t printable = 0, total = 0;
	uint64_t min_off = UINT64_MAX;
	int have_file = 0;

	if (count == 0 || count > MAX_ENTRIES)
		return -1;

	for (i = 0; i < count; i++) {
		uint32_t off, size, type, nlen;
		entry_t e;

		if (pos + 16 > p->size)
			return -1;
		off = rd32(p->base + pos);
		size = rd32(p->base + pos + 4);
		type = rd32(p->base + pos + 8);
		nlen = rd32(p->base + pos + 12);
		pos += 16;

		if (type > 1 || nlen == 0 || nlen >= MAX_NAME)
			return -1;
		if (pos + nlen > p->size)
			return -1;
		if (p->base[pos + nlen - 1] != '\0')
			return -1;
		if (nlen > 1 && memchr(p->base + pos, '\0', nlen - 1) != NULL)
			return -1;              /* embedded NUL: not a name */
		pos += nlen;

		{
			uint32_t k;
			int ok = 1;
			for (k = 0; k + 1 < nlen; k++) {
				unsigned char ch = p->base[pos - nlen + k];
				if (ch < 0x20 || ch > 0x7e)
					ok = 0;
			}
			total++;
			if (ok)
				printable++;
		}

		memcpy(e.name, p->base + pos - nlen, nlen - 1);
		e.name[nlen - 1] = '\0';

		e.id = 0;
		e.type = type;
		e.offset = off;
		e.size = size;
		if (type == 1) {
			if (size == 0 || !range_ok(off, size, p->size))
				return -1;
			if (off < min_off)
				min_off = off;
			have_file = 1;
		}

		if (out) {
			out->v = realloc(out->v, (out->n + 1) * sizeof(entry_t));
			if (!out->v)
				die("out of memory");
			out->v[out->n++] = e;
		}
	}

	table_end = pos;
	/* payloads must live after the table, not inside it */
	if (!have_file || total == 0 || min_off < table_end)
		return -1;
	/* the table should be mostly text, or we are reading noise */
	if (printable * 5 < total * 4)
		return -1;
	return (int)count;
}

/* CFMS header field placement drifted between revisions; try the known
 * combinations and keep the first one that yields a self-consistent table. */
static void parse_ps3(const pkg_t *p, hdr_t *h, list_t *out)
{
	static const struct { uint32_t cnt, tbl; } cand[] = {
		{ 0x0C, 0x20 }, { 0x10, 0x24 }, { 0x10, 0x20 },
		{ 0x14, 0x28 }, { 0x08, 0x20 }, { 0x0C, 0x24 }
	};
	size_t i;

	h->fmt = FMT_PS3;
	h->version = rd32(p->base + 4);
	h->image_type = rd32(p->base + 8);
	h->sig_size = rd32(p->base + 0x18);
	h->sig_offset = rd32(p->base + 0x1c);
	h->data_len = rd32(p->base + 0x14);
	h->table_off = 0;

	for (i = 0; i < sizeof(cand) / sizeof(cand[0]); i++) {
		uint32_t count;
		uint64_t probe;
		if (cand[i].tbl + 4 > p->size)
			continue;
		count = rd32(p->base + cand[i].cnt);
		if (count == 0 || count > MAX_ENTRIES)
			continue;
		/* cheap pre-check: the table cannot claim more bytes than exist */
		probe = (uint64_t)cand[i].tbl + 16 * (uint64_t)count;
		if (probe > p->size)
			continue;
		out->n = 0;
		if (parse_ps3_table(p, cand[i].tbl, count, out) > 0) {
			h->count = count;
			h->table_off = cand[i].tbl;
			h->table_end = cand[i].tbl;
			return;
		}
	}
	die("CFMS header found, but no plausible entry table could be parsed "
	    "(%s; is this really an update package?)",
	    "file may be encrypted, truncated, or a newer revision");
}

/* SCEUF: verified layout - 32-byte records at 0x80. */
static void parse_vita(const pkg_t *p, hdr_t *h, list_t *out)
{
	uint32_t i;

	h->fmt = FMT_VITA;
	h->version = (uint32_t)p->base[7];      /* "SCEUF\0\0" then version */
	h->image_type = rd32(p->base + 8);
	h->count = rd32(p->base + 0x18);
	h->data_len = rd32(p->base + 0x28);     /* end of segment data */
	h->reserved = rd32(p->base + 0x10);
	/* everything past data_len is a trailing signature blob */
	h->sig_offset = h->data_len;
	h->sig_size = (h->data_len <= p->size)
			      ? (uint32_t)(p->size - h->data_len) : 0;
	h->table_off = 0x80;

	if (h->count == 0 || h->count > MAX_ENTRIES)
		die("SCEUF header claims %u entries (0 or >%d is nonsense)",
		    h->count, MAX_ENTRIES);
	/* the declared table must actually be inside the file */
	if (!range_ok(0x80, (uint64_t)h->count * 32, p->size))
		die("SCEUF entry table (%u entries) does not fit in a %" PRIu64
		    " byte file", h->count, p->size);

	out->v = xmalloc((size_t)h->count * sizeof(entry_t));
	out->n = 0;

	for (i = 0; i < h->count; i++) {
		const unsigned char *r = p->base + 0x80 + (size_t)i * 32;
		entry_t e;

		e.id = rd32(r);
		e.offset = rd64(r + 8);
		e.size = rd64(r + 16);
		e.type = rd64(r + 24);
		e.name[0] = '\0';

		if (e.size == 0)
			warn("entry %u (id 0x%04x) is empty, skipping", i, e.id);
		else if (!range_ok(e.offset, e.size, p->size))
			warn("entry %u (id 0x%04x) runs past end of file, skipping",
			     i, e.id);
		else
			out->v[out->n++] = e;
	}
	h->table_end = 0x80 + 32 * h->count;
}

/* ------------------------------------------------------------------ */
/* path safety                                                         */
/* ------------------------------------------------------------------ */

/* Copy one path component, neutralising anything nasty. */
static void sanitize(const char *in, char *out, size_t outsz)
{
	size_t o = 0;

	for (; *in && o + 1 < outsz; in++) {
		unsigned char ch = (unsigned char)*in;
		if (ch == '/' || ch == '\\' || ch < 0x20 || ch == ':' ||
		    ch == '*' || ch == '?' || ch == '"' || ch == '<' ||
		    ch == '>' || ch == '|')
			ch = '_';
		out[o++] = (char)ch;
	}
	out[o] = '\0';
	/* no component may be "." / ".." / empty */
	if (!o || !strcmp(out, ".") || !strcmp(out, ".."))
		strcpy(out, "_");
}

static int mkdir_p(const char *path)
{
	char tmp[PATH_MAX];
	size_t i, n = strlen(path);

	if (n == 0 || n >= sizeof(tmp))
		return -1;
	memcpy(tmp, path, n + 1);
	for (i = 1; i < n; i++) {
		if (tmp[i] == '/') {
			tmp[i] = '\0';
			if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
				return -1;
			tmp[i] = '/';
		}
	}
	if (mkdir(tmp, 0777) != 0 && errno != EEXIST)
		return -1;
	return 0;
}

/* Join base + rel.  Empty, "." and ".." components are dropped, so hostile
 * names such as "../../etc/passwd" or "/etc/passwd" are rewritten to stay
 * inside base rather than escaping it. */
static int safe_join(char *dst, size_t dstsz, const char *base, const char *rel)
{
	char acc[PATH_MAX];
	char comp[MAX_NAME];
	const char *p = rel;
	size_t n;
	int had_component = 0;

	if (snprintf(acc, sizeof(acc), "%s", base) >= (int)sizeof(acc))
		return -1;
	n = strlen(acc);

	while (*p) {
		const char *slash = strchr(p, '/');
		size_t len = slash ? (size_t)(slash - p) : strlen(p);

		if (len >= sizeof(comp))
			return -1;
		memcpy(comp, p, len);
		comp[len] = '\0';

		/* drop no-ops and traversal attempts */
		if (!comp[0] || !strcmp(comp, ".") || !strcmp(comp, "..")) {
			p = slash ? slash + 1 : p + len;
			continue;
		}
		sanitize(comp, comp, sizeof(comp));

		if (n + 1 + strlen(comp) + 1 > sizeof(acc))
			return -1;
		acc[n++] = '/';
		strcpy(acc + n, comp);
		n += strlen(comp);
		had_component = 1;
		p = slash ? slash + 1 : p + len;
	}

	if (!had_component) {
		/* the whole name was traversal, e.g. "../../.." */
		if (n + 2 > sizeof(acc))
			return -1;
		acc[n++] = '/';
		acc[n++] = '_';
		acc[n] = '\0';
	}
	if (n + 1 > dstsz)
		return -1;
	memcpy(dst, acc, n + 1);
	return 0;
}

/* ------------------------------------------------------------------ */
/* segment naming (SCEUF has no names)                                 */
/* ------------------------------------------------------------------ */

static void vita_name(const pkg_t *p, const entry_t *e, char *out, size_t outsz)
{
	const unsigned char *m = p->base + e->offset;
	const char *kind = "bin";

	if (e->size >= 4) {
		if (!memcmp(m, "SCE\0", 4))
			kind = "sce";
		else if (!memcmp(m, "pUpC", 4))
			kind = "pupc";
		else if (m[0] == 0x7f && !memcmp(m + 1, "ELF", 3))
			kind = "elf";
	}
	(void)e->size;
	snprintf(out, outsz, "image_0x%04x.%s", e->id, kind);
}

/* ------------------------------------------------------------------ */
/* extraction                                                          */
/* ------------------------------------------------------------------ */

typedef struct {
	int list_only;
	int verbose;
	int force;
	int checksum;
	const char *outdir;
} opts_t;

/* Write [off, off+size) of the (already loaded) package to `path`. */
static int dump_range(const pkg_t *p, const char *path, uint64_t off,
		      uint64_t size, const opts_t *o)
{
	FILE *out;
	sha256_ctx ctx;
	char hex[65] = "";

	if (!range_ok(off, size, p->size)) {
		warn("refusing to write %s: range past end of package", path);
		return -1;
	}

	out = fopen(path, "wb");
	if (!out)
		return -1;
	if (o->checksum)
		sha256_init(&ctx);

	if (size && fwrite(p->base + off, 1, (size_t)size, out) != (size_t)size) {
		warn("write failed on %s: %s", path, strerror(errno));
		fclose(out);
		remove(path);
		return -1;
	}
	if (o->checksum) {
		sha256_update(&ctx, p->base + off, (size_t)size);
		sha256_hex(&ctx, hex);
		if (o->verbose)
			fprintf(stderr, "         sha256 %s\n", hex);
	}
	if (fclose(out) != 0) {
		warn("cannot flush %s: %s", path, strerror(errno));
		return -1;
	}
	return 0;
}

/* Does this blob start with a PUP magic? */
static int is_nested_pup(const pkg_t *p, const entry_t *e)
{
	if (e->size < 8 || !range_ok(e->offset, 8, p->size))
		return 0;
	return !memcmp(p->base + e->offset, "CFMS", 4) ||
	       !memcmp(p->base + e->offset, "SCEUF", 5);
}

static int unpack(const pkg_t *p, const list_t *l, const char *dir,
		  const opts_t *o, int depth);

static int extract_entry(const pkg_t *p, const entry_t *e, const char *dir,
			 const opts_t *o, int depth)
{
	char rel[MAX_NAME], name[MAX_NAME], path[PATH_MAX];
	struct stat st;

	if (e->name[0])
		snprintf(rel, sizeof(rel), "%s", e->name);
	else
		vita_name(p, e, name, sizeof(name)), snprintf(rel, sizeof(rel),
							    "%s", name);

	if (safe_join(path, sizeof(path), dir, rel) != 0) {
		warn("path too long, skipping %.64s", rel);
		return 0;
	}

	if (e->type == 0) {
		if (mkdir_p(path) != 0 && errno != EEXIST) {
			warn("cannot create directory %s: %s", path,
			     strerror(errno));
			return -1;
		}
		if (o->verbose)
			fprintf(stderr, "  + dir  %s\n", rel);
		return 0;
	}

	if (!o->force && stat(path, &st) == 0) {
		warn("%s already exists (use --force to overwrite)", path);
		return 0;
	}

	/* make sure the parent directory exists */
	{
		char parent[PATH_MAX];
		char *slash;
		snprintf(parent, sizeof(parent), "%s", path);
		slash = strrchr(parent, '/');
		if (slash && slash != parent) {
			*slash = '\0';
			mkdir_p(parent);
		}
	}

	if (dump_range(p, path, e->offset, e->size, o) != 0) {
		warn("failed to extract %s", rel);
		return -1;
	}

	{
		char sz[32];
		fprintf(stderr, "  + file %s (%s)\n", rel, human(e->size, sz));
	}
/* recurse into nested packages: unpack beside the file, not inside it */
	if (depth + 1 < MAX_DEPTH && is_nested_pup(p, e)) {
		char sub[PATH_MAX];
		char stem[MAX_NAME];
		const char *base, *slash;
		pkg_t inner;
		hdr_t ih;
		list_t il;

		base = strrchr(path, '/');
		base = base ? base + 1 : path;
		slash = strrchr(base, '.');
		if (slash && slash != base) {
			if ((size_t)(slash - base) >= sizeof(stem))
				die("name too long");
			memcpy(stem, base, (size_t)(slash - base));
			stem[slash - base] = '\0';
		} else {
			snprintf(stem, sizeof(stem), "%.*s", MAX_NAME - 1, base);
		}
		if (strlen(stem) + sizeof("/_nested") > sizeof(stem))
			die("name too long");
		strcat(stem, "_nested");

		inner.base = p->base + e->offset;
		inner.size = e->size;
		il.v = NULL;
		il.n = 0;

		if (looks_like_vita(inner.base, inner.size))
			parse_vita(&inner, &ih, &il);
		else if (looks_like_ps3(inner.base, inner.size))
			parse_ps3(&inner, &ih, &il);
		else {
			free(il.v);
			return 0;
		}

		if (il.n && safe_join(sub, sizeof(sub), dir, stem) == 0) {
			fprintf(stderr, "  -> nested package: %zu entr%s in %s\n",
				il.n, il.n == 1 ? "y" : "ies", stem);
			if (mkdir_p(sub) != 0)
				warn("cannot create %s: %s", sub,
				     strerror(errno));
			else
				unpack(&inner, &il, sub, o, depth + 1);
		}
		free(il.v);
	}
	return 0;
}

static int unpack(const pkg_t *p, const list_t *l, const char *dir,
		  const opts_t *o, int depth)
{
	size_t i;
	int rc = 0, files = 0;
	uint64_t total = 0;
	char sz[32];

	for (i = 0; i < l->n; i++) {
		if (extract_entry(p, &l->v[i], dir, o, depth) != 0)
			rc = -1;
		if (l->v[i].type != 0) {
			files++;
			total += l->v[i].size;
		}
	}
	if (o->verbose && files)
		fprintf(stderr, "  -- %d file%s, %s total\n", files,
			files == 1 ? "" : "s", human(total, sz));
	return rc;
}

/* ------------------------------------------------------------------ */
/* listing                                                             */
/* ------------------------------------------------------------------ */

static void print_hdr(const hdr_t *h, const pkg_t *p, const char *path)
{
	char sz[32];

	printf("file            : %s\n", path);
	printf("format          : %s\n",
	       h->fmt == FMT_VITA ? "PS Vita (SCEUF)" : "PS3/PSP (CFMS)");
	printf("size            : %s (%" PRIu64 " bytes)\n", human(p->size, sz),
	       p->size);
	printf("header version  : %u\n", h->version);
	printf("image type      : 0x%02x\n", h->image_type);
	printf("entries         : %u (table @ 0x%x)\n", h->count, h->table_off);
	if (h->fmt == FMT_VITA) {
		printf("data length     : 0x%x (declared end of segments)\n",
		       h->data_len);
		printf("reserved@0x10   : 0x%x\n", h->reserved);
		printf("signature blob  : %u bytes @ 0x%" PRIx64 "\n",
		       h->sig_size, h->sig_offset);
		printf("note            : SCEUF segments carry no filenames,\n"
		       "                  and most payloads are opaque\n"
		       "                  (max entropy), so segments are\n"
		       "                  reproduced exactly as stored.\n");
	}
}

/* ------------------------------------------------------------------ */
/* self test (known-answer vectors, so you can trust the checksums)     */
/* ------------------------------------------------------------------ */

static int selftest(void)
{
	static const struct {
		const char *in;
		const char *want;
	} vec[] = {
		{ "",
		  "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
		{ "abc",
		  "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" },
		{ "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		  "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1" },
	};
	unsigned char blk[1000];
	char hex[65];
	size_t i;
	int fails = 0;

	for (i = 0; i < sizeof(vec) / sizeof(vec[0]); i++) {
		sha256_ctx c;
		sha256_init(&c);
		sha256_update(&c, (const unsigned char *)vec[i].in,
			      strlen(vec[i].in));
		sha256_hex(&c, hex);
		if (strcmp(hex, vec[i].want) != 0) {
			printf("FAIL  sha256(\"%.32s\")\n        got  %s\n"
			       "        want %s\n", vec[i].in, hex, vec[i].want);
			fails++;
		} else {
			printf("ok    sha256(\"%.32s\")\n", vec[i].in);
		}
	}

	/* one million 'a' - exercises multi-block updates */
	memset(blk, 'a', sizeof(blk));
	{
		sha256_ctx c;
		int n;
		sha256_init(&c);
		for (n = 0; n < 1000; n++)
			sha256_update(&c, blk, sizeof(blk));
		sha256_hex(&c, hex);
		if (strcmp(hex,
			   "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0") != 0) {
			printf("FAIL  sha256(1e6 x 'a')\n        got  %s\n", hex);
			fails++;
		} else
			printf("ok    sha256(1e6 x 'a')\n");
	}

	printf("%s\n", fails ? "SELFTEST FAILED" : "selftest passed");
	return fails ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

static void usage(FILE *f)
{
	fprintf(f,
"The PlayStation PUP extractor 5000  v%s\n"
"Copyright-free firmware liberation since never.\n"
"\n"
"Usage: %s [options] <file.PUP>\n"
"\n"
"Options:\n"
"  -l, --list        list the package contents, write nothing\n"
"  -i, --info       print header information only\n"
"  -o, --output DIR output directory (default: <input>_extracted)\n"
"  -c, --checksum   print a SHA-256 for every extracted file\n"
"  -f, --force      overwrite existing files\n"
"  -v, --verbose    chatty output\n"
"  -q, --quiet      only print errors\n"
"  -h, --help       this text\n"
"      --about      you already know\n"
"\n"
"Examples:\n"
"  %s -l PSP2UPDAT.PUP\n"
"  %s -o out/ -c PSP2UPDAT.PUP\n",
	VERSION, PROG, PROG, PROG);
}

int main(int argc, char **argv)
{
	opts_t o;
	pkg_t p;
	hdr_t h;
	list_t l;
	FILE *f;
	const char *path = NULL, *outdir = NULL;
	int i, listing = 0, info = 0;

	memset(&o, 0, sizeof(o));
	memset(&l, 0, sizeof(l));
	memset(&h, 0, sizeof(h));
	memset(&p, 0, sizeof(p));

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (!strcmp(a, "-h") || !strcmp(a, "--help")) {
			usage(stdout);
			return 0;
		} else if (!strcmp(a, "--selftest")) {
			return selftest();
		} else if (!strcmp(a, "--about")) {
			printf("%s %s: extracts PlayStation update packages.\n"
			       "Not affiliated with, endorsed by, or aware of Sony.\n"
			       "No keys were harmed in the making of this file.\n",
			       PROG, VERSION);
			return 0;
		} else if (!strcmp(a, "-l") || !strcmp(a, "--list")) {
			listing = 1;
		} else if (!strcmp(a, "-i") || !strcmp(a, "--info")) {
			info = 1;
		} else if (!strcmp(a, "-v") || !strcmp(a, "--verbose")) {
			o.verbose = 1;
		} else if (!strcmp(a, "-f") || !strcmp(a, "--force")) {
			o.force = 1;
		} else if (!strcmp(a, "-c") || !strcmp(a, "--checksum")) {
			o.checksum = 1;
		} else if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) {
			g_quiet = a;
		} else if ((!strcmp(a, "-o") || !strcmp(a, "--output")) &&
			   i + 1 < argc) {
			outdir = argv[++i];
		} else if (a[0] == '-' && a[1]) {
			die("unknown option '%s' (try --help)", a);
		} else if (!path) {
			path = a;
		} else {
			die("one package at a time, please");
		}
	}

	if (!path) {
		usage(stderr);
		return 2;
	}
	if (!outdir && !listing && !info) {
		static char def[PATH_MAX];
		const char *dot = strrchr(path, '.');
		size_t stem = dot ? (size_t)(dot - path) : strlen(path);
		if (stem >= sizeof(def) - 16)
			die("input name too long");
		memcpy(def, path, stem);
		strcpy(def + stem, "_extracted");
		outdir = def;
	}

	f = fopen(path, "rb");
	if (!f)
		die("cannot open %s: %s", path, strerror(errno));
	if (fseeko(f, 0, SEEK_END) != 0)
		die("cannot seek %s: %s", path, strerror(errno));
	{
		off_t end = ftello(f);
		if (end < 0)
			die("cannot size %s: %s", path, strerror(errno));
		p.size = (uint64_t)end;
	}
	rewind(f);

	p.base = xmalloc((size_t)p.size + 1);
	if (p.size && fread((void *)p.base, 1, (size_t)p.size, f) != p.size)
		die("short read on %s", path);
	fclose(f);

	if (looks_like_vita(p.base, p.size))
		parse_vita(&p, &h, &l);
	else if (looks_like_ps3(p.base, p.size))
		parse_ps3(&p, &h, &l);
	else
		die("%s does not look like a PUP "
		    "(expected \"CFMS\" or \"SCEUF\" magic)", path);

	print_hdr(&h, &p, path);

	if (info) {
		free(l.v);
		free((void *)p.base);
		return 0;
	}

	printf("\n");
	for (i = 0; (size_t)i < l.n; i++) {
		const entry_t *e = &l.v[i];
		char sz[32], nm[MAX_NAME];

		if (e->name[0])
			snprintf(nm, sizeof(nm), "%s", e->name);
		else
			vita_name(&p, e, nm, sizeof(nm));

		if (h.fmt == FMT_VITA)
			printf("  0x%04x  %10" PRIu64 "  %6s  @ 0x%08" PRIx64
			       "  %s\n", e->id, e->size, human(e->size, sz),
			       e->offset, nm);
		else
			printf("  %-9s %10" PRIu64 "  %6s  @ 0x%08" PRIx64
			       "  %s\n",
			       e->type == 0 ? "<dir>" : "<file>", e->size,
			       human(e->size, sz), e->offset, nm);
	}

	if (listing) {
		free(l.v);
		free((void *)p.base);
		return 0;
	}

	if (!g_quiet)
		printf("\nBEEP-BOOP. Unpacking into %s/ ...\n", outdir);

	if (mkdir_p(outdir) != 0)
		die("cannot create %s: %s", outdir, strerror(errno));

	o.outdir = outdir;
	unpack(&p, &l, outdir, &o, 0);

	if (!g_quiet)
		printf("Done. %zu top-level entr%s processed. "
		       "Firmware liberated.\n", l.n, l.n == 1 ? "y" : "ies");

	free(l.v);
	free((void *)p.base);
	return 0;
}
