# The PlayStation PUP extractor 5000

A single-file C program that unpacks PlayStation update packages (`.PUP`) for
**PS Vita** and **PS3/PSP**. No dependencies, no network, no keys.

```
$ ./pup5000 -l PSP2UPDAT-0.902.PUP

file            : PSP2UPDAT-0.902.PUP
format          : PS Vita (SCEUF)
size            : 13.2 MiB (13865982 bytes)
header version  : 1
image type      : 0x02
entries         : 6 (table @ 0x80)
data length     : 0xd3911e (declared end of segments)
reserved@0x10   : 0x900000
signature blob  : 736 bytes @ 0xd3911e

  0x0204       20286  19.8 KiB  @ 0x000002e0  image_0x0204.sce
  0x0302     1680256  1.6 MiB  @ 0x0000521e  image_0x0302.sce
  0x0303     3941248  3.8 MiB  @ 0x0019f59e  image_0x0303.sce
  0x0304     1233792  1.2 MiB  @ 0x0056191e  image_0x0304.sce
  0x2005     3482992  3.3 MiB  @ 0x0068ec9e  image_0x2005.pupc
  0x2006     3506672  3.3 MiB  @ 0x009e120e  image_0x2006.pupc
```

## Build

```sh
make            # -> ./pup5000
make check      # SHA-256 known-answer self test
make test       # self test + full run against the bundled sample firmware
```

Or just: `cc -O2 -o pup5000 pup5000.c`

## Usage

```
pup5000 [options] <file.PUP>

  -l, --list        list the package contents, write nothing
  -i, --info       print header information only
  -o, --output DIR output directory (default: <input>_extracted)
  -c, --checksum   print a SHA-256 for every extracted file
  -f, --force      overwrite existing files
  -v, --verbose    chatty output (includes per-file digests)
  -q, --quiet      suppress progress chatter
      --selftest   verify the checksum code against known answers
      --about      you already know
```

## Supported formats

| magic  | platform | notes |
|--------|----------|-------|
| `SCEUF` | PS Vita | 32-byte entry records `{ u32 id; u32 pad; u64 offset; u64 size; u64 type }` at `0x80` |
| `CFMS`  | PS3 / PSP | `{ u32 offset; u32 size; u32 type; u32 name_size; char name[] }`, real filenames |

The PS3 entry table location is **not** hardcoded: field placement has varied
between revisions, so the parser tries the known combinations and keeps the
first one whose table validates (types in range, names NUL-terminated, every
payload inside the file and past the end of the table, names mostly printable).
A package that fails validation is rejected with an explanation instead of
producing garbage files.

### Nested packages

PS3 firmware packages commonly contain a second package inside an entry. Any
member whose payload starts with `CFMS` or `SCEUF` is detected and unpacked
recursively into `<name>_nested/` (depth limited to 8).

## Behaviour and safety notes

- **Nothing escapes the output directory.** `..`, `.`, absolute paths and empty
  components are dropped rather than written, so a hostile entry named
  `../../../../etc/passwd` lands at `etc/passwd` *inside* the output directory.
  Path separators, control characters and shell/Windows-reserved characters are
  replaced with `_`.
- **Every range is checked before it is read or written**, using overflow-safe
  arithmetic (`off <= total && size <= total - off`) so a crafted 64-bit
  `offset`/`size` pair cannot wrap around into an out-of-bounds access.
- **Existing files are never clobbered** unless you pass `--force`.
- Entries that are empty or that run past the end of the file are reported and
  skipped rather than aborting the run.
- The code is clean under `-Wall -Wextra -Wpedantic -Wshadow -Wconversion`, and
  under AddressSanitizer + UndefinedBehaviorSanitizer across the sample
  firmware, hand-built PS3 fixtures, and ~750 mutated/random inputs.

## What the segments actually are

`SCEUF` packages do not store filenames, so segments are named
`image_<id>.<kind>`, where `kind` comes from the 4-byte magic at the start of
each segment.

**The `.sce` and `.pupc` extensions are this tool's own naming convention, not
real Sony extensions.** They exist so you can tell the segment kinds apart at a
glance. The underlying formats are:

| magic | what it is |
|-------|------------|
| `SCE\0` + version 3 | the Sony Computer Entertainment signed-image container. This is the standard wrapper for signed Vita binaries: in the one plaintext segment here (`0x0204`) it holds genuine SCE-signed ARM ELF modules — `cui_update_starter_module`, `SceCuiUpdater`, `SceLibKernel` — with their stub/symbol sections intact. |
| `pUpC` | a "PUP container": a package-within-a-package, carrying further PUP-formatted entries inside the update package. Header carries its own total size redundantly at `+0x16`. |

Header layout observed in the `SCE\0` containers: `+0x10` holds the header/table
size (`0x880` in the plaintext segment, `0x300` in the others), `+0x18` is
`total - header_size`, and `+0x20` is the total size, which matches the
top-level segment size exactly.

There is also a **digest table** immediately after the entry table: 64-byte
records, stride `0x40`, each `[u32 index][u32 pad][32-byte digest][24 pad]`,
with indices 0..n-1 visible at `0x140, 0x180, ...`, followed by a lone 32-byte
value just before the first payload. None of these digests is a plain SHA-256
of the stored bytes (I checked: raw segment, header, entry table, digest table,
all payloads, whole file), so the digest layer is keyed or computed over the
*decrypted* image. Which fits the note that accompanies this particular
prototype build — it ships an older keyset, so it does not decrypt with a
console's internal keys.

Inside the `SCE\0` containers of the **opaque** segments there is a plaintext
128-byte descriptor at `+0x300`, bracketed by 32-byte hash values at `+0x2e0`
and `+0x380`. Its layout is identical across segments with only the values
changing; a 64-bit field repeats the header's `+0x10` value, and another holds
`segment_size - 0x380` — i.e. it declares the payload window `[+0x380, EOF)`.
So the opaque part begins at `+0x380` and is exactly `size - 0x380` bytes long.
Both that offset and length are 16-byte aligned in every segment, which is a
strong hint at a 128-bit block cipher (and is *not* explained by compression,
whose framing we already ruled out).

Note this descriptor belongs to the *encrypted* variant, not to the `SCE\0`
format generally: the one plaintext container (`0x0204`) has no descriptor at
`+0x300` at all, and a different internal layout. So there are effectively two
nested layers here — the container, and a separate encrypted-payload wrapper —
and I have decoded only the outer one plus this wrapper's header.

### About the payload contents

One thing worth being blunt about: in this sample, **only segment `0x0204` has
readable content**. The other five measure ~8.0 bits/byte — the theoretical
maximum — with a zero-byte fraction of 0.39%, which is exactly `1/256` and so
characteristic of uniformly random data. I confirmed there is no plaintext file
table hiding anywhere inside them, and ruled out compression directly: no valid
zlib/gzip/xz/zstd/bzip2/lz4/lzfse stream exists at any offset, and the apparent
compression-magic hits are exactly the counts expected from random data.

Entropy at 8.0 bits/byte is consistent with **encryption, and equally consistent
with strong compression** of already-incompressible data; entropy alone cannot
distinguish the two. The accompanying README for this build states it uses an
older keyset, which points to encryption, though that is not something I can
confirm from the file itself. Either way this tool reproduces the segments
byte-for-byte and attempts no decryption.

Note that the sample firmware bundled here is a **pre-release prototype build**
(`0.902`, well below the 1.00 retail baseline), not a retail image. Treat its
internals accordingly.

## Building packages: `pup5000-mk`

`pup5000-mk` is the inverse — it writes containers in both formats:

```sh
# PS Vita
./pup5000-mk fw.PUP 0x0204:ro.img 0x0302:data.img

# PS3
./pup5000-mk -f ps3 fw.PUP EBOOT.BIN=EBOOT.BIN data.img=data.img
```

Verified by round-trip: feeding the extractor's output back through the builder
and re-extracting gives **byte-identical payloads** for both formats
(`make roundtrip` checks the PS3 case continuously).

**What it cannot do:** the builder writes a correct *container*, but it does not
forge the digest table or the trailing signature. Those are keyed, and real
hardware verifies them — a Vita will reject a package whose digests and
signature don't check out no matter how well-formed the layout is. So a custom
PUU built here is useful for tooling, testing, and format work; it is not
installable. That boundary is the signature check, and it isn't something this
tool tries to work around.

Extracted files can be checked against the source at any time:

```sh
./pup5000 -o out -c -v PSP2UPDAT-0.902.PUP
#  sha256 50b5ea97dc2b63776eafcb167e451c365bcc74cfd9be1f6f5034a5cf911f48ac
```

The same digests come out of `sha256sum` on the extracted files.

## Not affiliated

Not affiliated with, endorsed by, or aware of Sony. No keys were harmed in the
making of this file.
