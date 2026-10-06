# The PlayStation PUP extractor 5000

CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -Wpedantic -Wshadow
LDFLAGS ?=

PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin

EXTRACT := pup5000
BUILDER := pup5000-mk
BINS    := $(EXTRACT) $(BUILDER)
TEST    := PSP2UPDAT-0.902.PUP

.PHONY: all clean test check roundtrip install uninstall

all: $(BINS)

$(EXTRACT): pup5000.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(BUILDER): pup5000-mk.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# checksum implementation sanity check (no package needed)
check: $(BINS)
	./$(EXTRACT) --selftest

# build a package from scratch and read it back with the extractor
roundtrip: $(BINS)
	@rm -rf .rt && mkdir -p .rt
	@printf 'hello from the year 2006\n' > .rt/EBOOT.BIN
	@printf 'second payload' > .rt/data.img
	./$(BUILDER) -f ps3 .rt/test.pup EBOOT.BIN=.rt/EBOOT.BIN data.img=.rt/data.img
	./$(EXTRACT) -o .rt/out .rt/test.pup
	@cmp .rt/EBOOT.BIN .rt/out/EBOOT.BIN && echo "roundtrip ok: EBOOT.BIN"
	@cmp .rt/data.img  .rt/out/data.img  && echo "roundtrip ok: data.img"
	@rm -rf .rt

# full run against the sample firmware, when it is present
test: check
	@test -f "$(TEST)" || { echo "skipping: $(TEST) not present"; exit 0; }
	./$(EXTRACT) -l "$(TEST)"
	./$(EXTRACT) -o out -c "$(TEST)"
	@echo "--- extracted ---"
	@ls -l out
	@echo "--- verifying ---"
	@for f in out/*; do \
		printf '%s  ' "$$(sha256sum "$$f" | cut -d' ' -f1)"; \
		echo "$$f"; \
	done

install: $(BINS)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(EXTRACT) $(DESTDIR)$(BINDIR)/$(EXTRACT)
	install -m 755 $(BUILDER) $(DESTDIR)$(BINDIR)/$(BUILDER)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(EXTRACT) $(DESTDIR)$(BINDIR)/$(BUILDER)

clean:
	rm -f $(BINS)
	rm -rf out .rt
