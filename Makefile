# IOC Scanner - Ransomware Threat Detection Tool
# Makefile
#
# Targets:
#   all       build the scanner
#   test      unit + e2e tests for the Python platform layer (needs the scanner)
#   check     alias for test
#   selftest  scanner smoke test only
#   schema    regenerate the canonical event JSON Schema
#   clean     remove build artifacts
#
# The scanner exits 0 (clean), 2 (threats found), 1 (usage/IO error). Anything
# that branches on scan results must use that, which is why the old `|| true`
# in this file is gone: it hid exactly the bug it should have caught.

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lssl -lcrypto
TARGET = ioc_scanner
SRC = ioc_scanner.c
PYTHON ?= python3

.PHONY: all clean install uninstall test check selftest schema

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Regenerate the canonical event schema from the dataclass.
schema:
	$(PYTHON) -m tiox.schemas.jsonschema

# Full platform test suite: unit tests plus the end-to-end run against the real
# scanner binary. Both must pass.
test check: $(TARGET)
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) tests/e2e_scanner.py

# Scanner-only smoke test: confirms a known-bad filename fires and that the
# documented non-zero exit code actually propagates.
selftest: $(TARGET)
	@echo "=== Creating test files ==="
	@mkdir -p /tmp/ioc_selftest
	echo "test ransom note" > /tmp/ioc_selftest/RECOVER-FILES.txt
	echo "clean" > /tmp/ioc_selftest/clean.txt
	@echo "=== Running scan (expect exit 2) ==="
	@./$(TARGET) -q /tmp/ioc_selftest; \
	 rc=$$?; \
	 if [ "$$rc" -eq 2 ]; then \
	   echo "PASS: exit code 2 as documented"; \
	 else \
	   echo "FAIL: expected exit 2, got $$rc"; exit 1; \
	 fi
	@echo "=== Cleaning up ==="
	rm -rf /tmp/ioc_selftest
	@echo "=== Test complete ==="
