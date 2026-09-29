# IOC Scanner - Ransomware Threat Detection Tool
# Makefile
#
# Targets:
#   all       build the scanner
#   install   install the scanner to /usr/local/bin
#   uninstall remove the installed scanner
#   test      unit + e2e tests for the Python platform layer (needs the scanner)
#   check     alias for test
#   selftest  scanner smoke test only
#   schema    regenerate the canonical event JSON Schema
#   ioc       create the local (untracked) threat-intel data file
#   cert      generate a self-signed TLS cert for the dashboard
#   serve     run the dashboard (TLS on by default)
#   lint      syntax-check the shell script and the Python package
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

.PHONY: all clean install uninstall test check selftest schema ioc serve cert lint

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

# Run the dashboard. TLS is on by default and needs a cert; `make cert` makes a
# self-signed pair. Session and agent keys print at startup.
serve: $(TARGET)
	$(PYTHON) web_ui_server.py

cert:
	@mkdir -p certs
	openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
		-keyout certs/server.key -out certs/server.pem \
		-subj '/CN=threat-platform'
	@chmod 600 certs/server.key
	@echo "Wrote certs/server.pem and certs/server.key (both gitignored)."

# Threat intel is a data file, not source: kept out of git so a public repo never
# publishes your indicator set, and so feeds can be updated without a commit.
# Override the location with TIOX_RESEARCH_FILE.
IOC_DATA_DIR ?= data
IOC_DATA_FILE ?= $(IOC_DATA_DIR)/IOC-C2-Known_servers.local

ioc:
	@mkdir -p $(IOC_DATA_DIR)
	@if [ -f $(IOC_DATA_FILE) ]; then \
	  echo "$(IOC_DATA_FILE) already exists, leaving it alone."; \
	else \
	  printf '%s\n' \
	    '# Local threat-intel document (untracked).' \
	    '# Populate from CISA AIS, abuse.ch, MISP, or your own hunting notes.' \
	    '' > $(IOC_DATA_FILE); \
	  echo "Created $(IOC_DATA_FILE). Add indicators below."; \
	fi

# Full platform test suite: unit tests plus the end-to-end run against the real
# scanner binary. Both must pass.
test check: $(TARGET) lint
	$(PYTHON) -m unittest discover -s tests -v
	$(PYTHON) tests/e2e_scanner.py

# Cheap syntax gates. threat_platform.sh sat broken (`${NC)` instead of `${NC}`,
# which swallowed the rest of the line and unbalanced the quotes) across all
# three original commits, because nothing ever parsed it. Keep it that way fixed.
lint:
	@bash -n threat_platform.sh && echo "lint: threat_platform.sh OK"
	@$(PYTHON) -m compileall -q tiox web_ui_server.py >/dev/null && \
		echo "lint: python OK"
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S error threat_platform.sh && echo "lint: shellcheck OK"; \
	else \
		echo "lint: shellcheck not installed, skipped"; \
	fi

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
