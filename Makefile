# IOC Scanner - Ransomware Threat Detection Tool
# Makefile

CC = gcc
CFLAGS = -O2 -Wall -Wextra -std=c11
LDFLAGS = -lssl -lcrypto
TARGET = ioc_scanner
SRC = ioc_scanner.c

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(TARGET)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET)

# Run a quick self-test
test: $(TARGET)
	@echo "=== Creating test files ==="
	echo "test ransom note" > /tmp/test_RECOVER-FILES.txt
	echo "test" > /tmp/test_tomcat.exe
	echo "test" > /tmp/test.lockbit
	@echo "=== Running scan ==="
	./$(TARGET) -q /tmp/ 2>&1 || true
	@echo "=== Cleaning up ==="
	rm -f /tmp/test_RECOVER-FILES.txt /tmp/test_tomcat.exe /tmp/test.lockbit
	@echo "=== Test complete ==="
