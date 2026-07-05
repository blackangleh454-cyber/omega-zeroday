# OMEGA-ZERODAY HUNTER v2.0 — Build System
# C Engine compilation with OpenSSL + pthreads

CC = gcc
CFLAGS = -O2 -march=native -mtune=native \
         -std=c11 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
         -Wno-stringop-truncation -Wno-format-truncation \
         -Wno-sign-compare -Wno-unused-but-set-variable \
         -Wno-deprecated-declarations \
         -Iinclude
LDFLAGS = -lssl -lcrypto -lpthread -lm

SRC_DIR = src
BUILD_DIR = build
INCLUDE_DIR = include

SRCS = $(wildcard $(SRC_DIR)/*.c)
OBJS = $(patsubst $(SRC_DIR)/%.c, $(BUILD_DIR)/%.o, $(SRCS))
TARGET = $(BUILD_DIR)/omega-engine

.PHONY: all clean install test

all: $(TARGET)
	@echo "✅ Build complete: $(TARGET)"
	@echo "   Size: $$(ls -lh $(TARGET) | awk '{print $$5}')"
	@echo "   Binary: $(TARGET)"

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c $(INCLUDE_DIR)/omega.h | $(BUILD_DIR)
	@echo "  CC  $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJS)
	@echo "  LD  $@"
	@$(CC) $(OBJS) -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)
	@echo "🧹 Clean complete"

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/omega-engine
	@echo "✅ Installed: /usr/local/bin/omega-engine"

test: $(TARGET)
	@echo "🧪 Testing with --help..."
	@$(TARGET) --help
	@echo ""
	@echo "🧪 Testing with --version..."
	@$(TARGET) --version
