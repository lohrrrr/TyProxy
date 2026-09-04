export PATH := $(HOME)/.cargo/bin:$(PATH)

APP_NAME := typroxy
DIST_DIR := dist

TARGET_LINUX        := x86_64-unknown-linux-gnu
TARGET_WINDOWS      := x86_64-pc-windows-gnu
TARGET_DARWIN       := aarch64-apple-darwin
TARGET_DARWIN_INTEL := x86_64-apple-darwin
TARGET_BSD          := x86_64-unknown-freebsd

.PHONY: all linux windows darwin darwin-intel bsd clean

all: linux windows darwin darwin-intel bsd

linux:
	mkdir -p $(DIST_DIR)
	cargo build --release --target $(TARGET_LINUX)
	cp target/$(TARGET_LINUX)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-linux-amd64

windows:
	mkdir -p $(DIST_DIR)
	cargo build --release --target $(TARGET_WINDOWS)
	cp target/$(TARGET_WINDOWS)/release/$(APP_NAME).exe $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe

darwin:
	mkdir -p $(DIST_DIR)
	cargo zigbuild --release --target $(TARGET_DARWIN)
	cp target/$(TARGET_DARWIN)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-darwin-arm64

darwin-intel:
	mkdir -p $(DIST_DIR)
	cargo zigbuild --release --target $(TARGET_DARWIN_INTEL)
	cp target/$(TARGET_DARWIN_INTEL)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-darwin-amd64

bsd:
	mkdir -p $(DIST_DIR)
	cargo build --release --target $(TARGET_BSD)
	cp target/$(TARGET_BSD)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-freebsd-amd64

clean:
	cargo clean
	rm -rf $(DIST_DIR)
