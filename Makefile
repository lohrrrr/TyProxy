# Название бинарного файла (при необходимости измените на имя из Cargo.toml)
APP_NAME ?= typroxy
DIST_DIR := dist
CARGO    ?= cargo

# Таргеты компиляции Rust
TARGET_LINUX   := x86_64-unknown-linux-gnu
TARGET_WINDOWS := x86_64-pc-windows-gnu
TARGET_DARWIN  := aarch64-apple-darwin
TARGET_DARWIN_INTEL := x86_64-apple-darwin
TARGET_BSD     := x86_64-unknown-freebsd

.PHONY: all linux windows darwin bsd clean help setup-targets

all: linux windows darwin bsd ## Собрать под все поддерживаемые платформы

setup-targets: ## Установить недостающие rustup таргеты
	@echo "[*] Проверка и установка таргетов rustup..."
	@rustup target add $(TARGET_LINUX) $(TARGET_WINDOWS) $(TARGET_DARWIN) $(TARGET_DARWIN_INTEL) $(TARGET_BSD)

$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

## -------------------------------------------------------------
## Linux
## -------------------------------------------------------------
linux: $(DIST_DIR) ## Сборка для Linux (x86_64)
	@echo "===> [1/4] Сборка для Linux ($(TARGET_LINUX))..."
	@rustup target add $(TARGET_LINUX) > /dev/null 2>&1 || true
	$(CARGO) build --release --target $(TARGET_LINUX)
	@cp target/$(TARGET_LINUX)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-linux-amd64
	@echo "[+] Готово: $(DIST_DIR)/$(APP_NAME)-linux-amd64"

## -------------------------------------------------------------
## Windows
## -------------------------------------------------------------
windows: $(DIST_DIR) ## Сборка для Windows (x86_64 .exe)
	@echo "===> [2/4] Сборка для Windows ($(TARGET_WINDOWS))..."
	@rustup target add $(TARGET_WINDOWS) > /dev/null 2>&1 || true
	$(CARGO) build --release --target $(TARGET_WINDOWS)
	@cp target/$(TARGET_WINDOWS)/release/$(APP_NAME).exe $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe
	@echo "[+] Готово: $(DIST_DIR)/$(APP_NAME)-windows-amd64.exe"

## -------------------------------------------------------------
## macOS (Darwin)
## -------------------------------------------------------------
darwin: $(DIST_DIR) ## Сборка для macOS (Apple Silicon M1/M2/M3)
	@echo "===> [3/4] Сборка для macOS ($(TARGET_DARWIN))..."
	@rustup target add $(TARGET_DARWIN) > /dev/null 2>&1 || true
	$(CARGO) build --release --target $(TARGET_DARWIN)
	@cp target/$(TARGET_DARWIN)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-darwin-arm64
	@echo "[+] Готово: $(DIST_DIR)/$(APP_NAME)-darwin-arm64"

darwin-intel: $(DIST_DIR) ## Сборка для macOS (Intel x86_64)
	@echo "===> Сборка для macOS Intel ($(TARGET_DARWIN_INTEL))..."
	@rustup target add $(TARGET_DARWIN_INTEL) > /dev/null 2>&1 || true
	$(CARGO) build --release --target $(TARGET_DARWIN_INTEL)
	@cp target/$(TARGET_DARWIN_INTEL)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-darwin-amd64
	@echo "[+] Готово: $(DIST_DIR)/$(APP_NAME)-darwin-amd64"

## -------------------------------------------------------------
## FreeBSD
## -------------------------------------------------------------
bsd: $(DIST_DIR) ## Сборка для FreeBSD (x86_64)
	@echo "===> [4/4] Сборка для FreeBSD ($(TARGET_BSD))..."
	@rustup target add $(TARGET_BSD) > /dev/null 2>&1 || true
	$(CARGO) build --release --target $(TARGET_BSD)
	@cp target/$(TARGET_BSD)/release/$(APP_NAME) $(DIST_DIR)/$(APP_NAME)-freebsd-amd64
	@echo "[+] Готово: $(DIST_DIR)/$(APP_NAME)-freebsd-amd64"

## -------------------------------------------------------------
## Очистка
## -------------------------------------------------------------
clean: ## Очистить скомпилированные артефакты и папку dist
	@echo "[*] Очистка артефактов..."
	@$(CARGO) clean
	@rm -rf $(DIST_DIR)
	@echo "[+] Очищено."

help: ## Показать справку по доступным командам
	@echo "Доступные команды для сборки:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'
