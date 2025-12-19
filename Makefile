# Makefile for OTA Pay System

.PHONY: all build build-server build-client test lint clean release

# 项目信息
PROJECT_NAME := ota-pay-system
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.GitCommit=$(GIT_COMMIT)'

# Go 参数
GO := go
GOFLAGS := -trimpath
GOBUILD := $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)"

# 目标架构列表
ARCH_LIST := amd64 arm64 riscv64 s390x ppc64le mips mipsle mips64 mips64le
OS_LIST := linux darwin windows

# 输出目录
OUTPUT_DIR := dist

all: build

# 构建所有目标
build: build-server build-client

# 构建服务器
build-server:
	@echo "Building OTA server..."
	$(GOBUILD) -o $(OUTPUT_DIR)/ota-server ./cmd/server

# 构建客户端
build-client:
	@echo "Building OTA client..."
	$(GOBUILD) -o $(OUTPUT_DIR)/ota-client ./cmd/client

# 交叉编译所有架构
cross-build: clean
	@echo "Cross-compiling for multiple architectures..."
	@mkdir -p $(OUTPUT_DIR)
	@for arch in $(ARCH_LIST); do \
		echo "Building for linux/$$arch..."; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $(OUTPUT_DIR)/ota-server-linux-$$arch ./cmd/server; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $(OUTPUT_DIR)/ota-client-linux-$$arch ./cmd/client; \
	done
	@echo "Cross-compilation completed!"

# OpenWrt 特定架构编译
build-openwrt:
	@echo "Building for OpenWrt architectures..."
	@mkdir -p $(OUTPUT_DIR)/openwrt
	@# x86_64
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(OUTPUT_DIR)/openwrt/ota-x86_64 ./cmd/client
	@# ARM
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $(OUTPUT_DIR)/openwrt/ota-armv7 ./cmd/client
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(OUTPUT_DIR)/openwrt/ota-aarch64 ./cmd/client
	@# MIPS
	GOOS=linux GOARCH=mipsle GOMIPS=softfloat $(GOBUILD) -o $(OUTPUT_DIR)/openwrt/ota-mipsel ./cmd/client
	GOOS=linux GOARCH=mips GOMIPS=softfloat $(GOBUILD) -o $(OUTPUT_DIR)/openwrt/ota-mips ./cmd/client
	@echo "OpenWrt builds completed!"

# 使用 UPX 压缩
compress:
	@echo "Compressing binaries with UPX..."
	@which upx >/dev/null 2>&1 || (echo "UPX not found, installing..."; apt-get update && apt-get install -y upx)
	@for bin in $(OUTPUT_DIR)/*; do \
		if [ -f $$bin ] && [ -x $$bin ]; then \
			echo "Compressing $$bin..."; \
			upx --best --lzma $$bin 2>/dev/null || true; \
		fi; \
	done

# 运行测试
test:
	@echo "Running tests..."
	$(GO) test ./... -v -race -coverprofile=coverage.out

# 代码检查
lint:
	@echo "Running linters..."
	@which golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	golangci-lint run ./...

# 清理
clean:
	@echo "Cleaning up..."
	rm -rf $(OUTPUT_DIR) coverage.out

# 安装依赖
deps:
	@echo "Installing dependencies..."
	$(GO) mod download
	$(GO) mod verify

# 生成文档
docs:
	@echo "Generating documentation..."
	$(GO) doc ./...

# 显示帮助
help:
	@echo "Available commands:"
	@echo "  make build           - 构建服务器和客户端"
	@echo "  make build-server    - 仅构建服务器"
	@echo "  make build-client    - 仅构建客户端"
	@echo "  make cross-build     - 交叉编译多架构"
	@echo "  make build-openwrt   - 编译 OpenWrt 架构"
	@echo "  make compress        - 使用 UPX 压缩"
	@echo "  make test           - 运行测试"
	@echo "  make lint           - 代码检查"
	@echo "  make clean          - 清理构建文件"
	@echo "  make deps           - 安装依赖"
	@echo "  make docs           - 生成文档"

# Docker 构建
docker-build:
	@echo "Building Docker image..."
	docker build -t ota-pay-system:$(VERSION) -f Dockerfile .

# 发布准备
release: clean build-openwrt compress
	@echo "Release build completed!"
	@ls -la $(OUTPUT_DIR)/openwrt/
