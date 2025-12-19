# OTA Pay System Makefile

.PHONY: all build build-server build-client test lint clean release help
.DEFAULT_GOAL := help

# 项目信息
PROJECT_NAME := ota-pay-system
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go 参数
GO := go
GOFLAGS := -trimpath
GOBUILD := $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)"
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.BuildTime=$(BUILD_TIME)' \
	-X 'main.GitCommit=$(GIT_COMMIT)'

# 目标架构
ARCH_LIST := amd64 arm64 arm riscv64 s390x ppc64le mips mipsle mips64 mips64le
OS_LIST := linux darwin windows

# 输出目录
DIST_DIR := dist
OUTPUT_DIR := $(DIST_DIR)/bin

# 帮助信息
help:
	@echo "OTA Pay System 构建工具"
	@echo ""
	@echo "可用命令:"
	@echo "  make build             构建客户端和服务器"
	@echo "  make build-server      构建服务器"
	@echo "  make build-client      构建客户端"
	@echo "  make cross-build       交叉编译所有架构"
	@echo "  make build-openwrt     编译 OpenWrt 版本"
	@echo "  make compress          使用 UPX 压缩二进制文件"
	@echo "  make test              运行测试"
	@echo "  make lint              代码检查"
	@echo "  make clean             清理构建文件"
	@echo "  make deps              安装依赖"
	@echo "  make docker-build      构建 Docker 镜像"
	@echo "  make release           发布版本构建"
	@echo ""

# 安装依赖
deps:
	@echo "安装依赖..."
	$(GO) mod download
	$(GO) mod verify
	@echo "✓ 依赖安装完成"

# 构建所有
all: build

# 构建客户端和服务器
build: deps build-server build-client

# 构建服务器
build-server:
	@echo "构建 OTA 服务器..."
	@mkdir -p $(OUTPUT_DIR)
	$(GOBUILD) -o $(OUTPUT_DIR)/ota-server ./cmd/server
	@echo "✓ 服务器构建完成: $(OUTPUT_DIR)/ota-server"

# 构建客户端
build-client:
	@echo "构建 OTA 客户端..."
	@mkdir -p $(OUTPUT_DIR)
	$(GOBUILD) -o $(OUTPUT_DIR)/ota ./cmd/client
	@echo "✓ 客户端构建完成: $(OUTPUT_DIR)/ota"

# 交叉编译
cross-build: deps clean
	@echo "交叉编译多架构..."
	@mkdir -p $(OUTPUT_DIR)
	@for arch in $(ARCH_LIST); do \
		echo "构建 linux/$$arch..."; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $(OUTPUT_DIR)/ota-linux-$$arch ./cmd/client; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -o $(OUTPUT_DIR)/ota-server-linux-$$arch ./cmd/server; \
	done
	@echo "✓ 交叉编译完成"

# OpenWrt 特定构建
build-openwrt: deps clean
	@echo "构建 OpenWrt 版本..."
	@mkdir -p $(DIST_DIR)/openwrt
	
	# 定义 OpenWrt 架构映射
	# 格式: 目标文件名:GOARCH:额外参数
	OPENWRT_TARGETS := \
		x86_64:amd64:: \
		aarch64:arm64:: \
		armv7:arm:7: \
		mips:mips:softfloat: \
		mipsel:mipsle:softfloat: \
		mips64:mips64:softfloat: \
		mips64el:mips64le:softfloat:
	
	@for target in $(OPENWRT_TARGETS); do \
		IFS=':' read -r name arch extra1 extra2 <<< "$$target"; \
		echo "构建 OpenWrt $$name..."; \
		GOOS=linux GOARCH=$$arch \
		$$([[ -n "$$extra1" ]] && echo "GOARM=$$extra1" || [[ -n "$$extra1" ]] && echo "GOMIPS=$$extra1") \
		$(GOBUILD) -o $(DIST_DIR)/openwrt/ota-$$name ./cmd/client; \
	done
	@echo "✓ OpenWrt 构建完成"

# 使用 UPX 压缩
compress:
	@echo "使用 UPX 压缩二进制文件..."
	@which upx >/dev/null 2>&1 || (echo "安装 UPX..."; sudo apt-get update && sudo apt-get install -y upx)
	@for bin in $(OUTPUT_DIR)/* $(DIST_DIR)/openwrt/* 2>/dev/null; do \
		if [ -f "$$bin" ] && [ -x "$$bin" ]; then \
			echo "压缩 $$bin..."; \
			upx --best --lzma "$$bin" 2>/dev/null || true; \
		fi; \
	done
	@echo "✓ 压缩完成"

# 运行测试
test:
	@echo "运行测试..."
	$(GO) test ./... -v -race -coverprofile=coverage.out
	@echo "✓ 测试完成"

# 代码检查
lint:
	@echo "运行代码检查..."
	@which golangci-lint >/dev/null 2>&1 || (echo "安装 golangci-lint..."; curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.54.2)
	golangci-lint run ./...
	@echo "✓ 代码检查完成"

# 清理
clean:
	@echo "清理构建文件..."
	rm -rf $(DIST_DIR) coverage.out
	$(GO) clean -cache
	@echo "✓ 清理完成"

# 构建 Docker 镜像
docker-build:
	@echo "构建 Docker 镜像..."
	docker build -t ota-server:$(VERSION) -f Dockerfile.server .
	docker build -t ota-client:$(VERSION) -f Dockerfile.client .
	@echo "✓ Docker 镜像构建完成"

# 发布版本
release: clean build-openwrt compress
	@echo "发布版本构建完成!"
	@echo "生成的文件:"
	@ls -la $(DIST_DIR)/openwrt/
	@echo ""
	@echo "版本信息:"
	@echo "  版本号: $(VERSION)"
	@echo "  构建时间: $(BUILD_TIME)"
	@echo "  Git提交: $(GIT_COMMIT)"
