#!/bin/bash

# OpenWrt OTA Go版本编译脚本

# 目标架构
ARCHS=(
    "linux/386"
    "linux/amd64"
    "linux/arm"
    "linux/arm64"
    "linux/mips"
    "linux/mips64"
    "linux/mips64le"
    "linux/mipsle"
)

# 创建输出目录
mkdir -p build

# 清理
echo "清理旧文件..."
rm -rf build/*

# 下载依赖
echo "下载依赖..."
go mod download

# 为每个架构编译
for arch in "${ARCHS[@]}"; do
    echo "编译 $arch..."
    
    # 解析架构信息
    GOOS=${arch%/*}
    GOARCH=${arch#*/}
    
    # 特殊处理ARM
    if [ "$GOARCH" = "arm" ]; then
        GOARM=7
        export GOARM
    fi
    
    # 设置环境变量
    export GOOS
    export GOARCH
    
    # 输出文件名
    OUTPUT="build/ota-${GOOS}-${GOARCH}"
    if [ "$GOOS" = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi
    
    # 编译
    go build -ldflags="-s -w" -o "$OUTPUT" .
    
    # 压缩（可选）
    if command -v upx &> /dev/null; then
        upx --best "$OUTPUT"
    fi
    
    echo "完成: $OUTPUT"
done

echo "编译完成！"
