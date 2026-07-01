#!/bin/bash
# DeepSentry 一键交叉编译

set -e

APP_NAME="deepsentry"
OUTPUT_DIR="build"
APP_VERSION="2.0"
BUILD_TIME="$(date '+%Y-%m-%d')"
LDFLAGS="-s -w -X 'ai-edr/internal/ui.Version=${APP_VERSION}' -X 'ai-edr/internal/ui.BuildTime=${BUILD_TIME}'"

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "🧹 清理旧产物（保留 config.yaml / reports / .env）..."
PRESERVE_DIR=$(mktemp -d)
if [[ -d "$OUTPUT_DIR" ]]; then
  for item in config.yaml reports .env; do
    [[ -e "$OUTPUT_DIR/$item" ]] && cp -a "$OUTPUT_DIR/$item" "$PRESERVE_DIR/"
  done
fi
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR/bin"
if [[ -d "$PRESERVE_DIR" ]]; then
  for item in config.yaml reports .env; do
    [[ -e "$PRESERVE_DIR/$item" ]] && cp -a "$PRESERVE_DIR/$item" "$OUTPUT_DIR/"
  done
  rm -rf "$PRESERVE_DIR"
fi

build_main() {
  local goos=$1 goarch=$2
  local out="$OUTPUT_DIR/${APP_NAME}-${goos}-${goarch}"
  [[ "$goos" == "windows" ]] && out="${out}.exe"

  echo "🔨 $goos/$goarch → $(basename "$out")"
  if [[ "$goos" == "windows" ]]; then
    env CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
      go build -ldflags "$LDFLAGS" -o "$out" \
      ./cmd/main.go ./cmd/usage.go ./cmd/survey_compat.go ./cmd/console_windows.go
  else
    env CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
      go build -ldflags "$LDFLAGS" -o "$out" \
      ./cmd/main.go ./cmd/usage.go ./cmd/survey_compat.go ./cmd/console_other.go
  fi
}

build_aux() {
  local name=$1 pkg=$2
  local goos=$3 goarch=$4
  local out="$OUTPUT_DIR/bin/${name}-${goos}-${goarch}"
  [[ "$goos" == "windows" ]] && out="${out}.exe"
  env CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
    go build -ldflags "$LDFLAGS" -o "$out" "$pkg"
}

platforms=(
  "darwin/amd64"
  "darwin/arm64"
  "linux/amd64"
  "linux/arm64"
  "linux/386"
  "windows/amd64"
  "windows/386"
)

echo "🏷  版本: v${APP_VERSION}  ·  Build Time: ${BUILD_TIME}"
echo "🚀 开始编译..."
echo "------------------------------------------"
for p in "${platforms[@]}"; do
  IFS=/ read -r goos goarch <<< "$p"
  build_main "$goos" "$goarch"
done

# 当前主机架构的 benchmark / smoke（便于本地评测）
HOST_OS=$(go env GOOS)
HOST_ARCH=$(go env GOARCH)
build_aux benchmark ./cmd/benchmark/main.go "$HOST_OS" "$HOST_ARCH"
build_aux smoke ./cmd/smoke/main.go "$HOST_OS" "$HOST_ARCH"
build_aux toolsmoke ./cmd/toolsmoke/main.go "$HOST_OS" "$HOST_ARCH"

# 本机快捷名称（避免记 darwin-arm64 等后缀）
cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}"* "$OUTPUT_DIR/bin/deepsentry" 2>/dev/null || \
  cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}.exe" "$OUTPUT_DIR/bin/deepsentry.exe" 2>/dev/null || true
cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}"* "$OUTPUT_DIR/deepsentry" 2>/dev/null || \
  cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}.exe" "$OUTPUT_DIR/deepsentry.exe" 2>/dev/null || true
cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}"* "$ROOT/deepsentry" 2>/dev/null || \
  cp "$OUTPUT_DIR/${APP_NAME}-${HOST_OS}-${HOST_ARCH}.exe" "$ROOT/deepsentry.exe" 2>/dev/null || true

echo "------------------------------------------"
echo "✅ 编译完成"
echo "💡 运行: cd build && ./deepsentry -c config.yaml"
echo "   或:   ./bin/deepsentry -c config.yaml"
ls -lh "$OUTPUT_DIR"
ls -lh "$OUTPUT_DIR/bin" 2>/dev/null || true
