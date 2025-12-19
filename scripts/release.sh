#!/usr/bin/env bash
set -euo pipefail

# Build binaries and upload to GitHub Releases via gh CLI (uses current auth).
# Requirements:
# - gh CLI (authenticated) and git
# - Go toolchain

REPO="NiuStar/arouter"
# 东八区时间，精确到分钟，保持与镜像构建一致
VERSION="${VERSION:-$(TZ=Asia/Shanghai date +v%Y%m%d%H%M)}"
OUT_DIR="dist"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

# Build front-end and prepare embed assets
echo "Building front-end..."
(cd web && npm install && npm run build)
rm -rf cmd/controller/web/dist
mkdir -p cmd/controller/web
cp -r web/dist cmd/controller/web/dist
tar -czf "${OUT_DIR}/web-dist.tar.gz" -C web dist

build_one() {
  OS=$1; ARCH=$2
  BIN="${OUT_DIR}/arouter-${OS}-${ARCH}"
  echo "Building node binary $BIN"
  GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -ldflags "-X main.buildVersion=${VERSION}" -o "$BIN" .

  CTRL_BIN="${OUT_DIR}/arouter-controller-${OS}-${ARCH}"
  echo "Building controller binary $CTRL_BIN"
  GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -ldflags "-X main.buildVersion=${VERSION}" -o "$CTRL_BIN" ./cmd/controller
}

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64

assets=()
for f in ${OUT_DIR}/arouter-*; do
  if [ -f "$f" ]; then
    assets+=("$f")
  fi
done
if [ -f "${OUT_DIR}/web-dist.tar.gz" ]; then
  assets+=("${OUT_DIR}/web-dist.tar.gz")
fi

if [ ${#assets[@]} -eq 0 ]; then
  echo "no build artifacts found in ${OUT_DIR}, aborting release"
  exit 1
fi

command -v gh >/dev/null 2>&1 || { echo "gh CLI required"; exit 1; }

echo "Deleting existing release/tag if exists..."
gh release delete "$VERSION" -y --repo "$REPO" || true
git tag -d "$VERSION" 2>/dev/null || true
git tag "$VERSION"

echo "Creating release $VERSION"
gh release create "$VERSION" "${assets[@]}" --repo "$REPO" --title "$VERSION" --notes "Automated release $VERSION"

echo "Done. Published files:"
ls -l "$OUT_DIR"
