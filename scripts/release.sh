#!/usr/bin/env bash
set -euo pipefail

# Build binaries and upload to GitHub Releases.
# Requirements:
# - gh CLI logged in with repo write (GH_TOKEN or gh auth login)
# - Go toolchain

REPO="NiuStar/arouter"
VERSION="${VERSION:-$(date +v%Y%m%d%H%M%S)}"
OUT_DIR="dist"

rm -rf "$OUT_DIR"
mkdir -p "$OUT_DIR"

build_one() {
  OS=$1; ARCH=$2
  BIN="${OUT_DIR}/arouter-${OS}-${ARCH}"
  echo "Building $BIN"
  GOOS=$OS GOARCH=$ARCH CGO_ENABLED=0 go build -o "$BIN" ./...
}

build_one linux amd64
build_one linux arm64
build_one darwin amd64
build_one darwin arm64

echo "Deleting existing release/tag if exists..."
gh release delete "$VERSION" -y || true
git tag -d "$VERSION" 2>/dev/null || true
git tag "$VERSION"

echo "Creating release $VERSION"
gh release create "$VERSION" ${OUT_DIR}/arouter-* --latest --title "$VERSION" --notes "Automated release $VERSION"

echo "Done. Published files:"
ls -l "$OUT_DIR"
