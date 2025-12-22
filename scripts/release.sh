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

# Build embedded node binaries for controller downloads.
echo "Building embedded node binaries..."
VERSION="${VERSION}" ./scripts/build_nodes.sh
cp -f cmd/controller/dist/arouter-* "$OUT_DIR"/

# Build front-end and prepare embed assets
echo "Building front-end..."
(cd web && npm install && npm run build)
if [ ! -d "cmd/controller/web/dist" ]; then
  echo "front-end build output not found at cmd/controller/web/dist"
  exit 1
fi
tar -czf "${OUT_DIR}/web-dist.tar.gz" -C cmd/controller/web dist

build_one() {
  OS=$1; ARCH=$2
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

# Build & push Docker (controller) if docker is available
PUBLISH_DOCKER="${PUBLISH_DOCKER:-1}"
DOCKER_IMAGE="${DOCKER_IMAGE:-24802117/arouter}"
if [ "$PUBLISH_DOCKER" != "0" ] && command -v docker >/dev/null 2>&1; then
  echo "Building and pushing Docker image ${DOCKER_IMAGE}:${VERSION} (and :latest)..."
  docker buildx build --platform linux/amd64,linux/arm64 -t "${DOCKER_IMAGE}:${VERSION}" -t "${DOCKER_IMAGE}:latest" --build-arg BUILD_VERSION="${VERSION}" --push .
else
  echo "Skip Docker publish (PUBLISH_DOCKER=${PUBLISH_DOCKER}, docker command not found?)."
fi

echo "Done. Published files:"
ls -l "$OUT_DIR"
