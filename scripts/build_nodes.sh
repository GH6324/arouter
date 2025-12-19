#!/usr/bin/env bash
set -euo pipefail

# Build node binaries for common OS/Arch targets into cmd/controller/dist.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/cmd/controller/dist"
PKG="${ROOT_DIR}"

mkdir -p "${OUT_DIR}"

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
)

for t in "${targets[@]}"; do
  read -r GOOS GOARCH <<<"${t}"
  out="${OUT_DIR}/arouter-${GOOS}-${GOARCH}"
  echo "==> Building ${out}"
  env CGO_ENABLED=0 GOOS="${GOOS}" GOARCH="${GOARCH}" \
    go build -trimpath -ldflags="-s -w" -o "${out}" "${PKG}"
done

echo "Done. Binaries are in ${OUT_DIR}"
