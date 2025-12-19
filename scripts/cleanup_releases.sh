#!/usr/bin/env bash
set -euo pipefail

# 删除名称中不含两个及以上点号的 GitHub Releases 与对应 tag（用于清理 vYYYYMMDDHHMM 等自动版本）
# 需要 gh CLI 已登录，并在仓库根目录运行

REPO="NiuStar/arouter"

command -v gh >/dev/null 2>&1 || { echo "gh CLI required"; exit 1; }

echo "Fetching releases from $REPO ..."
tags=()

# 优先用 gh api（包含 Draft），失败回退 release list
resp=$(gh api "repos/${REPO}/releases?per_page=200" 2>/dev/null || true)
echo "gh api raw response (trimmed):"
echo "$resp" | head -n 5
if [ -n "${resp}" ]; then
  echo "Parsing gh api response..."
  # 如果 jq 可用，直接解析
  if command -v jq >/dev/null 2>&1; then
    while IFS= read -r tag; do
      [ -n "$tag" ] && tags+=("$tag")
    done <<<"$(echo "$resp" | jq -r '.[].tag_name' 2>/dev/null || true)"
  fi
  # jq 不可用或解析失败时，退回 sed
  if [ ${#tags[@]} -eq 0 ]; then
    while IFS= read -r line; do
      tag=$(echo "$line" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]\+\)".*/\1/p')
      if [ -n "$tag" ]; then
        tags+=("$tag")
      fi
    done <<<"$(echo "$resp" | tr -d '\r')"
  fi
fi

if [ ${#tags[@]} -eq 0 ]; then
  rel_list=$(gh release list --repo "$REPO" --limit 200 2>/dev/null || true)
  echo "gh release list output:"
  echo "$rel_list" | head -n 20
  if [ -n "${rel_list}" ]; then
    # 优先用 awk 第 1 列获取 tag
    echo "Parsing gh release list via awk..."
    tags=($(echo "$rel_list" | awk '{print $1}'))
    # 兜底逐行解析
    if [ ${#tags[@]} -eq 0 ]; then
      echo "Fallback parsing line by line..."
      while IFS= read -r line; do
        tag="${line%% *}"
        [ -n "$tag" ] && tags+=("$tag")
      done <<<"$rel_list"
    fi
  fi
fi

if [ ${#tags[@]} -eq 0 ]; then
  echo "No releases fetched (network/GH API unavailable?). Nothing to clean."
  exit 0
fi

# 规则：名称中点号数量 < 2 则删除
to_delete=()
for t in "${tags[@]}"; do
  dots=${t//[^.]}
  dot_count=${#dots}
  if [ "$dot_count" -lt 2 ]; then
    to_delete+=("$t")
  fi
done

echo "Fetched ${#tags[@]} releases/tags. Matching for cleanup: ${#to_delete[@]}"
echo "All fetched tags: ${tags[*]}"

if [ ${#to_delete[@]} -eq 0 ]; then
  echo "No matching releases to delete. Tags fetched: ${tags[*]}"
  exit 0
fi

echo "Releases to delete:"
printf '  %s\n' "${to_delete[@]}"

read -r -p "Proceed to delete these releases and tags? [y/N] " ans
case "$ans" in
  y|Y|yes|YES) ;;
  *) echo "Cancelled."; exit 0 ;;
esac

for r in "${to_delete[@]}"; do
  echo "Deleting release $r ..."
  gh release delete "$r" -y --repo "$REPO" || true
  echo "Deleting tag $r ..."
  git tag -d "$r" 2>/dev/null || true
  git push --delete origin "$r" 2>/dev/null || true
done

echo "Done."
