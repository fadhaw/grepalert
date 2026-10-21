#!/usr/bin/env bash
# Builds the release archives into dist/: both binaries for every platform,
# with the README, release notes, license and example configs, plus checksums.
#
#   VERSION=0.1.0 scripts/release.sh          # defaults to `git describe`
#   TARGETS="linux/amd64" SKIP_UI=1 scripts/release.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null | sed 's/^v//')}"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"
LDFLAGS="-s -w -X github.com/fadhaw/grepalert/internal/version.Version=${VERSION}"

# The dashboard embeds the web UI, so build it first.
if [ "${SKIP_UI:-}" != 1 ]; then
  (cd ui && npm ci --no-audit --no-fund && npm run build)
fi
if [ ! -f internal/dashboard/web/dist/index.html ]; then
  echo "the web UI is not built (internal/dashboard/web/dist); run without SKIP_UI=1" >&2
  exit 1
fi

archive_zip() { # dir name -> name.zip, with zip or Python
  if command -v zip >/dev/null; then (cd dist && zip -qr "$1.zip" "$1")
  else (cd dist && python3 -m zipfile -c "$1.zip" "$1" 2>/dev/null || python -m zipfile -c "$1.zip" "$1"); fi
}

rm -rf dist
mkdir -p dist
for target in $TARGETS; do
  os=${target%/*} arch=${target#*/} ext=""
  [ "$os" = windows ] && ext=.exe
  name="grepalert_${VERSION}_${os}_${arch}"
  dir="dist/$name"
  mkdir -p "$dir/examples"
  for cmd in grepalert-agent grepalert-dashboard; do
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" -o "$dir/$cmd$ext" "./cmd/$cmd"
  done
  cp README.md "$dir/"
  [ -f LICENSE ] && cp LICENSE "$dir/"
  [ -f "docs/releases/v$VERSION.md" ] && cp "docs/releases/v$VERSION.md" "$dir/RELEASE_NOTES.md"
  cp examples/agent.yaml examples/rules.yaml examples/dashboard.yaml examples/grepalert-agent.service "$dir/examples/"
  mkdir -p "$dir/examples/quickstart" && cp examples/quickstart/*.yaml "$dir/examples/quickstart/"
  chmod +x "$dir"/grepalert-*
  if [ "$os" = windows ]; then archive_zip "$name"; else tar -C dist -czf "dist/$name.tar.gz" "$name"; fi
  rm -rf "$dir"
  echo "built $name"
done
(cd dist && sha256sum grepalert_* > checksums.txt)
ls -l dist
