#!/bin/sh
set -eu
mkdir -p dist
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
  os=${target%/*}; arch=${target#*/}; suffix=""
  if [ "$os" = windows ]; then suffix=".exe"; fi
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -buildvcs=false -trimpath -ldflags='-s -w' -o "dist/relaynote-${os}-${arch}${suffix}" ./cmd/relaynote
done
