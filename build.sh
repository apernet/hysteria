#!/bin/bash

# Hysteria local build script for Linux

# Change these to whatever you want
platforms=("windows/amd64" "linux/amd64" "darwin/amd64")
ldflags="-s -w"

if ! [ -x "$(command -v go)" ]; then
    echo 'Error: go is not installed.' >&2
    exit 1
fi

mkdir -p build
rm -rf build/*

echo "Starting build..."

for platform in "${platforms[@]}"; do
    GOOS=${platform%/*}
    GOARCH=${platform#*/}
    echo "Building $GOOS/$GOARCH"
    output="build/hysteria-$GOOS-$GOARCH"
    if [ $GOOS = "windows" ]; then
        output="$output.exe"
    fi
    env GOOS=$GOOS GOARCH=$GOARCH go build -o $output -ldflags "$ldflags" ./cmd/
done

echo "Build complete."

ls -lh build/ | awk '{print $9, $5}'
