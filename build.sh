#!/usr/bin/env bash

set -e

# Hysteria build script for Linux
# Environment variable options:
#   - HY_APP_VERSION: App version
#   - HY_APP_COMMIT: App commit hash
#   - HY_APP_PLATFORMS: Platforms to build for (e.g. "windows/amd64,linux/amd64,darwin/amd64")

export LC_ALL=C
export LC_DATE=C

has_command() {
    local cmd="$1"
    type -P "$cmd" > /dev/null 2>&1
}

if ! has_command go; then
    echo 'Error: go is not installed.' >&2
    exit 1
fi

if ! has_command git; then
    echo 'Error: git is not installed.' >&2
    exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo 'Error: not in a git repository.' >&2
    exit 1
fi


platform_to_env() {
    local os="$1"
    local arch="$2"
    local env="GOOS=$os GOARCH=$arch CGO_ENABLED=0"

    case "$arch" in
    arm)
        env+=" GOARM=7 GOARCH=arm"
        ;;
    armv5)
        env+=" GOARM=5 GOARCH=arm"
        ;;
    armv6)
        env+=" GOARM=6 GOARCH=arm"
        ;;
    armv7)
        env+=" GOARM=7 GOARCH=arm"
        ;;
    mips | mipsle)
        env+=" GOMIPS="
        ;;
    mips-sf)
        env+=" GOMIPS=softfloat GOARCH=mips"
        ;;
    mipsle-sf)
        env+=" GOMIPS=softfloat GOARCH=mipsle"
        ;;
    amd64)
        env+=" GOAMD64= GOARCH=amd64"
        ;;
    amd64-avx)
        env+=" GOAMD64=v3 GOARCH=amd64"
        ;;
    esac

    echo "$env"
}

make_ldflags() {
    local ldflags="-s -w -X 'main.appDate=$(date -u '+%F %T')'"
    if [ -n "$HY_APP_VERSION" ]; then
        ldflags="$ldflags -X 'main.appVersion=$HY_APP_VERSION'"
    else
        ldflags="$ldflags -X 'main.appVersion=$(git describe --tags --always --match 'v*')'"
    fi
    if [ -n "$HY_APP_COMMIT" ]; then
        ldflags="$ldflags -X 'main.appCommit=$HY_APP_COMMIT'"
    else
        ldflags="$ldflags -X 'main.appCommit=$(git rev-parse HEAD)'"
    fi
    echo "$ldflags"
}

build_for_platform() {
    local platform="$1"
    local ldflags="$2"

    local GOOS="${platform%/*}"
    local GOARCH="${platform#*/}"
    if [[ -z "$GOOS" || -z "$GOARCH" ]]; then
        echo "Invalid platform $platform" >&2
        return 1
    fi
    echo "Building $GOOS/$GOARCH"
    local output="build/hysteria-$GOOS-$GOARCH"
    if [[ "$GOOS" = "windows" ]]; then
        output="$output.exe"
    fi
    local envs="$(platform_to_env "$GOOS" "$GOARCH")"
    local exit_val=0
    env $envs go build -o "$output" -tags=gpl -ldflags "$ldflags" -trimpath ./app/cmd/ || exit_val=$?
    if [[ "$exit_val" -ne 0 ]]; then
        echo "Error: failed to build $GOOS/$GOARCH" >&2
        return $exit_val
    fi
}


if [ -z "$HY_APP_PLATFORMS" ]; then
    HY_APP_PLATFORMS="$(go env GOOS)/$(go env GOARCH)"
fi
platforms=(${HY_APP_PLATFORMS//,/ })
ldflags="$(make_ldflags)"

mkdir -p build
rm -rf build/*

echo "Starting build..."

for platform in "${platforms[@]}"; do
    build_for_platform "$platform" "$ldflags"
done

echo "Build complete."

ls -lh build/ | awk '{print $9, $5}'
