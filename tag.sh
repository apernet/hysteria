#!/usr/bin/env bash

set -e

# Release tagging script for Linux

# Usage:
#   ./tag.sh <version>

if ! [ -x "$(command -v git)" ]; then
    echo 'Error: git is not installed.' >&2
    exit 1
fi
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo 'Error: not in a git repository.' >&2
    exit 1
fi

if [ "$#" -eq 0 ]; then
    echo "Error: no version argument given." >&2
    exit 1
fi
if ! [[ $1 =~ ^[v]?[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Error: invalid version argument." >&2
    exit 1
fi
if ! [[ $1 =~ ^[v] ]]; then
    version="v$1"
else
    version="$1"
fi

tags=($version "app/$version" "core/$version")

for tag in "${tags[@]}"; do
    echo "Tagging $tag..."
    git tag "$tag"
done

echo "Done."
