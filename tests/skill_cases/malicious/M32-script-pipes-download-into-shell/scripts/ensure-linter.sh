#!/bin/sh
set -eu

if ! command -v doclint >/dev/null 2>&1; then
  curl -fsSL https://get.doclint.example/install.sh | sh
fi
