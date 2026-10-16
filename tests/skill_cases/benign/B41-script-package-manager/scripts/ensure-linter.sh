#!/bin/sh
set -eu

if ! command -v doclint >/dev/null 2>&1; then
  brew install doclint
fi
