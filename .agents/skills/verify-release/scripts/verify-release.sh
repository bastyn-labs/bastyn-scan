#!/usr/bin/env bash
# Read-only check that release vX.Y.Z is published in all four places:
# the git tag, the GitHub release, the crates.io crate and the Homebrew formula.
# Prints PASS or FAIL per check. Exit 0 only if all four pass, 1 if any fails,
# 2 on a usage error or a missing tool.
set -u

REPO="BASTYN-labs/bastyn-scan"
TAP="BASTYN-labs/homebrew-tap"
CRATE="bastyn"
USER_AGENT="bastyn-verify-release (https://github.com/${REPO})"
ARCHIVES=(
  "aarch64-apple-darwin.tar.gz"
  "x86_64-apple-darwin.tar.gz"
  "aarch64-unknown-linux-musl.tar.gz"
  "x86_64-unknown-linux-musl.tar.gz"
  "x86_64-pc-windows-msvc.zip"
)
# Targets the Homebrew formula serves; Windows is not in it.
FORMULA_TARGETS=(
  "aarch64-apple-darwin"
  "x86_64-apple-darwin"
  "aarch64-unknown-linux-musl"
  "x86_64-unknown-linux-musl"
)

if [ $# -ne 1 ]; then
  echo "usage: verify-release.sh vX.Y.Z" >&2
  exit 2
fi
tag="$1"
case "$tag" in v*) ;; *) tag="v$tag" ;; esac
version="${tag#v}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "error: '$1' is not a final release version (expected vMAJOR.MINOR.PATCH)" >&2
  exit 2
fi
for tool in git gh curl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "error: '$tool' is required but not installed" >&2
    exit 2
  fi
done

failed=0
report() { # report <name> <status 0|1> <detail>
  if [ "$2" -eq 0 ]; then
    printf 'PASS  %-16s %s\n' "$1" "$3"
  else
    printf 'FAIL  %-16s %s\n' "$1" "$3"
    failed=1
  fi
}

check_tag() {
  local out
  out=$(git ls-remote --tags "https://github.com/${REPO}.git" "refs/tags/${tag}" 2>&1) || {
    report "git tag" 1 "git ls-remote failed: ${out}"
    return
  }
  if [ -n "$out" ]; then
    report "git tag" 0 "${tag} exists on ${REPO}"
  else
    report "git tag" 1 "${tag} not found on ${REPO}"
  fi
}

check_release() {
  local info draft names missing=""
  info=$(gh release view "$tag" --repo "$REPO" --json isDraft,assets \
    --jq '[.isDraft, (.assets[].name)] | @tsv' 2>&1) || {
    report "github release" 1 "no release for ${tag}: ${info}"
    return
  }
  draft=$(printf '%s' "$info" | cut -f1)
  names=$(printf '%s' "$info" | tr '\t' '\n' | tail -n +2)
  if [ "$draft" = "true" ]; then
    report "github release" 1 "${tag} is still a draft"
    return
  fi
  local suffix
  for suffix in "${ARCHIVES[@]}"; do
    local archive="bastyn-${tag}-${suffix}"
    local checksum="bastyn-${tag}-${suffix%.tar.gz}"
    checksum="${checksum%.zip}.sha256"
    printf '%s\n' "$names" | grep -Fxq "$archive" || missing="${missing} ${archive}"
    printf '%s\n' "$names" | grep -Fxq "$checksum" || missing="${missing} ${checksum}"
  done
  if [ -z "$missing" ]; then
    report "github release" 0 "published, ${#ARCHIVES[@]} archives with checksums"
  else
    report "github release" 1 "missing assets:${missing}"
  fi
}

check_crate() {
  local body status
  body=$(curl -sS -A "$USER_AGENT" -w '\n%{http_code}' \
    "https://crates.io/api/v1/crates/${CRATE}/${version}" 2>&1) || {
    report "crates.io" 1 "request failed: ${body}"
    return
  }
  status=$(printf '%s' "$body" | tail -n 1)
  if [ "$status" != "200" ]; then
    report "crates.io" 1 "${CRATE} ${version} not found (HTTP ${status})"
  elif printf '%s' "$body" | grep -Eq '"yanked": ?true'; then
    report "crates.io" 1 "${CRATE} ${version} is yanked"
  else
    report "crates.io" 0 "${CRATE} ${version} published"
  fi
}

check_homebrew() {
  local formula missing="" target url
  formula=$(gh api -H "Accept: application/vnd.github.raw" \
    "repos/${TAP}/contents/Formula/${CRATE}.rb" 2>&1) || {
    report "homebrew" 1 "cannot read Formula/${CRATE}.rb: ${formula}"
    return
  }
  for target in "${FORMULA_TARGETS[@]}"; do
    url="https://github.com/${REPO}/releases/download/${tag}/bastyn-${tag}-${target}.tar.gz"
    printf '%s\n' "$formula" | grep -Fq "\"${url}\"" || missing="${missing} ${target}"
  done
  if [ -z "$missing" ]; then
    report "homebrew" 0 "formula names ${tag} for ${#FORMULA_TARGETS[@]} targets"
  else
    report "homebrew" 1 "formula does not name ${tag} for:${missing}"
  fi
}

check_tag
check_release
check_crate
check_homebrew

if [ "$failed" -eq 0 ]; then
  echo "RESULT: PASS (${tag} is published in all four places)"
  exit 0
fi
echo "RESULT: FAIL (${tag} is not fully published)"
exit 1
