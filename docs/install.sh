#!/bin/sh
# https://tfps.co/install.sh — the one-line installer.
#
#     curl -fsSL https://tfps.co/install.sh | sh
#
# This file only fetches the real installer (packaging/install.sh in the repository) and
# runs it as root, so the same script serves the one-liner, a checkout and a release
# tarball. Read that one to see what is installed and where.
set -eu

SCRIPT="https://raw.githubusercontent.com/sippulse/tfps/master/packaging/install.sh"

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || die "curl is required"

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM
curl -fsSL -o "$TMP" "$SCRIPT" || die "could not download $SCRIPT"

# Environment knobs (TFPS_VERSION, TFPS_TARBALL, TFPS_FORCE_BUILD) pass through sudo
# explicitly, because sudo resets the environment by default.
if [ "$(id -u)" -eq 0 ]; then
    sh "$TMP"; exit $?
fi
command -v sudo >/dev/null 2>&1 || die "not root and sudo is not available; run as root"
sudo env \
    ${TFPS_VERSION:+TFPS_VERSION="$TFPS_VERSION"} \
    ${TFPS_TARBALL:+TFPS_TARBALL="$TFPS_TARBALL"} \
    ${TFPS_FORCE_BUILD:+TFPS_FORCE_BUILD="$TFPS_FORCE_BUILD"} \
    sh "$TMP"
