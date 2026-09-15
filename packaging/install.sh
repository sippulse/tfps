#!/bin/sh
# Installs or upgrades TFPS on the machine it runs on.
#
#   One line, on the target, as root or with sudo:
#       curl -fsSL https://tfps.co/install.sh | sh
#
#   From a checkout (builds the binaries first if they are not there):
#       sudo ./packaging/install.sh
#
# Where the binaries come from, in order:
#   1. TFPS_TARBALL=<file or URL>   a release tarball you already have (air-gapped hosts,
#                                   or a build from another machine)
#   2. a checkout                   when run from inside the repository
#   3. the GitHub release           TFPS_VERSION=latest (default) or a tag such as v0.2.0
#   4. the source                   built here, only when the host can afford it
#
# Everything is idempotent: run it again to upgrade. /etc/tfps/config.json is written
# only when absent and is never overwritten. INSTALL.md has the long version.
set -eu

REPO="sippulse/tfps"
VERSION="${TFPS_VERSION:-latest}"
ASSET="tfps-x86_64-linux-musl"
MUSL_TARGET="x86_64-unknown-linux-musl"
BIN_DST=/usr/local/bin
OBJ_DST=/usr/local/lib/tfps/tfps_xdp.o
UNIT_DST=/etc/systemd/system/tfps.service
CONF_DST=/etc/tfps/config.json
# A source build on a small box can starve the softswitch it is meant to protect.
BUILD_MIN_MEM_MB=1500

say() { printf '%s\n' "$*"; }
die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

TMP=$(mktemp -d)
# set -eu means a failure anywhere must not leave the download or vmlinux.h behind.
trap 'rm -rf "$TMP"' EXIT INT TERM

# ---------------------------------------------------------------- 0. preflight
[ "$(uname -s)" = Linux ] || die "TFPS runs on Linux only"
[ "$(uname -m)" = x86_64 ] || die "the prebuilt binaries are x86_64; on $(uname -m) build from source (INSTALL.md)"
if [ "$(id -u)" -ne 0 ]; then
    die "run as root:  curl -fsSL https://tfps.co/install.sh | sudo sh"
fi
have curl || die "curl is required"
have systemctl && [ -d /run/systemd/system ] || die "systemd is required (the service is a systemd unit)"
[ -r /sys/kernel/btf/vmlinux ] || die "no /sys/kernel/btf/vmlinux: TFPS needs kernel 5.15 or newer built with BTF"
kver=$(uname -r | cut -d- -f1)
kmaj=${kver%%.*}; krest=${kver#*.}; kmin=${krest%%.*}
if [ "$kmaj" -lt 5 ] || { [ "$kmaj" -eq 5 ] && [ "$kmin" -lt 15 ]; }; then
    die "kernel $kver is too old: TFPS needs 5.15 or newer"
fi

# --------------------------------------------------------- 1. build tools for XDP
# The XDP program is compiled here, against this kernel's BTF, so clang and bpftool
# are needed on every install. They are installed only when missing.
os_id=$(. /etc/os-release 2>/dev/null && printf '%s' "${ID:-}")
apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null
}
pkg_install() {
    if have apt-get; then
        apt-get update -qq >/dev/null
        apt_install "$@"
    elif have dnf; then
        dnf install -y -q "$@" >/dev/null
    else
        die "install these yourself, then run again: $*"
    fi
}
if ! have clang || ! have bpftool; then
    say "installing clang and bpftool"
    if have apt-get; then
        if [ "$os_id" = ubuntu ]; then
            # Ubuntu ships bpftool inside the kernel-versioned tools package.
            pkg_install clang linux-tools-common "linux-tools-$(uname -r)"
        else
            pkg_install clang bpftool
        fi
    else
        pkg_install clang bpftool
    fi
    have clang || die "clang is still missing after the install"
    have bpftool || die "bpftool is still missing after the install"
fi

# ----------------------------------------------------------- 2. get the binaries
# On exit from this section: $SRC has ebpf/tfps_xdp.c and packaging/, $BIN has tfps and
# tfps_ctl, and $ORIGIN says where they came from, for the summary line.
SRC=""; BIN=""; ORIGIN=""

unpack_tarball() {
    # $1: tarball path. Layout: tfps-x86_64-linux-musl/{tfps,tfps_ctl,ebpf/,packaging/}
    mkdir -p "$TMP/rel"
    tar -xzf "$1" -C "$TMP/rel"
    SRC="$TMP/rel/$ASSET"
    BIN="$SRC"
    [ -x "$BIN/tfps" ] && [ -x "$BIN/tfps_ctl" ] && [ -f "$SRC/ebpf/tfps_xdp.c" ] \
        || die "the tarball does not have the expected layout ($ASSET/tfps, tfps_ctl, ebpf/tfps_xdp.c)"
}

fetch_release() {
    # Returns 1 quietly when there is no such release; the caller decides what next.
    if [ "$VERSION" = latest ]; then
        base="https://github.com/$REPO/releases/latest/download"
    else
        base="https://github.com/$REPO/releases/download/$VERSION"
    fi
    curl -fsSL -o "$TMP/$ASSET.tar.gz" "$base/$ASSET.tar.gz" 2>/dev/null || return 1
    curl -fsSL -o "$TMP/$ASSET.tar.gz.sha256" "$base/$ASSET.tar.gz.sha256" \
        || die "the release has a tarball but no checksum; refusing to install unverified binaries"
    ( cd "$TMP" && sha256sum -c --quiet "$ASSET.tar.gz.sha256" ) \
        || die "checksum mismatch on $ASSET.tar.gz"
    unpack_tarball "$TMP/$ASSET.tar.gz"
    ORIGIN="release $VERSION"
}

build_from_source() {
    # $1: directory with Cargo.toml. Builds the static musl binaries in place.
    mem_avail=$(awk '/MemAvailable/ {print int($2/1024)}' /proc/meminfo)
    if [ "$mem_avail" -lt "$BUILD_MIN_MEM_MB" ] && [ "${TFPS_FORCE_BUILD:-0}" != 1 ]; then
        die "only ${mem_avail} MB of memory is available and a Rust build wants more; a build here could starve
           the SIP service this host runs. Build on another machine and pass TFPS_TARBALL=<file>
           (INSTALL.md shows how), or set TFPS_FORCE_BUILD=1 if you accept the risk."
    fi
    have gcc || pkg_install gcc
    if have apt-get; then have musl-gcc || pkg_install musl-tools; fi
    have musl-gcc || die "musl-gcc is needed to build the static binaries (Debian/Ubuntu: apt install musl-tools)"
    cargo_bin=""
    for c in cargo "$HOME/.cargo/bin/cargo" /root/.cargo/bin/cargo; do
        if have "$c" || [ -x "$c" ]; then cargo_bin=$c; break; fi
    done
    if [ -z "$cargo_bin" ]; then
        say "installing a temporary Rust toolchain (nothing is left behind)"
        export CARGO_HOME="$TMP/cargo" RUSTUP_HOME="$TMP/rustup"
        curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal --no-modify-path \
            --target "$MUSL_TARGET" >/dev/null
        cargo_bin="$CARGO_HOME/bin/cargo"
    else
        "$(dirname "$cargo_bin")/rustup" target add "$MUSL_TARGET" >/dev/null 2>&1 || true
    fi
    say "building the static binaries (this takes a while on a small machine)"
    ( cd "$1" && "$cargo_bin" build --quiet --release --target "$MUSL_TARGET" )
    SRC="$1"
    BIN="$1/target/$MUSL_TARGET/release"
}

if [ -n "${TFPS_TARBALL:-}" ]; then
    case "$TFPS_TARBALL" in
        http://*|https://*)
            curl -fsSL -o "$TMP/$ASSET.tar.gz" "$TFPS_TARBALL" || die "could not download $TFPS_TARBALL"
            unpack_tarball "$TMP/$ASSET.tar.gz" ;;
        *)
            [ -f "$TFPS_TARBALL" ] || die "no such file: $TFPS_TARBALL"
            unpack_tarball "$TFPS_TARBALL" ;;
    esac
    ORIGIN="tarball $TFPS_TARBALL"
elif [ -f Cargo.toml ] && [ -f ebpf/tfps_xdp.c ] && [ -f packaging/tfps.service ]; then
    if [ -x "target/$MUSL_TARGET/release/tfps" ] && [ -x "target/$MUSL_TARGET/release/tfps_ctl" ]; then
        SRC=$(pwd); BIN="$SRC/target/$MUSL_TARGET/release"
    else
        build_from_source "$(pwd)"
    fi
    ORIGIN="checkout $(git rev-parse --short HEAD 2>/dev/null || echo '(not a git checkout)')"
elif fetch_release; then
    :
else
    if [ "$VERSION" != latest ]; then
        die "no release named $VERSION has a $ASSET.tar.gz asset"
    fi
    say "no release with prebuilt binaries yet; building from source"
    curl -fsSL -o "$TMP/src.tar.gz" "https://github.com/$REPO/archive/refs/heads/master.tar.gz" \
        || die "could not download the source"
    mkdir -p "$TMP/src" && tar -xzf "$TMP/src.tar.gz" -C "$TMP/src" --strip-components=1
    build_from_source "$TMP/src"
    ORIGIN="source (master)"
fi

# --------------------------------------------- 3. compile XDP against this kernel
say "1/4 compiling the XDP program against this kernel's BTF"
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"
cp "$SRC/ebpf/tfps_xdp.c" "$TMP/"
( cd "$TMP" && clang -O2 -g -target bpf -c tfps_xdp.c -o tfps_xdp.o )

# ------------------------------------------------------------------- 4. install
say "2/4 installing binaries and the BPF object"
install -m755 "$BIN/tfps" "$BIN/tfps_ctl" "$BIN_DST/"
install -D -m644 "$TMP/tfps_xdp.o" "$OBJ_DST"

say "3/4 installing the unit and, only if absent, a starting configuration"
install -D -m644 "$SRC/packaging/tfps.service" "$UNIT_DST"
[ -f "$CONF_DST" ] || install -D -m600 "$SRC/packaging/config.example.json" "$CONF_DST"

say "4/4 starting"
systemctl daemon-reload
systemctl enable -q tfps
# `enable --now` does nothing when the service is already up, so an upgrade would install
# the new binary and leave the old process running — with the script reporting success.
systemctl restart tfps
sleep 2
if systemctl -q is-active tfps; then
    say "tfps is running (from $ORIGIN)"
else
    systemctl --no-pager --lines=20 status tfps || true
    die "tfps did not come up; the unit's last lines are above"
fi
say ""
say "Watch it work:   journalctl -u tfps -f"
say "Ask it what it knows:  tfps_ctl status"
