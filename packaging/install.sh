#!/bin/sh
# Installs TFPS on the machine it is run on. Run as root, from the repo root, with the
# musl binaries already built (see README, "Building").
#
# Everything here is idempotent: run it again to upgrade.
set -eu

BIN=target/x86_64-unknown-linux-musl/release
[ -x "$BIN/tfps" ] || { echo "build first: cargo build --release --target x86_64-unknown-linux-musl" >&2; exit 1; }

echo "1/4 compiling the XDP program against this kernel's BTF"
command -v clang >/dev/null || { echo "clang is required (apt install clang)" >&2; exit 1; }
command -v bpftool >/dev/null || { echo "bpftool is required (apt install linux-tools-common)" >&2; exit 1; }
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT   # set -eu means a clang/bpftool failure must not leak vmlinux.h
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$TMP/vmlinux.h"
cp ebpf/tfps_xdp.c "$TMP/"
( cd "$TMP" && clang -O2 -g -target bpf -c tfps_xdp.c -o tfps_xdp.o )

echo "2/4 installing binaries and the BPF object"
install -m755 "$BIN/tfps" "$BIN/tfps_ctl" /usr/local/bin/
install -D -m644 "$TMP/tfps_xdp.o" /usr/local/lib/tfps/tfps_xdp.o

echo "3/4 installing the unit and, only if absent, a starting configuration"
install -D -m644 packaging/tfps.service /etc/systemd/system/tfps.service
[ -f /etc/tfps/config.json ] || install -D -m600 packaging/config.example.json /etc/tfps/config.json

echo "4/4 starting"
systemctl daemon-reload
systemctl enable tfps
# `enable --now` does nothing when the service is already up, so an upgrade would install
# the new binary and leave the old process running — with the script reporting success.
systemctl restart tfps
sleep 2
systemctl --no-pager --lines=0 status tfps || true
echo
echo "Done. Watch it work:   journalctl -u tfps -f"
echo "Ask it what it knows:  tfps_ctl status"
