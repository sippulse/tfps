# Installing TFPS

One line, on the machine that runs your SIP service:

```sh
curl -fsSL https://tfps.co/install.sh | sh
```

It asks for `sudo` if you are not root. Two minutes later `tfps` is running as a systemd
service, watching port 5060, and `tfps_ctl status` tells you what it has seen. Run the
same line again to upgrade. It never touches an existing `/etc/tfps/config.json`.

## What it needs

| requirement | why |
|---|---|
| Linux, x86_64 | the prebuilt binaries are static musl x86_64; other architectures build from source |
| kernel **5.15 or newer with BTF** (`/sys/kernel/btf/vmlinux` exists) | the XDP program is compiled against the running kernel |
| systemd | TFPS ships as a unit |
| root | it installs into `/usr/local`, `/etc/tfps` and `/etc/systemd/system` |
| `curl` | to fetch the release |
| `clang` and `bpftool` | to compile the XDP program; **installed for you** on Debian, Ubuntu and Fedora when missing |

Tested on Debian 12 and Ubuntu 24.04. Anything else with the kernel and systemd above
should work; the installer says exactly what is missing when it is not.

The daemon does not bind a UDP port, so your softswitch keeps its socket on 5060 and never
notices. Nothing in the installer changes your SIP service, your firewall or your routes.

## What the one line does

1. **Checks the host**: Linux, x86_64, root, systemd, kernel and BTF. It stops with a plain
   message when one is missing, before changing anything.
2. **Installs `clang` and `bpftool`** when they are not there, through `apt-get` or `dnf`.
3. **Gets the binaries**, from the first of these that applies:
   - `TFPS_TARBALL` — a release tarball you already have (see below);
   - the repository, when you run it from a checkout;
   - the **latest GitHub release**, verified against its published SHA-256;
   - the **source**, built on the spot — only when the host has memory to spare, because
     a Rust build on a small box can starve the SIP service the tool exists to protect.
4. **Compiles the XDP program** against this kernel's BTF, into
   `/usr/local/lib/tfps/tfps_xdp.o`.
5. **Installs** `tfps` and `tfps_ctl` into `/usr/local/bin`, the unit into
   `/etc/systemd/system/tfps.service`, and a starting `/etc/tfps/config.json` **only if
   there is none**.
6. **Starts** the service (a restart on upgrade, so the new binary is the one running) and
   prints where it came from.

The whole script is [`packaging/install.sh`](packaging/install.sh). The URL above serves a
short bootstrap that fetches it and runs it as root, so that reading one file tells you
everything the one-liner does.

## Right after installing

```sh
journalctl -u tfps -f      # watch it decide, live
tfps_ctl status            # what it has learned, what is blocked
```

The first lines in the journal are the startup report: the interface it chose, the ports it
watches, the exemptions it applied (your host's own addresses are always among them) and
whether enforcement is **ACTIVE**. If the report says enforcement is INACTIVE, the unit's
capabilities did not suffice on this kernel; `packaging/tfps.service` explains which ones
and why.

To **observe without blocking** for the first days, give the daemon `--no-enforce` through a
systemd drop-in rather than editing the unit the installer will overwrite on upgrade:

```sh
systemctl edit tfps
```

```ini
[Service]
ExecStart=
ExecStart=/usr/local/bin/tfps --no-enforce
```

Every verdict is still printed, as `WOULD BLOCK`, so you can read what it would have done.
Remove the drop-in to enforce.

Configuration lives in `/etc/tfps/config.json`; every field is optional and the README's
"Configuration" section describes each one. Restart after editing: `systemctl restart tfps`.

## Pinning a version

```sh
curl -fsSL https://tfps.co/install.sh | TFPS_VERSION=v0.2.0 sh
```

`TFPS_VERSION` is a tag from the [releases page](https://github.com/sippulse/tfps/releases).
The default is `latest`.

## Installing from a tarball you already have

For hosts without Internet access, or when you build on one machine and install on many:

```sh
curl -fsSL https://tfps.co/install.sh | TFPS_TARBALL=/root/tfps-x86_64-linux-musl.tar.gz sh
```

`TFPS_TARBALL` may also be a URL. The tarball is the release artefact,
`tfps-x86_64-linux-musl.tar.gz`, with this layout:

```
tfps-x86_64-linux-musl/
  tfps  tfps_ctl
  ebpf/tfps_xdp.c
  packaging/tfps.service  config.example.json  install.sh
```

To build one yourself, see "Building" in the README, then package the same layout. The
release workflow in [`.github/workflows/release.yml`](.github/workflows/release.yml) does
exactly that and is the reference.

## From a checkout

```sh
git clone https://github.com/sippulse/tfps.git
cd tfps
sudo ./packaging/install.sh
```

If the static binaries are already built (`cargo build --release --target
x86_64-unknown-linux-musl`), they are installed as they are; otherwise the script builds
them first, which needs `musl-tools` (or the zig alternative in the README) and a Rust
toolchain. When no toolchain is installed it fetches a temporary one into the script's own
temp directory and removes it afterwards.

## Upgrading

Run the one line again. Binaries, XDP object and unit are replaced; the configuration and
the database in `/var/lib/tfps` are kept. The service is restarted, so the new binary is the
one running, and the learned state and audit log survive the restart. Learned state is only
discarded on an incompatible schema change, which the daemon announces at startup; the audit
log survives even that.

## Uninstalling

```sh
systemctl disable --now tfps
rm -f /etc/systemd/system/tfps.service /usr/local/bin/tfps /usr/local/bin/tfps_ctl
rm -rf /usr/local/lib/tfps
systemctl daemon-reload
```

Keep or remove the state and configuration as you prefer:

```sh
rm -rf /var/lib/tfps /etc/tfps
```

Stopping the service removes the XDP program from the interface, so no block outlives it.

## When something is off

- **`no /sys/kernel/btf/vmlinux`** — the kernel was built without BTF or is older than
  5.15. Distribution kernels from Debian 11, Ubuntu 22.04 and later have it.
- **`bpftool` cannot be installed on Ubuntu** — it lives in `linux-tools-$(uname -r)`; the
  installer asks for that package, which exists for every Ubuntu kernel but may lag a few
  days behind a brand-new one. `apt update` and retry, or install `bpftool` from the
  nearest kernel version.
- **enforcement INACTIVE in the startup report** — the daemon is running and observing but
  could not attach XDP. On some kernels `CAP_SYS_ADMIN` is required to load BPF; the unit
  grants it and says why. Check `journalctl -u tfps -b` for the exact error.
- **`only N MB of memory is available`** — the host has no release to download from and
  not enough memory for a source build. Build on another machine and use `TFPS_TARBALL`,
  or set `TFPS_FORCE_BUILD=1` if you accept the risk to whatever else runs there.
- **Checksum mismatch** — the download did not match the SHA-256 published with the
  release. Nothing was installed. Run again; if it repeats, something between you and
  GitHub is altering the file.
