```
██████╗ ███████╗███╗   ██╗██╗██████╗ ██╗   ██╗███████╗████████╗
██╔══██╗██╔════╝████╗  ██║██║██╔══██╗██║   ██║██╔════╝╚══██╔══╝
██████╔╝█████╗  ██╔██╗ ██║██║██████╔╝██║   ██║███████╗   ██║   
██╔══██╗██╔══╝  ██║╚██╗██║██║██╔══██╗██║   ██║╚════██║   ██║   
██████╔╝███████╗██║ ╚████║██║██████╔╝╚██████╔╝███████║   ██║   
╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   
```

<p align="center">
  <img src="https://img.shields.io/badge/Status-Working-brightgreen.svg" alt="Status">
  <img src="https://img.shields.io/badge/License-Apache_2.0-blue.svg" alt="License">
  <img src="https://img.shields.io/badge/Python-3.10+-yellow.svg" alt="Python">
  <img src="https://img.shields.io/badge/Hardware-Mondo_Beni_LZ110-orange.svg" alt="Hardware">
</p>

<div align="center">

**Owner root jailbreak for the Mondo Beni robot**

</div>

BeniBust installs a key-only root SSH server on your own robot's unsigned `hbre`
partition, with an AP-only telnet fallback. 

It is owner-initiated, reversible, and
built entirely from firmware you supply. 

It does not bundle vendor images, keys, or
tokens, and it does not contact vendor infrastructure.

---

## What it does

1. Takes your own stock V26.11 `0300` firmware and an `hbre.img` from your own robot.
2. Patches the **package-supplied `ota_process`** with a single ARM64 branch so the
   LZ100 partition allowlist admits `hbre`. The stock verity images are untouched.
3. Adds a BeniBust boot hook to `hbre`:
   - **SSH** (default): a key-only `md_sshd` on `:2222`, with host keys and authorized
     keys in `/private/freewheel` (persistent across updates of the slot).
   - **Telnet** (default fallback): BusyBox `telnetd` bound **only** to the robot AP
     `192.168.7.1:23/:2323`.
   - The original camera service is preserved as `cam-service.real` and exec'd as before.
4. Uploads the package through the device's own OTA interface, installs it to the
   inactive A/B slot, reboots, and verifies root.
5. `/md` dm-verity, the signed boot chain and the TEE authorized-debug gate remain
   intact. BeniBust does not modify them.

The `md_sshd` binary is extracted from **your** `system.img`; only the public key you
provide is placed in the package. The private key stays on your host.

## Requirements

- **Python 3.10+** — the whole build path is standard library only.
- **`e2fsprogs`** — `debugfs`, `dumpe2fs`, `e2fsck`.
  macOS: `brew install e2fsprogs` · Debian/Ubuntu: `sudo apt install e2fsprogs`.
  (Homebrew's `sbin` is found automatically.)
- **`ssh-keygen`** — for the key-only SSH payload.
- Optional, per `packaging/requirements.txt`:
  - **`cryptography`** — only if your robot runs a `secure_v2` firmware that refuses
    the plaintext control channel.
  - **`bleak`** — only for BLE pairing on real Bluetooth hardware.

A device you own, reachable on its AP (`192.168.7.1`), or
your home LAN.

---

## The three things you supply

Nothing here is bundled. BeniBust ships **proof** that you recovered the right values,
not the values themselves.

### 1. The media bearer token

`md_upgrade` on `:8085` gates every read on `Authorization: Bearer <token>`, and the
firmware verifies it by comparing `sha256(token)` against a **fixed digest**. This repo ships only the digest, never the secret.
Recover the token from your own copy of the app:

```sh
python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk
```

It sweeps every entry of the APK, hashes each printable string, and on a digest match
writes `~/.config/freewheel/media_token` with mode `0600`. A hit is *proof* the token
is right, not a guess. `show-token` tells you what currently resolves.

### 2. `hbre.img` — from your own robot

Preferred: dump the partition off the device (needs a root shell — from a previous
BeniBust flash, or UART):

```sh
python3 -m freewheel.ota dump-partition hbre --host <robot-ip>
```

Byte-exact, size-checked, sha256 reported. **`--slot` matters**: after a flash,
`by-name/hbre` points at the *modified* image and the pristine original is on the
inactive slot, so `--slot a` / `--slot b` recovers a clean one.

Without root, the daemon's own work dir usually still holds it:

```sh
python3 -m freewheel.ota pull-firmware --host <robot-ip>    # the two build inputs
python3 -m freewheel.ota pull-workdir  --host <robot-ip>    # everything in the work dir
```

### 3. `all_in_one.zip` — the stock base

The same two commands fetch it (`pull-firmware` puts it at
`beni_fw/current_26.11/all_in_one.zip`). It supplies `ota_process`, `system.img` (where
`sshd` comes from) and the stock verity images.

Check what is still missing at any point:

```sh
python3 -m freewheel.ota doctor      # exit 1 if anything is missing
```

---

## Build

The jailbreak itself needs no setup — `benibust.py` adds `sdk/` to `sys.path`:

```sh
python3 benibust.py --help

# Build only: no network, no flashing. Patches ota_process, builds the hbre image,
# repacks both zips, and runs the full anti-brick verification on the result.
python3 benibust.py --dry-run --i-own-this-device

# Read-only device check before touching anything
python3 benibust.py --scan
python3 tools/beni_probe.py --host <robot-ip>
```

To produce the distributable release zip:

```sh
python3 packaging/build_release.py               # -> dist/benibust-<version>.zip
python3 packaging/build_release.py --with-tests  # include the offline suites
```

## Verify

`verify_release.py` unpacks the archive into a scratch directory and runs everything
with **`PYTHONPATH` unset and `HOME` pointed at an empty directory**, so a leaked
environment cannot mask a broken bundle. It checks the MANIFEST hashes, that the tree
is clean, that `NOTICE` shipped, that the CLI and probe run with no setup, that
`doctor` reports honestly, that a real package builds end to end — and, with
`--with-tests`, that every shipped suite passes.

```sh
python3 packaging/verify_release.py               # default zip in dist/
python3 packaging/verify_release.py --with-tests  # include the suite runs
```

Both must be run from a **fresh clone of this repository** with nothing else on
`PYTHONPATH`, which is the property this layout exists to guarantee.

Run the test suite directly with:

```sh
PYTHONPATH=$PWD/sdk python3 -m pytest sdk/tests -q
```

## Roll back

**Keep a pristine `hbre.img` before you flash.** `dump-partition --slot a|b` gets it.
A stock V26.11 package does *not* include `hbre`, so re-flashing stock will **not**
undo BeniBust on its own; you need your own dump or a vendor full package that ships
`hbre`.

To restore, dump the pristine image from the slot you did not modify while still
rooted, then re-flash it (or a vendor full package that includes `hbre`):

```sh
python3 -m freewheel.ota dump-partition hbre --host <robot-ip> --slot a   # or --slot b
```

If you have root, `/private/freewheel` holds the BeniBust keys and host keys, and
`cam-service.bak` (if present) is the pre-BeniBust wrapper. The original camera binary
remains at `/usr/hobot/bin/cam-service.real`.

Full detail — the key/firmware walkthrough, discovery chain, fallbacks, safety notes — is in [`docs/BENIBUST.md`](docs/BENIBUST.md).

---
