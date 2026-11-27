# BeniBust

**Owner root for the Mondo/Beni LZ110 X5 robot — a right-to-repair jailbreak.**

BeniBust installs a key-only root SSH server on the robot's unsigned `hbre`
partition, with an AP-only telnet fallback. It is owner-initiated, reversible,
and built entirely from firmware you supply. It does not bundle vendor images,
keys, or tokens, and it does not contact vendor infrastructure.

> This tool is for hardware you own. Keep vendor communication open for
> responsible disclosure. The legal basis for owner jailbreaking/rooting in the
> US includes the DMCA §1201 triennial exemptions (the same line of authority as
> iPhone jailbreaking) and right-to-repair principles. This document is not
> legal advice; confirm your jurisdiction's rules before distribution.

---

## What it does

1. Takes your own stock V26.11 0300 firmware and an `hbre.img` from your own robot.
2. Patches the **package-supplied `ota_process`** with a single ARM64 branch so
   the LZ100 partition allowlist admits `hbre` (the stock verity images are
   untouched).
3. Adds a BeniBust boot hook to `hbre`:
   - **SSH** (default): a key-only `md_sshd` on `:2222`, with host keys and keys
     in `/private/freewheel` (persistent).
   - **Telnet** (default fallback): BusyBox `telnetd` bound **only to the robot
     AP** `192.168.7.1:23/:2323`.
   - The original camera service is preserved as `cam-service.real` and is
     exec'd as before.
4. Uploads the package through the device's OTA interface, installs it to the
   inactive A/B slot, reboots, and verifies root.
5. `/md` dm-verity, the signed boot chain, and the TEE authorized-debug gate
   remain intact. BeniBust does not modify them.

The `md_sshd` binary is extracted from **your** `system.img`; only the public key
you provide is placed in the package. The private key stays on your host.

## Requirements

**Zero third-party SDK dependencies.** Everything runs from this repo's `sdk/`.

- Python 3.10+ (stdlib only; the optional encrypted `secure_v2` session needs `cryptography`).
- `e2fsprogs` (`debugfs`, `dumpe2fs`, `e2fsck`) and `ssh-keygen`.
- **Your own bare-metal artifacts**, both of which BeniBust now fetches for you:
  - the retail **media bearer token** (a plaintext constant inside your own copy of
    `MondoApp.apk`) — recovered and digest-verified, never bundled here;
  - the stock **V26.11 `all_in_one.zip`** and **`hbre.img`** — pulled straight off
    your robot's own `md_upgrade` daemon.
- A device you own, reachable on its AP (`192.168.7.1`), USB-C (`192.168.123.1`),
  or home LAN.

Check what you still need at any point:

```sh
python3 -m freewheel.ota doctor
```

---

## Getting your own key and firmware

BeniBust used to need a third-party SDK install plus hand-staged vendor images. Both
are gone. You need two things off hardware you already own, and there's a command for each.

### 1. Your media bearer token (from your own copy of the app)

`md_upgrade` (`:8085`) gates every read — `/health`, `/list`, `/files/*` — on
`Authorization: Bearer <token>`, and the firmware verifies it by comparing
`sha256(token)` to a **fixed digest** that is the same on every retail unit:

```
5500fdb05dcfc31e9ddd00b4892d4ded351227b09b8796ca8bb8cdd4b727b0e5
```

The token itself is a plaintext constant embedded in the MondoApp binary (SecNeo-wrapped
Flutter, so it lands in `lib/arm64-v8a/libapp.so` rodata or a DEX string pool). This repo
ships **only the digest** — never the secret — so the tool can *prove* a candidate is the
right one instead of guessing:

```sh
# Point it at your own APK (or the folder, for a split/App-Bundle install)
python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk
```

It sweeps every entry, hashes each printable string it finds, and on a digest hit writes
the token to `~/.config/freewheel/media_token` with mode `0600`. If you captured the token
another way, `python3 -m freewheel.ota set-token` verifies and stores it; `show-token`
tells you which source currently resolves.

Resolution order everywhere in BeniBust (so an existing install keeps working):

1. `--bearer-token` / explicit argument
2. `$FREEWHEEL_MEDIA_TOKEN`
3. `~/.config/freewheel/media_token`

Legacy environment variables and config paths from the earlier SDK generation are
still honoured, last in that order, so an existing install keeps working.

### 2. Your firmware (off your own robot)

The firmware comes off your own hardware — that's how it was first obtained, and it's
the most faithful source. The `md_upgrade` daemon on `:8085` serves exactly the images
the robot was built from, so this needs no vendor package, no capture rig, and no root.

#### The discovery chain (what this actually is)

Worth writing down plainly, because it's less work than it sounds:

1. **Join the robot's network.** It's a plain WPA2 AP; the password is *not* secret —
   our BLE pairing already retrieves it (`python -m freewheel.ble pair`). Once you have
   it you can join at will.
2. **Probe and find `:8085`.** `GET /health` answers, and `GET /list` is there too.
   `:8085` is `md_upgrade`, the robot's own firmware daemon.
3. **Reads need a bearer — and that token is baked into the app.** `/list` returns
   `AUTH_REQUIRED` without it. It's a plaintext constant in `MondoApp.apk`, which
   `extract-token` recovers and digest-verifies (step 1 above).
4. **The work dir is the whole kit and caboodle.** With the bearer, `/list` opens a
   work directory containing `extract_<uuid>/x5_0300/` — the fully unpacked
   `hbre.img`, `system.img`, `mondo.img`, `ota_process`, `data.json`, `gpt.conf` —
   plus the outer archives under `tmp/`.
5. **`/files` is sandboxed but `/list?path=` isn't.** `/files/<path>` only serves from
   inside the work dir, but `/list?path=<subdir>` enumerates any subdirectory of it,
   so every file is reachable. Enumerate, then grab.

```sh
# What's staged, before downloading anything
python3 -m freewheel.ota inventory --host 192.168.7.1

# Just the artifacts a build needs, into beni_fw/ where the builder looks
python3 -m freewheel.ota pull-firmware --host 192.168.7.1

# …or grab the entire work directory, every file, like the original capture
python3 -m freewheel.ota pull-workdir --host 192.168.7.1
```

All three are resumable: a file already local at the right size is skipped, and a
partial one continues with a Range request, so a dropped link costs you a re-run and
nothing else. `pull-firmware` lands:

```
beni_fw/current_26.11/all_in_one.zip
beni_fw/mirror/extract_<uuid>/x5_0300/hbre.img
```

| Artifact | Where it lives on the robot | Why you need it |
|---|---|---|
| `all_in_one.zip` (~590 MB) | `tmp/all_in_one.zip` | stock X5 images, `ota_process`, `system.img` (contains `sshd`) |
| `hbre.img` (~157 MB) | `extract_<uuid>/x5_0300/hbre.img` | the unsigned partition BeniBust patches |

#### The exact image: dump the partition (needs root)

`md_upgrade` only holds what it last unpacked, and it cleans up. Once you have a shell —
from a previous BeniBust flash, or UART — read the block device directly. This is
byte-exact and always matches the firmware actually on the robot:

```sh
python3 -m freewheel.ota dump-partition hbre --host 192.168.7.1
# -> beni_fw/dump/hbre.img, 157,286,400 bytes, sha256 verified against what was read
```

Two details that matter:

- **`--slot` selects the A/B slot.** `current` (the default) follows
  `/dev/block/platform/by-name/hbre`, i.e. whatever slot booted. After a BeniBust
  flash that is *your modified* image — the pristine original is on the other slot, so
  use `--slot a` / `--slot b` to pin it explicitly. That's how you recover a clean
  `hbre` from a robot whose vendor package you no longer have.
- **The size must be exact.** `hbre` is a fixed 157,286,400-byte slot and `md_upgrade`
  md5-checks the whole range, so a truncated dump is rejected on-device. Both
  `dump-partition` and `--hbre` verify the length and say so rather than letting you
  build a package that would fail at install.

> **Why pull V26.09's `hbre` at all, then?** Only because the stock **V26.11** package
> was a delta and doesn't ship `hbre` — the partition hadn't changed, so it wasn't
> included. Nothing about V26.09 makes the image special: `hbre` is unsigned, not in
> `vbmeta`, and has no dm-verity **on V26.11 too** (verified live — the `vbmeta`
> descriptors cover only `boot` and `system`). A dump from your own V26.11 robot is a
> better source than any older package.

#### Fallbacks, in order

1. **`dump-partition`** — exact, needs root.
2. **`pull-workdir` / `pull-firmware`** — whatever `md_upgrade` still has, needs only
   the bearer.
3. **Capture an app-driven update** — if the work dir was cleaned and you have no shell
   yet. The app uploads the package in plain HTTP over the robot AP, so host `tcpdump`
   or a monitor-mode capture works; carve it with
   `python3 -m freewheel.fwextract capture.pcap -o firmware.zip`.
4. **Vendor full V26.09 package** — last resort, and only if you have it. Budget for the
   known mismatch: V26.09 `hbre` on a V26.11 system runs older hobot/camera libs
   (functional instability, not a brick).

### 3. Confirm and go

```sh
python3 -m freewheel.ota doctor        # all rows must read "ok"
python3 benibust.py --i-own-this-device
```

## Usage

```sh
# Read-only scan
python3 benibust.py --scan

# Pull your own firmware off the robot first, then build + flash + verify
python3 benibust.py --fetch-firmware
python3 benibust.py --i-own-this-device

# Build + flash + verify (default: SSH + AP-only telnet fallback)
python3 benibust.py --i-own-this-device

# SSH only (no telnet)
python3 benibust.py --payload ssh --i-own-this-device

# Build only
python3 benibust.py --dry-run --i-own-this-device

# Connect to an existing root channel
python3 benibust.py --shell

# Save a device state snapshot after root
python3 benibust.py --i-own-this-device --backup-dir ./benibust-state

# Roll back by flashing a stock package (e.g. your own pre-FW dump, repackaged)
python3 benibust.py --restore /path/to/vendor_or_dump_package.zip
```

The SSH key defaults to `~/.ssh/freewheel_ed25519` (created if missing).
After a successful flash:

```sh
ssh -p 2222 -i ~/.ssh/freewheel_ed25519 root@<robot-ip>
```

If SSH does not come up, join the robot AP (`Beni-xxxxxx`) and use the telnet
fallback:

```sh
python3 -c 'import telnetlib,time; t=telnetlib.Telnet("192.168.7.1",23,timeout=10); time.sleep(.5); t.interact()'
```

## Restore / rollback

BeniBust writes only the inactive slot's `hbre` (plus stock verity images).
To restore the vendor `hbre`, dump the pristine image **from the slot you didn't
modify** while still rooted, and keep it:

```sh
python3 -m freewheel.ota dump-partition hbre --host <robot-ip> --slot a   # or --slot b
```

Re-flash that image (or a vendor full package that includes `hbre`) to revert. A stock
V26.11 package does **not** include `hbre`, so it will not remove BeniBust by itself.
Keeping your own dump is more reliable than hunting for a vendor package later.

If you have root, `/private/freewheel` contains the BeniBust keys/host keys and
`cam-service.bak` (if present) is the pre-BeniBust wrapper. The original camera
binary remains at `/usr/hobot/bin/cam-service.real`.

## Firmware tooling (`python -m freewheel.ota`)

Everything the jailbreak needs lives in one command, all of it reading only your own
hardware and your own app:

| Command | What it does |
|---|---|
| `doctor` | Which keys, images, and binaries are still missing (exit 1 if any) |
| `extract-token <MondoApp.apk>` | Recover your media bearer, verified against the retail digest, saved `0600` |
| `set-token` / `show-token` | Store a token you captured yourself / show which source resolves |
| `inventory [--host H]` | List the firmware artifacts staged on your robot |
| `pull-firmware [--host H]` | Resumably download `all_in_one.zip` + `hbre.img` into `beni_fw/` |
| `pull-workdir [--host H]` | Grab **every** file in `md_upgrade`'s work dir (the original capture method) |
| `dump-partition hbre --host H [--slot a\|b]` | Read a partition off a rooted robot over SSH — exact, slot-selectable |
| `status [--host H]` | `md_upgrade` `/health` + `/list` |
| `verify <pkg.zip> [--base ...]` | Full structural/anti-brick verification before flashing |
| `upload <pkg.zip> --install` | Mint a live V2 session, resumable TUS upload, then install |

The verification gates are the same anti-brick checks the build runs on itself:
outer manifest SHA-256 per module, inner `0300` per-partition MD5 scopes,
`ota_process` execute bits and AArch64 ELF header, required metadata files, and
protected bootloader/AVB partitions compared against the base firmware (which
requires `--allow-unsafe-x5-override` to deliberately change).

Safety gates before any upload/install: battery ≥ 30% unless docked/charging
(`--ignore-battery` to override), an optional posture check
(`--check-posture`), and a refusal to interfere with an OTA already in flight.

## Companion tools (also self-contained)

| Tool | Purpose |
|---|---|
| `python3 tools/beni_probe.py` | No-shell diagnostics: ports, firmware version, serial, OTA state |
| `python3 -m freewheel.ota pull-workdir` | Enumerate and grab **every** file in `md_upgrade`'s work dir |
| `python3 -m freewheel.ota dump-partition hbre` | Byte-exact partition read off a rooted robot (slot-selectable) |
| `python3 -m freewheel.ble pair` | BLE pairing: writes the MD-TS identity and joins the robot SoftAP |

## Safety

- Do not enable or change motor/safety limits (`parameters_unlocked_max_speed`,
  `parameters_unlocked_power_level`, etc.).
- A robot can move and injure; keep it on a stand or in a safe area while
  flashing.
- The OTA reboots the robot. Close the Mondo app first (UCP is single-session).
- Do not run this remotely or against third-party hardware.

## Responsible disclosure

The underlying mechanism — a package-supplied `ota_process`, a package-side
partition allowlist, and an unsigned/root-executed `hbre` — is also a vendor
security weakness. BeniBust is the owner-rights side; the vendor report is the
security side. Keep both tracks:

- Share the OTA/NFS/token/cloud findings with the vendor PSIRT.
- Request an official owner-unlock/repair mode as the clean fix.
- Coordinate publication (90 days, extendable by agreement).
- Request CVE assignment if the vendor agrees.

The vendor-facing security report is maintained privately, outside this repository.

## What BeniBust does not do

- No remote/network exploitation, no third-party targeting, no cloud/token use.
- No bootloader/vbmeta/TEE/efuse writes, no anti-rollback bypass.
- No DRM/paywall/paid-feature bypass.
- No vendor firmware, keys, or secrets bundled or redistributed.
- No safety-limit changes.
- No telemetry.

## Troubleshooting

- **SSH refused:** check `:2222`; join the AP and use the telnet fallback; inspect
  `/tmp/freewheel_sshd.log` on the robot.
- **SSH key mismatch:** re-flash with `--ssh-key`, or edit
  `/private/freewheel/authorized_keys` and restart `md_sshd`.
- **Package rejected:** the `ota_process` bytes may differ on your firmware
  version; the build fails closed rather than guessing.
- **Robot boots the other slot:** A/B behavior is controlled by the vendor
  bootloader; verify `/proc/cmdline` `hobotboot.slot_suffix` after reboot.
- **No camera after flash:** `cam-service.real` is preserved; check
  `/usr/hobot/bin/cam-service.real` and the vendor logs.
- **`md_upgrade` returns `AUTH_REQUIRED`:** your media token is missing or wrong —
  `python3 -m freewheel.ota show-token`, then re-run `extract-token`.
- **`inventory` lists nothing:** that unit's `md_upgrade` staging directory was
  cleaned. Capture an app update (`python3 -m freewheel.fwextract`) or `dd` the
  partition once rooted.
- **Missing `e2fsprogs`:** `brew install e2fsprogs` (macOS) or
  `sudo apt install e2fsprogs` (Linux); the tools are also looked up in
  `/opt/homebrew/opt/e2fsprogs/sbin` and `/usr/local/opt/e2fsprogs/sbin`.

## Status

First-pass MVP: build + flash + key-only SSH with AP telnet fallback, scan,
shell, backup snapshot, and restore. Next: end-to-end verify on hardware, a
public-safe advisory, and (ideally) an official vendor owner-unlock path.
