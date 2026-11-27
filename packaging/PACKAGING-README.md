# BeniBust — release candidate for secondary verification

This is a **self-contained** copy of BeniBust, the owner root jailbreak for
Mondo/Beni LZ110 (X5) robots, packaged so you can verify it end-to-end on your own
hardware without the research tree.

It contains only what the build and flash path needs. There is no vendor image,
no key, and no token in here — you supply all three from your own device and your
own copy of the app, which is the point: nothing is bundled.

---

## What's in here

```sh
benibust-release/
  benibust.py                the jailbreak: build package -> upload -> install -> verify
  sdk/freewheel/             the SDK (module set the build path needs)
  tools/beni_probe.py        read-only diagnostics: ports, firmware version, serial
  docs/BENIBUST.md           scope, the key/firmware walkthrough, rollback, disclosure
  docs/ota.md                the OTA/packaging protocol, for auditing what we do
  docs/shell-enable.md       the engineering log: how the route was found and proven
  requirements.txt           the two optional third-party packages
  NOTICE                     required third-party attribution for this bundle
  MANIFEST.json              every file with its sha256, plus the build commit
```

`MANIFEST.json` pins the commit this was built from and hashes every file, so you
can confirm you're testing what was reviewed. Run `python3 benibust.py --help`
to see the CLI.

---

## Before you start

**Requirements**

- Python **3.10+** — stdlib only for the build path.
- **`e2fsprogs`** — `debugfs`, `dumpe2fs`, `e2fsck`.
  macOS: `brew install e2fsprogs` · Debian/Ubuntu: `sudo apt install e2fsprogs`
  (Homebrew's `sbin` is found automatically.)
- **`ssh-keygen`** — for the key-only SSH payload.
- **`cryptography`** — *only* if your robot is on a `secure_v2` firmware that
  requires the encrypted control channel. `pip install cryptography`.
- **`bleak`** — *only* for the optional BLE pairing helper. `pip install bleak`.

Run the built-in check first; it tells you exactly what's still missing:

```sh
python3 -m freewheel.ota doctor       # run from the release root, with sdk/ on PYTHONPATH
```

> If `python3 -m freewheel.ota` can't find the package, run from the release root
> and set `PYTHONPATH=$PWD/sdk`. `benibust.py` adds `sdk/` itself, so the
> jailbreak itself needs no setup.

**Safety, briefly.** Flashing writes the inactive A/B slot and reboots. Have the
robot on a stand or in a safe area, close the Mondo app (UCP is single-session),
and do not cut power mid-flash — that's the only genuine brick vector. `hbre` is
not the rootfs and is not covered by `vbmeta`, so a bad `hbre` does not brick the
boot chain; the other slot remains bootable. Full detail in `docs/BENIBUST.md`.

---

## The three things you supply

### 1. The media bearer token

`md_upgrade` on `:8085` gates every read on `Authorization: Bearer <token>`. The
robot only checks `sha256(token)` against a fixed digest, so this package ships the
**digest** and not the secret. Recover the token from your own APK:

```sh
python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk
```

It sweeps every entry of the APK, hashes each printable string, and on a digest
match writes `~/.config/freewheel/media_token` with mode `0600`. A hit is *proof*
the token is right, not a guess. `show-token` tells you what currently resolves.

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

Same two commands above fetch it (`pull-firmware` puts it at
`beni_fw/current_26.11/all_in_one.zip`). It supplies `ota_process`, `system.img`
(where `sshd` comes from) and the stock verity images.

---

## Verify it

```sh
# 1. Nothing missing?
python3 -m freewheel.ota doctor

# 2. Build only — no network, no flashing. Verifies the package it produces.
python3 benibust.py --dry-run --i-own-this-device

# 3. Read-only device check before touching anything
python3 benibust.py --scan
python3 tools/beni_probe.py --host <robot-ip>
```

Step 2 is the one to scrutinise: it patches `ota_process`, builds the `hbre`
image, repacks both zips, and runs the full anti-brick verification on the result.
It prints what it changed. Nothing is uploaded until you run without `--dry-run`.

If you included the tests (`-tests` zip), run them from the release root:

```sh
export PYTHONPATH=$PWD/sdk
python3 sdk/tests/test_ota.py          # package build/verify, token recovery, ext4
python3 sdk/tests/test_ble.py          # BLE pairing, MD-TS over BLE, SoftAP
python3 sdk/tests/test_md_ts.py        # encrypted session (needs `cryptography`)
python3 sdk/tests/test_cmd_proto.py
python3 sdk/tests/test_transport.py
python3 sdk/tests/test_request.py
python3 sdk/tests/test_zenoh_pico.py
```

These are offline — real `mke2fs` images, synthetic APKs, and a mock `:8085`. No
hardware and no robot needed. `test_ota.py` is the one that matters most: it
exercises the same package build and verification path the flash uses.

---

## Flash it

```sh
python3 benibust.py --i-own-this-device
```

Default payload is key-only SSH on `:2222` **plus** an AP-only telnet fallback.
Then:

```sh
ssh -p 2222 -i ~/.ssh/freewheel_ed25519 root@<robot-ip>
```

Variants:

```sh
python3 benibust.py --payload ssh    --i-own-this-device   # no telnet
python3 benibust.py --payload telnet --i-own-this-device   # AP-only telnet
python3 benibust.py --skip-build PKG --host <ip> --force    # flash a built package
```

---

## Roll back

**Keep a pristine `hbre.img` before you flash.** `dump-partition --slot a|b` gets
it. A stock V26.11 package does *not* include `hbre`, so re-flashing stock will
**not** undo BeniBust on its own; you need your own dump or a vendor full package
that ships `hbre`.

---

## What we'd like verified

Roughly in order of value:

1. **The `ota_process` patch offset still matches.** The build fails closed if the
   bytes at offset `35364` differ from `2a020054`, so a mismatch is a clean error,
   not a bad flash. If it refuses, the `ota_process` in your base differs from ours
   — send us the version and we'll re-locate the branch.
2. **`hbre` is genuinely unsigned on your unit.** Ours was verified live:
   `vbmeta` descriptors cover only `boot` and `system`, and `dmsetup table` shows no
   verity target for `hbre`. Worth confirming independently.
3. **The wrapper actually executes at boot.** `/etc/init.d/S90cam-service` runs
   `/usr/hobot/bin/cam-service` as root; we replace it with a wrapper that execs the
   original at `cam-service.real`, so vision should be unaffected.
4. **A/B behaviour afterwards.** Check `/proc/cmdline` for `hobotboot.slot_suffix`
   and confirm the camera still works.
5. **Rollback works** from your own dump.

Please don't publish specifics of a working exploit before the vendor has been
notified — see the disclosure section of `docs/BENIBUST.md`.

---

## Scope

Personally-owned hardware only. This writes the inactive slot through the device's
own OTA interface; it does not touch the signed boot chain, `vbmeta`, `/md`
dm-verity, the TEE debug gate, or any safety limit. It is reversible with your own
image. The legal basis for owner jailbreaking in the US includes the DMCA §1201
triennial exemptions; confirm your own jurisdiction.
