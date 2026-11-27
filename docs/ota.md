# OTA / firmware update — path, encryption, and how to capture an image

Clean-room RE of MondoApp's firmware-update flow, for planning a day-one firmware
capture (the realistic path to an image without a teardown). The robot has no WAN
of its own, so **the phone is the OTA relay**.

## Flow

```
 app → POST /app/v1/files/package/latest   cloud manifest (needs JWT). body
         GetLatestPackageReq{product_code, board_id, batch_id,
           mondo_partition_size, firmware_version, os_version, platform,
           distribution, language, …}
       → PackageInfo{oss_path, sha256, file_size, package_version,
           is_force_update, release_note, …}        (oss_path = opaque object key)
 app → POST /app/v1/files/getDownloadUrl   (needs JWT). body {sub_path:oss_path, type:1}
       → DownloadUrlData{download_url, full_path, expiration, method, signed_headers}
                                             ← a SIGNED, EXPIRING CloudFront URL
 app ← downloads firmware .zip              HTTPS Range-GET the signed download_url
         (resumable: .zip.part, http_412), then SHA256(+md5) verify  [FirmwareDownloader]
 app → POST  http://192.168.7.1:16170/v2/upgrades/<taskId>/…   the raw .zip, PLAIN HTTP
         (Authorization: Bearer <token>)     [FirmwareUploader → robot LAN upload server]
 app ↔ cmd/ota/upgrade_control_req/_rsp + status/ota/upgrade_progress
                                             CONTROL/PROGRESS ONLY — not the bytes
 robot  decrypts (if needed) + board-verify + flash + reboot + version check
```

> **`/v2/upgrades/` is the ROBOT's LAN upload server** (`192.168.7.1:16170`,
> `upgrade_task_upload.dart`), **not** a cloud endpoint. The cloud manifest is
> `POST /app/v1/files/package/latest` (+ `/package/list`). This server is the
> `md_upgrade` daemon; its port moved across firmware (`:16170`/`:8085`/`:8088`) and
> it also exposes a v1 inbox API — see "External protocol notes" below.

Endpoints/classes (recovered): cloud `POST /app/v1/files/package/latest` &
`/getDownloadUrl` (`mondo_api_generated/src/api_impl/{db_api_impl,oss_api_impl}.dart`,
models `get_latest_package_req` / `download_url_data` / `package_info`); robot LAN
`http://192.168.7.1:16170/v2/upgrades/…`; `domain/upgrade/services/{firmware_api_service,
firmware_downloader,firmware_uploader,force_update_coordinator}.dart`;
`OtaUpgradeControlReqData{controlCmd, versionField1, versionField2, reserved, task}`;
robot-side native topics `/cmd/ota/upgrade_control_req`/`_rsp`,
`/status/ota/upgrade_progress`, `/cmd/common/get_partition_size_req`.

## The one gate: `firmware_encryption`

A **per-device cloud flag**, `FirmwareEncryption ∈ {NONE, ENCRYPTED}`, resolved by
`FirmwareEncryptionResolver.probe()` → `DeviceActivationSecurityService.queryState()`
— i.e. driven by the device's **activation/attestation state**, not a stored key.

| mode | captured image | key |
|------|----------------|-----|
| **NONE** (common/default) | **plaintext `.zip` — directly inspectable** | n/a |
| **ENCRYPTED** | ciphertext | **not on the phone** — robot/board decrypts; key must come from the robot |

`libmondo_native.so` contains **no crypto** (no AES/BoringSSL/mbedtls/EVP) — it is
pure UCP/zenoh transport. So there is nothing on the app side to decompile for a
firmware key; if a unit is ENCRYPTED, the key lives on the board.

## Integrity / signing (as seen from the app)

- **App-side:** SHA256 of the package vs the cloud value (fails closed:
  `"Firmware integrity verification failed…"`), plus md5 for the upload. **No
  RSA/ECDSA signature anywhere in the app.**
- **Robot-side:** a post-upload "board verify" + post-reboot version check
  (`APP_OTA_BOARD_VERIFY_TIMEOUT`, `APP_OTA_VERSION_VERIFY_TIMEOUT`). **Whether the
  board checks a cryptographic signature is invisible from the app.**

> **Hypothesis to test on hardware (do not overclaim):** if the board verifies only
> a hash/size (not a signature) and the unit is NONE-mode, a *modified* `.zip` might
> be accepted — a path to custom firmware. Unconfirmed: the board-verify step could
> enforce signing we can't see. Treat as a lead, not a finding, until tested.
>
> **UPDATE (external RE — see "External protocol notes" below):** largely confirmed, with a
> split the app can't see. The **userspace** images (`mondo.img`→`/md`,
> `hbre.img`→`/usr/hobot`) are **hash-only, unsigned** — a modified `.zip` with
> recomputed digests IS accepted and flashed. The **X5 boot chain**
> (`boot.img`/`system.img`) is **AVB-signed** (`vbmeta.img`) and cannot be modified
> without the vbmeta key. So "custom firmware" = userspace overlays, yes; kernel/system,
> no. Still worth a first-party hardware confirmation on a V26.11 unit.

## Image format — RESOLVED (external RE)

Opaque from the app (it relays the package as bytes — no squashfs/ext4/ubi/u-boot
strings anywhere, as expected). **The structure is now known from an independent
third-party project (see "External protocol notes" below), not yet confirmed
first-party on a captured V26.11 image.** The `.zip` is a nested bundle:

```
V26.10.28.04_lz110.zip                       ← outer ZIP (per-module size + "sha256:" in mass.cfg)
├── mass.cfg            (.mass.cfg.plain.unsign)   TOML manifest: size + sha256: per module
├── …_0300_V<ver>_<date>.mass.fw.plain.unsign      ← inner "0300" X5 bundle (ZIP, 600 MB+)
│   ├── miniboot.img · uboot.img · vbmeta.img · boot.img · system.img   ← AVB-signed boot chain
│   ├── gpt.conf
│   ├── ota_process     (aarch64 ELF, mode 0755)   the on-robot flasher
│   └── data.json       per-partition md5sum + md5_scope (byte size)
├── mondo.img           ext4 → mounts at /md         (Mondo daemons; HASH-ONLY, unsigned)
└── hbre.img            ext4 → mounts at /usr/hobot   (vision runtime; HASH-ONLY, unsigned)
```

- Part filename grammar: `{prefix}_{part:04X}_V{a.b.c.d}_{date}.{suffix}`.
- The `.plain.unsign` suffixes are the format's own name for **NONE mode** — plaintext,
  no outer signature. Matches the "NONE common/default" row above.
- **Two digest layers** (what the external patch tool recomputes): outer = ZIP CRC + `mass.cfg`
  `sha256:` per module; inner `0300` = `data.json` md5 per X5 partition. **No
  RSA/ECDSA** on the package — consistent with `libmondo_native.so` carrying no crypto.
- **Signing split:** AVB covers only the X5 boot chain (`vbmeta`/`boot`/`system`); the
  ext4 userspace (`mondo.img`, `hbre.img`) is verified by hash alone → modifiable.
- **Chipset tell:** `X5` + `/usr/hobot` + `hbre` (ext4) ⇒ **Horizon Robotics "Sunrise
  X5"** aarch64 SoC (strong inference — "hobot" is Horizon; confirm at teardown). This
  reframes the RTL8822CS/Noitom notes: X5 is the main compute SoC; any Realtek part is
  just the Wi-Fi/BT combo.

> **Where `firmware_encryption` comes from:** it is resolved from the device's
> **activation/security state** (`FirmwareEncryptionResolver.probe()` →
> `DeviceActivationSecurityService.queryState()`), i.e. learned from the device —
> not a field in the `package/latest` manifest (whose `PackageInfo` carries
> `oss_path`/`sha256`/`file_size`/`is_force_update`/…, no encryption flag).

## External protocol notes — independent RE of the package + an upload/inject path

An independent, third-party, pure-Python client for Beni (LZ110/LZ100), **worked out
without MondoApp** — so it's a second, corroborating source for the LAN protocol. Read at
revision `b0b73b3` (2026-11-21), **tested by its authors on V26.10.28** (ours is
V26.11.19.01 — expect drift). Two parts matter here:

- **The client half** = **comms + control only** (a client over the robot's own
  services: UCP/Zenoh `:9007`, Config `:8010`, Media `:8084`, OTA daemon, BLE pairing
  `MD-TS X25519 + AES-256-GCM` on GATT `FFF0`, `setup-wifi`). **No shell, no root, no
  code-exec.** Notably it reaches the control plane **without the app** via BLE pairing
  + Wi-Fi provisioning — which directly unblocks the "need the Beni PSK to control
  independent of the app" blocker from the day-1 hardware bring-up.
- **The patch toolset** = firmware **patcher + verifier + uploader**. It's where the
  format (above) came from, and it's a real **userspace code-exec / persistence
  primitive** (not an interactive root shell): overlay files into `mondo.img` (`/md`) or
  `hbre.img` (`/usr/hobot`), recompute the hashes, upload via the OTA daemon → robot
  flashes and **runs it on next boot** (the `/md` daemons + `S99ota_update_check.sh` run
  at boot, almost certainly as root). Stops at the AVB wall (can't touch
  `boot.img`/`system.img` without the vbmeta key).

### `md_upgrade` daemon — live-confirmed on `:8085` (TLS) on V26.11

The robot LAN upload/OTA server is the `md_upgrade` daemon. **Live probe of our unit
(V26.11.19.01, 2026-11-23): it listens on `:8085` over HTTPS (self-signed); `:8088` and
`:16170` are closed.** So on V26.11 it is `:8085`, the same port the external notes
record on V26.10.28 — our earlier MondoApp-RE `:16170` was a different firmware/observation, not the
live binding. Port has moved across firmware, so re-probe (`for p in 8085 8088 16170; do
curl -sSk https://192.168.7.1:$p/health; done`).

It serves **two APIs at once**:

- **v1 inbox:** `GET /health`, `GET /list` (stored packages), `POST /upload`, `/files/*`
- **v2 task:** `POST /v2/upgrades` → `PATCH /v2/upgrades/{id}/upload` (raw body +
  `Upload-Token`) → `GET /v2/upgrades/{id}` (poll to `READY`) → `POST /v2/upgrades/{id}/install`

> Note the v2 upload is a **`PATCH` raw body**, not multipart. Our `fwextract` assumes
> **multipart** — correct for the *MondoApp*-driven capture (path B), but an uploader that speaks
the v2 task API would need a different carver.

### Auth model (RESOLVED)

Two independent credentials, confirmed live (both endpoints return `AUTH_REQUIRED` without):

- **Reads** (`GET /health`, `/list`, `/files/*`) need `Authorization: Bearer <token>` where
  `<token>` is the **static, global retail media bearer** — the *same* token the `:8084`
  album uses, identical on every retail unit, non-expiring; the firmware checks
  `sha256(token)` against a fixed digest (`5500fdb0…727b0e5`).
  It is a plaintext embedded constant in `MondoApp.apk` (unzip → sweep all strings → match
  `sha256(candidate)` to the digest; exactly one of ~1.46M hit). **The literal value is
  kept out of this repo**; instead `freewheel.ota` ships only the digest and recovers the
  token from the owner's own APK:

  ```sh
  python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk   # -> ~/.config/freewheel/media_token (0600)
  ```

  `freewheel.ota.resolve_media_token()` then feeds `:8085` reads and the Freewheel
  console alike (it also honours the legacy config path).
- **v2 upload grant** is a *separate* `Upload-Token`, minted **live over Zenoh**
  (`/cmd/ota/upgrade_control_req`, `control_cmd=START` → `upload_grant_token`). No static
  secret; `freewheel.ota.create_ota_task()` mints it from the paired session. So path B
  (upload a modified package) authenticates with no bearer at all — only the live grant.

### Path (C) — pull a stored package straight off the robot (SOLVED, primary source)

`md_upgrade` has `GET /list` + a `/files/*` route and retains the staged images. With the
recovered bearer the auth gate is open, and this is now automated end to end — and it is
how the firmware was originally obtained:

1. **Join the robot's network.** Plain WPA2 AP; the password comes over BLE
   (`freewheel.ble`), so it isn't a barrier.
2. **Probe and find `:8085`** — `GET /health` answers, `GET /list` exists.
3. **Reads need a bearer**, and that bearer is a plaintext constant in `MondoApp.apk`
   (`freewheel.ota extract-token` recovers and digest-verifies it).
4. **The work dir is the whole kit and caboodle**: `extract_<uuid>/x5_0300/` holds the
   unpacked `hbre.img`, `system.img`, `mondo.img`, `ota_process`, `data.json`; `tmp/`
   holds the outer archives.
5. **`/files` is sandboxed but `/list?path=` is not.** `/files/<path>` serves only from
   inside the work dir, while `/list?path=<subdir>` enumerates any subdirectory of it —
   so every file is reachable by enumerating and then fetching.

```sh
python3 -m freewheel.ota inventory --host 192.168.7.1       # what's still on the unit
python3 -m freewheel.ota pull-firmware --host 192.168.7.1   # just the build inputs
python3 -m freewheel.ota pull-workdir --host 192.168.7.1    # every file in the work dir
```

All resumable (size-matched files are skipped; partials continue with a Range request).

Retention is per-unit: `md_upgrade` keeps `tmp/all_in_one.zip` until the next update and the
`extract_<uuid>/` tree after it, but it does clean up. If `/list` is empty, read the
partition directly instead (`python3 -m freewheel.ota dump-partition hbre --host …`, needs
root), fall back to a capture (path B), or the cloud pull (path A). (This yields the
userspace package — not the live/AVB-signed system image; for that it's still capture or
UART/eMMC.)

### Path (D) — dump the partition off a rooted robot (exact)

Once any shell exists, `dd` the block device for a byte-exact image of what is actually
installed. `freewheel.ota dump-partition` wraps it over SSH:

```sh
python3 -m freewheel.ota dump-partition hbre --host 192.168.7.1            # current slot
python3 -m freewheel.ota dump-partition hbre --host 192.168.7.1 --slot b   # pinned slot
```

`--slot current` follows `/dev/block/platform/by-name/hbre` (the booted slot). After a
Freewheel flash that node points at the **modified** image, so the pristine original is on
the inactive slot — pin `--slot a` / `--slot b` to recover it. `hbre` is a fixed
157,286,400-byte slot and `md_upgrade` md5-checks the whole range, so the length is
verified on both dump and build.

### Fastest route to an *interactive* shell + a live image dump

Bridge from "build modified firmware" to "root shell on the device": use `benibust.py`
(which uses `freewheel.ext4` + `freewheel.ota`) to inject a tiny SSH/telnet server into
`hbre`, upload, reboot → then you have a live shell to mount/read all partitions, dump the
**running** image (incl. an ENCRYPTED unit's decrypted rootfs), and pull on-board keys —
the things a captured OTA `.zip` alone can't give you. Userspace-only; does not defeat AVB
on the X5 kernel/system. See [`BENIBUST.md`](BENIBUST.md).

## Cloud infrastructure (fingerprinted)

- `global-api` / `*-apitest.mondorobotics.com` → **AWS API Gateway** (`execute-api`,
  us-west-1). Auth-gated; `/` → `404 {"message":"Not Found"}`.
- `us-cdn.mondorobotics.com` → **AWS CloudFront** over S3, with **mandatory signed
  URLs** — `/` → `403 <Error><Code>MissingKey</Code> Missing Key-Pair-Id …`. So
  firmware objects are **not** fetchable by guessing the path.
- `cn-cdn.mondorobotics.com` → **Alibaba Cloud CDN/OSS** (geo-restricted).

## Can we grab it from the CDN directly? (pre-hardware) — **No**

Two independent blockers (both confirmed):

1. **Signed-URL CDN.** The real object key (`oss_path`) is server-held and only
   turned into a short-lived signed CloudFront URL by `POST /app/v1/files/getDownloadUrl`.
   No path template or bucket name is in the app, and CloudFront rejects unsigned
   requests (`MissingKey`). Path-guessing (the open-bucket route) does not apply.
2. **The mint needs the robot.** Both `package/latest` and `getDownloadUrl` require
   a user **JWT** (not in the auth whitelist; no app-key/HMAC substitute), *and*
   `package/latest` needs device-derived params — `board_id`, `batch_id`,
   `mondo_partition_size` (the robot's `FirmwareHardwareProfile`) **+** current
   `firmware_version`. `product_code` (`LZ100`/`LZ110`) alone is insufficient.
   These are plain strings (replayable if obtained) but not computable from the
   model code.

**→ Pre-hardware: not feasible. At/after first boot: yes** — once you read the
robot's HW profile + current version (the app does this on connect; we can too, via
`/cmd` partition-size + a version query), then with your account login you can mint
the signed URL and pull the `.zip` straight from CloudFront. `board_id`/`batch_id`/
`mondo_partition_size` are likely per-batch/model constants, so once read off one
unit the cloud pull becomes repeatable without re-touching the robot.

## How to capture (day one) — paths, all need the robot present

> A third route — **(C)** pulling a retained package off the `md_upgrade` daemon, and an
> inject-to-shell bridge from the external patch tool — is described in the
> "External protocol notes" section above. (A) and (B) below remain the MondoApp-only paths.

**(A) Cloud pull** (cleanest; no update required): log in (your account) → read the
robot's `board_id`/`batch_id`/`mondo_partition_size`/`firmware_version` → `POST
/app/v1/files/package/latest` → `getDownloadUrl` → HTTPS-GET the signed URL before
it expires.

**(B) LAN sniff** (no account needed): the app POSTs the raw `.zip` to the robot at
`http://192.168.7.1:16170/v2/upgrades/…` in **plain HTTP** over the robot's AP.
Sniff the AP (Pineapple monitor mode on the AP channel, creds learned over BLE) or
tcpdump from a host on that network. **No TLS to defeat.** Needs the app to actually
run an update, and the first OTA is one-shot — set up capture *before* tapping
update. Then carve the package straight out of the pcap:

```bash
python -m freewheel.fwextract capture.pcap -o firmware.zip --sha256 <manifest-sha>
```

(`freewheel.fwextract` reassembles the TCP stream and pulls the multipart file out;
feed it a classic pcap — convert a .pcapng with `editcap -F pcap`, and decrypt a
WPA monitor capture first. A Freewheel `.fwcap` won't contain it — that's the UCP
link on :9007, a different flow.)

Then, for either path:

- **Check the mode** (`firmware_encryption`, from the device's activation state).
- **If NONE:** unzip and `file`/`binwalk` the contents — find the on-disk format
  and whether it's a mountable rootfs (what answers the internal-ROS2/DDS-graph and
  attestation questions).
- **If ENCRYPTED:** the bytes are ciphertext; the key is on the board (nothing in
  the app or `libmondo_native.so` can decrypt), so defer to robot-side extraction
  (the deferred hardware phase — UART/flash).
