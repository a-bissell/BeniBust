# Enabling a live root shell on the X5

**Target:** Mondo LZA5211 (SN RAARD026AD207311), X5 SoC. Currently running
**V26.11.19.12**, active slot **_b**.

**Goal:** Persistent root on the X5 via OTA firmware modification.

**Result (2026-11-25): ACHIEVED.** Persistent **root** shell over telnet on `:23`/`:2323`
via the unsigned `hbre` partition, with `/md` **dm-verity still intact**. See
§ v9–v14 and § v15 — SUCCESS below.

**Method (final):** `.plain.unsign` 0300 OTA package → `md_upgrade` (mondo) →
`/usr/hobot/bin/ota_tool` → device `libota_common` extracts and runs the
**package-supplied** `ota_process` as root → patched allowlist admits `hbre` →
OTA writes stock verity images + modified `hbre` to the inactive slot → reboot →
`S90cam-service` executes `/usr/hobot/bin/cam-service` (our wrapper) as root.

> **CORRECTION (2026-11-25).** The original premise of this document — "mondo has no
> dm-verity, modify `/md`" — is **wrong**. `/md` **is** dm-verity protected: the root hash
> `fd1bdc352dc3e6b681f9f978f34ea281560f0d6ead93f1d5937562e36d061192` is pinned in
> `/etc/lz100-mondo-verity.conf` on the AVB-signed `system.img`, and `lz100-mondo-check`
> sets up the `mondo-verity` target with `restart_on_corruption`. Verified live via
> `dmsetup table`. Consequently every `v9`–`v14` `/md` modification failed verification and
> was never used at runtime. The working route is the **unsigned `hbre` partition**, which
> is **not** covered by `vbmeta` and has **no** dm-verity.

**Historic status (superseded):** v8 package built and verified, awaiting upload.

## Why this is hard

Three independent mechanisms keep sshd dead on retail:

1. **Gate file** — `S50sshd` refuses to start sshd while
   `/md/etc/authorized_debug_profile` exists
2. **md_sys debug state machine** — `authorized_debug_owner` unconditionally kills any
   running sshd at boot, regardless of the gate file (see § md_sys kill chain below)
3. **mdctl.sh autostart verification** — apps started via autostart must keep their
   launch PID alive and pass `pidof` + cmdline checks (see § mdctl.sh autostart below)

The runtime enable is TEE/eFuse/CA-locked — no network bypass.

> **Superseded:** the original plan was to defeat these three mechanisms via `/md` edits.
> That is impossible on this firmware because `/md` is dm-verity protected (see correction
> above). These mechanisms still explain why no `/md` payload ever ran; the working design
> avoids `/md` entirely and hijacks the root-executed `S90cam-service` through `hbre`.

> **⚠ REINSTATED (corrected 2026-11-24).** We previously believed this unit's
> `is_encrypted:1` flag meant md_upgrade would reject plaintext OTA packages. **Binary
> analysis of `md_upgrade` disproves this** — see
> [`security-activation.md`](security-activation.md). md_upgrade has an explicit
> `process_plain_package` code path selected by filename suffix (`.plain.unsign`), and does
> NOT consult `is_encrypted` or `get_crypto_info` for local uploads. The OTA reflash route
> **is viable** on this ENCRYPTED unit.

## md_sys kill chain (RE'd from `/md/bin/md_sys`, Ghidra decompilation)

`md_sys` does **not** check the gate file — the string `authorized_debug_profile` does
not appear in the binary. Instead it enforces debug state via a TEE-backed state machine:

```
usb_gadget_manager() constructor          [0x4dfa20]
  └─ ALWAYS creates authorized_debug_owner
  └─ ALWAYS calls factory_adb_allowed()   → queries TEE, NOT gate file
  └─ ALWAYS calls establish_boot_service(factory_adb_allowed)
       └─ locked unit: factory_adb_allowed=false
       └─ transition_to(2)                [0x4e6470]
            ├─ step 1: stop_sshd          (vtable +0x28)
            │    └─ run_service_action("authorized-debug-stop")
            │         └─ /etc/init.d/S50sshd authorized-debug-stop (on system.img, AVB)
            │              └─ killall sshd  ← UNCONDITIONAL, no gate check
            ├─ step 2: stop_adbd
            ├─ step 3: stop_debug_authd
            ├─ step 4: reconfigure USB → mass_storage only
            └─ fallback: recover_closed   [0x4e5f10]
                 └─ scans /proc for process named "sshd"
                 └─ run_service_action("authorized-debug-stop")
                 └─ direct stop_sshd_and_wait (kill by PID)
```

**Steady state (state 2):** the policy tick does NOT actively re-kill sshd. It checks USB
gadget health and tries `request_verified_open` (TEE lease — always fails on locked unit),
then returns. It only re-kills if USB gadget state breaks (re-triggers transition_to).

**Implication:** gate-file-delete alone gives a **boot-race window of seconds**, NOT
persistent SSH. sshd starts via S50sshd, then md_sys initializes and kills it.
But sshd restarted *after* md_sys settles into state 2 stays up.

## mdctl.sh autostart mechanism (RE'd from `/usr/bin/mdctl.sh`, 2274 lines)

This is the third barrier, discovered during v5-v7 debugging. `S99md_app_startup.sh` calls
`mdctl.sh autostart` which reads `/md/etc/.config/md_app_autostart.conf` and starts each
app as `/md/bin/$app`.

**Launch path** (line 322-327): `nohup "$app_path" >/dev/null 2>&1 &`

**PID verification** (line 877, `wait_for_launched_pid`): checks `kill -0 "$pid"` for up
to 5 seconds (25 iterations x 0.2s). If the launch PID is dead by then, the app is marked
**FAILED** and retried once.

**Fanout check** (S99, `read_unique_md_app_pid` lines 549-568): uses BOTH `pidof "$app"`
(checks `/proc/pid/comm`) AND `grep -Fq "/md/bin/$app"` on `/proc/pid/cmdline`. Both must
pass.

**Stop function** (S99, `stop` lines 783-821): `pgrep -f "^/md/bin/md_"` to find and kill
all md_ processes. Matches any process whose cmdline starts with `/md/bin/md_`.

**Autostart conf validation** (line 816): app names must match `^md_[^/]+$`.

**Implications for sshd:**
- sshd calls `daemon()` → fork → parent exits → launch PID dies → `wait_for_launched_pid`
  FAILS → app marked FAILED
- Shell script wrappers: comm = "sh" → `pidof $app_name` FAILS
- Both are fatal to the autostart verification

## Version history

### v1-v2 (design only, never flashed)

v1: gate-file-delete only. v2: watchdog daemon. Both superseded before flash.

### v3 — flashed 2026-11-24, SSH failed

**Approach:** Delete gate file + renamed `md_sshd` binary + watchdog in autostart.

**Root cause:** Deleting `authorized_debug_profile` caused `S50sshd` to start **stock
sshd** on port 22 at boot priority 50 — before our `md_sshd` launched via S99 autostart.
Stock sshd occupied port 22; `md_sshd` got `EADDRINUSE` (silenced by `2>/dev/null`).

```
# S50sshd start case:
if uses_authorized_debug_owner; then    # checks if gate file exists
    echo "sshd remains closed; managed by md_sys authorized debug"
else
    start_sshd    # starts /usr/sbin/sshd on port 22!
fi
```

**Key insight:** `authorized_debug_profile` must be **kept**, not deleted.

### v4 — flashed 2026-11-24, version-match SKIP (no flash occurred)

**Approach:** Keep gate file + `md_sshd` binary + `md_sshd_config` + `md_sshd_persist`
watchdog script in autostart.

**Root cause:** Package version = `26.11.19.01` = robot's running version.
`skip_if_firmware_version_matched = true` in ota_tool caused the flash to be **silently
skipped**. Robot rebooted to the other A/B slot's stock mondo (no SSH files).

**Fix applied in v5:** bumped version to `26.11.19.02`.

### v5 — flashed 2026-11-24, SSH failed

**Approach:** Same as v4, version bumped to `26.11.19.02`.

**Root cause:** `md_sshd_persist` is a **shell script**. The S99 fanout check uses
`pidof md_sshd_persist` which checks `/proc/pid/comm`. For shell scripts, comm = `sh`
(the interpreter), NOT the script name. `pidof` never finds it. The fanout reports
`md_sshd_persist` as "missing" after 3 retries x 10 seconds.

**Key insight:** autostart entries must be compiled binaries, not shell scripts.

### v6 — built, never uploaded (connectivity issue)

**Approach:** Delete gate file, no custom binary, rely on stock sshd starting via S50sshd.
Stock `sshd_config` has `PermitRootLogin yes` + `PasswordAuthentication yes`.

**Abandoned before flash:** re-reading the md_sys kill chain revealed that md_sys kills
stock sshd during boot (§ md_sys kill chain, `transition_to(2)` → `killall sshd`), and
nothing would restart it. Gate-file-delete alone gives a boot-race window of seconds, not
persistent SSH.

### v7 — flashed 2026-11-25, SSH failed

**Approach:** Keep gate file + `md_sshd` binary (sshd copy) **directly in autostart**
(no shell wrapper). Version `26.11.19.04`.

OTA uploaded successfully (V2 TUS, 1.3 GB in 202s), install state = `SUCCEEDED`,
1 reboot. Port 22 still closed after reboot.

**Root cause:** sshd calls `daemon()` on startup — fork, parent exits. `mdctl.sh`
launches via `nohup /md/bin/md_sshd >/dev/null 2>&1 &` and tracks the launch PID.
`wait_for_launched_pid` checks `kill -0 "$pid"` → parent is dead → **FAILED**.

The daemon child may actually be running briefly, but sshd may also fail post-fork
(config issues, host key access, etc.) — without diagnostics we can't confirm.

**Key insight:** sshd must run with `-D` (don't daemonize) to keep the launch PID alive.
But autostart provides no way to pass command-line arguments.

### v8 — BUILT, VERIFIED, AWAITING UPLOAD (current)

**Approach:** Hand-assembled 253-byte aarch64 ELF wrapper + real sshd binary + explicit
config. Version `26.11.19.05`.

**The ELF wrapper** (`/md/bin/md_sshd`, 253 bytes, static, no libc):
```
execve("/md/lib/md_sshd",
       ["/md/bin/md_sshd", "-D", "-f", "/md/etc/md_sshd_config"],
       NULL)
```

**How it defeats all three barriers:**

| barrier | mechanism | how v8 defeats it |
|---------|-----------|-------------------|
| Gate file (S50sshd) | Checks `/md/etc/authorized_debug_profile` | **Kept** — S50sshd skips, port 22 free |
| md_sys kill chain | `killall sshd` + `/proc` scan for "sshd" | Real binary named `md_sshd` → invisible |
| mdctl PID check | `kill -0 $launch_pid` after 0.2-5s | `-D` flag: sshd stays foreground, PID lives |
| mdctl fanout `pidof` | Checks `/proc/pid/comm` | comm = `md_sshd` (from binary filename) |
| mdctl fanout cmdline | `grep -Fq "/md/bin/md_sshd"` | argv[0] = `/md/bin/md_sshd` in cmdline |

**Files in v8 mondo.img** (4 added, 1 modified vs stock V26.11):

| path | size | description |
|------|------|-------------|
| `bin/md_sshd` | 253 B | ELF wrapper (hand-assembled aarch64, static) |
| `lib/md_sshd` | 1,006,472 B | Real sshd binary (byte-copy of `/usr/sbin/sshd`) |
| `etc/md_sshd_config` | 318 B | sshd config (port 22, root+password, stock host keys) |
| `etc/authorized_debug_profile` | 18 B | **Stock, kept** (prevents S50sshd port conflict) |
| `etc/.config/md_app_autostart.conf` | modified | Stock 18 entries + `md_sshd` appended |

**Expected boot sequence (v8):**
1. BusyBox init runs `S50sshd start` → gate file present → "managed by md_sys" → **skips**
2. Port 22 remains **free**
3. md_sys starts → `killall sshd` → no process named "sshd" → no-op
4. md_sys settles into state 2 (steady state, no re-kill)
5. S99 → `mdctl.sh autostart` → starts `/md/bin/md_sshd` (the 253-byte wrapper)
6. Wrapper `execve`'s `/md/lib/md_sshd -D -f /md/etc/md_sshd_config`
7. sshd runs in foreground (`-D`), PID stays alive → `wait_for_launched_pid` **passes**
8. `pidof md_sshd` → comm = "md_sshd" (from `/md/lib/md_sshd` filename) → **passes**
9. cmdline = `/md/bin/md_sshd -D -f /md/etc/md_sshd_config` → grep for `/md/bin/md_sshd` → **passes**
10. sshd listens on port 22, root login with password enabled

**v8 package:** `beni_fw/build_26.11/V26.11.19.05_lz110_v8.zip` (1.3 GB)
Verified with an external patcher's `verify_package()` — all 4 partitions pass, zero warnings.

### v9–v14 — `/md` modifications (all superseded; blocked by dm-verity)

These packages modified `mondo.img` (md_sys patches, supervisor ELFs, autostart changes,
gate-file removal). All uploaded with `SUCCEEDED` and rebooted, but **none produced a
shell** because `/md` is dm-verity protected: the modified `mondo.img` never verified, and
the unit stayed on / rolled back to a verity-valid slot. Notably:

- v13/v14 patched `md_sys` `run_service_action` / `stop_sshd_and_wait` with
  `mov w0,#1; ret` (`20 00 80 52 c0 03 5f d6`) at `0x4e1de0`, `0x4e2cc0`, `0x4e25a0`.
  The patched binary was correct but never executed.

Confirmed by hashing the **stock** `mondo.img`: its dm-verity root is exactly
`fd1bdc35…`, matching the value pinned on `system.img`.

### v15 — SUCCESS (2026-11-25): unsigned `hbre` → persistent root

**Idea:** `vbmeta` covers only `boot` (hash) and `system` (hashtree); `hbre` is **not** in
`vbmeta` and has **no** dm-verity. `hbre` mounts at `/usr/hobot` (`ro`) and
`/etc/init.d/S90cam-service` executes `/usr/hobot/bin/cam-service` **as root on every
boot**. A wrapper at that path is therefore a persistent root execution point that never
touches `/md`.

**Obstacle:** the V26.11 `ota_process` restricts a package to the four protected partitions
whenever the device reports the LZ100 mondo/verity profile:
`unsupported partition %s in LZ100 mondo OTA` (`ota_update.c:1443`). Adding `hbre` to
`data.json` is rejected.

**Key insight:** that allowlist lives in the **package-supplied** `ota_process`, not on the
device:

- `md_upgrade` (Rust, mondo) extracts the 0300 `.fw` and spawns `/usr/hobot/bin/ota_tool`.
- `ota_tool` calls `libota_common.so.1` (hbre) → `get_ota_process()` →
  `hb_uncompress_one(package, "/tmp/process/", "ota_process")` → the package's
  `ota_process` is written to `/tmp/process/ota_process` and executed as root.
- `libota_common` has no allowlist logic; `md_upgrade`'s signature check is skipped for
  `.plain.unsign` (`process_plain_package`; `require_scheme_a_signature = false`).

**Patch (single branch, `ota_verify_system_image`):**

| item | value |
|------|-------|
| vaddr | `0x408a24` |
| file offset | `35364` |
| original | `2a 02 00 54` — `b.ge 0x408a68` |
| patched | `11 00 00 14` — `b 0x408a68` (unconditional) |

This bypasses only the allowlist rejection. All other checks remain: active dm-verity, no
anti-rollback request, all four protected images present, per-partition
medium/type/method/scope validation, inactive-slot requirement, and completeness. Verified
patched disassembly: `b 0x00408a68`.

**Payload:**

- Stock V26.11 `vbmeta.img`, `boot.img`, `system.img`, `mondo.img` (verity-valid).
- `hbre.img` from the vendor V26.09 0300 archive (157,286,400 B, exact `hbre_b` size):
  - `/bin/cam-service` → 369-byte wrapper: starts
    `/bin/busybox telnetd -b 0.0.0.0 -p 23 -l /bin/sh` and `-p 2323`, writes
    `/tmp/hbre_hook`, then `exec /usr/hobot/bin/cam-service.real "$@"`.
  - `/bin/cam-service.real` → original 54,744-byte aarch64 camera binary (vision kept).
  - `/bin/ota_tool` retained (needed to process future 0300 packages).
- `data.json`: `update_partition = [vbmeta, boot, system, hbre, mondo]` plus `hbre`
  partition_info (`md5_scope` = full 157,286,400).

**Why `md_sys` does not kill it:** `md_sys` scans `/proc/*/comm` for the exact name
`sshd` and runs `/etc/init.d/S50sshd authorized-debug-stop`. `telnetd` and
`cam-service.real` do not match; the shell is `/bin/sh`.

**Artifacts:**

| artifact | value |
|----------|-------|
| builder | `beni_fw/build_26.11/build_v15.py` (patch + hbre overlay + data.json + packs) |
| outer package | `V26.11.19.12_lz110_v15.zip` — 620,674,944 B · sha256 `278d68e4503fae30bccba4b123780e9b52a2e799e903effc9b3066b70803580d` |
| inner 0300 | `lz110_0300_V26.11.19.12_20261125.mass.fw.plain.unsign` — 620,674,171 B · sha256 `6e4ed8b4…` |
| patched `ota_process` | sha256 `2fcd5d23965c6598cac90236f486536fa9010ce167385b883ae2b38a5897028e` |
| patched `hbre.img` | 157,286,400 B · md5 `91b922ba2904ea2a0a446a10a29061e6` |
| wrapper / real | 369 B / 54,744 B · real md5 `5b87e8c53e8153339401b30188858795` |

**Live evidence (2026-11-25, telnet `:23`, after OTA + reboot):**

- `id` → `uid=0(root) gid=0(root)`; `Linux buildroot 6.1.83-rt28-DR-PL5.1_V1.1.1 #1 SMP PREEMPT Wed Nov 18 02:03:43 CST 2026 aarch64`.
- `/proc/cmdline` → `root=/dev/dm-0 ro … hobotboot.slot_suffix=_b … dm-mod.create="dm-verity,…,sha256 9021b1cd… f3f0c5c1… 2 restart_on_corruption"`.
- `by-name/` → `boot→boot_b`, `hbre→hbre_b (mmcblk0p15)`, `mondo→mondo_b (mmcblk0p17)`, `system→system_b (mmcblk0p13)`, `vbmeta→vbmeta_b (mmcblk0p9)`.
- `mount` → `/dev/block/platform/by-name/hbre on /usr/hobot type ext4 (ro,noatime)`.
- `dmsetup table` → `mondo-verity … sha256 fd1bdc35… f982f504… 1 restart_on_corruption` **and** `dm-verity … sha256 9021b1cd… f3f0c5c1… 2 restart_on_corruption`.
- `ls -l /usr/hobot/bin/cam-service*` → 369 B wrapper, 54,744 B real; `/tmp/hbre_hook` = `hbre-hook`.
- `ps` → `cam-service.real` PID 830; `telnetd` PIDs 835/837 (PPID 1); `/md/bin/md_sys` PID 1104.
- `/md/etc/authorized_debug_profile` still present (`auth_only_service`), yet root obtained — the TEE debug gate was bypassed, not defeated.
- `/blackbox/firmware/last_package.toml` → `package_version="26.11.19.12"`, path sha256 `278d68e4…`, `method="ota_tool"`, `legacy_package_compat=true`.

**Impact:** unauthenticated, persistent root on the robot AP (`:23`/`:2323`) that survives
reboots, **without** modifying `/md`, defeating dm-verity, or opening the TEE authorized
debug path. Anyone who joins the AP gets root.

**Root causes (for disclosure):**

1. The OTA updater trusts a **package-supplied** privileged binary (`ota_process`),
   extracted and executed as root with no integrity binding to signed firmware.
2. Partition eligibility is enforced in that package-supplied binary, not on the device.
3. `.plain.unsign` packages are accepted for local OTA.
4. `hbre` is unsigned, not covered by `vbmeta`, and has no dm-verity, yet is root-executed
   at boot.
5. A service is launched as root from a mounted, non-integrity-protected partition.

**Remediation ideas:** pin/verify `ota_process` (hash or signature from signed system);
keep partition allowlists device-side; add AVB/verity for `hbre`; do not execute code from
unsigned user-data partitions as root; authenticate the debug service; restrict inbound
ports.

## Reconnecting

Join the robot AP `Beni-207311` (`ipconfig getifaddr en0` → `192.168.7.x`). macOS may
auto-switch back to an internet-capable network; keep internet on **Ethernet** or turn off
Auto-Join for the home SSID.

Interactive root shell (Python 3.11 `telnetlib`; the method is **`interact()`**, not
`interactive()`):

```sh
~/Documents/venv/bin/python -c 'import telnetlib,time; t=telnetlib.Telnet("192.168.7.1",23,timeout=10); time.sleep(.5); t.interact()'
```

Exit with `exit` (remote sh exits) or Ctrl-]. For scripted batches, use a marker-based
reader — `write(cmd + " ; echo __RC__$?")` then `read_until(b"__RC__")` — to avoid
prompt/output races and paste newline loss.

## Established facts

| fact | source |
|------|--------|
| OTA flash works (A/B slot, no anti-rollback on mondo) | v3 flashed and booted |
| `skip_if_firmware_version_matched` skips same-version | v4 silently skipped |
| Shell scripts fail autostart pidof check (comm="sh") | v5 failure analysis |
| sshd `daemon()` fork kills launch PID | v7 failure + mdctl.sh RE |
| md_sys kills "sshd" once at boot, not "md_sshd" | md_sys RE (Ghidra) |
| md_sys state 2 does NOT re-kill | md_sys RE (Ghidra) |
| S50sshd starts stock sshd when gate file absent | v3 failure analysis |
| **mondo IS dm-verity protected** (root hash `fd1bdc35…` pinned on system) | `/etc/lz100-mondo-verity.conf` + live `dmsetup table` |
| **hbre is NOT in vbmeta and has NO dm-verity** | vbmeta descriptor parse + live `mount`/`dmsetup` |
| Device `libota_common` execs the **package-supplied** `ota_process` as root | `get_ota_process`/`hb_uncompress_one` RE + v15 |
| V26.11 `ota_process` allowlist is bypassable with one branch patch | v15, `0x408a24` |
| plain/unsign OTA accepted; signature check skipped for it | `md_upgrade` RE + v15 install |
| hbre wrapper persists; `md_sys` does not kill `telnetd` | v15 live `ps` / `:23` |
| Plain OTA packages accepted on ENCRYPTED units | md_upgrade RE |

## OTA build & upload procedure

### Building a new version

All builds start from stock `mondo.img` (md5 `6c5b5aede7718329f327f578d29b26d1`).
Modifications use `debugfs -w` from e2fsprogs (`/opt/homebrew/Cellar/e2fsprogs/1.47.3/sbin/`).

```
1. cp stock mondo.img → mondo_vN.img
2. debugfs -w modifications (add/replace files)
3. Update data.json with new mondo md5
4. Build inner zip: zip -0 (data.json gpt.conf ota_process vbmeta.img boot.img system.img mondo.img)
5. Write TOML manifest with inner zip sha256 + size, BUMPED version string
6. Build outer zip: zip -j -0 (manifest + inner zip as firmware file)
7. Verify: `verify_package()` (external patcher equivalent)
```

The V26.11 base images (vbmeta, boot, system, ota_process, gpt.conf) live in
`scratchpad/v4_build/inner_stage_v4b/`. Stock mondo is in `beni_fw/current_26.11/mondo.img`.

**Version strings used:** .01 (stock), .02 (v5), .03 (v6), .04 (v7), .05 (v8), …, .12 (v15).

**Working hbre route:** `benibust.py` does all of it in one pass — it patches
`ota_process` (offset `35364`), overlays `hbre`, updates `data.json` (adds `hbre` and
recomputes the patched image checksums), packs the inner/outer zips, and runs
`freewheel.ota.verify_package()` with `allow_unsafe_x5_override=True`. No third-party
packages are involved.

### Uploading and installing

```bash
# V2 TUS (resumable; needs UCP 9007 — close the Freewheel console first)
python3 -m freewheel.ota upload V26.11.19.12_lz110_freewheel.zip --host <robot_ip> --install
```

Or from Python:

```python
from freewheel.ota import upload_firmware, trigger_ota_install
result = upload_firmware(pkg_path, host="<robot_ip>", mode="v2")
trigger_ota_install("<robot_ip>", upgrade_id=result.upgrade_id, upload_token=result.upload_token)
```

The install itself is `POST /v2/upgrades/<upgrade_id>/install` with
`Authorization: Bearer <your media token>` + the live `Upload-Token`. The bearer comes
from `freewheel.ota.resolve_media_token()` — recover your own with
`python3 -m freewheel.ota extract-token ~/Downloads/MondoApp.apk`.

After install (state = `INSTALLING` → `AWAITING_REBOOT` → reboot → `SUCCEEDED`):
re-enroll robot to WiFi via BLE, then `ssh root@<ip>` (password in agent memory).

**UCP is single-session:** close any Freewheel console connection before V2 TUS upload.

## Connectivity issues

The robot has intermittent network drops on home WiFi (mesh network). Symptoms:
- UCP connections drop after 5-30 seconds with high latency
- HTTPS connections time out or SSL EOF mid-transfer
- Both WiFi and robot AP affected (less so on AP)

Robot IP changes on re-enrollment. Known IPs: .60, .58, .52 (home WiFi), .7.1 (robot AP).

## Risk & backstop

- **Brick risk (v15): Low.** The four AVB/verity images are byte-identical stock V26.11;
  `hbre` is not covered by vbmeta and is not boot-critical (mounted at `/usr/hobot`, a
  service payload, not the rootfs); the `ota_process` change is a single verified branch
  and a wrong patch fails before writing. A/B boot-control can fall back to the other slot.
- **Real risks:** (a) power loss during the OTA (the only genuine brick vector);
  (b) functional mismatch from running V26.09 `hbre` (older hobot/camera libs) on V26.11
  system — camera/user-space instability, not a brick; (c) the resulting `telnetd` is
  **unauthenticated root** on the AP.
- **Backstop:** UART console (`ttyS0,921600n8`), or A350 co-processor.
- **Revert:** Re-flash a **vendor full V26.09 package** (it includes `hbre`) to restore
  stock `hbre`. Note the stock V26.11 package **omits `hbre`**, so re-flashing V26.11 alone
  will *not* restore it.
- **Anti-rollback:** `sec_antirollback_update: 0`, `nosec_antirollback_update: 0` — not
  enforced. Can reflash any version.

## Reference: firmware verification findings (corrected 2026-11-25)

- **mondo IS dm-verity protected** — root hash `fd1bdc352dc3e6b681f9f978f34ea281560f0d6ead93f1d5937562e36d061192`
  pinned in `/etc/lz100-mondo-verity.conf` on `system.img`; live target `mondo-verity`
  confirmed via `dmsetup table` (`restart_on_corruption`).
- **dm-verity protects system.img (dm-0) and mondo** — the kernel cmdline `dm-mod.create`
  sets up the system hashtree; `lz100-mondo-check` creates `mondo-verity`.
- **hbre has NO dm-verity and is NOT covered by vbmeta** — vbmeta descriptors are
  kernel_cmdline ×2, `hash` for `boot`, `hashtree` for `system`; no `hbre`/`mondo` entry.
- **hbre mounts `ro` at `/usr/hobot`**; `S90cam-service` runs `/usr/hobot/bin/cam-service`
  as root at boot.
- **vbmeta is SHA256_RSA2048 signed**, flags=0.
- S50sshd stop uses `killall sshd` (exact name) + `pidof sshd` (exact name);
  `md_sys` scans `/proc/*/comm` for `sshd` only.

## Reference: ingest path

md_upgrade supports both Cfg (outer manifest) and FwAll (inner firmware-all) formats.
We use Cfg — the production-tested path. The filename parser expects:
`<product>_<part>_<version>_<date>.<build>.<type>.<enc>.<sig>`, e.g.,
`lz110_0300_V26.11.19.05_20261125.mass.fw.plain.unsign`.

Credentials/token live in agent memory, never this repo.
