# Light Phone III: verified media backup and unlock attempt

25 September 2026. The owner authorised backing up photos/videos and then attempting a bootloader unlock, including the expected factory reset on success.

**Later follow-up succeeded:** [local certificate authorisation unlocked the bootloader](light-phone-iii-local-authorisation.md), with post-reset ADB confirmation. This page records the earlier standard attempt that failed.

## Outcome

The media backup completed and was verified. Standard bootloader unlocking **failed**. No factory reset or firmware flashing occurred. The phone returned to Android and continued to report flash locked and verified boot green.

## Backup

- Destination: `/Users/vandam/Downloads/lp3_photos/`.
- 1,704 media files; 4,539,090,697 bytes (4.54 GB).
- Includes all 847 MediaStore-indexed photos/videos, plus media-extension files throughout readable shared storage, including thumbnails and unindexed images.
- Original directory structure retained. Shared-storage traversal reported no access errors. This is a media backup, not a full application/data backup.
- Every local file's SHA-256 matched its original on the device.
- A final MediaStore inventory before changing unlock settings still contained 847 entries, all included in the verified backup.
- Per-file evidence: `lp3_photos/_backup/verified-manifest.json`; completion summary: `lp3_photos/_backup/verification.json`.
- Completed at 11:09:48 BST. The transient transfer archive was removed after extraction; the actual media files and verification records remain.

## Preparing the unlock permission

Prism root was already active. ReSukiSU Shell access was enabled for the required root operations.

The Android OEM-unlocking switch was greyed out with a connection/carrier message, although the network was validated and the OEM-lock carrier getter returned true. `dumpsys user` revealed a base `no_factory_reset` restriction. AOSP's Settings controller disables OEM unlocking when this restriction exists.

After backup verification:

1. Temporarily cleared `no_factory_reset` for user 0 using `pm set-user-restriction` under root.
2. Called Android 14's `IOemLockService.setOemUnlockAllowedByUser(true)` (verified transaction 4) under root. This uses the framework service rather than manually modifying partition bytes.
3. Read-only getters returned carrier=true, user=true, combined=true.
4. The actual final byte of `frp` read **1**, and `sys.oem_unlock_allowed` read **1**.

Current FRP, devinfo, deviceinfo and AVB metadata were backed up locally before changes, under the ignored `artifacts/bootloader-research/2026-09-25/pre-unlock/` directory. These files are private and are not a complete recovery solution.

## Actual fastboot results

After `adb reboot bootloader`:

| Query | Result |
| --- | --- |
| `getvar is-userspace` | `no` — actual bootloader, not fastbootd |
| `getvar current-slot` | `a` |
| `getvar unlocked` | `no` |
| `flashing get_unlock_ability` | `0` |
| `oem device-info` | verity=true; unlocked=false; critical unlocked=false |
| `oem getpermissions` | `permissions=none` |
| `oem state_of_permission` | `NO permission!` |
| `oem getBootloaderType` | `commercial` |
| `oem getRootStatus` | `Disable` |
| `oem getRPMBStatus` | `RPMB=provisioned` |
| `oem frp get` | unknown command |

The authorised unlock request was issued once:

```text
$ fastboot flashing unlock
FAILED (remote: 'Flashing Unlock is not allowed
')
fastboot: error: Command failed
```

It failed immediately; no unlock confirmation or wipe occurred. No critical-unlock, erase, flash, slot-switch, OEM token mutation or modified bootloader operation was attempted.

The results are consistent with the [previously traced FIH override](light-phone-iii-bootloader-investigation.md): a real FRP permission of 1 is insufficient, bootloader ability becomes 0, and the normal unlock handler returns its explicit disallowed error. Runtime root does not supply the bootloader's separate OEM authorisation. This establishes the observable failure; it does not establish a safe bypass or prove whether Light intended the extra restriction.

## Return to Android

`fastboot reboot` returned the device to Android. Boot completion was confirmed, `ro.boot.flash.locked=1`, `ro.boot.verifiedbootstate=green`, and the Light photo directory still contained its 137 files. Installed Prism and Shizuku remained present. The temporary OEM-unlock permission persisted as 1 across the reboot before cleanup.

Exact command outputs are retained locally as `fastboot-pre-unlock.json`, `fastboot-unlock-attempt.json` and `fastboot-oem-readback.json` under `artifacts/bootloader-research/2026-09-25/`.

Cleanup: Prism was activated again successfully after the reboot (`status=pass`, `unsafe=0`). The OEM-lock service initially rejected a request to disable the permission because an admin restriction was already present again; after restoring `no_factory_reset=1`, readback confirmed user/combined OEM permission false and the final FRP byte 0. Thus the temporary unlock settings ended in their original state. ReSukiSU Shell access was revoked and another root-shell attempt returned `Operation not permitted`. Prism was returned to the foreground with runtime root active.

## Next productive step

Give Light the precise reproduction: on firmware `00WW_1_440000`, Android OEM-lock getters and the stored FRP bit are all enabled, yet bootloader fastboot reports ability 0, OEM permissions none, and rejects the standard unlock command. Ask for the intended commercial-device authorisation path or a corrected signed ABL removing/fixing the FIH gate. The matching live ABL hashes and code locations are in the investigation report.

Further offline tracing of the OEM authorisation verifier is possible. Blindly flashing a patched ABL or editing lock-state partitions is not established as a viable next step. No message was sent to Light.
