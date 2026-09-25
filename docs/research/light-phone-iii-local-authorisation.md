# Light Phone III: local bootloader authorisation

25 September 2026. Follow-up to the failed standard unlock attempt, at the owner's explicit request to pursue a local method using Prism.

## Confirmed result

**The bootloader was successfully unlocked.** After the owner confirmed the on-device prompt, the phone factory-reset and booted the original firmware. Following setup and restored ADB access, independent Android readback reported:

```text
ro.boot.flash.locked=0
ro.boot.vbmeta.device_state=unlocked
ro.boot.verifiedbootstate=orange
ro.boot.veritymode=enforcing
ro.boot.securityfused=true
ro.boot.slot_suffix=_a
ro.build.version.incremental=00WW_1_440000
sys.boot_completed=1
```

This verifies persistent bootloader unlock across the reset/reboot. It does not disable hardware secure boot or imply that critical bootloader partitions are unlocked. No custom ROM or Magisk image was flashed. Prism/ReSukiSU applications were removed by the reset, so temporary runtime root is not presently active.

Prism root allowed us to provide a one-use certificate record in the existing FIH authorisation area. On the next boot into bootloader fastboot:

| Query | Before | After |
| --- | --- | --- |
| `flashing get_unlock_ability` | 0 | **1** |
| `oem getRootStatus` | Disable | **Enable** |
| `oem getpermissions` | permissions=none | **permissions=flash** |
| `oem state_of_permission` | NO permission! | **HAVE permission!** |

The subsequent `fastboot flashing unlock` returned `OKAY` instead of the previous disallowed error and displayed an on-device confirmation screen. The first screen disappeared without a selection. The command was issued again; no further fastboot queries were sent while the owner selected the unlock option. The owner then reported that it was unlocked.

USB disconnected during the immediate verification attempt. The first query hit a USB transition error and the subsequent query timed out; afterwards neither ADB nor fastboot enumerated a device until setup and USB debugging were restored. The subsequent independent readback above confirmed the successful unlock. Exact final output is saved as `post-reset-unlock-verified.txt` in the artefact directory.

## Why this works

The bootloader has two relevant routes to the same RAM authorisation state:

- Interactive `fih_root_verify` selects a configured certificate and verifies a device-bound signature.
- Boot-time `fih_cert_init` reads a cached record containing both a certificate and signature from `mfd`, and passes that supplied certificate directly to `fih_root_auth`.

The latter path extracts the RSA public key from the supplied X.509 certificate and verifies the signature, but the inspected path does not validate that certificate against a Light trust anchor. The extraction helper closely matches EDK II's `RsaGetPublicKeyFromX509`, which is distinct from certificate-chain verification. See the [independent source and disassembly review](light-phone-iii-oem-public-sources.md).

This permits a locally generated self-signed certificate and matching device-bound signature to satisfy the cached-record path. It does not require modifying ABL or forging a signature under Light's key.

## Offline validation

The original, live-hash-matched ABL AArch64 code was executed using Unicorn. The host supplied allocation, SafeStack storage, debug stubs and simulated record I/O; the original certificate parser, SHA-256 implementation, RSA verifier and authorisation logic executed unchanged.

1. The direct authorisation routine accepted a freshly generated RSA-2048 self-signed certificate and correct signature, returning success and setting state 1.
2. A deliberately invalid signature was rejected and left state zero.
3. The full boot-time certificate initialisation accepted the correct record and rejected both a corrupted signature and a record bound to a different hardware ID.
4. With count=1, the full routine decremented the count, granted RAM authorisation, and cleared the stored record while leaving RAM authorisation active for that boot.

An implementation detail discovered through emulation: the EFI formatter emits uppercase hexadecimal for the hardware ID, even though the format string is `%08x`. Signing the lowercase representation fails. The actual fuse word was read through the read-only qfprom nvmem interface and matched the SoC serial value.

The record is consumed on any boot, not only a boot into fastboot. Its persistence writes return statuses that the caller ignores. Cleanup returned the simulated record to the original bytes in emulation, but the live mfd block could not be independently reread after the reset without restoring root; on-device cleanup therefore remains unverified. The original full partition backup is retained. This limitation does not affect the independently verified persistent unlock result.

## Device change and safeguards actually used

- Existing photo/video backup was already SHA-256 verified; the MediaStore inventory was checked again for unbacked additions before staging.
- The complete original 128 KiB `mfd` partition was copied locally and its live bytes rechecked before modification.
- The write was confined to the existing 4 KiB certificate block at byte offset `0x3000`.
- The original trailing padding was all zero, matching the bootloader's full-block write behaviour.
- The record requested one boot of authorisation. The entire partition was read back afterwards and compared with the expected image; every byte outside the 4 KiB region was unchanged.
- OEM-unlock permission was enabled through Android's OEM-lock service, and the actual FRP permission byte was checked as 1 before reboot.
- The phone was rebooted directly into bootloader fastboot. No intervening Android boot consumed the record.
- ABL, XBL, GPT, AVB images and ROM partitions were not modified.

Original mfd SHA-256: `209a0c5244ad5c176a78c3f975a214aa13405ada7df059c5d354305ed1145905`.

Staged mfd SHA-256: `92b6d5aea8236872a47bf5d8c4b299202e3fb4e29ec1da6d043f62ee68e43326`.

The backup, offline experiment, staging readback and exact fastboot outputs are retained in the ignored local directory `artifacts/bootloader-research/2026-09-25/`. Nothing was published or sent externally. This is a device-specific investigation, not a general-purpose unlock tool.
