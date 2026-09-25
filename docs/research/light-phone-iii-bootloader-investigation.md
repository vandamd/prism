# Light Phone III bootloader investigation

25 September 2026. Device inspection, authorised Prism root activation, and offline firmware analysis.

Follow-up: a subsequently authorised, media-backed-up unlock attempt reproduced the permission override and standard unlock rejection. See the [actual unlock-attempt results](light-phone-iii-unlock-attempt.md); the sections below describe the preceding investigation.

**Final outcome:** a [locally generated one-use authorisation record](light-phone-iii-local-authorisation.md) subsequently enabled the normal unlock flow. After the factory reset, ADB independently confirmed `flash.locked=0`, `device_state=unlocked`, and verified boot `orange`.

## Conclusion

There is a concrete bootloader-side lead: the saved ABL implements `flashing unlock`, but its FRP unlock permission is subject to an additional FIH check that can clear the permission even when the stored bit is enabled. The check identifies itself in diagnostic strings as `fih_lock_no_allow` and logs `no rooted by fused`.

This is a plausible explanation for the owner's observation that enabling OEM unlocking in Developer options does not make fastboot unlocking work. It is **not yet a confirmed diagnosis or a working unlock procedure**. After the owner authorised running Prism, root activation succeeded and live ABL hashes confirmed that the analysed backups exactly match the current device. No fastboot session, unlock request, reboot, boot-chain partition write or factory reset was performed.

The owner reports that Light permits unlocking and has been willing to help, but resolving the firmware problem has not been a priority. This is owner-provided context; the public-source search did not independently locate a published unlock contract. It should not be misrepresented as a deliberate refusal by Light to permit custom firmware.

## Connected device

| Observation | Value |
| --- | --- |
| Model / SoC | TLP301 / Qualcomm SM4450 |
| Firmware | `00WW_1_440000` |
| Android / security patch | 14 / 2025-03-01 |
| Kernel | `5.10.198-android12-9-g1a2636627c17` |
| Active slot | `_a` |
| Flash lock / AVB state | `1` / `locked` |
| Verified boot / verity | `green` / `enforcing` |
| Security-fused boot property | `true` |
| Current Android OEM-unlock property | `sys.oem_unlock_allowed=0` |
| Declared OEM-unlock support property | `ro.oem_unlock_supported` absent |
| Treble / virtual A/B | both `true` |
| Vendor VNDK | 32; system product VNDK 34 |

The current property snapshot does not contradict the owner's report that the toggle can be enabled. Its state was not changed here, and this is not a measurement taken immediately after enabling it.

Initially, `su` was unavailable to the ADB shell and no KernelSU/ReSukiSU module appeared in `/proc/modules`. Prism and ReSukiSU were installed; Shizuku was stopped. On the owner's instruction, Shizuku was started using the existing starter and Prism's Root button was pressed. Activation completed with `status=pass phase=complete unsafe=0`; Prism showed Active and the module appeared. ReSukiSU's Shell superuser permission was temporarily enabled to run read-only commands through `lp3-resukisu-ksud debug su`, producing UID 0 and `u:r:ksu:s0`.

With root, Android 14 `oem_lock` read-only getters reported carrier permission **true**, user permission **false**, combined permission **false**, and device unlocked **false**. The final FRP byte was **0**. No OEM-lock setter transaction was called. This establishes current state but does not reproduce the owner's historical enabled-toggle failure. The getter mapping was checked against [Android 14 IOemLockService.aidl](https://android.googlesource.com/platform/frameworks/base/+/android-14.0.0_r1/core/java/android/service/oemlock/IOemLockService.aidl).

The partition map includes both slots of `abl`, `boot`, `vendor_boot`, `recovery`, `vbmeta` and `vbmeta_system`; it also includes `frp`, `devinfo`, `deviceinfo`, `super` and several earlier Qualcomm boot-chain partitions. No `init_boot` partition appeared. Partition names alone establish neither a writable unlock state nor a recovery method.

## Artefacts and provenance

Existing files under `/data/local/tmp` were copied to the ignored local directory `artifacts/bootloader-research/2026-09-25/`. The previous partition-backup result is dated 18 August 2026; the boot backup is dated 16 August. Subsequent root reads hashed the actual `abl_a`, `abl_b` and `boot_a` block devices: all three exactly match the copied files. `vendor_boot_a` was also read directly into a local file.

| Artefact | SHA-256 |
| --- | --- |
| `abl_a.img` | `f51fa45314960b3da6f4dfc68e4d2bbc6b821f6a3f6221f77352f4e50e7af98a` |
| `abl_b.img` | `2a983666338dd04e6b2f8c4135c1cc8ae5a65457f9e557398d04774e7a282b30` |
| Extracted ABL A PE | `2d0ca093de3494b00a8d746deb489540411486c5e184ec5d744ef92977f4d551` |
| Extracted ABL B PE | `95f36ffd738ac253eac0eab2256d6348423cf8a323ffd426726ae129ef68a6f7` |
| `boot.img` | `ae2f5a99048d8ed2c9847b14a4d09d385c8dbfc8c849d57d9abb9d544c974868` |
| Live `vendor_boot_a.img` | `1931b2b0e1a9fba0898cb674adea55105a54c67cb8596a8a97a90f85f9f337a9` |

ABL hashes match the old backup result. The boot hash matches `app/src/main/assets/device_profiles.json`. A and B differ; no inference was made that one is more permissive or safe to boot.

The UEFI firmware volume starts at file offset `0x1000` within each ABL image. `uv run --with uefi_firmware` decompressed it into an AArch64 PE; `pefile` and Capstone were used through `uv` to inspect sections, references and instructions. The outer ELF identifying itself as ARM32 does not describe the inner AArch64 program.

Local evidence includes `device-state.txt`, `abl_a-relevant-strings.txt`, `abl_b-relevant-strings.txt`, `abl_a-xrefs.txt`, `abl_a-unlock-disassembly.txt`, `abl_a-oem-state-xrefs.txt`, and `boot-ramdisk-file-list.txt`. Firmware binaries and extracted images remain ignored by Git. FRP and device identity contents were not copied into the report.

## What the ABL code actually does

Addresses below are RVAs in the extracted **slot A PE**, whose image base is zero. They are not partition offsets or runtime addresses. Slot B was checked for corresponding strings but not fully traced.

1. **The standard command has a real handler.** The command table at `0xba4c8` associates `flashing unlock` with `0x3950c`. That handler passes `1` to the shared lock/unlock routine at `0x3b250`. The neighbouring lock handler passes `0`. The command registration loop is visible at `0x375e4` onwards. This goes beyond finding unused strings, but does not prove a particular fastboot session exposes the command.
2. **Fastboot reads the FRP permission.** The setup path references the UTF-16 partition name `frp` at `0xb6d48`. At `0x37768–0x37784`, it reads the final byte of the block just read, masks bit zero and stores the result at `0xf458c`.
3. **An OEM gate can override that permission.** If the bit is set, `0x3778c` calls `0x2e870`. A nonzero return causes `0x3779c` to overwrite the cached permission with zero.
4. **That gate depends on a fuse-related predicate and an OEM state.** `0x2e870` returns denial when `0x14890` is true and `0x13dd0` is false. Its own diagnostic strings identify `fih_lock_no_allow` and `no rooted by fused`. The latter helper accepts only state values 1 or 2 at `0xeb908`. The exact meanings and origin of all these values are not yet established; the string “rooted” must not be equated with Android `su`.
5. **The accepted OEM state is conditional.** The routine at `0x13988` clears that state, validates arguments and a requested value of 1 or 2, calls `0x13de8`, and stores the requested state at `0x13b0c` only on a zero return. This suggests an OEM authorisation mechanism worth tracing, but does not establish a usable token, secret or bypass.
6. **The reported unlock ability uses the overridden value.** The handler at `0x3948c` formats `get_unlock_ability` using the same cached word at `0xf458c`.
7. **Unlock checks it again.** At `0x3b2bc–0x3b2e8`, an unlock request with a zero cached permission and a true `0x14890` result produces `Flashing Unlock is not allowed`. A separate diagnostic identifies the alternative as a non-fused-device path. Later paths involve display/confirmation logic and lock-state changes, which were not exhaustively analysed.

Approximate description of the relevant portion, omitting error handling:

```text
allow = low_bit_of_FRP_final_byte
if allow and fih_lock_no_allow():
    allow = false

get_unlock_ability -> allow

on unlock request:
    if not allow and fuse_related_predicate():
        fail("Flashing Unlock is not allowed")
    otherwise continue towards confirmation/state transition
```

This explains why blindly setting the FRP bit again may achieve nothing. It also explains why Android's runtime root is useful for observation but does not itself remove a check executed before Android starts.

## Possibilities, in practical order

### Diagnose the existing unlock route

The next useful experiment is to compare the Android toggle and stored permission against **bootloader fastboot's** reported permission after enabling OEM unlocking. Live image hashes and current read-only permission information have now been obtained. A controlled bootloader visit remains to be arranged; its reboot will end Prism's temporary root.

Read-only fastboot queries to capture in that visit:

```sh
fastboot getvar is-userspace
fastboot getvar current-slot
fastboot getvar unlocked
fastboot flashing get_unlock_ability
fastboot oem device-info
```

These are proposed diagnostics, not commands run during this session. Unsupported queries should be recorded as such. `is-userspace=yes` means fastbootd; it is not the bootloader unlock environment. Do not use an actual unlock request merely as a diagnostic because it may reach a data-erasing confirmation flow.

If FRP says enabled but bootloader ability is zero, investigate the identified FIH override first. If ability is one, focus on command dispatch, confirmation input/display, and persistent-state storage instead. The owner's historical description does not supply an exact error, so that distinction remains open.

### Ask Light for a targeted firmware fix or supported authorisation

The evidence gives Light a much more specific question: does production LP3 ABL intentionally retain `fih_lock_no_allow`, and how is a customer with OEM unlocking enabled expected to satisfy the additional OEM state check? A corrected, signed ABL or official authorisation route would be preferable to speculative block edits. No message was sent to Light.

### Magisk after unlocking

The backed-up boot image has header v4 and a nonempty ramdisk, with no `init_boot` partition in the observed map. This makes the matching stock `boot` image the likely initial Magisk patch target, subject to confirming current images and Magisk's installation checks. Magisk does not require replacing Android with a newer ROM, but its documented initial install requires an unlocked bootloader. [Magisk installation](https://topjohnwu.github.io/Magisk/install.html)

### Newer Android through a GSI, then a device-specific ROM

Treble and dynamic partitions make a compatible ARM64 GSI a reasonable first experiment **after** a working boot/restore path exists. They do not guarantee that newer Android works with the existing vendor stack, kernel, radio/IMS, cameras or Light-specific controls. A polished ROM needs device configuration, proprietary components and hardware validation. [AOSP GSI documentation](https://source.android.com/docs/core/tests/vts/gsi)

Dynamic System Updates is a separate possibility: `com.android.dynsystem` exists and `gsi_tool status` returned `normal`. The live vendor boot ramdisk contains `avb/q-gsi.avbpubkey`, `avb/r-gsi.avbpubkey` and `avb/s-gsi.avbpubkey` (1032 bytes each). Both `first_stage_ramdisk/fstab.default` and `fstab.emmc` explicitly configure those keys through `avb_keys=` on the system mount. This is stronger evidence than the installed DSU package alone. Key hashes and exact fstab lines are saved in `vendor-ramdisk-avb-evidence.txt`.

The keys' filenames do not establish which newer GSI releases they accept. Compare the chosen image's signing key, rollback constraints and vendor compatibility, and check remaining DSU prerequisites before a boot experiment. No GSI was downloaded, installed or booted. Locked-device DSU requires trusted Developer GSI keys and other platform support; it cannot provide arbitrary custom boot images or persistent Magisk. [AOSP DSU documentation](https://source.android.com/docs/core/ota/dynamic-system-updates)

### Offline analysis before boot-chain modifications

Continue tracing the FIH state setter and its verification inputs using matching live backups. Do not assume that writing `devinfo`, changing a property, copying an ABL from another handset, or patching the identified branch will yield a bootable image. Earlier secure boot can reject modified ABL, and backups alone do not provide a way to restore a phone that no longer boots. No matching LP3 EDL programmer or demonstrated factory restoration route was verified. See the [public-source research](light-phone-iii-public-sources.md).

## Scope and remaining uncertainty

This investigation establishes an implemented unlock command and a concrete OEM permission override in firmware matched to the live device, plus GSI keys configured in the live vendor ramdisk. It does not establish that the phone takes this exact rejection branch, a bypass, an accepted OEM authorisation, a working flash/recovery procedure or a compatible newer Android build. The normal Android unlock process erases user data; any actual unlock/flash attempt is a separate step from this exploration. [AOSP bootloader locking and unlocking](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking)

After collecting the reads, the temporary ReSukiSU Shell permission was revoked; another `debug su` invocation returned `Operation not permitted`. Prism was brought back to the foreground, with its activated root module left running. No tests were written or run; application source was not changed. Existing edits to the release workflow and app build configuration were left untouched.
