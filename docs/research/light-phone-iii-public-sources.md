# Light Phone III: public bootloader and ROM research

Investigated 25 September 2026. This note covers public sources only; it does not establish the connected phone's state. Device observations belong in the accompanying investigation. No device commands were run for this note.

## Finding

I found no verified public Light Phone III bootloader-unlock procedure, official unlock policy, downloadable factory restoration package, or demonstrated native custom-ROM release in the sources searched. This is a search result, not proof that these do not exist. Existing runtime root makes local investigation useful, but does not itself establish permission to boot modified images.

The most promising questions are whether this specific ABL implements an unlock route and whether the stock ramdisk supports a trusted Developer GSI through Dynamic System Updates. The latter could permit trying another Android system without unlocking, but would not provide arbitrary custom kernels or a persistent Magisk installation.

## What the authoritative specifications establish

### Unlock permission and unlock state differ

AOSP distinguishes the OEM-unlocking permission from the actual bootloader state. Enabling OEM unlocking should permit an implemented unlock operation; it does not itself unlock. `ro.oem_unlock_supported` describes declared support. `androidboot.flash.locked` and the resulting boot properties describe the bootloader-provided state. A normal unlock includes physical confirmation and erasure of user data. These are reference requirements, not proof that Light implemented every operation. [AOSP: Lock and unlock the bootloader](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking)

Inference: modifying an Android property, or successfully acquiring `su`, is insufficient evidence of a persistent unlock. Read the original bootconfig and bootloader implementation as well as Android's displayed properties, especially on a rooted system where properties can be altered.

### Android root sits after earlier verification stages

Qualcomm documents a chain starting at immutable ROM and verifying subsequent executable images; its whitepaper describes PBL and XBL stages. This is a platform architecture reference, not a device-specific proof of Light's fuse settings or exact firmware chain. [Qualcomm: Secure boot and image authentication](https://www.qualcomm.com/news/onq/2017/01/secure-boot-and-image-authentication-mobile-tech), [Qualcomm whitepaper](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/secure-boot-and-image-authentication-version_final.pdf)

AVB requires lock state, verification keys and rollback indexes to use tamper-evident storage. It also defines signature and rollback checks. Therefore, a writable block device need not mean a modified image will boot, and blindly editing a presumed unlock byte is unjustified without tracing the actual implementation. Whether Light uses RPMB, a trusted application, or another mechanism must be established locally. [Android Verified Boot reference](https://android.googlesource.com/platform/external/avb/+/master/README.md)

### Magisk needs a separate boot-image acceptance path

Magisk's documented initial installation requires an unlocked bootloader. It patches the device's matching `boot`, `init_boot` or `recovery` image, depending on the ramdisk arrangement. Its documentation specifically warns against using someone else's patched image. [Magisk installation](https://topjohnwu.github.io/Magisk/install.html)

Inference: root could read and patch an image, but that does not solve its verification on the next boot. Magisk is therefore downstream of unlocking or another proven boot verification bypass; it is not an unlock mechanism. Retaining the working KernelSU/ResukiSU arrangement is sensible while investigating that boundary.

### A GSI is a useful first target once image booting is established

AOSP's direct-flash GSI procedure expects a Treble device and an unlocked, flashable state. GSI support does not prove that the phone's radio, camera, fingerprint reader, special buttons or Light-specific interfaces will work correctly. [AOSP: Generic system images](https://source.android.com/docs/core/tests/vts/gsi)

For dynamic partitions, AOSP separates bootloader fastboot from userspace `fastbootd`; a failure in one is not proof that the other is unavailable. Fastbootd is a different execution environment, not a documented escape from verification. [AOSP: Move fastboot to userspace](https://source.android.com/docs/core/architecture/bootloader/fastbootd)

### DSU is a narrower alternative worth checking

AOSP permits Developer GSIs in the locked state when the OEM includes the appropriate GSI verification keys. DSU also needs appropriate kernel support, filesystem/metadata support and compatible vendor HAL behaviour. Trusted keys belong in the first-stage ramdisk under `/avb/*.avbpubkey`. [AOSP: Dynamic System Updates](https://source.android.com/docs/core/ota/dynamic-system-updates)

Read-only evidence to collect: `gsid` and DynamicSystemInstallationService availability, dynamic-partition declarations, stock ramdisk AVB public keys, kernel configuration and vendor compatibility information. Having a DSU menu or daemon alone does not prove a downloadable GSI will pass verification or boot. If keys/support are absent, ordinary Android root cannot simply add a trusted key to the verified boot ramdisk and expect the next boot to accept it.

### EDL access is not equivalent to a recovery guarantee

Qualcomm describes its PBL emergency-download interface as deploying signed loader images. A usable restoration route therefore needs an accepted programmer and the matching firmware, not merely a USB device appearing in EDL mode. [Qualcomm-hosted PBL/EDL research presentation](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/qpss22-christopher-wade.pdf)

The EDL tool's own documentation notes loader identification constraints on newer Qualcomm phones. It does not establish Light Phone III support. I found no verified matching LP III programmer in the material reviewed. [bkerler/edl](https://github.com/bkerler/edl)

## Light-specific evidence and limits

Light's official changelog separates LightOS application releases from underlying firmware releases, including LP III firmware 1.410000, 1.420000 and 1.440000. Application versions therefore must not be treated as Android firmware versions. That page is a changelog, not a factory-image restoration guide. [Light software and firmware changelog](https://support.thelightphone.com/hc/en-us/articles/360031105751-Software-Versions-Change-Log)

Light's public SDK scaffolds applications for LP III. It is not a bootloader-unlock tool or a native ROM device tree. [Light's SDK](https://github.com/lightphone/light-sdk)

The elizaOS project's own LP III issue states that its OS repository lacks a device tree, kernel/vendor manifest, product definition and flashing contract for TLP301. It is an explicit request to build support, not evidence that a working alternative ROM exists. [elizaOS/os issue 10](https://github.com/elizaOS/os/issues/10)

Searches also returned Light Phone II EDL/root/GSI reports. They concern a different device and provide no evidence that LP III accepts the same programmer, unlock sequence or images. Searches of Light support and public repositories did not produce an authoritative LP III unlock contract. Community claims of disabled unlocking were not promoted to confirmed device facts.

## Investigation order suggested by these findings

1. Record stock identity, firmware, slot/partition layout, bootconfig and verified-boot state while retaining the existing working root route.
2. Read and hash stock boot-chain and AVB images for offline analysis, preserving both slots where present. Keep any identifiers, calibration or user data private.
3. Inspect ABL command handlers and the storage/trusted-service calls behind unlock permission and lock state. Strings alone establish neither a reachable command nor successful unlocking.
4. Inspect DSU capability and first-stage GSI keys as an independent possibility for trying newer Android.
5. Establish a practical stock restoration route before any persistent boot-chain changes. A backup without a working way to restore it is incomplete recovery preparation.
6. If normal unlocking is confirmed, treat its data wipe as a separate, explicit user decision. First establish stock reboot/recovery, then evaluate a compatible GSI or a matching Magisk-patched image.

These are research recommendations, not a claim that any untested LP III flashing path is safe or functional.
