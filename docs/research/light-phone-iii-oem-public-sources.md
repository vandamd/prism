# Light Phone III: OEM authorisation and Qualcomm ABL references

Investigated 25 September 2026. Public source research plus an explicitly labelled independent review of the local disassembly. No device commands or changes were performed for this note.

## Public FIH/HMD protocol evidence

HikariCalyx's FIH client at commit `8e63ac03493184fbb6b3107b029177f987a313eb` implements separate commercial/service flows. Its service flow obtains a server signature, downloads it as `encUID`, selects the service key and invokes `doKeyVerify`. Its commercial flow obtains a signature for a challenge and submits it to `veracity`. The implementation distinguishes security versions and bootloader types. This is direct client code, not Light's bootloader source, and establishes neither Light compatibility nor access to the signing service. [fihGetPermission.py](https://github.com/HikariCalyx/uu4-linux/blob/8e63ac03493184fbb6b3107b029177f987a313eb/auth_utility/fihGetPermission.py)

The same author's separate HMDSW client exposes `getpermissions`, `auth_start`, and permission types flash/repair. Its README explicitly says its signature-calculation module is unavailable. The implementation restricts its claimed target to Nokia smartphones released since mid-2019. Similar command strings in Light's binary support a code-family hypothesis; they do not show that any Nokia token or service will work on Light. [README](https://github.com/HikariCalyx/python-fastboot/blob/d26bcfbc0013a24ce144c61ea929b8b0641eb5f4/README.md), [fastboot.py](https://github.com/HikariCalyx/python-fastboot/blob/d26bcfbc0013a24ce144c61ea929b8b0641eb5f4/pyfastboot/fastboot.py)

No exact public primary-source implementation of `fih_lock_no_allow` or `flashtestsign` was found. A wiki surfaced `state_of_permission` and old service-bootloader workflows, but it was not treated as proof of modern LP III behaviour. No external signing service was contacted.

## A concrete Qualcomm vulnerability family to distinguish offline

Qualcomm's CodeLinaro commit `1b2e5f9c4e95db4c74570b828d047e45f9f426d1`, dated 4 February 2026, changes `Is_VERIFIED_BOOT_2()` from GPT-dependent detection to a build-time decision. The old implementation checks for `vbmeta_a`, then `vbmeta`; the replacement returns true when verified boot was compiled in. The commit explicitly identifies changing GPT as the threat. This verifies the upstream defect/fix independently of any exploit author's report. It does **not** establish whether Light's ABL contains the vulnerable implementation. [Vendor patch](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/commit/1b2e5f9c4e95db4c74570b828d047e45f9f426d1.patch)

In the same revision, `LoadImageAndAuth()` has a `NO_AVB` case returning through `LoadImageNoAuthWrapper()` before the later `VBSendMilestone()` call. Useful binary anchors are the AVB-version diagnostic, the milestone diagnostic and its TZ failure diagnostic. Trace control flow; finding a `vbmeta` string alone proves nothing. [VerifiedBoot.c](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/blob/1b2e5f9c4e95db4c74570b828d047e45f9f426d1/QcomModulePkg/Library/avb/VerifiedBoot.c)

The Qualcomm client defines device-state read/write and milestone commands consecutively after the utility command base. `DeviceInfo.c` changes unlock fields through `ReadWriteDeviceInfo`; `LinuxLoaderLib.c` delegates that operation through the Qualcomm verified-boot protocol's `VBRwDeviceState`. A block partition named `devinfo` is therefore not sufficient evidence that it holds the authoritative state. [KeymasterClient.c](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/blob/1b2e5f9c4e95db4c74570b828d047e45f9f426d1/QcomModulePkg/Library/avb/KeymasterClient.c), [DeviceInfo.c](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/blob/1b2e5f9c4e95db4c74570b828d047e45f9f426d1/QcomModulePkg/Library/BootLib/DeviceInfo.c), [LinuxLoaderLib.c](https://git.codelinaro.org/clo/la/abl/tianocore/edk2/-/blob/1b2e5f9c4e95db4c74570b828d047e45f9f426d1/QcomModulePkg/Library/BootLib/LinuxLoaderLib.c)

Atlas's PoC, pinned at `d9ebe4c9d04f356c8836489bea9252161fa16f62`, reports successful use on Redmi 14R/Snapdragon 4 Gen 2. Its explanation links the missing milestone to Keymaster state access. This is an author-reported result on another device. Its prerequisite boot path involves persistent partition changes and custom recovery, so it is not a procedure to try on the connected Light Phone. [PoC README](https://github.com/atlas4381/qualcomm_avb_exploit_poc/blob/d9ebe4c9d04f356c8836489bea9252161fa16f62/README.md)

### Could a read-only Keymaster query settle applicability?

The PoC's default branch sends version (`0x200`) and state-read (`0x202`) requests, then exits before its separately gated state-write branch. However, it first opens QSEE, allocates/registers shared memory and attempts to load a trusted application. This is an active trusted-service interaction, not passive file inspection. Its hard-coded image length, ABI structures and device-state layout require independent validation. [PoC source](https://github.com/atlas4381/qualcomm_avb_exploit_poc/blob/d9ebe4c9d04f356c8836489bea9252161fa16f62/poc.c)

Inference: a successful read could establish exposure of that read operation under the current boot state, but would not prove write permission. A denied read under an ordinary green boot would not rule out the missing-milestone path: that path deliberately changes earlier boot behaviour. An unsupported command, wrong ABI or unavailable transport can also cause failure. Offline comparison of the actual ABL is the stronger first discriminator, without GPT, RPMB or partition changes.

## Offline tools and interpretation

UEFI Firmware Parser documents firmware-volume/section extraction and Tiano/EFI decompression; UEFITool provides another parser for comparison. These operate on local files and do not confer signing authority. [UEFI Firmware Parser](https://github.com/theopolis/uefi-firmware-parser), [UEFITool](https://github.com/LongSoft/UEFITool)

Use extraction metadata and PE section mappings when assigning addresses. Offsets from a different phone, another ABL version, or a compressed container cannot be transplanted. Preserve the original signed images and hashes; reconstructed images are analysis products.

## Independent review of the local certificate path

This section is **local binary evidence**, separate from the public-source claims above. Input: `artifacts/bootloader-research/2026-09-25/fih-cert-disassembly.txt` and `abl_a-code-annotated.txt`, supplied by the main investigation. Addresses refer only to that extracted ABL.

At `0x1c888`, `fih_cert_init` reads the record through `0x1cbd8`; that reader requests 0x1000 bytes from `mfd` offset 0x3000 and copies 0x918 bytes into the structure. The record holds a mode at +4, use count at +8, signature at +0x0c, signature length at +0x10c, certificate at +0x110, certificate length at +0x910, and trailing magic at +0x914.

At `0x1ca48`, this path passes the record's own certificate and signature directly to `fih_root_auth` (`0x13988`). That function checks arguments and mode 1/2, invokes `fih_rsa_auth`, and on success writes the mode to global state `0xeb908`. In contrast, the separate `fih_root_verify` function chooses a certificate from a built-in table or another provider before calling the same authentication helper. The record path does not visibly make that selection.

The helper at `0x86a6c` closely matches EDK II's `RsaGetPublicKeyFromX509`: parse a DER certificate, extract its public key, require RSA, duplicate the RSA key and free temporary objects. The helper at `0x86a10` matches `X509ConstructCertificate`, which performs DER decoding. Neither performs issuer-chain validation; the upstream code has a separate `X509VerifyCert` function. [EDK II CryptX509.c, stable202308](https://github.com/tianocore/edk2/blob/edk2-stable202308/CryptoPkg/Library/BaseCryptLib/Pk/CryptX509.c)

Within the inspected path there is no visible pinned-key comparison or certificate-chain verification between reading the record and setting the authorisation state. The signed digest is derived separately by the UID helper (`0x13588`); that device binding does not itself authenticate the supplied certificate. **Inference:** a certificate controlled together with its signature may satisfy this local authorisation check. This is a strong candidate for offline emulation, not a confirmed device unlock. Still unresolved are protection of the `mfd` bytes, invocation order, persistence/reset of the global state, and downstream requirements for actually changing bootloader state.

### Follow-up review: consumption and unlock gating

The main investigation subsequently reported that exact-code emulation accepted a fresh self-signed RSA-2048 certificate and rejected a bad signature. Independent static review of the surrounding initialisation establishes the following; it does not demonstrate hardware success.

- A record with count 1 is decremented and written before authentication. On success, mode 1 is retained in RAM at `0xeb908`. The subsequent count-zero cleanup resets the on-storage record but contains no write clearing that RAM state.
- The writer at `0x1cd28` allocates and zeroes a full 0x1000-byte buffer, copies the 0x918-byte structure, and writes 0x1000 bytes to `mfd` byte offset 0x3000. It therefore also zeroes offsets 0x3918–0x3fff. In the inspected original 131072-byte backup, this tail was already all zero; the 4096-byte candidate preserved it. Preservation outside the full 4 KiB region remains the correct boundary.
- `fih_cert_init` ignores the status of decrement and cleanup writes. If persistence fails, a grant intended for one boot may remain stored. If authentication fails, the use count has already been consumed. Hardware read-back is necessary to establish consumption.
- The call at `0xf610` is part of early initialisation, before later boot-mode selection. An ordinary Android boot can consume the record; it is not reserved for the next fastboot session.
- The block readers/writers select a partition by name and invoke EFI BlockIO. No mfd-wide authentication check is visible in these helpers or the direct certificate-reader path. That finding does not establish whether hardware or another boot stage write-protects the region.
- The FIH grant does **not** set the Android OEM-unlocking permission. The path at `0x37768` reads the existing FRP bit, then applies the FIH veto. The unlock handler at `0x3b250` still denies a fused device when the resulting flag is zero. Consequently, permission state 1 and `get_unlock_ability=1` are separate requirements.
- Known direct authorisation-state resetters include signature upload (`0x13808`), key selection (`0x13918`) and entry to a new root-authentication attempt (`0x13988`). These should not be confused with read-only permission queries. A later reboot also loses the RAM grant.

The candidate therefore supports a bounded authorisation experiment, followed by checking the normal unlock prerequisites in the same bootloader session. It is not itself a persistent unlock, and the normal unlock still has its own data-erasure and device-confirmation semantics. A restored `mfd` record also does not reverse an already completed bootloader unlock.
