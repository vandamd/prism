# ReSukiSU rc3 payload

## Compatibility

Source: ReSukiSU `v4.2.0-rc3`, commit `239e1e8871b8fcd51a6e5b3002e0ba522fdd99fb`.
Kernel version code: **35171**. UAPI: **4**. Device kernel remains
`5.10.198-android12-9-g1a2636627c17` on Light firmware `00WW_1_440000`.

The official rc3 manager checks UAPI equality. The previous UAPI 2 module was
recognised but its Superuser and Modules pages were unavailable. This update
builds the rc3 module and ksud together, rather than changing that version check.
Prism's installer selects rc3 explicitly so a later incompatible manager is not
installed automatically.

## Source and build

Apply `patches/light-phone-iii-rc3.patch` to a full checkout of the commit above.
It replaces both historical rc1 patches; do not apply them as well.
The patch includes the loader source and Cargo lockfile, the SELinux exec_sid
fix, synchronous manager hand-off and completion reporting.
It also restores the loader's mapped-image replacement entry point used by
the native activation supervisor.

Use the DDK, NDK and kernel build command in README.md. Copy the resulting
stripped `kernel/kernelsu.ko` to
`userspace/ksud/bin/aarch64/android12-5.10_kernelsu.ko` before building userspace.
The loader requires the original 563,952-byte rescue module, with SHA-256
`b39c988662b31b16aedc2b42680daa764c90f3f842229591372a3e376fb8a0ff`.
The current 119,712-byte asset is a different rescue variant and is not a
substitute for this embedded image. The correct bytes can be recovered from
the existing loader by locating its embedded ELF with that exact size and hash.
Place it at `userspace/lp3_loader/bin/lp3_ctlbuf_rescue.ko`.

Run the README's cargo commands from each crate's directory. This build used
`cargo +nightly ndk -t arm64-v8a -p 29 build --release` with NDK 29.0.14206865.
Build Prism's native `prism-primitive` target and strip its debug symbols before
copying it to assets. It is now staged and hash-checked alongside the other
payloads, rather than relying on an existing development copy on the phone.
If native code changes, rebuild this asset and update its payload hash.

The loader adds `__arm64_sys_close` and `install_session_keyring_to_cred` to its
hidden-symbol relocation list; `param_ops_string` is exported normally.
The complete existing address map and all additions were checked against the
phone's kallsyms after subtracting the runtime kernel slide.

## Bundled artefacts

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `kernelsu.ko` | 398720 | `857f893e3ff7e6153c64cc02762456acf6d4f12560cbe90236431ceb37a521bb` |
| `lp3-resukisu-ksud` | 4238456 | `801c9ec9775f86b7dff1f0fe472ab1127684a4a18f1c8ff9692c0594a39b5db4` |
| `lp3-resukisu-loader.so` | 1308056 | `70e4d7458a327874f38c657ea60f65d31712cd481f994855d093b28b1eed7b0f` |
| `prism-primitive` | 899472 | `c8f9a0ac3fda8da8ed6c7e943daed4cb5ac73fd6b348468d065d3e35e42e3042` |

All byte counts, hashes, version checks and expected status output in Prism
were updated together. The device and firmware gates remain in place.

## Validation — 25 September 2026

- Kernel build and symbol check passed; ksud and loader release builds passed.
- Prism built and installed with `:app:installDebug`.
- One activation from stock boot completed on the unlocked TLP301, with the same
  boot ID, successful terminal cleanup and `phase=complete unsafe=0`.
- Kernel reported 35171 / UAPI 4 / late-load mode; official rc3 displayed Working
  and exposed Superuser and Modules without the kernel-update error.
- Shell root was denied, then granted using rc3's Superuser switch; `id` reported
  UID 0 and SELinux context `u:r:ksu:s0`. Revoking it denied a new root request.
- Active boot partition SHA-256 still matched the original stock backup.

This validates root and manager access on one activation, not a fresh reliability
series or third-party Magisk-module compatibility. Root remains temporary until
reboot. No partitions were flashed for this update. Local logs are under
`artifacts/resukisu-rc3/` and are not for publication.
