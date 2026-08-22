# Light Phone III ReSukiSU payload

This directory preserves the source changes and exact build inputs used for the
Light Phone III late-load payload. The workflow loads a module into the running
kernel. It does not unlock the bootloader, flash a partition, or erase user
data.

## Exact inputs

- ReSukiSU commit: `746686390b0cf2256818a97b2f620eadbd079995`
- Device kernel: `5.10.198-android12-9-g1a2636627c17`
- Kernel link base: `0xffffffc008000000`
- DDK image: `ghcr.io/ylarod/ddk-min:android12-5.10-20260313`
- DDK compiler: Clang `12.0.5` (`clang-r416183b`)
- Android NDK: `29.0.14206865`
- Target: `aarch64-linux-android`, API 29
- Source patch: `patches/light-phone-iii.patch`
- Patch SHA-256: `d36b2efbbec7422dffbd05c2a758133479d40bfacd454c6bafed66ef293a3546`

The patch adds the exact LP3 symbol map and relocation loader, synchronous
manager-UID hand-off for late loading, and the SELinux `exec_sid` correction.
Clearing `exec_sid` is required because the chain temporarily borrows a
`ueventd` credential. Without it, the next executable inherits an invalid
transition and SELinux rejects the `ksud` entry point.

## Apply the patch

Start from the exact ReSukiSU commit, then apply the preserved patch:

```sh
git checkout 746686390b0cf2256818a97b2f620eadbd079995
git apply /path/to/light-side-of-the-moon/resukisu/patches/light-phone-iii.patch
```

Before building the loader, create its binary directory and copy the proven
non-diagnostic rescue module:

```sh
mkdir -p userspace/lp3_loader/bin
cp /path/to/light-side-of-the-moon/app/src/main/assets/lp3_ctlbuf_rescue.ko \
  userspace/lp3_loader/bin/lp3_ctlbuf_rescue.ko
```

The rescue module must have these properties:

```text
size: 563952
sha256: b39c988662b31b16aedc2b42680daa764c90f3f842229591372a3e376fb8a0ff
vermagic: 5.10.198-android12-9-g1a2636627c17 SMP preempt mod_unload modversions aarch64
```

## Build the kernel module

Set `SOURCE` to the patched ReSukiSU checkout, then run:

```sh
docker run --rm --platform linux/amd64 \
  -v "$SOURCE:/work" \
  -w /work/kernel \
  ghcr.io/ylarod/ddk-min:android12-5.10-20260313 \
  bash -lc '
    make clean
    sed -i "s/.*/#define UTS_RELEASE \\\"5.10.198-android12-9-g1a2636627c17\\\"/" \
      /opt/ddk/kdir/android12-5.10/include/generated/utsrelease.h
    printf "%s\\n" "5.10.198-android12-9-g1a2636627c17" \
      > /opt/ddk/kdir/android12-5.10/include/config/kernel.release
    CONFIG_KSU=m \
    CONFIG_KSU_MULTI_MANAGER_SUPPORT=y \
    CONFIG_KSU_TRACEPOINT_HOOK=y \
    CC=clang make -j8
    llvm-strip -d kernelsu.ko
  '
```

Copy `kernel/kernelsu.ko` to
`userspace/ksud/bin/aarch64/android12-5.10_kernelsu.ko` before building
`ksud`. The exact module used for the successful activation has these
properties:

```text
size: 391944
sha256: 03d7ee10ed0d9f17bca6f328ec1eded4d3ac6e7367e2f16ce8cb49736984b3a6
```

## Build userspace

Build `ksud` from `userspace/ksud`:

```sh
LP3_NDK=/path/to/Android/sdk/ndk/29.0.14206865
cargo +nightly clean
ANDROID_NDK_HOME="$LP3_NDK" \
BINDGEN_EXTRA_CLANG_ARGS_aarch64_linux_android="--sysroot=$LP3_NDK/toolchains/llvm/prebuilt/darwin-x86_64/sysroot --target=aarch64-linux-android29" \
cargo +nightly ndk -t arm64-v8a -p 29 build --release
```

Build the loader from `userspace/lp3_loader`:

```sh
LP3_NDK=/path/to/Android/sdk/ndk/29.0.14206865
cargo +nightly clean
ANDROID_NDK_HOME="$LP3_NDK" \
cargo +nightly ndk -t arm64-v8a -p 29 build --release
```

Expected production outputs:

| Output | Size | SHA-256 |
| --- | ---: | --- |
| `ksud` | 4214888 | `7765acff69651e31629433fa6095a41b7ca034b62e17f9180c2a820b1f177483` |
| `liblp3_resukisu_loader.so` | 1301464 | `1fe42682ad736f43eb5acb42dc0ebba79828a6090f61e47970277b12fdb61275` |

The loader deliberately embeds the non-diagnostic rescue module. Do not add
kernel-log capture to the rescue module in production artefacts.

## Activation validation

Validate a new payload through Prism's app flow. A successful run must retain
the same boot ID, complete terminal cleanup, report no unsafe state, return
from ReSukiSU to Prism, and leave the `kernelsu` module active. The device must
continue to report verified boot `green` and `ro.boot.flash.locked=1`.
