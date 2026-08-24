# Light Phone III `ctl_buf` rescue module

This module is only for the exact `tlp301-00ww-1-440000` kernel profile. It repairs the saved `x23` value for five blocked `sendmsg` workers before userspace wakes them.

The exact device disassembly keeps the 128-byte control buffer in `x23` across `unix_dgram_sendmsg()`. That function saves the caller value at `frame_pointer + 56`. The module stops all CPUs, validates the full frame chain and exact instruction fingerprints, and replaces each stale pointer with one new 128-byte allocation. The normal syscall exit then frees the new allocation and balances the socket memory charge.

The module must not load unless all parameters come from the current run and all temporary SELinux pointer changes are exact. Module initialisation restores those SELinux pointers and their collateral words first. Module removal restores the helper task to its saved private shell credential. Userspace must verify the final shell identity before it wakes any repaired worker.

Build with the `android12-5.10-20260313` DDK image. In the disposable container, set `include/generated/utsrelease.h` and `include/config/kernel.release` to `5.10.198-android12-9-g1a2636627c17` before the external-module build. The DDK `Module.symvers` CRC values must match the recovered device kernel for every imported symbol. Do not use force-load or ignore-version flags.

This directory does not provide a standalone device command. The Android controller must supply the exact five-entry TID/node manifest, helper and credential addresses, kernel slide, and both temporary SELinux restoration records. The module must load on the verified donor-credential watchdog thread; it resolves and normalises the exact helper leader before finalisation continues there.
