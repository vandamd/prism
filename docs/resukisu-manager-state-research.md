# ReSukiSU Manager state after LP3 late-load

Research target: ReSukiSU commit
[`746686390b0cf2256818a97b2f620eadbd079995`](https://github.com/ReSukiSU/ReSukiSU/commit/746686390b0cf2256818a97b2f620eadbd079995),
with Prism's preserved LP3 patches. Device inspection was read-only.

## Conclusion

The observed activation loaded KernelSU successfully, but the ReSukiSU Manager
process did not establish its KernelSU control channel. The Manager's **Not
installed** label does not test whether a boot image was patched or whether the
`kernelsu` module exists. At this pinned commit it means the app could not
confirm that its own UID is a recognised KernelSU manager.

The device evidence proves the live kernel component:

```text
/proc/modules: kernelsu ... Live
version: 35088
flags: 0x5
lkm: true
late_load: true
runtime_mode: late-load
```

This is a successful transient late-load activation, not a persistent boot
installation. It is not, by itself, a complete end-to-end success because it
does not prove that the actual Manager app can use KernelSU.

The most likely cause of the observed bad state is the qualified run's launch
ordering. Its trace started the Manager at uptime `57797` before the ReSukiSU
action returned at `58447`. KernelSU can only inject the control descriptor
when zygote creates a process whose UID has already been registered. A Manager
spawned before that point remains alive without the descriptor. The current
source has since moved `beginManagerReturn()` after the accepted action frame;
that ordering must be preserved.

## Meaning of **Not installed**

The home card shows **Working** when `systemStatus.ksuVersion != null`; otherwise,
on this GKI device it shows **Not installed**. See
[`HomePage.kt`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/java/com/resukisu/resukisu/ui/screen/main/HomePage.kt#L582-L655).

`KernelRepository` assigns `ksuVersion` only after `Natives.isManager` returns
true. It deliberately converts an exception into `false`, so a missing or
unusable IPC descriptor has the same UI result as an absent kernel component.
See
[`KernelRepository.kt`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/java/com/resukisu/resukisu/data/kernel/KernelRepository.kt#L19-L36).

The Manager's native code does not request a control descriptor. It scans its
own inherited descriptors for `[ksu_driver]`, performs `GET_INFO` on that
descriptor, and treats the caller as a manager only when the returned flags
contain `KSU_GET_INFO_FLAG_MANAGER`. See
[`ksu.c`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/cpp/ksu.c#L15-L80)
and its
[`is_manager()` implementation](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/cpp/ksu.c#L123-L139).

## Why the shell probe is insufficient

`ksud debug info` reads `GET_INFO` and derives `lkm`, `late_load`, and
`runtime_mode` from its flags. See
[`cli.rs`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/userspace/ksud/src/android/cli.rs#L782-L821)
and
[`ksucalls.rs`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/userspace/ksud/src/android/ksucalls.rs#L69-L107).

KernelSU permits every caller to use `GET_INFO`, and sets the Manager flag
according to the calling UID. See the
[`GET_INFO` handler](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/supercall/dispatch.c#L60-L87)
and its
[`always_allow` permission entry](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/supercall/dispatch.c#L1195-L1216).
Therefore, shell output `flags: 0x5` proves LKM (`0x1`) plus late-load (`0x4`),
but the absent Manager bit (`0x2`) only says that shell is not a Manager. It
does not query the Manager app's IPC state.

## Manager registration and descriptor delivery

Late-loaded KernelSU force-scans installed APKs during module initialisation and
registers matching signed Manager UIDs. See
[`core/init.c`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/core/init.c#L228-L267)
and
[`throne_tracker.c`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/manager/throne_tracker.c#L35-L53).
The stock `ksud late-load` operation does not set a Manager UID explicitly.

Prism's LP3 patch strengthens this path. Its `handoff_to_manager()` adopts the
verified app UID, waits until `GET_INFO` contains the Manager flag, checks the
UAPI version, requests root, and requires UID/GID 0 with SELinux context
`u:r:ksu:s0`. See
[`light-phone-iii.patch`](../resukisu/patches/light-phone-iii.patch).
A passed action therefore proves that KernelSU registered that UID and granted
root to the patched `ksud` hand-off process.

This hand-off cannot retrofit a descriptor into an already-running Android app.
KernelSU installs `[ksu_driver]` while handling zygote's setuid transition for
an already-recognised Manager UID. See
[`setuid_hook.c`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/hook/setuid_hook.c#L79-L101)
and
[`supercall.c`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/kernel/supercall/supercall.c#L54-L79).

For this reason, upstream late-load ends by force-stopping and starting the
Manager specifically so that it receives a fresh KernelSU descriptor. See
[`late_load/mod.rs`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/userspace/ksud/src/android/late_load/mod.rs#L134-L154).
Prism's fast-action patch removes that synchronous restart so the external
controller can perform it after strict action acceptance; see
[`lp3-fast-action.patch`](../resukisu/patches/lp3-fast-action.patch).

## Acceptance probe

Use two independent, read-only observations after a fresh Manager process has
been launched **after** action acceptance:

1. Require `/proc/modules` to contain live `kernelsu` and require `ksud debug
   info` to report exact version `35088`, LKM true, late-load true, and runtime
   mode `late-load`. This proves the kernel component.
2. Require the ReSukiSU home screen to finish loading and visibly report
   **Working**, with the **LKM** and **Jailbreak mode** labels, and no **Failed
   to grant root!** warning. In the pinned source, **Working** proves the app's
   own `Natives.isManager` call succeeded; absence of the warning proves its
   `ksud debug su` root shell succeeded. The relevant root check is
   [`KernelStatus.isValid`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/java/com/resukisu/resukisu/domain/model/KernelState.kt#L16-L38)
   and the warning is emitted by
   [`HomePage.kt`](https://github.com/ReSukiSU/ReSukiSU/blob/746686390b0cf2256818a97b2f620eadbd079995/manager/app/src/main/java/com/resukisu/resukisu/ui/screen/main/HomePage.kt#L305-L323).

If a suitably privileged read-only observer is available, additionally require
the exact current Manager PID to own an fd whose `/proc/<pid>/fd/<n>` target is
`anon_inode:[ksu_driver]`. This is the most direct IPC proof, but ordinary adb
shell cannot inspect that app's fd directory on the current device. Treat
**Not installed** as an acceptance failure even when the kernel-only probe
passes.
