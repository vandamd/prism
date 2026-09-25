# Browser-driven, unlock-only Prism helper

Investigation: 25 September 2026. Source inspection only; no device operations or production changes. This is a proposed port, not a validated alternative to the current Prism flow.

## Conclusion

A browser can orchestrate the chain over the existing ADB transport, but the native acquisition and recovery code must still execute on the phone. The promising simplification is replacing ReSukiSU activation with narrowly scoped backup and unlock-preparation actions. Removing the installed APK is a separate, unproven port. See [the app-free dependency review](prism-app-free-chain.md).

The current web tool already uploads bytes and starts shell processes through ADB. Its privileged commands currently depend on `lp3-resukisu-ksud debug su`; replace that boundary with a helper protocol rather than embedding kernel operations into JavaScript. [Current transport](/Users/vandam/Developer/light-guide/webusb/transport.js:51), [current preparation](/Users/vandam/Developer/light-guide/webusb/app.js:171).

## What can be simplified

| Current piece | Proposed unlock-only treatment |
| --- | --- |
| Shizuku user-service launcher | Replace with a shell process launched through browser ADB. The controller requires shell UID/GID, which is the relevant starting privilege. |
| Prism's activity, prompts and progress UI | Move progress and user interaction into Light Guide. Preserve app-side services until an app-free acquisition path is proven. |
| ReSukiSU manager installation, UID/signature check, manager hand-off | Remove from an unlock-specific controller. They support a general root manager, not the bootloader certificate itself. |
| ReSukiSU kernel and userspace activation | Replace with a fixed privileged operation; verify its SELinux access separately. |
| Terminal success check against ksud version | Replace with verified backup/staging results plus the existing kernel/process cleanup checks. |
| Device gate, nonce/boot identity, donor lifetime, watchdogs, rescue and cleanup | Preserve. An imminent reboot is not evidence that interrupted kernel mutations are harmless. |

Evidence: [Shizuku pre-arm and service call](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShizukuBridge.kt:77), [shell and manager identity gates](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ReSukiSuActivationController.java:619), [activation preparation](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java:304), [fixed root action](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java:624), [postflight checks](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java:929).

## Why it is not just replacing a command

The clean helper accepts only identity and ReSukiSU probe/activation commands. Its privileged operation is dispatched to a guarded native thread, with descriptor, identity and manager checks. Root is not exposed as an arbitrary shell at this stage. [Command whitelist](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:698), [native action dispatch](/Users/vandam/Developer/prism/app/src/main/cpp/direct.cpp:17036).

Activation also stages the rescue plan, changes the effective security context, normalises helper/donor identities and waits for strict cleanup. Removing the ReSukiSU loader wholesale could also remove machinery needed for recovery; separate those responsibilities before trimming payloads. [Action and cleanup sequence](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java:704), [helper deferred activation](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:1026).

There is an older partition-backup mode, but it explicitly requires `hal_bootctl_default` and reads GPT ranges. That is useful reference material, not proof that the current activation window can read/write every unlock resource. Validate access to the required partitions, hardware ID and OEM-lock service under the proposed helper's actual identity and SELinux context. UID 0 alone is not sufficient evidence. [Backup mode](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:1679), [root-window checks](/Users/vandam/Developer/prism/app/src/main/java/com/vandam/prism/ShellBridgeMain.java:2341).

## Proposed browser flow

1. Authorise ADB. Identify the supported phone and upload a versioned, hash-checked helper.
2. Run a bounded backup operation on the phone. Acquire the required privilege, read the allowlisted inputs, complete cleanup, then return the backup and result to the browser.
3. Save and verify the backup on the computer. Generate the certificate locally. No privileged acquisition window remains open while waiting for the user.
4. Run a second bounded preparation operation. Reacquire privilege, revalidate the phone and original partition, enable OEM unlocking, write only the existing certificate region, verify the entire expected partition, and complete cleanup.
5. Only after successful staging and cleanup, reboot directly into fastboot and reuse the existing serial-bound permission checks and physical unlock prompt.

Two acquisitions may increase latency and compound failure probability. This is a proposed way to preserve the user-controlled backup boundary, not an established speed improvement. A single long-lived helper would require a separately proven, safely retained privilege mechanism; extending watchdog timeouts to wait for a Save dialog is not an adequate substitute.

The phone-side controller should own acquisition deadlines, cleanup and a per-boot result journal even if USB disconnects or the page closes. The browser should request a small set of operations, display progress and retrieve receipts. Session IDs and boot IDs must bind every operation. A page refresh must never implicitly repeat a partition write. Recovery should compare readback to the original/expected data before deciding whether any continuation is safe.

## Implementation order

1. **Separate action from acquisition:** introduce an unlock-specific fixed-action interface while keeping the working app services, donor handling and cleanup. First validate read-only backup access and terminal cleanup; do not begin with partition writes.
2. **Remove manager dependence:** add the bounded backup/preparation actions and replace manager-specific postflight with action-specific receipts. Retain independent cleanup verification.
3. **Browser-controlled launcher:** replace Shizuku with an ADB-started shell controller. A small temporary helper APK can preserve the proven app process/service arrangement while removing manual Prism/Shizuku/ReSukiSU setup. This still installs an APK and must be presented honestly.
4. **Optional app-free port:** replace app services and their Binder lifetime assumptions with shell/native endpoints. Prove acquisition and cleanup before connecting the write action. Existing probes are not sufficient evidence.

The best first delivery is browser-controlled setup with the smallest helper that preserves the proven acquisition environment. A completely APK-free version remains a separate feasibility milestone. Do not optimise acquisition timing, process counts or recovery checks merely to make the helper smaller.
