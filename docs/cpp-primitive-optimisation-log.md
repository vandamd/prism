# C++ primitive optimisation log

## Goal

Develop a standalone ARM64 Android C++ implementation of the
CVE-2024-46740 primitive, then optimise and integrate the same core into Prism.
Acceptance requires an end-to-end duration of at most 10 seconds for five
consecutive fresh-boot runs without weakening cleanup or reliability.

## Safety constraints

- Never wipe, factory-reset or flash the device.
- Never write bootloader or partition block devices.
- Preserve the existing reboot watchdog, mutation gates and cleanup proofs
  until an equally strong positive proof replaces them.
- Treat any unexplained reboot, persistent root state, process residue, donor
  damage, SELinux collateral or JobScheduler change as a failed strategy.
- Change one timing mechanism at a time and retain the previous known-good
  build until the candidate passes its gate.

## Device baseline

- Device: Light Phone III (`TLP301`), serial `LP3LHMA531900140`.
- ABI: `arm64-v8a`.
- Android: 14 user build, security patch `2025-03-01`.
- Kernel: `5.10.198-android12-9-g1a2636627c17`.
- SELinux: enforcing.
- ADB context: `u:r:shell:s0` with `readtracefs` group access.
- Boot completed before work began.

## Available instrumentation

- Perfetto, `simpleperf` and `atrace` are installed on the device.
- Shell can read `/sys/kernel/tracing`.
- Binder driver and Binder lock tracepoints are exposed.
- Scheduler process, wake-up, switch and runtime tracepoints are exposed.
- CPU frequency, thermal, disk and synchronisation atrace categories are
  available.

## Existing evidence

- Fourteen successful APK runs establish a 94.786-second best controller time
  and a 98.191-second best Root-tap time.
- The current root chain's zero-miss, fast-victim estimate is about 67 seconds.
- Average write misses cost about 10.3 seconds per run.
- Deferred-victim collection has an unexplained approximately 9.3-second slow
  mode.
- The Direct-controller path contains 34.5 seconds of unconditional sleeps;
  the user-visible path contains 35.75 seconds.

## Acceptance gates

1. Instrumentation gate: unchanged behaviour and strict cleanup for five
   consecutive fresh boots.
2. Primitive development gate: five consecutive fresh boots for each accepted
   mechanism change.
3. Milestone gate: 20 consecutive fresh boots with no unsafe outcome.
4. Standalone performance gate: at most 10 seconds for five consecutive fresh
   boots, measured inside the executable from entry to terminal cleanup proof.
5. APK performance gate: at most 10 seconds for five consecutive fresh boots,
   measured from Root tap to Prism active with strict postflight complete.

## Strategy record

| ID | Strategy | Result | Decision and reason |
| --- | --- | --- | --- |
| S000 | Establish immutable baseline and trace capabilities | Binder and scheduler tracepoints are available to shell | Retain; use kernel events to replace timing guesses with positive evidence |
| S001 | Build reusable core plus standalone CLI probe | First compile found a missing `<cinttypes>` include in the CLI formatter; the core compiled | Correct the adapter include and retain the module shape |
| S002 | Use the public NDK ServiceManager registration header | NDK r28 exposes app Binder types but omits `binder_manager.h` | Reject direct compile-time use; probe the platform symbol dynamically and keep the reusable core public-NDK compatible |
| S003 | Register a unique process-lifetime native broker from the shell domain | ServiceManager returned `-1`; audit recorded `{ add }` denial from `u:r:shell:s0` to `default_android_service` | Reject package-free ServiceManager registration; do not retry names or Binder contexts without evidence of a permitted service type |
| S004 | Trace the standalone runner with atrace Binder, scheduler and frequency categories | The runner and its process exit are visible with microsecond-resolution scheduler events | Retain; use the same trace categories for end-to-end critical-path analysis |
| S005 | First traced fresh-boot activation | Stopped before Root: the Light launcher reclaimed focus approximately two seconds after Prism opened, and preflight timed out | Harden preflight to reopen Prism up to three times; do not classify this as a primitive failure. App-private evidence from a pre-activation failure may be stale |
| S006 | Second traced fresh-boot activation | Stopped before Root because the display slept during Shizuku startup; `NotificationShade` remained current although Prism was the focused app | Wake, dismiss keyguard and collapse the status bar immediately before Prism launch and each preflight reopen; avoid changing the device's global screen-timeout setting |
| S007 | Trace one complete activation with atrace | Passed with Root-tap time 112.2 seconds and strict cleanup, but produced 362 MiB and omitted `binder_transaction_buffer_release` | Retain as one diagnostic artefact only; reject atrace for the iteration loop |
| S008 | Targeted Perfetto proof with standalone CLI | Captured Binder release, lifecycle and workqueue sources into a 3.4 KiB trace | Replace diagnostic atrace with targeted Perfetto; keep normal performance runs untraced |
| S009 | Targeted Perfetto on one complete unchanged activation | Passed strict cleanup; Root-to-Prism foreground was 113.5 seconds and the trace was 4.3 MiB. The vendor Perfetto service accepted Binder transaction and scheduler exit/free events, but rejected Binder buffer-release, Binder ioctl and workqueue events as unknown despite those tracefs directories existing | Retain the trace for process-exit and Binder-transaction timing. Do not infer deferred-release completion from process death alone, and do not retry the rejected event names through Perfetto |
| S010 | Correlate the nine consumed raw-client identities with scheduler exits | Each client exited 81–158 ms after its retirement checkpoint. Each checkpoint returned about 1.59–1.65 seconds later because `queueExtraRawClientAndWaitExit` sleeps another fixed 1,500 ms after observing death | Replace the fixed settlement only after adding a positive Binder-release or outcome gate. The nine sleeps cost 13.5 seconds in this run |
| S011 | Replace raw-client fixed settlement with a reusable C++ Binder death barrier | First fresh-boot candidate passed strict cleanup. Seven consumed clients produced death-plus-unlink receipts in 35–91 ms; one internal miss was recovered safely. Root flow fell from 85.22 to 69.94 seconds and Root-to-ReSukiSU foreground fell from 99.9 to 81.6 seconds | Candidate retained for a five-boot reliability gate. Death is stronger evidence than `/proc` disappearance because transaction-buffer release precedes node death notification in `binder_deferred_release` |
| S012 | Five-boot gate for the first death-barrier candidate | Run 1 stopped before write four: victim 5 emitted a valid death-plus-unlink receipt in 78 ms, but its exact `/proc` identity was still briefly visible. Three prior writes had completed, so the controller requested and confirmed a safety reboot; boot reason was `reboot,shell`, with no kernel-crash evidence | Reject death receipt as a complete process-retirement proof. Require death-plus-unlink first, then poll the exact PID/start-time identity to disappearance. Keep the fixed 1,500-ms dwell removed |
| S013 | Five-boot gate for death-plus-unlink-plus-identity retirement | Four consecutive runs passed strict cleanup. Root-flow duration ranged from 71.27 to 86.33 seconds with 1–11 write misses; all death receipts completed within 26–146 ms. Run 5 had an unrelated victim-0 acquisition miss before any extra-client barrier and requested a controlled reboot after its same-boot helper had already died | The barrier itself is 4/4 but the whole-chain gate is not passed. Retain the stronger gate and address acquisition reliability separately; do not count the early miss as a barrier pass |
| S014 | Batch-cache all spare victim Binder nodes in one C++ traversal | Candidate implementation scans the target node tree once, matches all 18 pointer/cookie identities, rejects duplicate matches and duplicate nodes, and commits only an all-or-nothing cache | Replace 18 repeated arbitrary-read traversals; validate the batch receipt and strict cleanup on a fresh boot before the five-boot gate |
| S015 | Resolve the target by PID and multi-search its Binder node tree | First fresh-boot run passed strict cleanup with zero write misses. The batch visited 26 nodes, matched 18 unique victims with no duplicates, and completed in 10.445 ms. The prior full batch took 9.705 seconds; `resukisu-stage-plan-ready` to `root-write-arm-ready` fell from 10.32 seconds to 0.70 seconds | Retain for the five-boot gate. The root flow is now 58.65 seconds; the next hard bounds are disclosure construction and six serial write cycles |
| S016 | Five-boot gate for PID-targeted multi-search plus the strengthened death barrier | All five fresh boots passed strict cleanup. The scanner completed in 9.455-13.472 ms after visiting 24-27 nodes and matching all 18 unique victims. Root-flow duration was 56.61-66.36 seconds with 1-5 safely recovered write misses | Accept as the new known-good implementation. Preserve the all-or-nothing scan receipt and death-plus-unlink-plus-exact-identity retirement proof while optimising earlier disclosure and serial writes |
| S017 | Replace controller donor and postflight stability sleeps with pidfd-bound liveness and two exact snapshots | The first candidate passed strict cleanup. Harness dispatch moved from about 12.3 seconds after controller entry to 2.6 seconds; strict postflight fell from about 11.4 seconds to 1.3 seconds | Retain. Continuous pidfd liveness plus repeated exact identity and system-state samples are stronger than elapsed-time stability guesses |
| S018 | Replace the 64-isolated-process settlement sleep with pre-armed Binder death barriers and exact PID retirement | The first candidate passed strict cleanup. All 64 death-plus-unlink receipts and exact identity retirement completed in 806 ms, after which reclaim began immediately | Retain. Preserve all-or-nothing barrier arming and the total bounded deadline |
| S019 | Replace terminal Java and native settlement sleeps with Binder death barriers, exact identity retirement and immediate native cleanup proof | The first candidate passed strict cleanup. Terminal identities, Binder deaths and settlement completed within 2 ms of one another; native terminal cleanup then completed in about 300 ms | Retain. The terminal path no longer uses 2.5 seconds of timing guesses |
| S020 | Reuse the second disclosure as the first file/epitem disclosure | Three successful second-stage leak artefacts contained zero file candidates and zero epitem candidates | Reject. The second heap geometry discloses Binder nodes only and cannot replace the first phase |
| S021 | Replace both native 1,500-ms BatchClient settlements with a bound service Binder death receipt | The first attempt guarded only the first of two client launch paths. Phase one passed, while phase two timed out safely because it had no barrier. After guarding both paths, a fresh-boot candidate passed strict cleanup: first reader readiness took 5.90 seconds and second reader readiness took 5.10 seconds | Retain as a candidate. The failure exposed a missing proof path without mutation; require a later five-boot gate after the next structural disclosure change |
| S022 | Move the 8,192-object fragment export and 2,304 transaction queue from Java proxy creation to a direct Binder C++ transport | The first fresh-boot candidate passed disclosure validation and strict cleanup. Its second reader became ready in 4.31 seconds, about 0.8 seconds faster than S021, but five write misses made the complete Root-to-Prism duration 71.2 seconds | Retain the native transport as a candidate. The result removes Java object and Parcel overhead, but the observed saving is modest relative to run variance and requires a later five-boot gate |
| S023 | Interpose the opaque ReSukiSU loader's `syscall` GOT entry so `finit_module` uses `init_module` and removes the inode-label write | The candidate triggered the command safety watchdog before the controller started. The device returned with boot reason `reboot,shell`; no controller evidence or kernel-crash reason was present, and shell cannot read pstore | Reject and revert. A hard-coded binary GOT offset is too brittle for this safety-critical path. Do not retry runtime loader interposition |
| S024 | Re-establish the known-good native-fragment build after reverting S023 | Fresh boot `20260823-034831` passed every strict cleanup gate. Root-to-Prism took 54.5 seconds with one safely recovered write miss; harness root flow took 46.4 seconds | Retain as the comparison build for worker-pool and structural-write candidates |
| S025 | Reuse the 1,024 blocked C++ `sendmsg` threads across write attempts while preserving spray size and terminal joins | Failed safely. Attempts became about 0.6-0.9 seconds shorter, but only five of 18 victim nodes produced the exact replacement. The chain exhausted its cohort at write six and requested a controlled reboot; the returned boot reason was `reboot,shell` | Reject and revert. Fresh thread lifetime is part of the observed allocator geometry, not just orchestration overhead. Do not trade the accepted hit rate for faster misses |
| S026 | Cache the rescue module bytes before mutation and load them with `init_module` while retaining all six known-good writes | Failed closed. The helper reached the existing root and `ueventd` gates, but `init_module` returned `EACCES` from the buffer-load security path; the watchdog requested a controlled reboot and the device returned with `reboot,shell` | Reject and revert. This policy requires the inode-backed `finit_module` route and its validated file label; do not retry buffered module loading |
| S027 | Omit the helper `real_cred` pointer and collateral writes, retaining the repaired subjective `cred`, task-security, and inode-security writes | Candidate. The root watchdog is armed after the donor credential collateral is repaired. Its new thread receives the parent's subjective donor credential as both child pointers, while the helper leader keeps its private objective credential. The rescue module now requires that exact split, repairs both SELinux collateral words, then normalises `real_cred` before its existing strict finalisation. The first launch stopped cleanly before dispatch because the rebuilt module-size constant still described the old asset. The second reached the split but the parent watchdog gate used objective `capget`; the safety path rebooted before cloning. The corrected third run had an unrelated arbitrary-read reclaim miss before credential mutation and completed its controlled process-teardown reboot. Run `20260823-042747` then proved the corrected watchdog clone and native skip receipt, reaching `root-window-ready`; the controller deliberately rebooted because its legacy `/proc/<helper>` gate still expected the leader's objective credential to be the donor. Run `20260823-043616` completed all four exact writes and both security/collateral readbacks, but the newly early rescue proof rejected five valid retained control buffers because its collector still required the six-write total of seven. Run `20260823-044120` passed the corrected five-buffer rescue proof, then the second host gate rejected the watchdog's exact `ueventd` context because that thread shares the donor credential object whose security pointer write 5 deliberately changes. Run `20260823-044421` passed both host gates and the final ReSukiSU action, then rejected the rescue plan before module load because the helper-side list parser and module repair array still required seven carriers. Run `20260823-045238` accepted the five-carrier plan but stopped at the pre-load gate: `capget(pid=0)` reported the leader's private objective capabilities, as expected for the split, despite exact subjective root IDs. Run `20260823-045714` retained that failure after the cap fix because the helper's self-context gate expected the external objective shell label. Run `20260823-050254` preserved the exact gate bitmask and proved that every condition except the helper's self proc-context observation passed; that observer matched neither externally proven label in the split. Run `20260823-050734` passed the corrected pre-load gate, then `open(/proc/self/fd/<module>)` returned `EACCES` before `finit_module` because procfs evaluated the split objective identity | Keep the four-write mechanism. Duplicate the already open, hash-verified module descriptor with `F_DUPFD_CLOEXEC` instead of reopening its procfs alias. Preserve the exact module inode-label readback and let `finit_module` remain the first capability/SELinux policy decision |
| S028 | Dispatch the inode-backed rescue-module load on the exact root watchdog, then use module `current` to repair the exact leader task | Candidate. Run `20260823-051140` passed all four writes, rescue-plan proof, both host gates, ReSukiSU activation, and descriptor duplication, but `finit_module` returned `EACCES` on the split leader. The watchdog already has donor/donor credentials and the exact `ueventd` label, so it is the existing policy-authorised loader. The module now requires a non-leader loader in the exact helper thread group, resolves the leader by PID with a task reference, checks both its address and private/donor split, and changes only that leader's `real_cred` pointer. It does not call `commit_creds()` or change IDs while the task is split. Run `20260823-052238` failed closed before module load: watchdog gate bits were exactly `124`, proving root capabilities, PID/TID, and seccomp, but `/proc/self/attr/current` observed the split process leader instead of the calling thread. The safety watchdog produced a controlled `reboot,shell`. Run `20260823-052651` did not exercise S028: the unchanged first fake-node check missed before mutation, the helper retired, teardown arming correctly rejected the dead helper, and the controller requested a controlled reboot. Runs `20260823-052904`, `20260823-053323`, and `20260823-053813` showed generic stage `6`. Live inspection during the last run proved watchdog TID `14936` remained alive with objective root IDs; stage `6` detail `-1` proves the watchdog had stored a completed loader failure. The dispatcher was erasing the precise loader failure stage, not timing out. Run `20260823-054517` preserved the exact failure: `/proc/thread-self/attr/current` also omitted the ueventd bit while every objective identity gate passed (`124`). Run `20260823-055052` passed the revised userspace gates but `finit_module` returned `EACCES`; that errno was initially ambiguous because module init's loader validator also returned `-EACCES`. Run `20260823-055600` still returned `EACCES` after assigning distinct errors to thread-group, role, credential-pointer, and ueventd-object checks. | Give the sole remaining module-side `EACCES`—private shell UID mismatch—a distinct `EUCLEAN` rejection. An unchanged `EACCES` will then prove denial before module init. |
| S029 | Fork a single-threaded module-loader child from the exact donor/donor watchdog | Candidate. Run `20260823-060532` still returned `EACCES` after the last module-side `EACCES` became `EUCLEAN`, proving the non-leader watchdog is denied before module init. The already-successful ReSukiSU loader demonstrates the required process shape on every accepted run: it forks from that watchdog and its process-leader child successfully calls `finit_module` with the same staged descriptor. Re-adding the omitted leader write is not a five-write option because that write corrupts `donor_cred+8`; its paired repair is mandatory. Run `20260823-061920` reached the new single-threaded child but still returned `EACCES` before module init. The remaining difference from the proven loader was file-description provenance: S029 inherited an `F_DUPFD` duplicate of the shell-opened file, while ReSukiSU reopens `/proc/self/fd/<fd>` inside its coherent process-leader child. Run `20260823-062336` matched that reopen shape and advanced from `EACCES` to `ESRCH`; the child exited cleanly and the device later performed the expected controlled `reboot,shell`. This proves the loader and file policy path. Run `20260823-063022` still returned `ESRCH` after assigning distinct errors to target lookup, leader normalisation, and carrier PID/stack acquisition. Run `20260823-063508` also returned `ESRCH` after removing the final two explicit module-side `ESRCH` returns. Android 12 kernel 5.10.198 primary source contains no `ESRCH` return in `kernel/module.c`, `kernel/stop_machine.c`, `security/security.c`, or SELinux hooks; an invoked helper could still return it into module init. Run `20260823-064031` did not exercise the remapped module: the initial fake-node check missed before mutation, the helper retired, and teardown rejected the dead helper. | Repeat the exact remapped asset from a fresh boot. If `ESRCH` persists, it is conclusively after module init; otherwise the mapped errno identifies the helper phase. Preserve every validation and repair operation. |
| S030 | Refresh the shared rescue memfd from the independently verified APK module after ReSuki restores its embedded copy | Candidate. Run `20260823-064239` again returned the old module's `ESRCH`, revealing that `lp3-resukisu-loader.so` embeds `../bin/lp3_ctlbuf_rescue.ko` and `restore_rescue_module()` overwrites the shared memfd with that build-time copy after loading KernelSU. Rebuilding only the APK asset therefore never changed the module under test. The helper now retains the SHA-256-verified APK bytes, rewrites them to the same already-labelled memfd after a successful ReSuki action, calls `fsync`, then verifies a full SHA-256 readback before allowing rescue dispatch. The inode and its security object are unchanged. Run `20260823-064836` did not reach the ReSuki action or refresh: after donor freeze the controller stopped producing transport input and hit its unchanged socket deadline. Run `20260823-065304` lost harness UI observation but continued safely; all four writes passed on their first attempts in 10.8 seconds, then the controller stopped after `root-window-security-ready`, before sending the action request, and the safety path eventually rebooted. Neither run exercised the refresh. | Repeat the exact build after a fresh boot. A mapped phase errno or successful load now describes the current C module rather than the stale loader-embedded copy. Retain the refresh/readback as part of the development and production path unless the Rust loader is rebuilt from the same module artefact. |
| S031 | Add phase-level controller traces and require a cooler five-sample harness start | Runs `20260823-070324` and `20260823-070433` failed cleanly at the unchanged in-app health gate because the CPU exceeded its safety limit after launch, despite the harness accepting two samples below 65°C before launch. The repeated heavy runs lacked thermal headroom. The harness now waits for five consecutive samples below 45°C and battery below 40°C; the app's independent limits remain unchanged. The controller now records each plan and subjective-root host-read boundary so the post-write pause can be located without another ART dump. | Let the device cool, then repeat the exact S030 build. Do not attribute health-preflight failures to the primitive. |
| S032 | Trace the ReSuki action child around module load and late-load exec | Run `20260823-070720` passed the stricter thermal gate but missed the initial fake node before mutation. Run `20260823-070925` reached the four-write root window. The new controller traces proved the rescue plan, helper read, watchdog read, exact 18-task set, donor identity, helper identity, boot identity, and full subjective-root host gate all completed. The pause begins only after socket action `7`, while the watchdog waits up to 120 seconds for its fork child. | Emit inherited helper-log markers immediately before and after `g_resukisu_load()` and immediately before the `ksud late-load` exec. Use the last marker to identify the blocking component without relaxing the watchdog deadline. |
| S033 | Drain ReSuki child diagnostics while the watchdog waits | Run `20260823-071407` proved `g_resukisu_load()` returns success and the child reaches the `lp3-resukisu-ksud late-load` exec, which then remains alive until the unchanged 120-second deadline. The upstream late-load path performs installation, module stages, SELinux/profile setup, feature initialisation, manager restart, and normally returns; treating exec entry alone as success would be unsafe. | Make the existing diagnostic pipe non-blocking and forward it continuously while waiting. Use the last emitted ksud stage to locate the blocking operation; do not shorten the deadline or detach the process. |
| S034 | Stop waiting for diagnostic-pipe EOF after the verified ReSuki child exits | Run `20260823-071924` showed `g_resukisu_load()` and exec entry again, but live `/proc` inspection then found no child owned by any helper task while the watchdog remained alive. The watchdog had already reaped the child and was blocked in its separate post-wait diagnostic read. A descendant had retained the pipe writer, so EOF was not a valid action-completion proof. Diagnostics are already forwarded non-blockingly inside the bounded wait loop. | After the actual child wait completes, close the diagnostic read end without waiting for EOF, then continue to validate `WIFEXITED` and the exit status exactly. Retain the 120-second child deadline and all result checks. |
| S035 | Make the final ReSuki Manager `am start` asynchronous in the pinned `ksud` build | Run `20260823-074316` proved the rebuilt and hash-verified `ksud` loaded KernelSU and brought the Manager to the foreground at 44.8 seconds, but the `ksud` process still did not exit before the controller's unchanged socket deadline. The command root watchdog therefore never emitted its child-wait-exit receipt, and the safety path produced a controlled reboot. | Reject UI launch from the privileged recovery transaction. Keep the synchronous Manager force-stop, let `ksud` return immediately, complete rescue and strict cleanup, then launch the Manager from the shell-side controller. |
| S036 | Wake the display immediately before the harness Root tap and update both payload size gates | Run `20260823-073405` never started the primitive because the device entered doze during the thermal wait; the coordinate tap was sent to a sleeping display. Run `20260823-074138` then failed before staging because both expected-size constants still described the previous `ksud`, although the SHA-256 constants were current. | Retain the pre-tap wake, keyguard dismissal, and status-bar collapse. Keep independent size and SHA-256 checks in both staging components; update both whenever the pinned binary changes. |
| S037 | Move the ReSuki Manager launch after strict chain completion | Candidate build removes the final Manager start from `ksud`. The shell-side controller now starts the Manager with `am start -W` only after `DirectReSukiSuActivation` returns a terminal pass, then returns to Prism. The pinned patch applies cleanly; new `ksud` size is 4,091,048 bytes and SHA-256 is `bd1c3f344856d90026c2838ae14d0c39918aa3c256e42514bdcc4d4f2fafed12`. | Validate one fresh boot. Require a clean `ksud` child exit, hash-verified rescue-module refresh, successful rescue load, strict cleanup, observable Manager transition, and stable active Prism state before accepting. |
| S038 | Distinguish a late-load operation hang from process-exit and parent-return hangs | A stage file retained across standard-stream reset proved `ksud` reached every synchronous stage and `manager-force-stop`. Explicit `_exit(0)` removed Rust shutdown ambiguity, but the mutated watchdog parent still did not publish its post-clone receipt. | The privileged operation itself is complete. Do not retry Manager launch variants or Rust shutdown changes. Replace implicit process-lifetime signalling with a positive completion record and exact reap proof. |
| S039 | Send a dedicated `ksud` completion record over an inherited descriptor | The worker wrote `LP3_KSUD_DONE`, but linker command-line mode repurposed both FD 57 and FD 3. Runs failed closed with `ENOMSG`; the separately persisted `completion-written` stage proved the write call succeeded against the wrong post-linker descriptor. | Reject fixed inherited descriptor numbers across manual `linker64` invocation. Use a nonce-bound inode opened after linker initialisation or avoid linker command-line mode. |
| S040 | Add a standalone C++ `clone3` process-lifecycle probe | On-device shell execution returned to the parent in 308,281 ns while the child deliberately remained alive for two seconds, then `waitpid` returned the exact exit status 42. | Retain `clone3` as the standalone process primitive. The kernel syscall is fast and correct outside the mutated ART helper; the app-hosted stall is contextual, not an inherent clone cost. |
| S041 | Move child collection from the mutated root watchdog thread to the unmodified shell leader | The watchdog publishes an exact child PID and diagnostic/completion descriptors; the JNI caller owns bounded `pread` and `waitpid`. A memfd completion record still failed because linker command-line mode replaced the inherited descriptor before `ksud` started. | Retain split spawn/collect ownership for a native standalone design, but replace inherited descriptor numbering with an object reopened and validated after exec. |
| S042 | Use a nonce-bound exclusive completion inode opened by `ksud` after linker initialisation | `ksud` reliably wrote and fsynced the record, as proven by `completion-written`. The ART-hosted root watchdog nevertheless failed to publish the child to the collector within both 5- and 15-second bounds; the safety path rebooted with `ETIMEDOUT`. The standalone clone3 probe does not reproduce this. | Stop iterating process creation inside the mutated multithreaded `app_process`. This seam cannot support the 10-second target or a clean lifecycle proof. Move the complete process topology to the standalone C++ executable. |
| S043 | Pivot the optimisation loop to a package-free standalone C++ chain | The existing `prism-primitive` executable now provides structured event output and a verified clone3 probe, but its current core contains lifecycle/death-barrier probes rather than the full CVE chain. The app chain remains the behavioural oracle and source for exact offsets, gates, repair rules, and cleanup receipts. | Extract the Binder topology, disclosure, batch arbitrary-read, four-write, action, and terminal-repair mechanisms into native process roles. Preserve every fail-closed invariant; measure executable entry through terminal cleanup on fresh boots. |
| S044 | Register a package-free native Binder broker from `u:r:shell:s0` | `/dev/binder` open, version, and mapping pass in 0.7 ms, but `AServiceManager_addService` returns `-1`; the existing audit evidence denies `{ add }` to `default_android_service` | Reject ServiceManager registration. Use a minimal pushed `app_process` adapter only for Binder-reference exchange; keep topology, exploit phases, safety, and cleanup in C++ |
| S045 | Exchange a Binder reference through an unattached `app_process` and ActivityManager broadcast | Direct registration with the synthetic application thread and with a null caller both reach AMS, but AMS logs `registerReceiverWithFeature: no app` and retains no receiver because the process has no `ProcessRecord` | Reject the package-free framework broker. Keep Android only as a topology adapter, pass all endpoints to one C++ controller, and do not claim the topology itself is package-free |
| S046 | Start all 64 isolated reference holders concurrently with disclosure construction | Starting at the first disclosure increased that phase by about three seconds. Starting at the second disclosure preserved a 13.5-second acquisition time but disturbed its allocator geometry and caused a safe node-analysis miss | Reject overlap with either grooming phase. Process launch and Binder allocations are part of the heap experiment, not independent setup work |
| S047 | Reduce disclosure reference holders from 64 to 16 while preserving exactly 1,536 filler references | First fresh boot passed in 11.9 seconds with 13 node hits. The next fresh boot missed: all 64 leaked candidates had one hit, showing that 96 fillers per process displaced the controlled reference from its repeated slot | Reject the 96-filler geometry. Preserve the accepted 24 fillers per process while testing fewer independent holders |
| S048 | Keep 16 holders and vary filler placement: 24 total, then 24 before the controlled node plus 72 after it | Both fresh boots missed safely. With 24 total, no Binder-ref candidate appeared; with the 24+72 split, the tail allocations still removed all candidates. The accepted repeated node observation depends on 64 distinct per-process controlled refs, not only the aggregate filler count | Reject fewer holders and restore 64 holders with 24 fillers each. Do not weaken the eight-hit analyser threshold |
| S049 | Reduce the native fragment export from 8,192 handles to 4,096 while preserving all 2,304 alternating transactions and 1,152 gaps | Five consecutive fresh boots passed. Checkpoint times were 6.930-7.250 seconds and host times were 7.826-8.063 seconds. Every run retained exact analyses; controlled-node hits were 17-642. The second fragment call fell from 3.075 seconds (`reply_us=2969975`) to 0.334 seconds (`reply_us=251463`) | Accept as the new disclosure baseline. Preserve the complete transaction/gap geometry and the existing analyser thresholds |
| S050 | Re-evaluate launching all 64 isolated holders during the first disclosure after the 4,096-handle optimisation | The holders bound in 4.019 seconds, but the second disclosure then produced zero Binder-reference candidates and failed safely before mutation. This confirms that the already-live holder allocations alter the second heap geometry even when their launch latency is hidden | Reject prebinding. Bind the 64 accepted holders only after the second reader is ready until a structurally different holder mechanism passes its own disclosure gate |
| S051 | Recover a Java `Parcel` template and Binder-object table from native code without copying or altering it | A bounded on-device probe passed: C++ resolved the already-loaded Android 14 platform symbols against their exact ELF images, recovered a 76-byte Parcel, its sole object offset at byte 4, and the expected local Binder pointer/cookie. No CVE transport or kernel mutation ran | Retain as a fingerprint-gated topology-adapter capability. Use it to prototype a harmless ActivityManager callback route before creating controlled-node references |
| S052 | Replace zygote processes structurally with independent Binder driver contexts and an ActivityManager rendezvous | One context completed ServiceManager lookup, an explicit `startService`, callback, and same-node marker verification in 6.658 ms. A 64-context gate then passed in 404.089 ms with all contexts simultaneously retained; all 64 transaction buffers, 64 mappings, and 64 descriptors were released exactly | Retain the rendezvous. Separate empty-context bootstrap from reference delivery so the CVE decrement ordering and holder lifetime remain unchanged |
| S053 | Bootstrap 64 raw contexts after the second reader is ready, then deliver 24 unique fillers plus the controlled node to each after the decrement | The transport and cleanup gates passed: 1,600 unique handles arrived in 3.529 ms and all 64 callback death receipts completed. Disclosure nevertheless had zero Binder-ref candidates. The 0.523-second ActivityManager bootstrap immediately before the decrement perturbed the target slab geometry | Reject late bootstrap. Create empty contexts after first-owner cleanup, then let second-owner construction and grooming settle the temporary rendezvous allocations before reference delivery |
| S054 | Move empty-context bootstrap between the first-owner cleanup and second-owner bind | The first run did not exercise disclosure: each internal broker `startService` overwrote the harness's shared requested stage, so the second-owner connection was dispatched as a generic bootstrap. All 64 broker callbacks completed and the app was force-stopped without mutation | Preserve the outer stage across internal broker invocations. Treat broker starts as messages to the running stage, not new stage ownership |
| S055 | Preserve the outer stage and repeat early bootstrap | The stage remained correct, but the second owner lookup used a 512-handle descriptor scan. Its synchronous probes encountered dormant raw callback nodes and stalled; it eventually failed safely without reaching the second disclosure | Decode the handle directly from the exact service-connection `IBinder`, then validate only that handle's descriptor. Apply the same direct lookup to the controlled Binder to eliminate all post-bootstrap scans |
| S056 | Use direct owner/controlled handle decoding and deliver references after the decrement | Direct lookup removed the stall and the decrement passed. All 64 one-way payload transactions were submitted, but the receiver observed none: payload reception ran on a new native thread that had not entered the looper for any retained Binder context | Enter the current receiver thread as a looper on every retained context before reading its queued payload. Keep the callbacks one-way and preserve the post-decrement ordering |
| S057 | Enter all retained loopers and repeat early bootstrap | All 1,600 handles arrived in 3.624 ms and all cleanup/death gates passed, but disclosure still contained zero Binder-ref candidates. Unlike Java `readStrongBinder`, the raw receiver kept each transaction buffer rather than materialising user-owned strong and weak references | Send `BC_INCREFS` plus `BC_ACQUIRE` for every handle, then free the transaction buffer. During teardown, send the paired `BC_RELEASE` plus `BC_DECREFS` before closing each context |
| S058 | Materialise raw handles with the exact libbinder ownership protocol | First fresh boot passed in 4.540 seconds host time and 3.688 seconds between checkpoints. The analyser found one candidate with 310/310 hits. Cleanup explicitly released/decremented all 1,600 handles, unmapped and closed all 64 contexts, and observed all 64 callback deaths | Candidate for the five-boot disclosure gate. Preserve early empty-context bootstrap, post-decrement delivery, persistent ref acquisition, and exact paired cleanup |
| S059 | Five-boot gate for the 64-context persistent-ref candidate | Run 1 passed in 4.532 seconds with 224/224 hits. Run 2 transported and cleaned all 1,600 refs exactly but disclosed no candidate | Increase only the cheap raw cohort to 96 independent contexts. Keep 24 fillers per context by cycling the accepted 64 filler sets; do not change the second-owner fragment or stale-read geometry |
| S060 | Increase the native holder cohort from 64 to 96 while cycling the accepted filler sets | First fresh boot transported and released all 2,400 holder refs and all 96 callbacks exactly, but disclosed no controlled candidate | Reject overfilling. Restore 64 contexts. Retain each context's ActivityManager and route-marker refs across the second groom instead of freeing them during bootstrap, matching the long-lived framework-ref baseline of an isolated app process |
| S061 | Retain each raw context's ActivityManager and route-marker refs across grooming | All 1,728 refs and all 64 contexts cleaned up exactly, but the first fresh boot disclosed no candidate | Reject bootstrap-ref retention. Restore empty contexts and diversify the controlled-ref alignment: eight contexts each receive 20–27 fillers before the controlled node, preserving eight observations per alignment and slightly reducing total pressure |
| S062 | Diversify raw-context filler alignment across eight groups of eight holders | Fresh boot `20260823-105344` transported and materialised all 1,568 refs in 9.744 ms, then released all 1,568 handles, 64 mappings, 64 descriptors and 64 callback nodes exactly. All 1,152 stale records nevertheless contained zero Binder-ref candidates | Reject payload alignment as the missing variable. The raw path submits 64 one-way transactions before consuming any; unlike the accepted isolated-service path, this keeps every asynchronous transaction live during the complete ref allocation burst. Reproduce the accepted serial synchronous request/reply lifetime with a native receiver before changing allocator pressure again |
| S063 | Reproduce the isolated-service serial synchronous transaction lifetime on all 64 raw contexts | Fresh boot `20260823-105741` completed all 64 synchronous request/reply cycles in 46.800 ms and reconciled all 1,568 handles and resources, but again disclosed zero Binder refs. The raw leak contained 302 repeated kernel pointers ending at a 64-byte, not 128-byte, boundary; none had the `binder_ref` overlay shape | Reject asynchronous transaction lifetime as the missing variable. Capture the `kmalloc-128` allocation/free sequence for this path and the accepted isolated-holder path before the next allocator change; the target-process topology or pre-decrement holder launch must account for the remaining difference |
| S064 | Match Android 14 libbinder's synchronous `BC_FREE_BUFFER`-before-`BC_REPLY` ordering and drain each `BR_TRANSACTION_COMPLETE` | First fresh boot `20260823-110937` passed in 4.534 seconds host time and 3.583 seconds between checkpoints. All 64 completions were consumed, the analyser found the controlled node with 207 hits, and teardown reconciled 1,568 handles, 64 mappings, 64 descriptors and 64 callback deaths. The five-boot gate then missed on run 1 with the same complete transport and cleanup proof but zero Binder-ref candidates | Retain the exact protocol ordering because it removes a real race, but reject it as sufficient allocator control. The traced isolated control performs 6,248 Binder transactions between reader readiness and decrement, taking 3.849 seconds; prime the raw contexts with a held, CPU-2 allocation cohort before decrement to replace that accidental freelist drain explicitly |
| S065 | Hold 4,096 unique raw-context refs before decrement to replace the isolated-process `kmalloc-128` drain | First fresh boot `20260823-111348` passed in 4.794 seconds host time and 3.724 seconds between checkpoints. Priming completed in 130.367 ms, the controlled spray in 61.257 ms, and the analyser saw 631 Binder-node candidates with 412 selected hits. Teardown reconciled all 5,664 handles, 64 mappings, 64 descriptors and 64 callback deaths. Five-boot gate run 1 passed at 4.852 seconds; run 2 produced 147 candidates but only seven controlled hits, one below the unchanged threshold | Retain the explicit 4,096-ref prime. Double independent controlled observations to 128 contexts while halving prime refs per context to 32, so the priming allocation budget remains fixed and the weak seven-hit geometry has margin above eight |
| S066 | Use 128 raw contexts with 32 prime refs each, keeping the total prime at 4,096 | Five consecutive fresh boots passed in evidence set `20260823-111919`. Host durations were 5.246–5.599 seconds and checkpoint durations were 4.251–4.452 seconds. Every run disclosed 925–1,102 Binder-ref candidates and 46–47 controlled hits, released all 7,232 handles, unmapped and closed all 128 contexts, observed all 128 callback deaths, retired the package, and remained disclosure-only | Accept as the raw-holder disclosure topology. Preserve 128 independent contexts, the 4,096 held pre-decrement prime, free-before-reply ordering, completion draining, the eight-hit threshold, and exact 7,232-handle/context/death cleanup while moving it into the full primitive |
| S067 | Measure the unchanged full root path after accepting the raw disclosure holder | Fresh boot `20260823-112614` retained the old 64-isolated-process root holder. Harness dispatch entered at 47.940 seconds of boot, preparation passed at 47.997 seconds, the subjective-root proof passed at 71.119 seconds, and the root-window security gate passed at 75.845 seconds. The ReSuki action then timed out at 90.850 seconds; the watchdog produced a controlled `reboot,shell`, with no success claimed. The runner reported 145.884 seconds including fresh boot and evidence collection | Reject this as a performance baseline and retain it as the honest failure reference. The accepted raw holder is not yet a root-path drop-in: it must reproduce the controlled-node reference, anchor death-notification reference, anchor-holder lifetime, and exact pre-mutation context retirement proof before it can replace the isolated processes |
| S068 | Replace the root path's isolated holders with 128 raw Binder contexts, a direct victim-node transfer, and one death-notified anchor ref per context | Primitive probe `20260823-103348-198489` passed both disclosures with 20 selected controlled-node hits and 20 observed death-bearing anchor records. It then failed closed before arbitrary-read mutation because teardown cleared zero of 128 death notifications: release ran on a thread that had not entered each Binder context, so clear completions remained unavailable. All 128 callback deaths still arrived and every mapping and descriptor closed, but no release proof was accepted | Retain the direct victim-owner transfer and separate anchor geometry. Enter the teardown thread as a looper on every context before issuing `BC_CLEAR_DEATH_NOTIFICATION`; continue to require all 128 clear completions, all handle releases, all context closes, and all callback deaths before mutation |
| S069 | Enter every raw Binder context on the teardown thread before clearing anchor death notifications | Fresh primitive probe `20260823-103649-493667` passed the complete raw-holder retirement gate in 219 ms, before arming arbitrary-read reclaim. Both disclosures passed; the raw root path reached arbitrary-read preparation 8.389 seconds after `root-flow-start`. The first unlink then produced `exact_payload=0`, an existing safely contained acquisition miss, and the controller confirmed its planned `reboot,shell` | Accept the exact raw-context retirement mechanism. Repeat from a fresh boot to distinguish ordinary arbitrary-read allocator variance from a topology regression; never retry the unlink on the same boot after the miss |
| S070 | Repeat S069 from a second fresh boot | Primitive probe `20260823-103809-144081` again passed raw-holder retirement, this time in 226 ms, and again reached arbitrary-read preparation in 8.273 seconds. The first unlink produced the identical safe `exact_payload=0` miss | Classify the miss as structural. Raw teardown frees 7,360 held Binder refs on the CPU-2 critical allocator immediately before arbitrary-read reclaim, unlike the dispersed deferred release of 64 isolated processes. Perform the already-proven exact teardown on CPU 0, restore CPU 2 explicitly, and retest from a fresh boot |
| S071 | Perform exact raw-context teardown on CPU 0, then restore CPU 2 before reclaim | Fresh primitive probe `20260823-104028-897896` again passed both disclosures and raw retirement, but the first arbitrary-read unlink still returned the same safe `exact_payload=0` miss | Reject CPU placement as the cause. The direct victim-owner forwarding path imports every filler and anchor proxy into the victim process; its exit then frees roughly 1,500 refs immediately beside the victim node, unlike the old path where the harness sent fillers directly to holders. Split the root spray into direct support refs and victim-owned controlled refs so the victim imports only the 128 raw callback endpoints |
| S072 | Split root delivery into direct filler/anchor transactions followed by one victim-node transaction per context | Four consecutive fresh probes (`20260823-104302-342323` through `20260823-104611-753102`) failed closed at node analysis before mutation. The split removed the victim's filler proxies but also removed the accepted single-transaction allocation geometry | Reject split delivery. Preserve one composite payload while avoiding Java `BinderProxy` materialisation: copy the remote victim handle directly from its export `Parcel`, validate its exact `BINDER_TYPE_HANDLE` layout in C++, append that object into each composite holder payload, and recycle the sole temporary handle before analysis |
| S073 | Forward the victim handle as a validated raw `Parcel` object in the original composite payload | Fresh primitive probe `20260823-105030-129177` passed node analysis, retired all 128 raw contexts in 200 ms, reclaimed the exact fake-node payload, and passed arbitrary-read handoff and controlled-free gates. It then failed closed because the native unlink ledger still required the old isolated-process retirement state; no write occurred and the planned reboot completed | Accept zero-proxy composite forwarding. Publish a distinct native raw-context retirement receipt only after reconciling exactly 7,360 handle releases, 128 death-notification clears, 128 mappings, 128 descriptors, and 128 Java callback deaths. Let the existing unlink and terminal-cleanup ledger consume either the 64-process proof or the stronger 128-context proof explicitly |
| S074 | Publish and consume a distinct 128-context retirement proof | Fresh primitive probe `20260823-105437-301958` passed both disclosures and the new native retirement ledger, then encountered a safely contained `exact_payload=0` arbitrary-read acquisition miss before any write. The prior S073 run with identical zero-proxy geometry reclaimed the exact payload | Accept the proof integration and classify this as ordinary reclaim variance. Run the full activation path to measure the remaining write/action critical path; retain one unlink attempt per boot and count only complete strict-cleanup successes |
| S075 | Exercise the zero-proxy raw-holder candidate through the full four-write path | Run `20260823-115454` missed the first arbitrary-read reclaim safely, 6.42 seconds after harness dispatch, and performed no write. Run `20260823-115656` passed arbitrary read in 6.45 seconds, reached all four exact writes on their first attempts, and published the security-ready gate 25.07 seconds after the native root flow began. The modified `ksud` wrote its nonce-bound completion marker, but the ART-hosted `clone3` parent did not return to publish the exact child PID within 15 seconds; the controller therefore requested its required controlled reboot. No activation success was claimed | Retain the raw-holder root path. Move only the action child into a fresh single-threaded C++ supervisor so the exact parent can publish the child PID immediately; preserve the completion inode, exact PID/status collection, artefact identity, credential, cleanup, and reboot gates |
| S076 | Build the C++ action supervisor and replace complex work in the post-`clone3` ART child | The native target builds. The watchdog now uses `CLONE_VM | CLONE_VFORK`; before `execveat`, the child performs only raw `close` and `dup3` syscalls. The supervisor requires a single-threaded process leader, exact root IDs, `CAP_SYS_MODULE`, shell-owned mode-0755 loader/action/supervisor artefacts, matching descriptor/path identities, a regular module descriptor, a valid runtime kernel base, and a nonce-bound completion path. It reloads and restages the rescue module from inherited exact descriptors, then executes the exact action descriptor through `/proc/self/fd`. The deployed binary's ordinary standalone `clone3` lifecycle still returned in 0.374 ms and reaped the exact child/status | Run one fresh-boot full safety gate. If it completes, measure the action span and strict cleanup before beginning a five-run series. Do not count this build-only result as a CVE or activation pass |
| S077 | First full safety gate for the native supervisor | Run `20260823-120739` reached all four security-ready writes on the accepted raw-holder path, then failed closed at `resukisu-action reason=prepare` before spawning a child. Loader preparation precedes command-watchdog preparation; the latter's reset code incorrectly closed the supervisor's newly retained loader descriptor. The existing controller requested and confirmed the planned `reboot,shell`, and no action or success was claimed | Keep the loader source descriptor for the lifetime of the one command process. Continue to duplicate and close a distinct per-action descriptor, then repeat the fresh-boot gate |
| S078 | Repeat after correcting loader-descriptor lifetime | Run `20260823-121039` stopped at the existing `safe-acquisition-miss` gate before any kernel write or action. Root-to-failure UI was about 14 seconds. This run provides no evidence for or against the supervisor | Repeat from a fresh boot without changing the candidate. Retain one arbitrary-read reclaim attempt per boot and do not count a pre-action miss as an action result |
| S079 | Exercise the corrected supervisor on a write-complete boot | Run `20260823-121220` reached the four-write security-ready gate 25.42 seconds after harness dispatch. The supervisor loaded the module and `ksud` wrote `completion-written`, proving both native `exec` boundaries and the action itself completed. Nevertheless, the ART watchdog thread remained inside `clone3` and did not publish the child PID within the unchanged 15-second deadline, so the controller requested its controlled reboot and claimed no success | Let the child self-publish its exact `getpid()` result and action-ready futex before `exec`. Pre-publish the diagnostic and completion descriptors from the watchdog before `clone3`, then let the JNI sibling perform the unchanged exact `waitpid`, completion-content, and unlink proof. Do not depend on the anomalous originating thread returning |
| S080 | Test shared-memory self-publication from the pre-exec child | Run `20260823-121639` again reached all four writes and the exact `ksud` completion marker, but the sibling could not observe the child's atomic PID/action publication within 15 seconds. This proves that relying on the nominal `CLONE_VM` visibility is not robust in this ART-hosted shape | Replace shared-memory publication with a new private registration pipe. Require one fixed binary receipt containing magic, equal PID/TID, exact action, exact manager UID, and exact kernel base before accepting the child; keep the diagnostic and completion pipes separate |
| S081 | First gate for the private child-registration receipt | Run `20260823-122115` stopped at the existing pre-mutation `fake-node-check` miss 6.60 seconds after harness dispatch. The persisted `lp3-ksud-stage` file was stale evidence from the preceding boot and was not used; the controller result proves no root window or action occurred on this boot | Repeat the unchanged receipt build from a fresh boot. Attribute evidence only to the nonce-bound controller/action receipts, never to a persistent auxiliary marker alone |
| S082 | Exercise the watchdog-created registration pipe on a write-complete boot | Run `20260823-122319` reached all four security writes, but the JNI sibling received no valid child receipt in 15 seconds. Because the watchdog created and then published the observer descriptor, this still depended on reverse cross-thread publication immediately before the non-returning `clone3` call | Create the registration pipe in the JNI action thread before publishing the action request. Keep its read end local to that thread, publish only the inherited descriptor numbers to the watchdog under the action's release/acquire boundary, and validate the receipt directly from the local read end |
| S083 | Exercise a JNI-owned registration pipe | Run `20260823-122813` again reached all four writes, but the JNI-owned read end received no child receipt. This removes reverse descriptor publication as the cause. The persistent auxiliary `completion-written` marker remains non-nonce-bound and is rejected as proof that this boot's `CLONE_VFORK` child ran | Remove `CLONE_VFORK | CLONE_VM`. The earlier plain `clone3(SIGCHLD)` child is known to run in this process shape; keep that process creation but limit its child branch to fixed raw syscalls, write the exact private receipt first, and immediately `execveat` the C++ supervisor. The sibling can collect it even if the originating watchdog remains in `clone3` |
| S084 | Exercise plain `clone3(SIGCHLD)` with syscall-only child and private receipt | Run `20260823-123139` reached all four writes but again returned the generic 15-second receipt timeout. The result did not distinguish whether the watchdog entered `clone3`, whether the child wrote bytes, or whether receipt validation rejected them | Add read-only bounded diagnostics to the existing failure result: watchdog spawn stage, receipt stage, byte count, and validation/errno detail. Preserve the candidate and every success gate; use the next write-complete boot to locate the stall before changing process creation again |
| S085 | Locate the pre-receipt failure with bounded spawn diagnostics | Run `20260823-123515` reached all four writes and returned `spawn_stage=-1 receipt_stage=7 receipt_bytes=0`: the watchdog entered spawn and returned a failure before creating a child. The late supervisor `open()` and path `stat()` occurred after write 5 under the watchdog's temporary `ueventd` security identity, unlike the loader and action descriptors that were opened and verified while still shell | Open and descriptor/path-verify the supervisor alongside the loader before mutation. Retain that exact descriptor, duplicate it per action, revalidate descriptor metadata without a late path traversal, and invoke `execveat` on the descriptor. Also publish the exact spawn errno on future failures |
| S086 | Retain an early-verified supervisor descriptor | Run `20260823-123933` proved that the supervisor path was no longer the blocker but exposed `spawn_errno=24` (`EMFILE`). Opening the completion inode succeeded; creating a second, diagnostic pipe after the new registration pipe exceeded the process descriptor limit | Use the already pre-created registration pipe as the diagnostic pipe. Require its first 32 bytes to be the fixed child receipt, then let the unchanged collector consume subsequent loader diagnostics from the same descriptor. This removes two descriptors while retaining separate completion-inode evidence and exact process collection |
| S087 | Reuse one pipe for child registration and diagnostics | Run `20260823-124401` cleared the descriptor-limit failure but returned `spawn_errno=13` (`EACCES`) before child creation. The registration reader saw the descriptor being closed (`receipt_stage=4 detail=9`). The sole remaining late filesystem operation was creation of the nonce-bound completion inode under the temporary watchdog identity | Create and truncate the exact nonce completion inode in the JNI action thread before publishing the action. Publish its open descriptor with the action request; let the watchdog and collector use only that descriptor, and leave completion content/status/unlink requirements unchanged |
| S088 | Pre-create every late action artefact | Run `20260823-124732` still returned `spawn_errno=13` after moving completion creation. Every pre-clone operation was then descriptor-only, locating `EACCES` in the post-write task-creation security hook itself | Pre-spawn a single-threaded C++ action daemon immediately after the watchdog proves root, while its shared credential still has the permitted shell security identity. Keep the daemon dormant on a private socket. After writes 5 and 6, send the already verified loader, staged module, and action descriptors with `SCM_RIGHTS`; require the daemon's exact PID/TID ready receipt, then retain the existing exact wait status, completion content, and unlink proof. Join the sacrificial spawner thread during terminal cleanup |
| S089 | First gate for the pre-spawn action daemon | Run `20260823-125711` stopped at the existing pre-mutation `epitem-analysis` safe miss 1.91 seconds after harness dispatch. The helper teardown closed the private daemon socket, and no `prism-action-daemon` process remained on the unchanged boot | Repeat the unchanged daemon candidate from a fresh boot. Do not count this as an action result |
| S090 | Exercise daemon pre-spawn on a write-complete boot | Run `20260823-125851` reached all four writes, then timed out with `spawn_stage=-2` and no ready bytes. Stage `-2` is the spawner's exact retained-supervisor duplication gate; the extra `F_DUPFD` failed at the process descriptor ceiling before `clone3` | Use the already retained and identity-verified supervisor source descriptor directly with `execveat`. It remains owned by the helper and needs no per-spawn duplicate; this removes one descriptor without changing the executed inode or its validation |
| S091 | First gate after removing the daemon supervisor duplicate | Run `20260823-130202` did not reach Root: although the host starter process was present, Prism's independent preflight reported Shizuku stopped until its 30-second deadline | Treat as a preflight failure, not a primitive or daemon result. Repeat from a fresh boot without changing the candidate |
| S092 | Repeat the no-duplicate daemon candidate | Run `20260823-130334` reached all four writes but again returned `spawn_stage=-2`; after removing `F_DUPFD`, this stage now means the retained source descriptor failed its redundant late metadata check | Instrument the exact late `fstat`: preserve errno, file type, UID, GID, and mode in `spawn_errno`. Do not remove or weaken the check without identifying which predicate differs from the earlier accepted identity |
| S093 | Exercise the instrumented retained-descriptor gate | Run `20260823-130822` passed the independent shell preflight and progressed beyond the former bounded action failure, then the native watchdog requested a `reboot,shell` before the controller could publish a result. The surviving trace contained only the command-buffered record, so the generic reboot path did not preserve which later invariant failed. The persistent `completion-written` auxiliary marker remains non-nonce-bound and is not accepted as action evidence | Add one fsynced, read-only watchdog state snapshot immediately before every native safety reboot. Preserve every reboot condition and use the next write-complete boot to distinguish action collection, donor freezing, rescue loading, thread retirement, and final normalisation |
| S094 | Repeat with durable reboot diagnostics | Run `20260823-131126` reached the security-ready gate, then the nonce-bound controller trace reported `spawn_stage=-2 spawn_errno=13` after the unchanged 15-second ready deadline. The detailed errno proves the retained descriptor still existed but `fstat` was denied. The watchdog had published readiness immediately after `pthread_create`, allowing the daemon spawner's validation to race write 5 and inherit the temporary `ueventd` security context before its filesystem check | Do not publish the command watchdog as ready until the daemon spawner has reached exact stage 3, after the early metadata check and successful parent return from `clone3`. Fail closed and retain the controlled reboot if the stage is not reached within five seconds |
| S095 | Require the daemon parent-return gate before mutation | Run `20260823-131435` failed before mutation publication at the helper-marker timeout. Its nonce-bound helper trace recorded `command-root-watchdog` invalid immediately after the arm receipt, proving that the spawner cleared metadata validation but the ART-hosted parent again did not return from `clone3`. No security-ready checkpoint or accepted action result was published | Retain the pre-mutation stage-3 gate but use the legacy raw `clone(SIGCHLD, nullptr, ...)` fork ABI for this one sacrificial daemon. It provides the same separate-process and exact-wait semantics without depending on the anomalous `clone3` entry path; keep `execveat`, PID/TID receipt, SCM descriptor transfer, completion inode, status, and cleanup checks unchanged |
| S096 | Test legacy raw `clone` under the parent-return gate | Run `20260823-131934` again stopped at the helper-marker timeout with the watchdog identity unavailable. The child-creation entry point therefore does not control the ART parent suspension: both `clone3` and legacy `clone` create the separate child but do not return to the originating thread within five seconds | Gate mutation on the stronger child-side proof instead: consume and validate the exec'd daemon's fixed ready receipt before publishing watchdog readiness, cache that exact PID for the later request and `waitpid`, and close the helper's duplicate child endpoint. Continue to require the suspended spawner thread to return and join after the exact daemon has exited |
| S097 | Gate on the daemon's child-side exec receipt | Run `20260823-132313` still timed out at the helper marker and published no watchdog identity. Neither the spawner parent stage nor the child exec receipt became observable when process creation originated from the non-leader pthread, so retaining that thread cannot provide a reliable lifecycle | Spawn the daemon synchronously from the exact helper process leader immediately after its root identity is proven and before creating the watchdog pthread. Require both the parent return and the daemon's equal PID/TID receipt before continuing; cache the exact child PID, and treat the already-returned leader spawn as the spawner-retirement proof during cleanup |
| S098 | Spawn synchronously from the exact process leader | Run `20260823-132822` still stopped at the helper-marker timeout with no watchdog identity, proving that raw `clone` is held after the helper's credential split even on the process leader. The failure is therefore not an ART non-leader lifecycle issue | Use Android bionic's supported multithreaded `posix_spawn` handshake while the leader still has the permitted shell security identity. Execute the already-open, shell-owned supervisor through `/proc/self/fd`, clear `FD_CLOEXEC` only around the bounded spawn, restore it immediately, and preserve the parent-return plus exact daemon PID/TID receipt gates |
| S099 | Use bionic `posix_spawn` before the security-pointer write | Run `20260823-133412` again timed out at the helper marker with no watchdog identity. Process creation is therefore held after the credential split even through bionic's supported path; changing fork APIs cannot solve the pre-action boundary | Stop creating a child before module load. In the exact root process leader, descriptor-validate and load the already-staged ReSukiSU module first. Only after the loader returns success, spawn the fixed `ksud` descriptor through `linker64`; retain exact child PID/status, nonce completion inode, diagnostics, and all terminal cleanup gates |
| S100 | Load the module in the root leader before spawning `ksud` | Run `20260823-134040` reached security-ready in 27.09 seconds from harness dispatch and returned the action failure in 4 ms rather than hanging. The exact diagnostic was `receipt_detail=-1`: `lp3_resukisu_load` rejected the earlier staged image, and no child was spawned | Match the accepted C++ supervisor sequence in the leader: rerun exact-kernel relocation and stage the same verified module descriptor immediately before load. Spawn `ksud` only if relocate, stage, and load all return zero, and encode the failing substage in the existing diagnostic field |
| S101 | Re-run relocate/stage/load on the existing loader mapping | Run `20260823-134328` returned immediately with `receipt_detail=999`, which encodes relocation result `-1`. The loader instance is stateful and rejects a second relocation after the earlier stage; the standalone supervisor succeeds because `exec` gives it a fresh mapping | Force-load a second loader instance from the already-retained, exact shell-owned loader FD with `ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_FORCE_LOAD`. Resolve and validate all four symbols on that isolated mapping before relocate/stage/load; perform no late path lookup |
| S102 | Force-load the retained loader FD after the security write | Run `20260823-134703` still returned `receipt_detail=999`. The late forced load did not yield a usable first-relocation instance under the temporary security context, so it cannot replace the supervisor's fresh address space at that point | During shell-time loader preparation, copy the already-open exact loader bytes into a private memfd, force-load that distinct inode, validate its probe and all action symbols, and leave it unstaged. Preserve the mapping until action time so its first relocation occurs only after the kernel base is known, with no late linker or filesystem operation |
| S103 | Use the preloaded, never-staged action loader | Run `20260823-135056` cleared relocation but returned `receipt_detail=2026`, encoding stage result `26` (`ETXTBSY`). The primary staging pass leaves the original module inode mapped in the helper; unlike the exec'd supervisor, a second loader mapping in the same process cannot rewrite that busy inode | Before the primary stage, copy the exact 595,800-byte module descriptor into a private action memfd. Stage and load that pristine, distinct inode with the isolated action loader, while retaining the original module descriptor for the existing rescue refresh and cleanup protocol |
| S104 | First gate with distinct action loader and module inodes | Run `20260823-135433` missed safely at `epitem-analysis` 1.74 seconds after harness dispatch, before arbitrary read, mutation, or action. The controlled fresh-run reboot completed normally | Repeat the unchanged candidate. Do not attribute this pre-mutation miss to action isolation and do not count it as an action result |
| S105 | Exercise distinct action loader and pristine action module | Run `20260823-135631` cleared action relocation and staging, then returned load code `42` before spawn. Disassembly proves `42` is the loader's internal branch after a failed `open(path, O_CLOEXEC)`, not Linux errno 42; nearby static data identifies `/dev/kmsg` discovery and “No kernel log device candidate” as the likely source | Persist the immediate `errno` and a bounded copy of the loader's already-open diagnostic socket to the nonce-bound watchdog trace. Identify the exact failed path before changing access semantics |
| S106 | Resolve load code `42` and select the proven coherent loader identity | Run `20260823-170257` persisted `LP3_RESUKISU_FINIT_ERROR code=42 restored=1`. Loader source in the pinned patch proves code `42` is specifically `open("/proc/self/fd/<module>", O_RDONLY | O_CLOEXEC)`, and S027 already proved procfs evaluates the split leader's objective identity. S028 already proved descriptor duplication followed by direct `finit_module` is still denied on that split leader, so repeating either candidate would violate the experiment discipline. Earlier S033 evidence proves the existing donor/donor root watchdog successfully returns from `g_resukisu_load()` | Run the isolated action loader's first relocate/stage/load sequence on the existing coherent donor/donor watchdog. Publish exact substage results over release/acquire atomics, then let the JNI leader spawn and exactly collect `ksud` only after module installation. Preserve the same loader, pristine module, identity gates, nonce completion inode, diagnostics, and cleanup |
| S107 | Separate policy-neutral staging from policy-sensitive loading | Runs `20260823-170832` and `20260823-171130` reached the watchdog with every one of 11 exact loader gates set, but its isolated relocation entry returned `-1`. The same isolated entry succeeds on the process leader, and relocation/staging only transform the already-verified private module image; they do not require the temporary root or `ueventd` policy identity | Relocate and stage the isolated action image once in the existing pre-mutation staging call on the leader. Require both results to be zero before arming any write. After security writes, dispatch only `lp3_resukisu_load()` to the coherent donor/donor watchdog, retaining exact gate and substage publication |
| S108 | Exercise pre-staged isolated action image | Run `20260823-171445` reached the staging response and stopped before mutation because the controller's exact response string had not yet been extended for the new `action_relocation=0 action_stage=0` proof fields. This was a fail-closed protocol mismatch, not a relocation or stage failure | Extend the controller's exact expected response with both zero-valued action substage fields. Keep the one-line, exact-equality check so neither action result can be omitted or accepted loosely |
| S109 | Locate the post-stage action admission failure | Run `20260823-171744` accepted both pre-stage results and reached all four security writes, but returned in six milliseconds with the untouched relocation sentinel `-1` (`receipt_detail=999`). No watchdog loader request ran, so this is an action-thread admission predicate failure rather than a loader or spawn result | Encode the action selector, isolated loader validity, exact action descriptor, exact staged-module descriptor, and exact root identity as a five-bit gate in the existing relocation diagnostic. Preserve all five predicates and identify the missing one on a fresh boot |
| S110 | Resolve action gate `7/31` without weakening it | Run `20260823-172042` encoded action gate `7`: action selector, isolated loader and exact action executable passed, while exact staged-module metadata and exact root identity failed. This is before watchdog dispatch and does not describe module loading | Persist the observed action-module size plus the caller's PID/TID, root IDs and effective capabilities in the failure frame. Keep the exact expected module size and process-leader/root requirements unchanged until the observations identify their cause |
| S111 | Use the observed coherent action worker as the supported spawn origin | Run `20260823-172354` was an unrelated safe `epitem-analysis` miss before mutation. Run `20260823-172524` then measured the staged action module as exactly 563,952 bytes and the action caller as a non-leader shell worker with zero capabilities. Loader source proves staging truncates to its embedded rescue-module length; the later S030 refresh independently replaces that image with the current 595,800-byte, hash-verified APK module before rescue. The action worker is coherent, unlike the split helper leader | Pin 563,952 bytes as the post-action-stage size while retaining 595,800 bytes at source-copy and rescue-refresh gates. Dispatch module installation to the proven donor/donor watchdog. After it succeeds, call the same loader hand-off on the exact shell worker: because KernelSU is then present it skips `finit_module`, adopts the validated manager UID, requires KernelSU-granted root and the loader's `u:r:ksu:s0` context proof, then uses that coherent worker for supported `posix_spawn` and exact child collection |
| S112 | Replace user-space child PID publication with a kernel pidfd | Run `20260823-172857` passed action gate `31` but the watchdog's in-process loader again returned code `42`: even its donor/donor credentials cannot make `/proc/self/fd` ignore the split process leader. This rejects all in-process reopen variants. The supervisor child remains the only path already proven to load and complete the action | Fork the existing exact C++ supervisor from the donor/donor watchdog using `clone3(CLONE_PIDFD)`. Point `clone_args.pidfd` at a dedicated aligned word so the kernel publishes the exact pidfd before the anomalous parent return. Let the JNI sibling collect only that child with `waitid(P_PIDFD)`, plus the unchanged diagnostic stream, nonce completion inode, zero exit status, unlink proof, watchdog resumption and terminal join. Do not rely on a child-written PID receipt |
| S113 | Prove pidfd collection and expose the remaining child result | Run `20260823-173418` passed action gate `31`, received the kernel pidfd, published spawn stage `3` with zero spawn error, and collected the child in about 40 ms. It failed with `ENOMSG`, meaning the nonce completion content was not accepted; the current error precedence hid the child exit code and the collector discarded diagnostics | Forward the already-bounded supervisor/ksud diagnostic stream to the nonce-bound watchdog trace. Persist pidfd wait result, `siginfo` code/status, completion observation, unlink result and clean-exit decision before altering completion semantics |
| S114 | Identify the pre-supervisor child failure | Run `20260823-173714` reaped exact pidfd child 13,912 with `CLD_EXITED`, status `126`, no diagnostics and no completion. Status `126` is the raw child branch's generic `execveat` failure, so the C++ supervisor never started | Exit with the immediate `execveat` errno when it fits in the status byte. Preserve the same descriptor-only exec, pidfd collection and all action gates; use the next status to distinguish descriptor, policy and invocation failures |
| S115 | Route the exact supervisor through Android's trusted linker | Run `20260823-174003` stopped before the root window and did not exercise S114. Run `20260823-174154` exercised it and returned exact child status `13` (`EACCES`): SELinux denied direct `execveat` of the shell-owned supervisor inode under the temporary `ueventd` child identity | Clear `FD_CLOEXEC` only on the already-open, shell-owned and identity-verified supervisor descriptor in the child, then execute `/system/bin/linker64 /proc/self/fd/<supervisor> action-supervisor ...`. The supervisor must still revalidate coherent root identity and every loader/module/action descriptor before use; retain pidfd, completion and cleanup proofs |
| S116 | Remove the forbidden pre-load exec boundary | Run `20260823-174509` again returned exact child status `13`: the temporary `ueventd` child identity is also denied direct execution of `/system/bin/linker64`, so routing the supervisor through it cannot precede module installation | The pidfd child is already a coherent root process and inherits the isolated loader mapping that was relocated and staged before mutation. Call only that mapping's `lp3_resukisu_load()` in the child. Require its existing manager UID, KernelSU grant and `u:r:ksu:s0` identity checks to pass; only then execute the exact ksud descriptor through `/system/bin/linker64`. Preserve pidfd collection and every completion/cleanup proof |
| S117 | Use the existing labelled module inode in the coherent child | Run `20260823-174837` reaped the pidfd child with exact status `42`, proving its in-process loader reached the same `/proc/self/fd/<module>` denial. The child credentials are coherent; the remaining difference is inode provenance. The private action memfd never receives write 6's exact vendor inode-security pointer, while the original primary staged inode does. Adding a fifth write solely for the duplicate would violate the accepted four-write design | Duplicate the original module descriptor supplied to the action, not the private action memfd. In the pidfd child call the inherited primary loader mapping, which was already relocated/staged against that exact inode. This preserves the existing write-6 inode label and adds no CVE operation. Keep the private action artefact temporarily until this path is proven, then remove its redundant copy/stage work |
| S118 | Bound the verified post-completion worker lifetime with its pidfd | Run `20260823-175135` failed only at independent Shizuku preflight. Run `20260823-175252` then proved the complete privileged action: `LP3_RESUKISU_IDENTITY_PASS uid=0 gid=0 context=u:r:ksu:s0`, exact nonce completion, exact pidfd reap with `CLD_EXITED/status 0`, and successful unlink. The controller timed out at 100 seconds because the worker lingered after writing completion | Match the previously accepted lifecycle using the stronger pidfd handle: on exact completion content, send `SIGKILL` only through that pidfd, reap only that pidfd, and accept the terminal state only if it is either clean status 0 or the completion-triggered `CLD_KILLED/SIGKILL`. Continue to require completion, unlink, watchdog resumption, rescue, normalisation and joins |
| S119 | Move the redundant Manager restart out of the privileged worker | Run `20260823-175752` again proved loader identity, nonce completion, exact clean pidfd exit and unlink, but completion arrived only at the controller's 100-second boundary. Primary-source inspection at pinned ReSukiSU commit `7466863` shows the last synchronous operation is `am force-stop com.resukisu.resukisu`; Prism already opens that Manager only after strict cleanup | Rebuild pinned ksud with the exact embedded module hash. Write and fsync the nonce completion immediately after all late-load, post-mount, service and boot-completed setup; remove the privileged `am force-stop`. Before Prism's existing final Manager launch, perform the force-stop from the shell controller. Pin the new ksud size/hash in both staging authorities and preserve the source delta as `lp3-fast-action.patch` |

## Latest timing decomposition

The successful `20260823-032328` candidate uses boot-time timestamps, together
with `chain.progress`:

- Controller dispatch before the root flow: 2.34 seconds.
- First epitem disclosure: 6.68 seconds.
- Second-owner and node disclosure: 11.01 seconds.
- Arbitrary-read establishment and target profiling: 7.94 seconds.
- Root-write arm preparation: 0.90 seconds.
- Six accepted writes plus five safely recovered misses: 25.70 seconds.
- Root action and strict terminal cleanup: 2.91 seconds.
- Strict controller postflight and return to Prism: 2.07 seconds.

The Root-to-Prism foreground time is now 62.2 seconds. A zero-miss estimate is
about 54 seconds. Reaching 10 seconds therefore still requires native fragment
transport and a structural reduction from six serial writes; micro-optimising
the remaining polling loops is insufficient.

## Current next step

Prototype multiple independent Binder driver file contexts inside the existing
package-backed topology adapter. Determine whether each context can receive a
reference to the same controlled node through an exact ActivityManager Binder
transaction. Exercise that replacement only in the non-mutating disclosure
stage, then require five fresh-boot passes before it can enter the root flow.
Preserve the accepted 4,096-handle fragment export, transaction/gap geometry,
eight-hit analyser threshold, and exact cleanup gates.

## 2026-08-23 — Batched write-carrier acquisition

- Candidate run `20260823-222318` measured the Root action correctly and
  entered the new one-pool, four-carrier path. The controller began at device
  uptime 46.571 seconds, native root flow began at 48.439 seconds, and the
  batch reclaim returned at 63.392 seconds.
- The 32-worker-per-victim design was rejected. Victim 3 mapped exactly to
  indexed worker 55, while victims 1, 2 and 4 retained their original pointer
  and cookie values. No semantic write was freed or executed.
- The failure set `root-window-reboot-required`; the controller performed the
  expected controlled reboot. This confirms that incomplete batch mapping is
  fail-closed, but it is not a reliable carrier acquisition strategy.
- The next bounded candidate assigns the proven 1,024 fresh control buffers to
  each victim. It uses one 4,097-slot pool because the arbitrary-read carrier
  already occupies one slot. All four indexed replacements must still map
  uniquely and match their complete 128-byte payloads before any write can be
  armed.
- Run `20260823-222818` passed that full-width design on its first fresh boot.
  Workers 23, 1048, 2073 and 3099 matched the four complete indexed payloads;
  all writes, action, repair, retirement and terminal cleanup passed. Measured
  Root-to-visible-Active time was 46.754 seconds.
- Full-pool construction and activation took 3.436 seconds, but retiring 4,092
  rejected workers took 12.138 seconds. The workers were all pinned to CPU 2
  for the critical allocation and remained pinned while returning from
  `sendmsg()`.
- Next candidate: retain CPU 2 through mapping, then widen only non-selected
  workers to the device CPU set immediately before their peer sockets are
  closed. Continue to join every worker before arming any semantic write.
- The first attempted timing run before this candidate did not start the
  controller because a stale vendor UI Automation registration raced the
  injected Root tap. The runner now avoids UI hierarchy collection until the
  current-boot controller has passed and Prism has returned. A fresh reboot
  confirmed that the same Root coordinate then dispatches normally.
## 2026-08-23 — Action response stall isolated

- Evidence: run `20260823-180817` wrote the exact ksud completion at 18:09:49 and native collection proved a clean pidfd exit, but the controller timed out waiting for its frame.
- The helper log ends after the native action result and before `COMMAND_RESCUE_MODULE_REFRESHED`. The block is therefore the post-action rewrite of the rescue memfd, not ksud late-load.
- Correction: load from the already staged disposable action-module memfd. Keep the rescue memfd content immutable and verify its SHA-256 after activation instead of rewriting it.
- Also return the established concise native success record; retain extended state only on failure so the Java proof remains exact.
- First isolation attempt failed immediately with `action_gate=31`. Staging intentionally resizes the private source image from 595,800 bytes to the 563,952-byte rescue envelope. Correct the post-stage size proof and dispatch through the correspondingly staged action-loader mapping; the primary mapping owns the rescue inode and must not be paired with the disposable image.
- The corrected private pair then failed safely with loader code 42: its shell-created inode cannot be reopened from the temporary policy identity. Retain the already proven primary loader/rescue pairing. Its loader restores the staged bytes synchronously; remove the redundant Java rewrite and retain a full digest readback as the independent restoration proof.
- A read-only Java digest blocks for the same reason: the rescue inode deliberately retains its temporary vendor security label until write 6 is repaired. Do not access it from the shell thread in that window. Loader success already requires synchronous `MS_SYNC` restoration plus byte comparison; terminal normalisation then proves the restored image functionally by loading and unloading that exact rescue module before accepting cleanup.
- Run `20260823-182445` completed the full ReSukiSU action in 3.37 seconds and returned its exact proof, then cleanup `finit_module` failed with errno 3 from the transient fork child. The rescue module explicitly supports the coherent non-leader watchdog identity. Load directly on that already proved thread, eliminating the post-KernelSU fork identity change and its pipe/wait overhead.
- Direct watchdog loading was denied before module initialisation (`EACCES`), confirming the fork/reopen shape remains required. The apparent `ESRCH` came from the loader-embedded 563,952-byte historical rescue build. Preserve an immutable 595,800-byte copy before staging; after action, have the authorised watchdog rewrite and byte-compare the labelled inode, then use the proven fork/reopen load path.
- Run `20260823-183859` proved the non-leader watchdog is also denied write access to the temporarily labelled inode (`module-restore`, `EACCES`). Perform restoration and full byte comparison inside the same single-threaded fork child whose procfs reopen is already policy-authorised, then immediately load from that exact descriptor.
- KernelSU denies the subsequent cleanup module even from that child. Combined ordering candidate: install and validate the rescue plan before action; in the authorised child, restore and load the current rescue module first, retain only the inode's borrowed label, rewrite the same labelled inode with the saved relocated KernelSU image, load KernelSU, then invoke the rescue module's one-shot inode-label restoration parameter. Normalisation accepts only the rescue module's exact repair manifest and restored-inode receipt before finalise/unload.
- Rebuilt rescue module: 118,096 bytes, SHA-256 `e26ece2d79c65cf934946f086f4f7755240a38a3c650b207e90bc470fc763930`, exact device vermagic `5.10.198-android12-9-g1a2636627c17 SMP preempt mod_unload modversions aarch64`.
- Run `20260823-185150` reached the combined child but exited at backup restoration (code 60): inherited file-description writes remain denied. Reopen the already-labelled inode once as `O_RDWR` through the proven process-leader procfs path, then bind both byte-verified rewrites and both `finit_module` calls to that exact file description.
- Run `20260823-185437` proved that reopening the labelled procfs inode as
  `O_RDWR` is also denied. Do not retry userspace writes through either the
  inherited description or a reopened description.
- The rebuilt loader now exports a bounded replacement operation over its
  existing writable shared mapping. It zero-fills, copies, `msync`s and fully
  compares the staged bytes, so no new filesystem write permission is
  assumed.
- Run `20260823-190026` replaced all 563,952 mapping bytes, then rescue
  `finit_module` returned `EBADE` before KernelSU hand-off. This is the rescue
  module's exact current-task `real_cred` rejection: the process-leader action
  child has the already known private-objective/donor-subjective split. The
  harness performed its normal controlled fresh-run reboot; there was no
  kernel-crash boot reason.
- Admit only the two exact loader objective pointers, `donor_cred` or the
  independently validated `private_cred`, while continuing to require the
  exact donor subjective pointer, donor security object, parent topology and
  helper split. Expose the one-shot inode restoration parameter as `0600` so
  terminal normalisation can read its exact receipt. Candidate module:
  118,120 bytes, SHA-256
  `2be7d19b3ed39536b77721f24f10221e965570c81801f5524042e2e32e4a1456`.
- The four retained mutations deliberately keep semantic IDs `1`, `2`, `5`
  and `6`; former semantic writes `3` and `4` were removed with the helper
  `real_cred` path. Diagnostic output must identify both ordinal sequence
  `1`–`4` and semantic ID so the gap is not mistaken for missing execution.
- Run `20260823-190628` still returned `EBADE`. Distinct errno instrumentation
  then made run `20260823-190944` return `EL2NSYNC`, proving the rejected field
  was the action child's objective credential pointer rather than either
  helper credential check.
- Run `20260823-191415` reached the bounded content validator and returned
  `EUCLEAN`: the separate worker's objective credential is not shell-valued.
  Admit a non-reference pointer only if every stable credential field matches
  either the validated private reference or donor reference: all UID/GID
  variants, securebits, five capability sets, user and user namespace,
  supplementary groups, and the first 16 bytes of SELinux credential state.
  Continue to require the exact donor subjective pointer and existing exact
  parent/helper topology. Candidate module: 119,536 bytes, SHA-256
  `73f1b2b661ff770e3109b10f8424be166beef6d16ec49d3211cb05b1276f08c5`.
- Runs `20260823-192124`, `20260823-192444` and `20260823-192830` returned
  status 77. Correct interpretation is Linux `EBADFD`, not an encoded
  securebits value: the objective full-equivalence check passed, then the
  child's subjective pointer differed from the donor pointer. Remove the
  unproved securebits exception. Require the separate subjective credential
  to pass the same full stable-field equivalence against the exact donor;
  retain exact pointer requirements for the parent and helper. Candidate:
  119,648 bytes, SHA-256
  `f0be198e4a4d2da59691156593b463ec138ab96ea6558fb66f2a1551386343c3`.

## 2026-08-23 — First strict end-to-end pass with the combined loader order

- Run `20260823-194506` completed the privileged action, returned the exact
  nonce-bound Manager launch receipt, passed native terminal cleanup, passed
  controller postflight and returned to Prism with `unsafe=0`.
- The controller published `chain-pass` at 77.562 seconds after boot and
  `postflight-pass` at 78.939 seconds. Root-flow start to terminal cleanup was
  approximately 30.3 seconds; Root tap to controller completion was
  approximately 32.8 seconds.
- The accepted combined order is: restore and load the current rescue module
  through the existing loader mapping; defer only the borrowed inode-label
  restoration; replace the mapping with staged KernelSU; load KernelSU;
  request the rescue module's one-shot inode restoration; execute `ksud`;
  then require the rescue module's exact repair manifest before finalise and
  unload.
- The four kernel mutations have semantic IDs `1`, `2`, `5` and `6`. The UI
  now reports ordinal progress `1/4` through `4/4`, followed by the semantic
  ID in brackets. There are no missing write operations.
- Phase timing from `chain.progress`: disclosures and acquisition consumed
  approximately 6.4 seconds; security-target preparation approximately 5.6
  seconds; the four serial writes approximately 10.8 seconds; action
  approximately 2.7 seconds; strict cleanup approximately 1.6 seconds.
  Reaching 10 seconds requires overlapping or removing major phases rather
  than reducing polling delays.
- The device harness sampled the foreground too slowly to observe the Manager
  window, which lasted less than 500 ms. The controller's exact same-boot
  `return-to-prism-manager-pass` receipt is durable. The host harness now uses
  that receipt only when the final Prism UI is active and the sampled Manager
  foreground was missed; this changes observation only, not chain behaviour
  or measured timing.

## Current next step

Build and install the current candidate once, then require one formal
fresh-boot baseline pass. Use the package only as a Binder topology adapter
while iterating the pushed ARM64 C++ executable. Profile and prototype
independent, freshly created write cohorts so their preparation can overlap;
do not reuse a consumed cohort or weaken any exact cleanup receipt.

## 2026-08-23 — Qualification and timing-contract correction

- Disclosure series `20260823-195814` passed five consecutive fresh boots.
  On-device checkpoint durations were 4.181, 4.479, 4.293, 4.433 and 4.548
  seconds.
- Full series `20260823-200342` passed its first three runs, then run 4 failed
  closed before mutation. The epitem reclaim returned all 1,152 records, but
  analysis found zero valid file or epitem candidates. The controller proved
  the no-mutation reset and returned Retry. Do not checkpoint this candidate
  as five-run qualified.
- The optimisation clock is defined as Root-button press through the first
  verified return to Prism with Root Status Active. Fresh boot, thermal
  settling, Shizuku preparation and the subsequent three-sample stability
  confirmation are harness overhead and are excluded.
- ReSukiSU can remain foreground for less than the host's 500 ms sample
  period. When the foreground poll misses it, the host must print an explicit
  `controller-receipt` transition event and must not imply that it sampled the
  Manager package. The same-boot controller receipt remains mandatory.

## 2026-08-23 — Two-victim CVE unwind qualified for the first disclosure

- Candidate `20260823-201256` proved one failed Binder transaction can unwind
  two independently identified epitem victims. It produced exactly 1,152
  decrements in 576 transactions and preserved every existing reclaim and
  analysis gate.
- Qualification series `20260823-201413` passed five consecutive fresh boots
  at 4.228, 4.216, 4.415, 4.253 and 4.603 seconds through both disclosures.
- Halving first-phase ioctl count improved the median only modestly, from
  approximately 4.43 to 4.25 seconds. The main value is structural: bounded
  multi-node unwind is reliable enough to extend to the second disclosure.
- Do not infer that four write carriers are qualified. This experiment batches
  only disclosure-node decrements; all arbitrary-read and write paths remain
  unchanged.

- The same pair unwind was then enabled for the second disclosure.
  Qualification series `20260823-202110` passed five consecutive fresh boots
  at 4.340, 4.387, 4.317, 4.307 and 4.335 seconds. Each run proved 1,152
  decrements in 576 transactions independently for both disclosure phases.
- Advance the disclosure-only experiment to four victims per unwind. Keep all
  reclaim counts, unique-token checks and analysis thresholds unchanged.

## 2026-08-23 — Four-victim disclosure unwind qualified

- Safety gate `20260823-202649` passed with both disclosure phases using four
  independently identified victims per malformed transaction.
- Qualification series `20260823-202756` passed five consecutive fresh boots
  at 4.408, 4.409, 4.481, 4.366 and 4.353 seconds. Each disclosure proved
  1,152 decrements in 288 transactions, with all unique-token, epitem, file,
  Binder-node and retirement gates unchanged.
- The stable result proves that four-node CVE unwind is feasible. It does not
  yet prove simultaneous replacement by four distinct fake-node carriers.
  The next high-ceiling experiment must separate batch free from multi-carrier
  reclaim and require an all-or-nothing one-to-one carrier receipt.

## 2026-08-23 — In-memory module loading proved

- Full fresh-boot run `20260823-204144` loaded both the rescue module and the
  relocated KernelSU module with `init_module` from their already verified
  memory images. It passed strict Binder repair, module finalise and unload,
  donor resumption, credential retirement, same-boot checks and final Prism
  Active state.
- The measured Root-to-Active duration was 41.1 seconds. The first semantic
  write missed before free and retried safely, so this run is a transport
  proof rather than a speed comparison.
- The rescue module no longer needs the module memfd's borrowed inode label.
  Remove semantic write 6 only after adding an explicit inode-free rescue
  mode that validates zero inode-carrier parameters and preserves every other
  repair and retirement proof.
- After the inode-free mode is qualified, defer the semantic write 1
  collateral at `donor_cred + 8` to the rescue module. `init_module` has now
  proved the necessary load path without relying on a repaired effective UID;
  capability and SELinux gates remain mandatory.

## 2026-08-23 — First three-write attempt failed closed at the skip gate

- Fresh-boot run `20260823-205719` completed semantic writes 1, 2 and 5 with
  no carrier misses. It did not attempt semantic write 6.
- The inode-write skip gate then failed because the borrowed inode security
  object's expected collateral word is zero, but both the skip gate and rescue
  plan used the non-zero 64-bit read helper. The recorded value remained the
  initial `UINT64_MAX`, while the profile had already proved the expected word
  was zero.
- The chain returned `root-write-incomplete`. The controller's 90-second
  failure timeout then performed a shell reboot. This was a controlled reset,
  not a spontaneous kernel crash, and it is not a performance result.
- Use the existing zero-capable arbitrary read with the credential slot as its
  control word at both validation sites. Do not weaken the expected-zero
  equality or any rescue receipt.

## 2026-08-23 — Three-write module loading rejected; exact four-write module restored

- The corrected three-write candidate proved semantic writes 1, 2 and 5, but
  buffered `init_module` consistently returned `EACCES`. Inspection of the
  live SELinux CIL showed module-load permission only for the inode-backed
  vendor-labelled route used by `ueventd`; it does not authorise a fileless
  self-load. Semantic write 6 therefore remains a structural requirement on
  this device policy.
- Restoring semantic write 6 and the exact inode/collateral readbacks produced
  valid five-carrier rescue plans in runs `20260823-212549` and
  `20260823-212940`. Both stopped safely when the modified rescue module was
  rejected before initialisation with `EACCES`. No module-side path in that
  build explicitly returned `EACCES`.
- The only rescue-module changes after the last proven build were the abandoned
  memory-load mode and variable three-to-five repair cardinality. Removing
  those additions and returning to a fixed five-repair manifest rebuilt to
  exactly 119,648 bytes and SHA-256
  `f0be198e4a4d2da59691156593b463ec138ab96ea6558fb66f2a1551386343c3`.
  This is byte-for-byte identical to the module used by successful runs
  `20260823-203455` and `20260823-204144`; all size and hash authorities now
  refer to that exact artefact.
- The acceptance clock remains Root-button press through Prism regaining the
  foreground and visibly showing Active. Boot, installation, Shizuku
  preparation, thermal settling and post-return stability sampling are
  recorded separately and excluded.

## Current next step

Run one fresh-boot safety gate with the exact restored module. Require all four
semantic writes (1, 2, 5 and 6), rescue initialisation, KernelSU activation,
strict finalisation/unload, donor resumption, Manager receipt, return to Prism
and visible Active state before resuming speed work.

- Run `20260823-213744` again returned pre-init `EACCES` with the exact
  `f0be…` module, ruling out rescue-image drift. Primary-source review showed
  that SELinux stores the opener SID in each file security object: an inherited
  or duplicated shell-opened descriptor retains shell provenance even after
  the child borrows the `ueventd` label. Earlier S029 evidence already proved
  that reopening `/proc/self/fd/<module>` in this exact process-leader child
  advances beyond `EACCES`.
- Reintroduce that reopen immediately after the bounded mapping replacement.
  Require the reopened descriptor to match the original device, inode, mode
  and exact 563,952-byte staged size, then call rescue `finit_module` on the
  reopened description. Keep the original description for the subsequent
  verified KernelSU replacement/load.
- Run `20260823-214045` did not exercise the reopen candidate. The first
  fake-node check missed before mutation, the controller recorded the exact
  no-mutation chain failure and the teardown watchdog performed the expected
  controlled reboot. Its collected native-watchdog trace had the previous
  boot's nonce and is stale evidence. Repeat the unchanged build.
- Run `20260823-214241` exercised the candidate. The reopen and all strict
  descriptor identity checks passed, then `finit_module` still returned
  `EACCES`; the nonce-matched child exit was 13. Add a one-byte ELF-magic
  `pread` through that exact reopened description before loading. Encode
  read denial, other read error and content mismatch as distinct child exits
  so the next run separates SELinux file-read revalidation from the later
  `system:module_load` permission without relying on unavailable kernel logs.
- Run `20260823-214548` did not exercise the discriminator: it was another
  first fake-node miss before mutation. The collected child trace had the
  preceding run's nonce. Repeat the unchanged build.
- Run `20260823-214740` exercised the pre-read discriminator. Reopen, strict
  descriptor identity, `pread` and ELF-magic validation all passed; the child
  still exited with raw `EACCES` from `finit_module`. This isolates the
  failure beyond normal file permission checks, but raw errno alone cannot
  disprove an indirect init return. For one diagnostic run, enable and clear
  only `module:module_load` immediately before the syscall, inspect its bounded
  trace afterwards and restore the event's previous enable state. Encode a
  correlated event as 70, no event as 71 and unavailable tracing as 72.
- Deployment audit after run `20260823-215055` found that `tools/prism-runs`
  never installs an APK; it intentionally runs the package already on the
  device. The rebuilt diagnostic APK had not been installed for the preceding
  runs, which explains why the child continued to emit the old raw exit 13.
  Install the current APK with `adb install -r -g` (data-preserving), verify
  `lastUpdateTime`, then repeat. Do not interpret the preceding diagnostic
  runs as evidence about the new pre-read or trace code.
- Correctly deployed run `20260823-215346` reached the action child but still
  exited 13. That number is ambiguous: the rescue module can return `ENOKEY`
  from its private-credential security check, and the ReSuki loader maps a
  KernelSU `init_module(ENOKEY)` to its own code 13. Map rescue `ENOKEY` to
  73/74/75 according to the trace boundary and KernelSU loader code 13 to 76.
  Rebuild, install and repeat before changing either mechanism.
- Run `20260823-215707` returned exit 76, proving the rescue module loaded
  successfully and the later ReSuki KernelSU memory load returned its code 13
  (`init_module` errno `ENOKEY`). Remove the temporary trace-event diagnostic.
  After replacing the shared mapping with the already relocated KernelSU
  image, reopen the same labelled inode again in the authorised process-leader
  child; require matching device, inode, mode, exact staged size and ELF magic;
  load it with `finit_module`. Then call the existing loader only for its
  KernelSU-recognition, Manager-UID and `ksu` identity hand-off. Keep the rescue
  module's deferred inode restoration immediately after that hand-off.
- Run `20260823-220030` did not exercise the dual inode-backed loader. It was a
  first fake-node miss before mutation and performed the controlled teardown;
  the collected watchdog trace retained run `20260823-215707`'s nonce. Repeat
  the unchanged installed build.

## 2026-08-23 — Dual inode-backed module loading restored full reliability

- Run `20260823-220232` passed the complete fresh-boot chain with both the
  rescue module and relocated KernelSU module loaded through separately
  reopened descriptions of the same validated, temporarily vendor-labelled
  inode. The existing loader then performed only the KernelSU/Manager hand-off.
- All four semantic writes (1, 2, 5 and 6), five carrier repairs, rescue
  finalisation/unload, inode/task label restoration, donor resumption, helper
  and Binder retirement, same-boot postflight, Manager receipt and final Prism
  Active state passed. No safety or cleanup gate was removed.
- Root-button press to Prism Active was 43.712 seconds. The controller-receipt
  transition occurred at 43.243 seconds; the host did not falsely claim a
  sampled Manager foreground.
- On-device phase spans from `chain.progress` were approximately: disclosure
  and node acquisition 5.22 seconds; arbitrary-read/security preparation 7.35
  seconds; four serial writes 14.31 seconds (including one safe first-write
  retry); privileged action 4.62 seconds; terminal cleanup 1.74 seconds; final
  controller/postflight/Manager return approximately 3.0 seconds. Reaching ten
  seconds requires collapsing serial CVE carrier acquisition and overlapping
  independent preparation; polling micro-optimisation cannot supply enough
  headroom.

## Current next step

Preserve this full-pass topology while prototyping an all-or-nothing batched
write cohort in the pushed C++ primitive. Free the four independently tagged
victims in one bounded CVE unwind, reclaim all four with one fresh indexed
control-buffer cohort, and continue only after proving a unique one-to-one
victim/carrier mapping and exact payload for every semantic write. Do not reuse
a consumed carrier or weaken terminal repair receipts.

## 2026-08-23 — End-to-end timing contract and foreground evidence

- The acceptance interval is now fixed as the host time immediately before
  injecting the Root-button tap through the first observation that Prism is
  foreground and its UI hierarchy visibly contains `Active`. Boot, Shizuku,
  thermal settling, post-result stability checks and evidence collection are
  outside the interval. Controller completion is diagnostic evidence and can
  never stop the clock.
- The previous 500 ms `dumpsys window` sampler could block in UI Automator and
  miss the whole Manager visit. Android lifecycle evidence from the last full
  pass proves ReSukiSU resumed at uptime `84.517` and Prism resumed at
  `85.351`, an interval of only 834 ms.
- `tools/prism_runs.py` now records `wm_set_resumed_activity` events from the
  Android event buffer relative to a device-uptime marker captured immediately
  before the tap. Focus samples remain separately labelled. The controller
  receipt is recorded as `manager-return-receipt` with
  `foreground_sampled=false`; it no longer fabricates a foreground transition
  or sets `saw_resukisu`.

## 2026-08-23 — Batched-cohort rejection and 512-worker serial result

- The all-at-once four-write pool is not reliable on this device. A 4×1,024
  pool passed once in run `20260823-222818`, but its terminal thread release
  took 12.138 seconds. The next run cross-mapped victims 1↔2 and 3↔4 after
  freeing all clients before reclaim, and the exact-payload gate correctly
  rejected it before any semantic write.
- Serialising each victim exit while retaining earlier pre-created groups did
  not restore fresh-cohort behaviour. Runs `20260823-223858` and
  `20260823-224133` missed later victims; CPU spreading, detached per-group
  teardown and a staged 32→remaining activation also failed to reproduce the
  allocator geometry of a newly constructed CPU-2 cohort. Keep the batch path
  disabled. Do not reuse this strategy without a new allocator model.
- A 128-worker fresh serial cohort is below the reliability floor. Run
  `20260823-225939` produced only three exact replacements across all 18 safe
  victims, exhausted before semantic write 6, and used the controlled reboot.
- A 512-worker fresh serial cohort passed run `20260823-230325` with all four
  semantic writes (1, 2, 5 and 6), no internal miss, strict rescue finalisation,
  complete cleanup, the ReSukiSU→Prism lifecycle transition and visible
  Active state. Root tap to visible Active was 39.2 seconds.
- This is one successful sample, not a reliability gate. Do not commit the
  512-worker candidate until at least five consecutive fresh-boot passes meet
  every existing safety and cleanup condition.
- The next measured targets are the bundled 1.55-second deferred-client/current
  Binder-proc interval and the 2.93-second donor/security/rescue-profile
  interval. Split their telemetry, then move or cache only work whose identity
  and lifetime invariants remain proven.

## 2026-08-23 — Fixed-slot validation, overlap and reusable C++ spray proof

- Replace two 12 KiB linear task scans with direct validation of the kernel
  version's already proven `real_cred` and `cred` slots. Both slots are still
  read back and matched to the expected credential. In run
  `20260823-231131`, donor adoption plus direct security and rescue profiling
  fell from approximately 2.96 seconds to 1.42 seconds and all terminal gates
  passed.
- Overlap deferred victim setup with read-only security profiling only after
  the arbitrary-read carrier is stable. Run `20260823-231618` passed with the
  victim barrier and security profile both complete before the first write.
  The overlapped interval was 2.38 seconds rather than approximately 3.42
  seconds serially. Four safe spray misses made Root-to-Active 38.9 seconds;
  do not use that end-to-end number as the no-miss estimate.
- The first overlap attempt, `20260823-231413`, missed the earlier fake-node
  precondition before reaching the overlap and used the controller's normal
  no-partial-mutation reboot. Repeating the unchanged candidate passed.
- A standalone, non-mutating ARM64 C++ reusable-spray benchmark passed five
  consecutive cycles on the device with 512 pre-created workers, exactly
  5,632 freshly allocated datagrams per cycle and all 512 senders blocked.
  One-time socket/thread setup took 80.2 ms. Fresh refill took 25.4–25.6 ms,
  activation including a 20 ms dwell took 41.1–42.9 ms, and complete
  release/drain back to ready took 76.3–86.2 ms.
- This does not reuse a consumed control buffer or CVE carrier. It proves that
  dormant threads and socket endpoints can remain resident while each attempt
  receives a fresh control-buffer cohort. Port this lifecycle behind the
  existing exact-payload, poison ownership and terminal-retirement gates.

## 2026-08-23 — Reusable spray rejected for the live action path

- The reusable pool completed the semantic-write/security hand-off in runs
  `20260823-232838`, `20260823-233212` and `20260823-233514`, but all three
  then failed with the identical ReSukiSU action wrapper signature: action
  child status 22, wrapper errno 42 and no action phase record. Each run used
  the controller/watchdog recovery reboot.
- Retiring all 512 idle reusable workers immediately after validated write 6
  did not change the failure. The incompatibility therefore is not merely
  keeping idle threads or sockets resident during module loading.
- Disable the reusable topology in the live chain. Do not retry it solely on
  the strength of the non-mutating socket benchmark; successful socket reuse
  does not prove identical post-write kernel state for this CVE.
- Restored one-shot run `20260823-233751` passed all four writes, action,
  rescue finalisation, strict cleanup and Root-to-visible-Active in 36.9
  seconds with one safe write miss. This confirms that the three action
  failures correlate with reusable CVE cohorts rather than the 20 ms
  blocked-state dwell or sequential one-shot retirement.

## 2026-08-23 — Five-run checkpoint rejected; widened acquisition candidate

- The restored 512-worker candidate passed the first three fresh boots in
  `20260823-234238` at 34.0, 40.1 and 35.0 seconds, then failed the fourth
  boot before arbitrary-read hand-off. Do not commit or label that state as a
  five-run working checkpoint.
- The fourth run was safely contained. Victim 0 reported
  `worker_index=-1`, `exact_payload=0` and `buffer_freed=0`; no semantic
  write occurred. The nonce- and boot-bound process-teardown watchdog then
  performed the expected controlled reboot.
- The missed control allocation was at raw index 6,288. A 512-worker cohort
  supplies 5,632 freshly allocated datagrams, so the miss was outside its
  measured coverage rather than an ambiguous payload collision.
- Widen only the initial arbitrary-read acquisition to 1,024 fresh workers.
  Keep all four semantic-write cohorts at 512 workers. Preserve dynamic
  exact-count checks in the split-decrement and hand-off gates.
- Data-preserving deployment run `20260823-235127` passed every mutation,
  action and cleanup gate in 33.4 seconds, including the exact
  ReSukiSU-to-Prism lifecycle transition and visible Active result. This is
  one candidate pass, not a reliability gate.
- Fresh-boot series `20260823-235606` then passed five consecutive runs at
  34.6, 33.8, 39.6, 31.1 and 39.0 seconds. Every run retained the four
  semantic writes 1, 2, 5 and 6, exact readbacks, rescue finalisation and
  unload, donor resumption, Binder/process retirement, the ordered
  ReSukiSU-to-Prism lifecycle transition and visible Active result.
- Accept the widened victim-0 acquisition as the new recoverable reliability
  checkpoint. The five-run minimum is satisfied, but none of these runs meets
  the 10-second performance target.
- The acceptance clock remains the instant before the Root tap through Prism
  being foreground with visible Active. Controller completion and native
  phase timings remain diagnostic only.
