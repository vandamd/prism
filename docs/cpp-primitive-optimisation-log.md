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
| S071 | Retire all raw-holder resources on CPU 0, then restore CPU 2 before reclaim | Fresh probe `20260823-232129-677052` passed the exact 128-context retirement gate in 232 ms, acquired and validated the arbitrary-read carrier, and reached helper profiling in 8.51 seconds from root-flow start. It then failed closed before credential mutation because the shell leader still shared a usage-479 credential instead of the required private usage-2 credential; the planned `reboot,shell` completed | Accept CPU-separated retirement. The faster path exposed a latent helper-ordering assumption. For primitive-probe mode only, isolate the leader with the same raw same-ID `setresuid` operation already proven by the clean-command path before publishing its Binder target |
| S072 | Isolate the primitive-probe shell leader with same-ID `setresuid` before target registration | Fresh probe `20260823-232616-046612` again passed raw retirement and arbitrary-read acquisition, but the helper credential remained at usage 479. The raw syscall returned success, so same-ID `setresuid` alone was a no-op for credential ownership | Reject the incomplete sequence. Publish the Binder target first, then use the production sequence: verify ambient `CAP_CHOWN` is clear, lower it, perform same-ID `setresuid`, and revalidate securebits, ambient state and shell IDs |
| S073 | Apply the proven ambient-lower plus same-ID `setresuid` sequence after target publication | Fresh probe `20260823-232943-855088` passed on its first attempt. The helper leader had exact usage 2, both disclosures and the 128-context retirement proof passed, arbitrary-read acquisition completed, and root profiling reached `primitive-reboot-required` 9.613 seconds after `root-flow-start`; the planned reboot completed | Accept for primitive-probe mode. Carry the raw-holder topology into one full Root-to-visible-Active run without changing the four semantic writes, action, rescue or strict cleanup gates |
| S074 | Exercise the accepted raw-holder topology in the full Root-to-visible-Active path | Run `20260824-003004` failed safely during the first disclosure, before raw holders or mutation: the unchanged epitem analyser rejected the sample. Root-to-controller failure took 14.1 seconds. Failure collection then decoded binary logcat as strict UTF-8 and raised a second host exception | Do not attribute the pre-topology miss to raw holders. Make text evidence decoding loss-tolerant while preserving binary app artefacts byte-for-byte, then repeat from a fresh boot |
| S075 | Repeat the unchanged full raw-holder candidate after fixing evidence decoding | Run `20260824-003211` reached the raw path, then the controller observed a bounded unlink/fake-node miss 6.73 seconds after harness dispatch and the watchdog confirmed `reboot,shell`. The reboot pre-empted the app-private tar archive, so the exact payload receipt was unavailable; controller hashes and the failure signature survived. No root window, action or success was claimed | Count this as a reliability failure, not a timing pass. Repeat the unchanged candidate from a fresh boot to obtain either a complete raw-holder pass or an intact exact miss receipt before changing allocator geometry |
| S076 | Third full raw-holder sample | Run `20260824-003421` passed every gate in 32.332 seconds from Root tap to Prism foreground with visible Active. ReSukiSU resumed at 28.463 seconds and Prism at 29.310 seconds. All writes 1, 2, 5 and 6, one safely recovered write miss, rescue finalisation/unload, donor resumption, exact 128-context retirement and strict cleanup passed. Native root flow was 21.675 seconds | Accept this as the first full behavioural proof, not a reliability gate. Preserve the topology and remove structural serial work: 5.285 seconds disclosure, 5.058 seconds arbitrary-read/profile/arming, 8.892 seconds writes/action, and 1.493 seconds cleanup |
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
- The miss reported `raw_index=6288`. This field is the masked low portion of
  the unreclaimed original userspace pointer when no indexed payload matches;
  it is not an allocation ordinal and must not be compared with the 5,632
  prefilled datagrams. The earlier coverage interpretation was incorrect.
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
  checkpoint on the evidence of the five-run gate only. Do not claim that its
  width causally eliminates victim-0 misses. None of these runs meets the
  10-second performance target.
- A subsequent Perfetto run, `20260824-000609`, perturbed the allocator and
  missed victim 0 with the same original pointer signature despite all 1,024
  workers reaching the exact blocked state. The buffer remained unfreed, no
  semantic write occurred and the bound process-teardown watchdog rebooted.
  Reject full tracing for performance runs and continue to treat initial
  acquisition reliability as unresolved.
- The acceptance clock remains the instant before the Root tap through Prism
  being foreground with visible Active. Controller completion and native
  phase timings remain diagnostic only.

## 2026-08-24 — Aggregate read coherence

- Run `20260824-004218` passed strict cleanup in 33.207 seconds. Bracketing a
  complete donor snapshot with exact credential-pointer checks reduced the
  successful write-2 completion from 1.846 seconds to 0.446 seconds while
  retaining two identical, complete snapshots.
- Run `20260824-004519` passed strict cleanup in 33.049 seconds. Applying the
  same rule to the pre-write identity gate reduced each gate from roughly
  0.36–0.40 seconds to 0.025–0.031 seconds. Three safe allocator misses hid
  the saving in the end-to-end result.
- Run `20260824-004957` passed strict cleanup in 30.126 seconds with one safe
  write miss. The helper's two 19-word snapshots now use beginning, middle
  and end pointer checks, remain byte-for-byte equal, and retain every shell
  identity, capability, namespace and SELinux field. The native root flow was
  19.384 seconds; direct security profiling fell to 5 ms.
- Keep the aggregate checks. They remove repeated transport reads, not state
  invariants. The remaining no-miss native floor is still about 18 seconds:
  approximately 6.7 seconds for both disclosures, 2.4 seconds for target and
  rescue profiling, 5.5 seconds for four reclaim/write cycles and root-window
  gates, 1.4 seconds for the action, and 1.7 seconds for terminal cleanup.
- The upstream fix confirms that CVE-2024-46740 corrupts the transaction
  offsets array and can unwind arbitrary Binder-node decrements. It does not
  provide a second primitive that avoids the existing kmalloc-128 reclaim.
  Continue to optimise the reclaim lifecycle and orchestration rather than
  changing CVE identity.
- Run `20260824-005649` passed every gate with no allocator miss in 28.684
  seconds. The native root flow was 18.076 seconds. Non-zero target readbacks
  and the first-write preparation now avoid zero-specific transport checks
  while retaining exact equality; keep this change.
- Run `20260824-005948` overlapped raw-holder bootstrap with first-owner
  cleanup and failed at the first arbitrary-read reclaim before an accepted
  write. The controller performed its required `reboot,shell`. Reject that
  overlap because it changes the allocator history feeding victim 0. Retain
  the sequential holder bootstrap.
- Run `20260824-010239` isolated the deferred-client preparation move and
  passed strict cleanup in 30.950 seconds with two safe write misses. The
  preparation still completed at the same target-profile boundary because
  it was already hidden behind profiling. Reject the move as no-gain
  scheduler noise and restore its previous position after private-credential
  isolation.

## 2026-08-24 — Ordered lookup and native victim contexts

- Replace exhaustive Binder reference-tree scans with the kernel's ordered
  descriptor lookup and retain the exhaustive walk only as a fail-closed
  fallback. Run `20260824-010608` reduced helper, security, direct and rescue
  target lookup to 2–8 ms with 10 visited reference nodes. The run passed in
  30.2 seconds despite two safe write misses and a slow action.
- Parallelising transactions to the 18 Android victim services did not remove
  their dominant 1.6-second process-bind cost. Run `20260824-011124` passed in
  31.0 seconds with two safe write misses; starting preparation after the
  arbitrary-read hand-off hid about 0.67 seconds but left about 0.93 seconds
  on the critical path.
- Reuse the proven independent raw `/dev/binder` route for the 18 extra
  victims. Each context receives and explicitly retains one target handle,
  performs its export on a native thread, queues the controlled transaction,
  then uses exact `munmap` and descriptor-close receipts as its retirement
  event. Terminal cleanup explicitly releases both handles for every unused
  context before closing it.
- Run `20260824-012349` is not native-context evidence: the runner does not
  install the rebuilt APK, so it exercised the prior installed Android-client
  implementation and passed in 28.8 seconds. Always perform a data-preserving
  `adb install -r` after rebuilding a new APK candidate.
- The first installed native-context attempt, `20260824-012628`, missed the
  initial victim-0 arbitrary-read reclaim before native context preparation.
  Its 477-byte progress record ended at the arbitrary-read free boundary and
  the controller performed the required recovery reboot. Treat it as ordinary
  acquisition variance, not evidence for or against native contexts.
- Installed run `20260824-012927` proved the native-context lifecycle end to
  end in 28.2 seconds: all four semantic writes, action, terminal context
  release and strict cleanup passed. Context retirement took 2–3 ms, but only
  four of 17 reclaimed nodes matched the indexed spray; 13 misses were safely
  observed without freeing the buffer. Do not accept this as a reliability
  candidate. Test a short post-close settle before expanding the victim pool.
- A 20 ms settle run, `20260824-013313`, improved the observed hit rate to
  four successes from eight contexts and passed strict cleanup in 29.8
  seconds. Its action phase took an atypical 5.56 seconds, so the headline is
  not a useful settle comparison. Test 50 ms, close to the former Android
  Binder-death observation interval, before selecting the dwell.
- The 50 ms run, `20260824-013855`, passed strict cleanup in 25.5 seconds and
  established the current native-context speed best, aided by overlapping the
  unchanged 1.25-second bridge stability interval with preflight work. It used
  nine contexts for four writes, versus eight at 20 ms, so 50 ms provided no
  reclaim-rate evidence and added 30 ms per attempt. Restore 20 ms.

## 2026-08-24 — Shared C++ victim cohort and exact foreground clock

- The acceptance duration is exclusively the host monotonic interval starting
  immediately before the Root input event and ending after Prism is foreground
  and its visible UI hierarchy contains Active. Internal chain and controller
  timestamps are diagnostic only.
- Replace lossy foreground snapshots as the primary transition evidence with a
  live `wm_set_resumed_activity` event stream started before the tap. A run now
  requires the ordered ReSukiSU-to-Prism round trip. Retain window snapshots as
  corroboration and the event-buffer dump as a fail-closed fallback.
- Extract the 18-context route, export, token collection, controlled retirement
  and exact terminal release lifecycle into the standalone `VictimCohort` C++
  module. The JNI layer is now an adapter over that module rather than a second
  implementation. Parcel templates are exported once and all routes are opened
  in parallel.
- Installed run `20260824-015333` missed the original victim-0 arbitrary-read
  reclaim before deferred cohort preparation or kernel mutation. It followed
  the existing controlled reboot policy. This is not evidence against the new
  cohort.
- Installed run `20260824-015600` passed all four semantic writes (1, 2, 5 and
  6), exact readbacks, ReSukiSU action, rescue finalisation and unload, donor
  resumption, context/process retirement and strict cleanup. Root tap to visible
  Active was 26.251 seconds. The live lifecycle stream observed ReSukiSU at
  22.457 seconds and the return to Prism at 23.396 seconds.
- The 18 shared-core victim brokers completed in about 44 ms. The pass used 12
  contexts for four successful writes, including eight safely observed misses.
  Route setup is no longer a material bottleneck. The remaining critical path
  is approximately 3.6 seconds to harness dispatch, 6.9 seconds through initial
  arbitrary-read establishment, 4.7 seconds across write attempts, 5.5 seconds
  for action/cleanup/return, and 2.4 seconds for the current visible-UI proof.
  Reaching 10 seconds requires moving the disclosure and write orchestration
  behind the standalone C++ seam; further victim-route tuning cannot do it.

## 2026-08-24 — Indexed C++ holder cohort

- Replace the sequential 128-route holder bootstrap with a fixed-index
  `HolderCohort` in `primitive_core`. A single exported start-Service Parcel
  contains a unique holder-index sentinel; the core patches it for each route
  and opens routes using 32 bounded workers. The service stores callbacks by
  that explicit index, so ActivityManager scheduling cannot reorder the exact
  20–27 filler profile.
- Keep receive and release ownership in the C++ module. Full activation still
  requires exact receipts for 128 contexts, 7,360 handles, 128 death
  notifications, 128 mappings and 128 descriptor closes.
- Disclosure-only run `20260824-021025` passed in 4.872 seconds host and 3.764
  seconds of checkpoints. Holder bootstrap took 286,560 microseconds, down
  from roughly 0.9–1.2 seconds. Both the 128-route prime and controlled sprays
  retained their exact shape.
- Full Root-tap run `20260824-021138` passed in 31.010 seconds. The lifecycle
  stream observed ReSukiSU at +27.176 seconds and Prism at +28.080 seconds;
  the visible Active endpoint and manager receipt completed at +31.010
  seconds. Writes 1, 2, 5 and 6 and terminal cleanup all passed.
- That run had 13 safe write misses and used victims 3, 7, 14 and 17. The main
  intervals were approximately: tap to controller 5.5 seconds;
  controller/harness plus disclosure 8.7 seconds; writes 7.7 seconds; action
  4.8 seconds; cleanup/result 3.2 seconds; return 1.1 seconds. Even eliminating
  every write miss cannot make the current app/service/file-poll path meet 10
  seconds.
- Batched freeing of the 2,048 first-owner buffers remains reliable, but the
  disclosure data confirms that holder route bootstrap—not those ioctls—had
  dominated that interval. Do not revisit buffer-free batching as a material
  latency strategy.

## 2026-08-24 — Warm bridge and reusable live cohort rejection

- Reuse the same daemonised Shizuku user service for preflight and activation.
  Fresh-boot run `20260824-021630` found the existing service record and passed
  all action and cleanup gates in 29.7 seconds. Root tap to controller start
  still took about 5.3 seconds, so cold user-service creation was not the
  dominant preflight cost.
- Live reusable write cohorts remain unsafe. Run `20260824-022633` retired the
  idle cohort immediately after write 2 but later stalled before the post-action
  security-ready checkpoint. A narrower pre-action-only candidate in run
  `20260824-023118` completed all four writes and reached the final action, but
  reproduced action child status 22 and wrapper errno 42 exactly.
- This reproduces the three earlier failures even with no reusable idle worker
  or socket alive during the action. The incompatibility is residual CVE/kernel
  state, not merely resource lifetime. Keep one-shot live cohorts; do not retry
  reusable cohorts without a new kernel-state explanation and an equivalent
  cleanup proof.

## 2026-08-24 — Honest visible-frame timing and mixed disclosure

- The acceptance endpoint is the first completed Prism frame whose hierarchy
  reports Active, after the live resumed-activity stream has observed ReSukiSU
  and then Prism. Foreground snapshots alone are not accepted because they can
  miss both transitions.
- Fresh-boot process warming passed five runs, but the first strict full run
  remained 20.0 seconds. Launching the manager return concurrently with
  normalisation and postflight also retained every gate, but the next strict
  run was 20.2 seconds because six safe write misses consumed about 2.4
  seconds. Keep the manager overlap; it removes roughly 1.1 seconds of serial
  return work even when variance hides it in the headline.
- One CVE decrement can sometimes disclose both structures without weakening
  either analyser. Run `20260824-035651` passed with 118 file candidates, 142
  epitem candidates and an eight-hit controlled Binder identity. It omitted
  the 4,096-ref pre-prime, retained the full 4,096 epitem-pair population and
  added controlled refs afterwards.
- This mixed topology is not yet reliable. Full epitems plus the original ref
  spray produced zero epitem candidates when the pre-prime was present. Sparse
  replacement windows, including contiguous and every-fourth layouts, varied
  between zero epitem evidence and zero canonical pairs. Ref-first fine-grained
  interleaving produced a strong 22-hit Binder identity but no epitem-shaped
  record. Epitem-first populations below the full 4,096 pairs likewise produced
  no epitem-shaped record.
- A late 4,096-ref prime can be released exactly while keeping all 128 native
  holder contexts. The core preserves unreleased handles after any partial
  failure, so terminal route cleanup remains complete. Compact and phased
  8+1 sprays still yielded only zero to two repeated controlled-node hits;
  do not lower the unchanged eight-hit identity threshold.
- The 20.2-second full trace spends about 6.1 seconds preparing the private
  credential and another 2.2 seconds arming the root watchdog before the CVE
  chain starts. These intervals are now larger than the possible saving from
  merging the two disclosures and must be profiled and refactored for a
  ten-second end-to-end result.

## 2026-08-24 — Preparation trace and write-batch reassessment

- Full run `20260824-041440` passed every semantic write, readback, action,
  terminal cleanup and exact visible-frame gate in 17.813 seconds. Three safe
  write misses were recovered. This is the current end-to-end best, measured
  from immediately before the Root input through ReSukiSU, Prism and the first
  completed visible Active frame.
- Private command transport is not the former six-second bottleneck. In the
  17.8-second trace its authenticated private-credential exchange took about
  0.31 seconds and root-watchdog arming took about 0.08 seconds. The two
  independent disclosures, write attempts, action and terminal proof remain
  the material path.
- Run `20260824-044523` tested independent app-bridge and app-cohort gates in
  parallel with kernel-subject and helper preparation. It failed closed at the
  unchanged pre-mutation fake-node check, but the preparation trace was
  conclusive: Binder/service contention stretched the app-cohort proof from
  about 0.49 to 1.14 seconds, leaving total preparation unchanged. Reject and
  revert this overlap.
- Retain one full `getprop` parse in each device-profile sample instead of six
  property subprocesses. Retain exactly two postflight baseline samples, but
  reuse the second sample's JobScheduler count for the receipt instead of
  collecting a redundant third dump.
- The old all-at-once four-carrier design is not a route to ten seconds. Its
  qualified full-width reclaim needed 4,097 workers, took 3.436 seconds to
  construct and activate, then 12.138 seconds to retire 4,092 rejected
  workers. A smaller pool mapped only one of four victims and failed closed.
  Do not enable `BATCHED_TERMINAL_WRITES`; serial one-shot victims retain the
  only accepted safe-on-miss recovery semantics.
- Full run `20260824-044829` passed in 21.1 seconds with three safe write
  misses. Preparation took 1.905 seconds from controller entry to harness
  dispatch. The two disclosures and arbitrary-read establishment took 6.176
  seconds, the write/root-window phase took 3.485 seconds, the action took
  3.869 seconds, terminal cleanup took 1.502 seconds and strict postflight
  took 1.306 seconds. Launch the mandatory Manager foreground transition only
  after all writes and rescue/host checks pass, but overlap its process launch
  with the already independent final `ksud` action.

## 2026-08-24 — Early Manager overlap and controlled-only mixed rejection

- Dispatching the Manager foreground launch immediately after the four
  semantic writes, rescue plan and host-side root-window checks are complete
  is valid. A dispatch latch proves that ActivityManager received the launch
  before the native action starts; the chain still withholds Active until the
  action, normalisation, exact retirement, terminal cleanup and postflight all
  pass. Strict runs reached 17.534 seconds (`20260824-050858`) and 16.916
  seconds (`20260824-051611`). Keep this overlap.
- The 16.916-second run observed ReSukiSU at +13.487 seconds, Prism at +16.683
  seconds and the first completed visible Active frame at +16.916 seconds.
  It had two safe write misses. Preparation took 1.938 seconds; the two
  disclosures and arbitrary-read establishment took 5.622 seconds; the write
  and root-window phase took 4.212 seconds; action plus verified terminal work
  took 2.130 seconds; controller postflight and return took 1.478 seconds.
- The epitem selected by the arbitrary reader is not at a fixed spray index.
  Three fresh boots selected shared-spray indices 804, 731 and 851. Do not use
  a guessed index to avoid the file-to-epitem linkage proof.
- A controlled-only mixed spray with no filler Binder refs preserves the full
  epitem population much better than earlier mixed geometries. At 512 holder
  contexts, one run passed in 2.733 seconds of checkpoints with 96 file
  candidates, 150 epitem candidates and a 202-hit Binder node candidate; all
  512 contexts and handles retired exactly. The next fresh boot produced an
  epitem-only leak with no node candidates, so it failed the consecutive gate.
- Explicit epitem replacement windows made the trade-off deterministic within
  a boot but not stable across cold boots. A 512-slot/512-ref window produced
  513 exact controlled identity records and no file landmark. A 128-ref
  window retained 140–152 file candidates but produced zero repeated node
  identity. A 1,024-slot/512-ref window also varied between a node-only leak
  and an epitem-only leak. Removing the late 8,192 shared-only epitems did not
  stabilise placement. Reject this mixed path for activation; keep the normal
  two-disclosure path enabled.

## 2026-08-24 — Native dwell and split-disclosure experiments

- Reducing the arbitrary-read split dwell and fake-control release settle from
  200/500 ms to 20/20 ms retained every semantic write, action, cleanup and
  visible-frame gate in strict run `20260824-054435`. The run took 18.684
  seconds to the completed Active frame and incurred six recoverable write
  misses. The saving was only about 130 ms in arbitrary-read preparation, so
  retain this as a reliability candidate rather than treating it as the route
  to ten seconds.
- Closing all fake-control peers before joining their workers changed allocator
  retirement order and caused the next fake-node acquisition to fail closed.
  The controller performed its designed safety reboot; there was no root
  window. Restore one-at-a-time close/join ordering and do not retry batching
  without a new allocator proof.
- A full 4,096-slot dense replacement window with 512 controlled refs produced
  73 repeated Binder-node hits but no epitem candidates. Splitting the CVE
  decrements 576/576 around the full epitem allocation produced 318 controlled
  node hits but still no epitem candidates. Both disclosure-only runs retired
  all 512 refs exactly and performed no kernel mutation.
- The split path matches the proven syscall order but not its free-slab volume:
  the normal epitem disclosure frees all 1,152 nodes before SCM pressure and
  epitem allocation. Test a 1,024/128 split next, preserving most of the proven
  epitem reclaim geometry while reserving 128 victim nodes for the controlled
  Binder identity. Do not enable it for activation until it passes at least
  five consecutive fresh boots.
- The first 1,024/128 launch stopped before any decrement because the temporary
  native API accepted only an equal 576/576 partition. Generalise the
  experimental guard to accept exactly two batch-aligned, contiguous ranges
  totalling 1,152 while preserving inventory identity and call-order checks;
  repeat the same disclosure-only candidate.
- The corrected 1,024/128 launch then produced a 32-hit controlled Binder
  identity but no epitem landmark. Its receipt exposed two consecutive SCM
  pressure cycles: the new range function performed one and the existing mixed
  begin function performed another. The proven epitem disclosure uses exactly
  one cycle. Defer pressure entirely from the range API and keep the mixed begin
  call as the sole pressure phase before epitem allocation.
- With one pressure cycle, the next fresh boot produced 112 repeated controlled
  Binder hits but still no epitem landmark. The mixed path was also creating
  all 512 Binder holder routes before the epitem reclaim, unlike the proven
  first disclosure. Defer holder-route bootstrap until the full epitem
  population is retained, then create the routes before decrementing the
  reserved final 128 nodes.
- Deferring holder bootstrap passed immediately, then passed five consecutive
  fresh boots in `20260824-060913`. Host disclosure times were 3.898, 3.795,
  3.658, 3.663 and 3.613 seconds. Controlled-node hits ranged from 60 to 166,
  file candidates from 16 to 290 and epitem candidates from 55 to 443. Every
  run retired all 512 routes and handles exactly, and no run enabled arbitrary
  read or any kernel write.
- The 512-route bootstrap costs about 1.29 seconds. The split reserves only 128
  victim nodes for the controlled identity, and the observed hit margin is
  large, so restore the production holder count of 128 and gate that smaller
  topology separately before integrating the one-disclosure path into root.
- The 128-holder topology passed five consecutive fresh boots in
  `20260824-061636`, with host times of 2.571, 2.572, 2.479, 2.540 and 2.604
  seconds. Controlled hits ranged from 47 to 341, file candidates from 158 to
  222 and epitem candidates from 218 to 301. All 128 routes and handles retired
  exactly on every run.
- Promote this exact 1,024/128 chronology to `root-chain`: real raw-target and
  client preparation, controlled-node export and kernel anchor remain enabled;
  exact holder retirement still precedes the mutation checkpoint; arbitrary
  read, semantic writes, action, normalisation and terminal cleanup remain
  unchanged. Keep the package-free `chain-addresses` stage mutation-free.
- First integrated run `20260824-062225` failed before the root window because
  the compact root holder sender correctly rejected a missing filler-node
  inventory. The controller performed a controlled `reboot,shell`; there was
  no kernel crash or write. Fetch the unchanged filler inventory only after the
  epitem population is retained, then bootstrap holders and decrement the final
  128 nodes. This preserves the gated epitem allocator chronology.
- Integrated run `20260824-062523` disproved that late fetch: progress stopped
  after `mixed-epitem-early-pass` while synchronously fetching 1,536 filler
  objects from the already decremented owner. The six-minute runner timeout
  found the same boot, no arbitrary-read arm and no mutation. The five-run
  disclosure gate had fetched filler objects before decrement. Restore that
  exact ordering for root and do not transact for the inventory afterwards.
- Run `20260824-063436` then completed without a hang but both disclosure
  analysers missed and exact pre-window cleanup triggered a controlled
  `reboot,shell`. Root alone had created the raw target/client cohort before the
  epitem reclaim; the gated path did not. Move target/client preparation after
  the epitem population is retained and before the final 128-node decrement,
  matching its position between the two disclosures in the proven root chain.
- Run `20260824-063701` still failed closed before the root window. The full
  receipt showed 896 retained handles: compact root mode was sending the
  controlled node, five filler nodes and the kernel anchor to every holder.
  Only six controlled hits remained and the epitem landmark was gone. Make the
  mutation-free `chain-addresses` stage exercise the same target/client,
  controlled-node and anchor topology as root. Reduce compact root payloads to
  the two semantically required objects (controlled node plus anchor), then
  qualify this 256-handle disclosure before another root run.
- The first root-topology probe stopped before sending holder payloads because
  the old `chain-addresses` validator expected zero exported siblings while the
  emulated root client correctly exported 95. Require the exact 95-sibling
  cohort whenever mixed disclosure is active; keep the same uniqueness and
  native cohort validation.
- The corrected two-object root-topology probe retained the epitem proof (198
  file and 323 epitem candidates) and retired all 256 handles exactly, but no
  controlled Binder identity occupied the reserved 128 nodes. Test an 896/256
  split so the second free partition matches the 256-object payload while the
  first retains substantial epitem margin.
- The 896/256 probe again retained strong epitem evidence but produced only two
  controlled hits. Raw export was materialising and validating 95 cohort
  siblings after the second decrement, consuming the reserved allocation
  window before the holder payloads. Move the complete export and validation
  before the second decrement, then send holder payloads immediately after it.
- That reorder raised the controlled identity only to four hits. The mandatory
  kernel anchor was still competing with the controlled node in the same
  transaction. Send only the controlled node in the reclaim window. After both
  unchanged analysers pass, send the anchor as a separately accounted holder
  phase and prove its dedicated retention before arbitrary read. Exact native
  release continues to cover handles from both phases.
- Separating the anchor retained strong epitem evidence but the raw-client
  controlled identity still produced only two hits. Re-test a balanced 576/576
  split now that duplicate pressure, early holder bootstrap, post-decrement
  cohort export and anchor competition have all been removed. Earlier balanced
  results do not represent this corrected chronology.
- The corrected balanced probe exposed 99 hits in the second-ranked candidate
  but selected none: the sole controlled object was also the death-subscribed
  object, and multi-cohort analysis deliberately excludes death-marked nodes.
  Use no per-object death subscription for the one-object reclaim phase, as in
  the reliable disclosure topology. Continue proving all 128 route-process
  deaths independently. Terminal native accounting accepts only the exact old
  7,360-handle/128-death profile or the new 256-handle/zero-object-death profile.
- The first zero-death balanced probe passed both analysers, but the next fresh
  boot retained 64 controlled hits and lost the epitem landmark. Restore the
  896/256 split: its epitem proof was consistently strong, and its only prior
  node failure was the now-corrected death-candidate exclusion.
- The corrected 896/256 root-topology gate passed four fresh boots, then run 5
  retained 122 controlled hits but lost its epitem landmark. Increase the
  epitem partition to 1,024 and reserve 128 nodes, exactly matching the 128
  zero-death controlled references. Earlier 1,024/128 root results predate the
  export-order, anchor-phase and death-filter corrections.
- The corrected 1,024/128 gate passed three fresh boots, then run 4 retained
  strong epitem evidence but produced only two controlled hits. Increase the
  holder cohort to 256 for reclaim coverage. Extend terminal proof with one
  explicit exact profile: 256 contexts, 512 handles across controlled and
  anchor phases, zero object-death subscriptions, and 256 callback deaths,
  mappings and descriptors.
- The 256-holder exact root-topology gate passed five consecutive fresh boots
  in `20260824-070944`. Host times were 3.940, 4.094, 4.168, 3.995 and
  3.888 seconds. Each run used the 1,024/128 split, validated the full raw
  cohort and controlled template, passed both unchanged analysers, retained the
  anchor only after analysis, and retired exactly 512 handles, 256 route
  contexts, 256 callbacks, 256 mappings and 256 descriptors. Promote this
  topology to one strict end-to-end root run.
- The saved lifecycle evidence is authoritative, but the live console observer
  was consuming old buffered `logcat` history before reaching current events.
  Start the observer at the tail of the buffer so ReSukiSU and Prism foreground
  transitions print when Android emits them. Continue measuring from just
  before the Root input command through the first completed visible Active
  frame; `dumpsys` focus samples are diagnostic only.
- End-to-end run `20260824-071513` proved the one-disclosure arbitrary-read
  path and exact 512-handle holder retirement, then failed closed at
  `current-binder-proc` before the root window. Moving the kernel anchor until
  after analysis had removed every leaked node owned by the Harness process;
  after the raw client retired, the resolver had no live process cursor. Add a
  distinct Harness-owned marker to exactly eight holder routes between the
  controlled spray and leak analysis. Death-mark only those eight references
  so analysis still selects the 256-reference zero-death controlled identity
  but retains the marker in the ranked candidate set. Extend cleanup proof
  only with exact 256-context profiles: 264 handles/eight death requests before
  anchor retention, or 520/eight after it.
- Marker probe `20260824-072319` wedged before stale-read enable because the
  JNI receiver allowlist still rejected an eight-route phase and returned
  before Java sent route 0. There was no arbitrary-read arm or mutation. Admit
  the exact eight-route receiver in addition to the existing exact cohort
  sizes; do not change receiver bounds or cleanup proof.
- Corrected marker probe `20260824-072742` passed in 3.967 seconds, including
  both unchanged leak analysers and exact retirement of 520 handles, eight
  death requests and all 256 routes. The leak sampled only two marker records,
  which is enough for the resolver but is not a robust margin. Increase marker
  fan-out to 64 death-marked routes while retaining all 256 zero-death
  controlled references. Replace the experimental marker cleanup profiles
  with exact 320-handle/64-death pre-anchor and 576-handle/64-death post-anchor
  profiles, then repeat the five-boot mutation-free gate.
- The 64-route gate `20260824-072958` passed run 1 in 3.943 seconds, then
  displaced the controlled identity on run 2: 49 death-marked records remained
  while no zero-death controlled identity was identified. Exact pre-anchor
  cleanup retired 320 handles and 64 death requests; no mutation occurred.
  Reject the larger late fan-out. Restore eight routes and require both five
  consecutive disclosure passes and non-zero death-marked leak evidence on
  every run before returning to the root chain.
- The restored eight-route gate `20260824-073345` passed five fresh boots in
  3.911, 3.919, 4.151, 4.116 and 4.002 seconds. Every run retired exactly 520
  handles and eight death requests and had non-zero death-marked records, but
  run 5 had no repeated death-marked candidate (`second_hits=0`). Do not rely
  on that ambiguous resolver input. Interleave the same eight marker objects
  into the controlled phase at exact 32-route intervals. Keep the same exact
  cleanup totals and eliminate the late marker allocation wave.
- Initial interleaved probe `20260824-074137` wedged during the holder send,
  before stale-read enable or mutation. `Parcel.appendFrom()` appended the raw
  controlled object without advancing the write cursor, so the marker write
  overwrote the payload and the exact receiver rejected route 0. Move the
  cursor to `dataSize()` after the append and before writing the marker.
- A second direct diagnostic run showed no interleaved receiver telemetry. The
  receiver mode had been changed on the inactive legacy sender, while the
  active root-shaped sender still declared one fixed object and sent two on
  marker route 0. Restore the legacy declaration and apply `-1` only to the
  root-shaped compact sender. Remove the temporary native diagnostics.
- Corrected interleaving passed a direct probe with 121 controlled and six
  repeated marker hits. The fresh-boot gate `20260824-075012` then passed four
  runs in 3.858–4.094 seconds; run 5 retained a repeated marker but only six
  controlled hits, below the unchanged hard threshold of eight. Exact
  pre-anchor cleanup retired 264 handles/eight deaths and no mutation occurred.
  Do not weaken the analyser. Increase the cohort to 384 controlled routes,
  keep exactly eight evenly interleaved markers, and require exact 392/8
  pre-anchor or 776/8 post-anchor handle/death retirement across 384 contexts.
- The first 384-route direct probe failed cleanly at bootstrap because the JNI
  route-creation allowlist still admitted only 128, 256 or 512 routes. The C++
  cohort already supports any count up to 512. Add the explicit 384 entry to
  route creation, matching the receiver and exact cleanup profiles.
- The corrected 384-route topology passed five consecutive fresh boots in
  `20260824-075727`: 4.331, 4.462, 4.446, 4.475 and 4.567 seconds. Controlled
  hits were 128, 122, 50, 122 and 122 against the unchanged threshold of eight;
  every run retained a repeated death-marked marker candidate and retired
  exactly 776 handles, eight death requests and all 384 contexts, callbacks,
  mappings and descriptors. Promote this exact qualified state to one strict
  Root-input-to-visible-Active run.
- Strict run `20260824-080256` completed the qualified disclosure and arbitrary
  read but again failed closed at `current-binder-proc`; the controller issued
  a normal `reboot,shell` before the root window. Repeated leak ranking does not
  authoritatively identify the live Harness node. Extract the device-matched
  5.10.198 kernel from the supplied `boot.img` with `vmlinux-to-elf`. Its
  recovered symbols independently reproduce the existing `eventfd_fops`
  (`0x02156800`), `fair_sched_class` (`0x022e6bc0`) and `init_cred`
  (`0x027a0ae0`) offsets exactly, and place `binder_procs` at `0x02a61e90`.
  After the existing kernel-base and init-credential validation succeeds, read
  that global hlist head and traverse it with the existing exact Binder proc
  PID/task/ref checks. Keep leak candidates only as a fallback cursor.
- Strict run `20260824-080946` passed global current-proc discovery, then failed
  closed at `credential-target-adopt` and performed a normal `reboot,shell`.
  Each native holder route opens another Binder context, so 384 `binder_proc`
  entries legitimately share the Harness PID. PID alone selected a holder
  context without the Java credential-target handle. For each same-PID proc,
  resolve that exact cached handle and additionally require its target proc PID
  to equal the cached credential-target PID. Select only that structurally
  bound Java Binder context.
- Strict run `20260824-081308` passed the resolver, writes and guarded action.
  ReSukiSU foreground appeared at +13.1 seconds and activation returned success;
  ctlbuf restoration, donor resume and credential normalisation all passed.
  The controller then waited 180 seconds without receiving terminal cleanup and
  issued a normal `reboot,shell`. The exact native holder release and all 384
  holder callback deaths occur before mutation, but their Android service
  connections remained until the 10-second terminal Java retirement window.
  Unbind exactly all 384 connections as part of that pre-mutation holder proof.
  Also trace changing terminal checkpoints and stop immediately on an app-chain
  failure so a later terminal fault is preserved rather than hidden by timeout.
- A direct mutation-free probe disproved the connection hypothesis: the native
  holder cohort does not populate Java's `isolatedConnections` list, so its
  exact size is zero rather than 384. Revert the pre-mutation unbind requirement;
  retain the improved terminal checkpoint and app-failure capture for the next
  strict diagnostic run.
- Strict run `20260824-083133` captured the actual failure within 11 seconds:
  terminal Java retirement passed raw-target retirement, then timed out at
  `owner-retire`. The Harness unbound bind-only `OwnerService2` before writing
  its retirement request, allowing Android to terminate it before its 10 ms
  file watcher observed the request. Keep the exact original Owner process
  bound, write and validate its nonce/PID/start-time/boot-bound self-exit
  receipt, then unbind the dead service connection. Preserve the existing
  death barrier and complete identity-set retirement proof.
- Strict run `20260824-083441` kept Owner2 bound but still timed out at the same
  watcher stage. Replace file polling as the trigger with OwnerService's
  existing same-UID, distinct-caller, exact PID/start-time terminal Binder
  transaction. Extend it with the existing nonce, boot identity and
  helper-retired marker; write the unchanged atomic self-exit receipt before
  releasing references and killing the process. The Harness still validates
  that receipt, the Binder death and the complete retired identity set before
  unbinding.
- Strict run `20260824-083935` proved the new Binder request was still rejected:
  the action passed, raw-target retired, and Owner2 again produced no receipt
  before the unchanged 10-second timeout. At this point Harness has adopted
  root credentials, so Binder reports its transaction UID as 0 rather than the
  package UID. Require that exact post-adoption UID, the distinct Binder caller
  PID, and a matching live caller `/proc` start time, in addition to the already
  bound Owner PID/start time, nonce, boot identity and helper-retired marker.
  Do not loosen any receipt, death-barrier or identity-set proof.
- Strict run `20260824-084352` still produced no Owner-side rejection receipt,
  proving the terminal Binder request never ran: Owner2's Binder pool is not an
  available terminal control plane. The earlier file watcher failed because an
  atomic write after credential adoption replaced the command with a root-owned
  inode that Owner2 could not read. Have Owner2 pre-create an empty app-owned
  command inode during its authenticated terminal bind, then update that same
  inode in place after helper retirement. The independent watcher ignores the
  empty armed state and acts only on the exact nonce/PID/start-time/boot payload.
- `20260824-084812` exposed a separate runner fault: the UI tap returned but no
  controller for the new boot started, leaving the runner on stale prior-boot
  files. Preserve the first-tap acceptance timestamp, require a current-boot
  `controller-start` within two seconds, and retry the still-enabled Root button
  at most twice without resetting the clock. Fail before mutation if dispatch
  remains absent.
- Strict run `20260824-085525` confirmed current-boot dispatch under that guard,
  then missed safely at the unchanged root-unlink/fake-node analysis gate before
  the root window. The controller performed its normal recovery reboot. Treat
  this as ordinary primitive variance; do not weaken the analyser.
- Creating and repeatedly reading the armed Owner command during the vulnerable
  phase caused two further safe root-unlink misses (`20260824-085740` and
  `20260824-090543`). A trigger-only watcher restored the previous primitive
  shape in `20260824-090106`, which again reached the action but demonstrated
  that Owner2 itself is not a dependable terminal co-ordinator. Replace its
  self-retirement request with an exact PID/start-time guarded unbind and
  `SIGKILL`; retain the already-armed Binder death barrier and complete original
  identity-set retirement proof. Process exit performs Binder reference cleanup
  in-kernel and removes the 10-second service-side scheduling dependency.
- The first direct-kill integration attempt `20260824-090829` missed safely at
  root-unlink. The new dispatch verifier had added 10 Hz ADB shell polling during
  allocator shaping; move retries into the existing 500 ms observer so the
  successful path adds no new polling. A separate mutation-free primitive run
  `20260824-091030` then passed in 4.396 seconds (3.446 seconds by device
  checkpoints), confirming the current 384-route C++ topology remains sound.

## 2026-08-24 — First complete 384-route chain and 17.554-second baseline

- Initial write reclaim with only 32 or 128 staged controls was too
  probabilistic. A 512-control first wave produced five consecutive reclaim
  successes (`20260824-091808` through `20260824-093004`), but two later safe
  exact-payload misses showed that it was not a reliable final setting.
- Keep the ordinary per-write batch at 512 controls, but stage all 1,024
  already-prepared controls for the initial split-decrement reclaim. This does
  not increase the pool or weaken the exact-payload gate. The first full run
  with this split passed initial reclaim and the complete chain.
- Owner2's terminal Binder request cannot be scheduled reliably and the
  watcher changed allocator timing. The terminal path now unbinds the exact
  bound Owner2 process, verifies its PID and `/proc` start time, sends
  `SIGKILL`, waits for that exact identity to disappear, and records
  `exit_signal=9`. Acceptance still requires the pre-armed Binder death,
  complete original identity-set retirement, an independently parsed receipt,
  and native `kill(pid, 0) == ESRCH`.
- Correct the terminal proof to the actual qualified topology: 384 raw holder
  contexts and 384 retired holder identities. Native cleanup passed with one
  retained arbitrary-read carrier, 384 raw contexts and five controlled
  unlink acknowledgements.
- `register-shell` mutated the shared requested-stage field and caused a valid
  root result to be labelled `root-unlink`. Capture the immutable chain stage
  and have `runArbitraryRoot()` publish an explicit `stage=root-chain` wrapper.
  This changes only result labelling, not success criteria.
- Full artefact `artifacts/prism-runs/20260824-094039` is the first complete
  accepted pass of this state. Root input to first completed visible Active
  frame was 17.554 seconds. Android lifecycle evidence shows ReSukiSU at
  +13.418 seconds, Prism at +17.321 seconds, and Active at +17.554 seconds.
  Terminal cleanup, strict postflight and foreground ordering all passed.
- Device critical path: controller start to harness dispatch 1.888 seconds;
  native root flow to mixed disclosure analysis 3.692 seconds; arbitrary-read
  establishment 1.191 seconds; credential and process profiling 1.065 seconds;
  semantic writes, action and terminal cleanup about 6.15 seconds; cleanup to
  visible Active about 3.54 seconds. The acceptance clock is unchanged and no
  state is reported Active before the full proof chain completes.
- Do not re-enable the old four-carrier batched-write path. Its qualified
  4,097-worker form took 15.574 seconds for construction plus rejected-worker
  retirement, and its smaller form failed exact mapping. It is slower than the
  whole current activation and lacks the serial path's safe-on-miss recovery.

## 2026-08-24 — Manager IPC acceptance and overlapped Prism return

- Candidate `20260824-094950` first displayed Active at 15.936 seconds, with
  ReSukiSU foreground at 12.155 seconds and Prism foreground at 14.654 seconds.
  Starting Prism as soon as the action and terminal chain pass, while strict
  postflight continues, saved about 1.6 seconds without exposing Active early.
  The run is not qualified: foreground stability was disturbed after Active,
  and ReSukiSU subsequently displayed **Not installed**.
- Kernel-only evidence from that run was exact and positive: the `kernelsu`
  module was live and `ksud debug info` reported version 35088, LKM true,
  late-load true and runtime mode `late-load`. Source inspection at pinned
  ReSukiSU commit `746686390b0cf2256818a97b2f620eadbd079995` showed that this
  is separate from Manager IPC acceptance. The Manager says **Working** only
  when its own process inherits `[ksu_driver]` and `Natives.isManager` passes.
- The previous controller launched ReSukiSU before socket action 7 had returned,
  so the already-running app process could miss descriptor injection. Move the
  force-stop/start until after the exact accepted action frame. Preserve the
  overlap with post-action normalisation and cleanup. Strengthen strict kernel
  postflight from `debug version` to exact `debug info`, and separately require
  the freshly spawned Manager UI to show **Working**, **LKM**, and **Jailbreak
  mode**, with no root-grant warning.
- `20260824-095558` and `20260824-095800` both missed safely at the unchanged
  root-unlink/unlink-observe/fake-node gate before any kernel write. Each used
  the controller's normal `reboot,shell` recovery. They are primitive variance,
  not evidence about the corrected Manager launch order.

## 2026-08-24 — Correct Manager state, prepared release, and 14.9-second best

- `20260824-100332` is the first fully qualified Manager run after moving the
  ReSukiSU launch behind the accepted action frame. It passed the exact KernelSU
  `debug info` contract, then ReSukiSU displayed **Working**, **LKM** and
  **Jailbreak mode**. Root input to visible Active was 16.8 seconds. Treat a
  loaded kernel module without this Manager proof as a failure.
- Split controller preparation from Root release. The user service, helper,
  watchdog, donor and app cohort can now become ready before the tap, while the
  Harness and CVE path cannot start until the authenticated session is released
  by Root. Run `20260824-101153` proved this boundary and passed in 16.7 seconds;
  two safe write misses masked the timing benefit.
- Long-idle epitem-reader preparation was unreliable. Runs
  `20260824-101603` and `20260824-101808` failed before mutation at epitem
  analysis and the first arbitrary-read exact-payload gate respectively. The
  reader prewarm was reverted. Do not repeat without a new allocator-lifetime
  explanation.
- Reorder the global `binder_procs` search so each holder context first checks
  its known handle and PID, then performs structural validation only for the
  matching process. This retains all validation but saved only about 31 ms.
- `20260824-102429` is the current honest best: exact action, cleanup, KernelSU
  postflight, Manager round trip and visible Active passed in 14.851 seconds.
  It contained three safe write misses; the estimated no-miss duration is about
  13.7 seconds. ReSukiSU appeared at +11.788 seconds, Prism at +13.469 seconds,
  and the first completed Active frame at +14.851 seconds.
- Warming extra Android owner/client processes before disclosure was rejected.
  `20260824-102721` missed the Binder disclosure and `20260824-102912` passed
  disclosure but missed the first arbitrary-read reclaim, both before mutation.
  The warm-process calls were reverted.
- The remaining no-miss path is roughly 3.8 seconds for mixed disclosure,
  1.2 seconds for arbitrary-read establishment, 1.1 seconds for credential and
  process profiling, 2.5 seconds for four writes, 1.3 seconds for action,
  1.7 seconds for terminal work and 1.3 seconds for postflight/UI completion.
  Small polling changes cannot close the gap. The next material candidate must
  amortise several write-victim decrements while retaining exact per-victim
  typed-reuse and safe cleanup proofs.

## 2026-08-24 — Holder routing and prepared command transport

- Raising native holder routing from 32 to 64 workers preserved the topology
  and passed five consecutive fresh-boot primitive runs in
  `20260824-104250`: 4.388, 4.516, 4.501, 4.420 and 4.418 seconds by the host
  clock. The corresponding device checkpoint durations were 3.419, 3.478,
  3.326, 3.419 and 3.314 seconds. Keep 64 workers.
- Strict run `20260824-104810` passed exact cleanup, KernelSU and Manager
  acceptance in 13.979 seconds despite one safe write miss. Holder bootstrap
  fell from roughly 1.03 seconds with 32 workers to 0.90 seconds with 64.
- Increasing interleaved current-process marker holders from 8 to 64 caused
  primitive run `20260824-103937` to time out before the CVE during holder
  receipt. Revert to 8; do not repeat this density change without a new Binder
  allocation explanation.
- Moving the complete private-credential handshake before Root is impossible:
  the Harness Binder transaction creates that credential while also passing
  the module and vendor descriptors. `20260824-105247` rejected the attempt
  safely before release, with no CVE entry or mutation.
- Prepare only the authenticated command socket before Root. Keep the private
  credential request, identity proof, task snapshots, semantic gates and arm
  after disclosure. Strict run `20260824-105502` passed with zero write misses
  and exact Manager acceptance. The split removed about 158 ms from the
  post-disclosure credential handshake. Its 15.583-second headline contained
  about 1.8 seconds of unrelated ReSukiSU action variance, so retain the narrow
  preparation but do not count the headline as a regression.
- Route construction at 128 workers passed five fresh boots in
  `20260824-110040`, but its 979.5 ms median holder bootstrap was 11.4 ms
  slower than the qualified 64-worker median. Revert to 64: framework and
  kernel serial work, rather than native worker availability, now bounds this
  stage.

## 2026-08-24 — Direct Manager registration and corrected native module load

- Strict runs `20260824-112610` and `20260824-113106` passed the exact kernel,
  cleanup and Manager gates at about 15.5 and 15.8 seconds. ReSukiSU displayed
  **Working**, **LKM** and **Jailbreak mode**. Treat **Not installed** as an
  unconditional failure even when the module and Prism result otherwise pass.
- The pinned ReSukiSU module now accepts the already verified Prism Manager UID
  as `lp3_manager_uid`, validates it, and registers it directly after throne
  tracker initialisation. The original asynchronous package scan remains as a
  fallback. This removes the package scan from the successful critical path
  without weakening Manager IPC acceptance.
- Initial fast-module runs rebooted immediately after action dispatch. Durable
  action entry and controller-side task-state samples proved JNI entered but
  never returned. Synchronous child phase logging was rejected because its
  filesystem synchronisation perturbed the privileged path.
- Root cause: the production C++ supervisor called `finit_module` with an empty
  parameter string. The module therefore received UID zero, installed several
  hooks, then rejected the UID late in initialisation. Pass the exact verified
  Manager UID from the native supervisor, and reject invalid UIDs at the start
  of module initialisation before installing any hooks. Keep direct Manager
  registration after tracker/list initialisation.
- Strict fresh-boot run `20260824-130158` is the first corrected fast-Manager
  pass. ReSukiSU was observed foreground at +10.649 seconds and displayed
  **Working**, **LKM** and **Jailbreak mode**; Prism returned at +12.729 seconds
  and completed its first visible Active frame at +13.733 seconds. The action
  itself returned in about 0.26 seconds. Two safely recovered write misses cost
  about 0.6 seconds; the remaining material path is disclosure/acquisition,
  four semantic write carriers, terminal cleanup and UI return.

## 2026-08-24 — Early Prism return and reusable-carrier rejection

- Launching Prism after the exact ReSukiSU action frame, in parallel with
  normalisation and cleanup, is valid because Active remains withheld until the
  full terminal and postflight contracts pass. Strict run `20260824-130942`
  passed in 13.314 seconds with one safe write miss.
- Deterministically starting and identity-validating three allocator processes
  before Root passed once in `20260824-131527` at 12.99 seconds with no write
  misses, but saved at most a few tenths and revisited a previously unreliable
  allocator perturbation. Remove the pre-Root warm call; retain the proven
  root-time process topology.
- An `io_uring` probe on this kernel submitted 512 blocked `SENDMSG` operations
  in about 1.5 ms after 23.8 ms preparation and reaped all of them in about
  49.8 ms. It cannot safely replace the current pthread carriers: the rescue
  module proves and repairs each blocked userspace `sendmsg` stack, whereas an
  `io_uring` request has a different lifetime and saved-pointer representation.
  Do not use it without a new, equally strict kernel-side rescue proof.
- The old reusable pthread prototype failed because its task name was
  `lp3-reuse-ctl`, while rescue deliberately accepts only `lp3-fake-ctl`.
  Correcting the task identity allowed the full rescue, cleanup, KernelSU and
  Manager contracts to pass in `20260824-132634`; this establishes that its
  blocked stack shape is valid.
- Reject that reusable topology as an optimisation. The run took 14.7 seconds
  and incurred 11 safe write misses. Reusing hundreds of live socket and thread
  objects perturbs the required kernel allocation sequence even though each
  individual carrier is rescuable. Restore fresh serial 512-worker sprays.
- Re-testing the historical 256-route, zero-marker topology against the current
  chain did not reproduce its old gate. Full run `20260824-133414` reached all
  four writes but rescue initialisation rejected the retained-carrier plan with
  `EINVAL` and the watchdog performed a controlled `reboot,shell`. The next
  mutation-free run in `20260824-133658` then missed both unchanged disclosure
  analysers: the controlled identity had seven hits against the hard minimum of
  eight, and there were zero file candidates. Restore the qualified 384-route,
  eight-marker topology; the smaller cohort no longer has adequate margin.
- Prestarting the real first `OwnerService` before Root constructs its Java
  Binder inventory early without exporting nodes, but it still changes the
  long-lived Binder process topology. Run `20260824-134402` passed disclosure
  and arbitrary read, then failed the exact credential-target adoption gate
  before the root window and performed controlled recovery. Revert; process
  construction is part of the qualified topology even when kernel nodes are
  lazy.
- The rebuilt 384-route source did not expose Root in preflight run
  `20260824-135003`. The shell controller reached its guarded `ready` phase in
  about 3.25 seconds and made no kernel mutation, while the app UI remained on
  **Preparing** until the 120-second preparation lease expired and clean
  recovery passed. Diagnose the app snapshot/handle hand-off before treating
  this as a primitive regression or running further activation experiments.
- Fresh-boot attempt `20260824-135449` did not enter Prism preparation because
  Shizuku's delayed boot receiver killed the manually started shell server
  about four seconds after the runner's 2.5-second stability gate. Extend the
  runner gate to five uninterrupted seconds and retain its bounded restart;
  this is preflight reliability work and is outside the Root-to-Active clock.
- Re-established 384-route run `20260824-135712` reached all four semantic
  writes. Write 6 missed safely once and then passed, but the rescue module
  rejected the five retained carriers with `EINVAL`; the action gate reported
  failure and the watchdog completed a controlled reboot. Count this as a full
  reliability failure. Repeat the unchanged baseline before attributing it to
  the reverted source, because the exact zero-miss baseline previously passed
  and this run used a different retained carrier after the safe retry.
- Unchanged repeat `20260824-140045` again passed the four writes, after one
  safe write-1 miss and two safe write-6 misses, then received the same rescue
  `EINVAL` and performed a controlled reboot. This is a repeatable regression,
  so add phase-specific errno mapping without relaxing any rescue predicate.
- The first diagnostic-module run `20260824-140600` stopped at the earlier
  ReSukiSU staging gate: the APK and Java asset size were updated to 119,712
  bytes, but the native exact-size constant remained 119,648. The fail-closed
  staging rejection and watchdog reboot were correct. Update the native size
  constant before using this build to diagnose rescue initialisation.
- Corrected diagnostic run `20260824-140903` reached all four writes with no
  misses and returned mapped errno 76 (`ENOTUNIQ`) from
  `lp3_prepare_repairs()`. The plan's five TIDs and five nodes were unique, so
  inspection exposed the actual regression: the fresh serial sender function
  had been reverted to task name `lp3-reuse-ctl`, while rescue deliberately
  accepts only `lp3-fake-ctl`. Restore the qualified fresh-worker name and keep
  `reusable = false`; this repairs identity validation without re-enabling the
  rejected reusable topology.
- Restored fresh-worker run `20260824-141142` passed every kernel, rescue,
  cleanup, Manager and UI gate in 13.1 seconds with no write misses. ReSukiSU
  became foreground at +10.2 seconds, Prism returned at +11.3 seconds and its
  first complete Active frame rendered at +13.1 seconds. This re-establishes
  the honest baseline after the rejected experiments.
- Candidate: begin the read-only global `binder_procs` traversal immediately
  after arbitrary-read establishment and await it after the independent
  private-credential handshake. The target handle/PID and kernel read state are
  already immutable at that point. Keep all existing result and timeout gates;
  reject the overlap if it changes disclosure or write reliability.
- Strict candidate run `20260824-141559` passed every kernel, rescue, cleanup,
  foreground, Manager and UI gate in 12.5 seconds with no reported write miss.
  ReSukiSU became foreground at +9.6 seconds, Prism returned at +10.7 seconds,
  and the first complete Active frame rendered at +12.5 seconds. Retain the
  read-only overlap for the final clean-build consistency gate; it changes no
  mutation or recovery predicate.
- The revised acceptance target is five consecutive strict fresh-boot runs
  below 15 seconds. Remove temporary `PrismPrepareTiming` diagnostic logging,
  rebuild and reinstall before starting the counted series so all five runs
  exercise the exact candidate that will be committed.
- The first strict series for that build passed at 12.5 and 12.2 seconds, then
  run 3 (`20260824-141903`) missed the controlled Binder-node disclosure before
  any kernel write. The controller correctly rejected the result and performed
  a controlled `reboot,shell`. This resets the qualification series and shows
  that 384 controlled routes no longer provide enough cold-boot margin.
- Increase only the zero-death controlled route cohort from 384 to 512. Keep
  the 1,024/128 decrement split, exactly eight interleaved death-marked current
  process markers, the eight-hit analyser threshold, and exact native cleanup.
  Extend successful cleanup acceptance to only the new exact 520-handle
  pre-anchor and 1,032-handle post-anchor profiles across 512 contexts.
- The mutation-free fresh-boot series `20260824-142712` passed five consecutive
  disclosures. Device checkpoint durations were 3.761, 3.705, 3.801, 3.688
  and 3.734 seconds. Controlled-node hits were 125, 140, 116, 138 and 78;
  file candidates were 126–192 and epitem candidates were 167–315. Every run
  retired exactly 1,032 handles, eight death notifications and all 512 route
  contexts, mappings, descriptors and callbacks. Promote this exact APK to the
  strict five-boot end-to-end gate without further code changes.
- Strict series `20260824-143336` passed its first three fresh boots at 13.6,
  13.2 and 13.4 seconds, then run 4 missed the initial arbitrary-read carrier
  reclaim before any semantic write. The controlled-node disclosure had
  already passed, so keep the 512-route topology and reset the strict count.
- The failed boot produced the exact initial no-payload shape and the helper
  armed its nonce/boot/PID-bound process-teardown watchdog. The controller did
  not parse that proof because `ActivationProofs` still expected a historical
  32-worker staged cohort and `isolated-retirement-proof-pass`, while the live
  path uses all staged workers and `raw-holder-retirement-proof-pass`. Correct
  those exact expectations; do not broaden the parser or accept a free buffer.
- Use all 2,048 existing fake-control slots for the initial split-decrement
  reclaim, rather than 1,024. Keep each exact indexed payload, the single
  decrement, CPU choreography, state-2 barrier, hand-off validation and
  one-retained-worker terminal proof unchanged. This increases only the
  pre-mutation allocation coverage; qualify it through the primitive path
  before restarting the strict five-boot series.
- Reject carrier widening. The first 2,048-carrier primitive probe
  (`primitive-probe-20260824-134415-806352.txt`) reached an exact prepared
  2,048-worker/state-2 cohort but still observed the unreclaimed original
  transaction payload. As earlier evidence warned, the masked `raw_index` is
  not an allocation ordinal. Restore the 1,024-carrier width and do not spend
  the timing margin on more equivalent allocations.
- The enlarged disclosure path was retiring 1,032 holder handles, eight death
  notifications and 512 complete Binder contexts immediately before victim-0
  reclaim. Split the existing native holder lifecycle instead. After both leak
  analysers pass, clear the eight marker deaths and release the exact 520
  controlled/marker handles while retaining every empty route context. Then
  retain the 512 kernel-anchor handles across victim-0 reclaim. Only after the
  arbitrary-read carrier passes its exact indexed-payload hand-off should the
  chain release those anchors, close all 512 contexts, observe all callback
  deaths and publish the unchanged cumulative 1,032/8/512 retirement proof.
  This moves allocator retirement without weakening final accounting or the
  semantic-write boundary.
- Update the initial-miss parser to the live 1,024 staged-worker fields and the
  new `raw-holder-retirement-deferred` progress marker. It must still require
  the exact no-free transaction shape and nonce/boot/PID-bound teardown token;
  this repairs recovery evidence only and does not turn a miss into success.
- The first split-lifecycle probe acquired and handed off the exact indexed
  carrier, then correctly failed at `controlled-free-evidence`: the unlink
  ledger only recognised fully retired holder cohorts. Add one exact
  generation-bound `kReferencesReleased` state. It is reachable only after
  the native core clears eight death notifications and releases exactly 520
  handles. Only victim 0 may record its controlled free in this state. Later
  write victims and terminal consumption still require `kProved`, which is
  published only after the cumulative 1,032 handles, all 512 contexts,
  mappings, descriptors and callback deaths reconcile.
- The corrected split lifecycle passed five consecutive primitive probes on
  their first attempts:
  `primitive-probe-20260824-135439-102864.txt`,
  `primitive-probe-20260824-135552-692616.txt`,
  `primitive-probe-20260824-135658-854250.txt`,
  `primitive-probe-20260824-135805-669098.txt` and
  `primitive-probe-20260824-135912-595000.txt`. Every run reached
  `arbitrary-read-pass`, completed root profiling through the retained carrier
  and performed the planned clean reboot. Promote this exact APK to a fresh
  strict five-run Root-to-visible-Active gate.
- The first strict split-lifecycle run (`20260824-145943`) passed disclosure,
  victim-0, full holder retirement, current-proc discovery and private
  credential validation, then a read-only `ctlbuf-rescue-profile` call failed
  before any semantic write. A direct root diagnostic
  (`root-probe-20260824-140457-302356.txt`) then passed that exact profile,
  both observed writes and the root window; its legacy host action later timed
  out and the controlled reboot completed, so it is diagnostic evidence only.
- Retry only the complete read-only ctlbuf rescue profile up to three times,
  with no delay. Each attempt retains every existing pointer, fd-table, SELinux
  label, epitem-link, donor and live-target predicate. Any pass is therefore a
  full profile pass; three failures still stop before mutation. This adds only
  a few milliseconds on a transient failure and does not retry a CVE decrement
  or a kernel write.
- Strict series `20260824-150615` passed its first three fresh boots at 14.398,
  12.860 and 12.708 seconds. Run 4 completed the chain, Manager activation and
  return to Prism, and the app visibly showed `Active` and ReSukiSU `Installed`,
  but no `PrismVisibleState` frame-metrics event was emitted. The strict runner
  timed out rather than inferring a timestamp, so reset the qualification
  count. The Active layout can be computed while Prism is backgrounded and be
  reused on resume without causing another measured frame. When an Active
  layout is pending, explicitly schedule one decor-view invalidation on the
  next animation frame. Continue to accept only the subsequent
  `OnFrameMetricsAvailableListener` completion timestamp; do not substitute a
  layout, lifecycle or UI-dump observation for a completed visible frame.
- The redraw candidate's next strict series `20260824-151952` passed run 1 at
  13.0 seconds, including a deterministic completed Active-frame event. Run 2
  then missed victim-0 indexed carrier acquisition before any semantic write.
  Its result followed the exact `root-unlink` → `unlink-observe` →
  `fake-node-check` signature, and the bound process-teardown watchdog armed
  and rebooted. This resets the count and confirms the remaining blocker is
  primitive variance, not UI observation.
- Test a two-wave initial carrier cohort: prepare 2,048 indexed workers, wake
  the existing first 1,024 immediately after the exact decrement, require all
  of them to remain blocked for the existing stability interval, then release
  the other 1,024 through the existing global gate. This differs from the
  rejected 2,048-at-once experiment by preserving the qualified first wave and
  adding a second allocation window. Keep write cohorts at 512, retain one CVE
  decrement and one victim observation, and reject any non-indexed payload.
- Reject the two-wave carrier cohort. Four consecutive first-attempt primitive
  probes passed, but the fifth artefact
  `primitive-probe-20260824-144131-851413.txt` missed victim 0. Its preparation
  proved all 2,048 workers blocked, with the first 1,024 stable before the
  second wave, but the target still received the exact original pointer and
  cookie. No buffer was freed and no semantic write occurred; the controlled
  reboot completed. Restore 1,024 workers. Additional allocation coverage is
  not causal because the node sometimes does not become reclaimable.
- The acceptance target is now five consecutive strict runs below 15 seconds;
  reliability and duration consistency take priority over further latency
  reduction. Continue to require the real ReSukiSU foreground transition,
  **Working**, **LKM**, **Jailbreak mode**, Prism foreground, and its first
  completed visible **Active** frame.
- Correct the previous node-lifetime diagnosis. Successful and failed cohort
  observations both contain 81 Binder responses, no victim reference response
  and the same transaction order. Across 145 saved successful observations,
  140 indexed replacements were workers 0–31; five saved misses retained the
  original pointer. The upstream KASAN trace frees the prematurely released
  node in `binder_thread_read`, while the current implementation wakes every
  spray worker before enabling that read. The nominally blocked cohort can
  therefore succeed through incidental allocations that reach the kernel
  after the target starts reading; widening an entirely pre-read cohort does
  not address that race.
- Candidate: retain exactly 1,024 indexed carriers and one decrement, but use
  a 512/512 target-gated allocation overlap. Prove the first 512 entered and
  remained stable, validate the exact `BR_NOOP`/`BR_FAILED_REPLY`, publish the
  existing no-free and read gates, and hold the target immediately before its
  Binder read. Only after that target-ready receipt, publish its read-go byte
  and wake the remaining 512 workers. Require all 1,024 state-2 carriers,
  the target-ready and read-go fields, the unchanged indexed-payload gate and
  the same one-retained-worker cleanup. This changes allocation chronology,
  not CVE count, payload semantics or failure acceptance.
- Reject the first target-ready-only 512/512 overlap. It passed twice, then
  `primitive-probe-20260824-150458-805687.txt` completed every overlap field
  but still delivered the original pointer. Waking the late cohort near the
  read does not prove the victim has already been freed.
- Add an exact Binder-work boundary instead. The first attempted 68-byte and
  72-byte boundary reads returned only `BR_NOOP` on this vendor kernel and
  stopped safely before dequeuing work. Use the already proven 128-byte read:
  it returns exactly `BR_NOOP`, `BR_INCREFS`, `BR_ACQUIRE`, `BR_INCREFS`,
  `BR_ACQUIRE`, drains the victim work plus the following two tail-node
  notifications, and cannot also fit the controlled transaction. Require the
  first two pointer/cookie pairs to be the exact tail nodes, proving the victim
  was released without a userspace reference notification. Migrate the target
  from CPU 2 to CPU 1, wake and retain the second cohort on CPU 2, then publish
  a separate continuation byte and migrate the target back before delivery.
- The exact boundary candidate passed five consecutive first-attempt primitive
  probes:
  `primitive-probe-20260824-151458-990360.txt`,
  `primitive-probe-20260824-151626-603665.txt`,
  `primitive-probe-20260824-151743-400357.txt`,
  `primitive-probe-20260824-151859-896178.txt` and
  `primitive-probe-20260824-152013-825253.txt`. Every boundary reported
  `victim_released=1`, `responses=5`, CPU `2->1`; final indexed workers were
  6, 4, 13, 15 and 30; arbitrary read and root profiling passed; and every
  planned recovery reboot was confirmed clean. Promote this exact APK to the
  strict Root-to-completed-visible-Active five-run gate.
- Strict series `20260824-162047` passed five consecutive fresh boots at
  13.009, 13.283, 14.870, 12.855 and 13.074 seconds. Every run showed the
  streamed ReSukiSU-to-Prism foreground round trip, a completed Active frame,
  Manager **Working / LKM / Jailbreak mode**, four verified writes and exact
  terminal cleanup. The 14.870-second tail contained five safely detected
  write-reclaim misses; the retry path added about 1.57 seconds and recovered
  without weakening any write predicate.
- Do not treat that first series alone as final reliability evidence. An
  unchanged confirmation series `20260824-163349` passed four boots at 12.603,
  13.823, 13.696 and 12.552 seconds, then victim 0 missed before any semantic
  write. Its exact five-response boundary still reported
  `victim_released=1`, but the final transaction retained the original
  pointer. The bound process-teardown watchdog performed the controlled
  `reboot,shell`. This resets qualification.
- Reject the 32/992 carrier split. The first actual primitive observation
  showed worker 0 had replaced the freed node, proving that `state=2` is a
  userspace pre-syscall marker rather than proof that an awakened worker has
  already allocated. Removing that invalid index restriction exposed a real
  original-pointer miss on the next probe. Restore the allocator-conditioning
  512/512 split.
- Extending the post-boundary dwell from 20 to 100 milliseconds passed five
  consecutive first-attempt primitive probes, but strict series
  `20260824-170244` failed on its second boot. The victim boundary was exact,
  yet the delivered pointer and cookie were both zero. An unrelated allocator
  had therefore consumed the freed slot during the target-file/coordinator-file
  round trip. A longer fixed sleep cannot close the free-to-wake gap.
- Replace that filesystem round trip with an eventfd created by the harness
  process and transferred to the raw target through an explicit Binder
  transaction. Immediately after the exact 128-byte boundary read, while
  still on CPU 2, the target writes the eventfd. The coordinator is blocked on
  that descriptor on CPU 1 and publishes the second spray gate before it
  waits for the detailed file receipt. Continue only when both
  `boundary_signal=1` and the ordered
  `victim_released=1 early_reclaim=0 signal=1` record pass. The first attempt
  to carry the descriptor in the bind Intent failed before the CVE because
  Android rejected the descriptor transport; do not repeat it.
- The Binder-transaction eventfd candidate passed five consecutive
  first-attempt primitive probes:
  `primitive-probe-20260824-161359-368575.txt`,
  `primitive-probe-20260824-161516-372104.txt`,
  `primitive-probe-20260824-161623-277224.txt`,
  `primitive-probe-20260824-161732-012495.txt` and
  `primitive-probe-20260824-161840-584537.txt`. All reached arbitrary read and
  root profiling, then completed the planned clean reboot. The first retained
  receipt showed `signal=1` and indexed worker 8.
- Final strict series `20260824-171850` passed five consecutive fresh boots at
  14.370, 13.149, 13.242, 14.761 and 12.513 seconds (mean 13.607, median
  13.242). Indexed victim-0 workers were 26, 25, 32, 7 and 5. Every run had an
  exact eventfd/free boundary, four of four verified writes, a real streamed
  ReSukiSU-to-Prism foreground round trip, a completed visible Active frame,
  Manager **Working / LKM / Jailbreak mode** with no **Not installed**, and
  clean durable terminal proof with the module loaded, finalised and unloaded
  and all primitive descriptors retired. Internal write misses were 4, 1, 1,
  5 and 0; this explains the two slower runs without hiding them. This exact
  candidate satisfies the revised under-15-second reliability target.
- After adding `boundary_signal` to both ordered prepare-result parsers, rebuild
  and qualify the exact shipped candidate again. APK SHA-256
  `8d09bf39ba9b3051be8f49c4ce8e85f69303b74ecdb61039e533ef904220bee0`
  passed strict series `20260824-173044` on five distinct fresh boots at
  14.775, 13.230, 13.524, 13.099 and 12.694 seconds (mean 13.464, median
  13.230, maximum 14.775). Indexed victim-0 workers were 31, 7, 9, 8 and 31;
  internal write misses were 4, 1, 1, 0 and 0. Every run passed the exact
  eventfd/free boundary, four verified writes, streamed ReSukiSU-to-Prism
  foreground order, frame-metrics Active completion, Manager **Working / LKM /
  Jailbreak mode** with no **Not installed**, durable normalisation and full
  descriptor, object and watchdog retirement. The installed APK hash matched
  the host build after the series, and the live Prism UI reported **Active**,
  Shizuku **Running** and ReSukiSU **Installed**. This is the final qualifying
  evidence set for the under-15-second target.
