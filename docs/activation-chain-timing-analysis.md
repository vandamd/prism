# Activation chain timing analysis

## Conclusion

The current chain cannot reliably complete in under one minute without changing
its safety model or exploit shape.

- The best defensible estimate for the fastest **current, safety-preserving
  activation** is **about 90–92 seconds** from controller start to return to
  Prism.
- From the user's Root tap, the corresponding best estimate is **about 94–96
  seconds**, including the activity startup and the controller's initial
  bridge proof.
- The corresponding fastest estimate for the **root chain itself**, from
  harness dispatch through strict cleanup, is **about 67 seconds**.
- The fastest complete activation actually observed in the supplied evidence
  was **94.786 seconds**. It included one safe kernel-write miss and retry.
- A purely mathematical estimate obtained by deleting all explicit settling
  and validation sleeps is about **56 seconds from controller start**, or
  **59–60 seconds from the Root tap**. This is not a valid operational target:
  several sleeps stand in for Binder deferred-release completion, for which
  this chain has no event or API proof.
- There is no rigorous physical lower bound in the available evidence. Android
  and Linux specify Binder ordering and blocking semantics, but they do not
  guarantee transaction, process-death, deferred-release, `fsync`, module-load,
  or scheduling latency.

In practical terms, **roughly 105–110 seconds** is the present steady-state
expectation from controller start, and **90–92 seconds is the unusually lucky
floor**. The fresh-boot test harness adds reboot, Shizuku, app-launch, and UI
work and therefore reports much larger totals.

## Scope and evidence

This analysis uses 14 successful fresh-boot runs:

- Ten runs in
  [`artifacts/prism-runs/20260823-000937`](../artifacts/prism-runs/20260823-000937/summary.json).
- Four runs in
  [`artifacts/prism-runs/20260823-005541`](../artifacts/prism-runs/20260823-005541/summary.json).

The checkpoints use `SystemClock.elapsedRealtime()`, which is the correct
Android clock for elapsed intervals and includes device sleep
([Android `SystemClock` reference](https://developer.android.com/reference/android/os/SystemClock.html)).
The local implementation writes and synchronises every checkpoint in
[`HarnessService.java`](../app/src/main/java/com/vandam/prism/HarnessService.java),
so the measurements include checkpoint I/O overhead.

The files in `~/Downloads/light stuff/` establish provenance rather than
timing. `boot.img` is a 96 MiB Android boot image with a version 4 header and an
ARM64, 4 KiB-page kernel image. Its SHA-256 is
`ae2f5a99048d8ed2c9847b14a4d09d385c8dbfc8c849d57d9abb9d544c974868`.
This is consistent with the exact Android 12/5.10 profile recorded in
[`resukisu/README.md`](../resukisu/README.md). Android documents version 4 as an
Android 12 GKI boot-image format
([AOSP boot image header](https://source.android.com/docs/core/architecture/bootloader/boot-image-header)).
The ABL and small partition backups contain no per-stage timing. The job-store
backup is Android Binary XML and explains why JobScheduler integrity is a
guarded precondition, but does not constrain a successful run's lower bound.

## What the reported totals contain

`tools/prism-runs` starts its duration before `fresh_reboot()`, then starts
Shizuku, opens Prism, waits for UI preflight, taps Root, waits for activation,
and collects evidence. The run duration is therefore not the activation
duration; see [`tools/prism_runs.py`](../tools/prism_runs.py).

| Measurement | Minimum | Median | Mean | Maximum |
| --- | ---: | ---: | ---: | ---: |
| Fresh-boot harness, 14 runs | 154.699 s | 170.117 s | 169.284 s | 179.848 s |
| Root tap to Prism foreground and active | 98.191 s | 113.813 s | 114.085 s | 125.618 s |
| Controller start to return-to-Prism command | 94.786 s | 109.982 s | 110.372 s | 121.711 s |
| Harness dispatch to `chain-pass` | 70.792 s | 85.936 s | 86.267 s | 97.657 s |
| Strict postflight only | 11.350 s | 11.409 s | 11.413 s | 11.517 s |

The overall `duration_seconds` measurement begins before reboot and therefore
cannot be interpreted as activation-only time. By contrast,
`foreground.jsonl` starts inside `wait_for_activation()` immediately after the
Root tap. Its final Prism-active timestamp is the supplied evidence's closest
user-visible activation interval. The controller's `controller-start`
checkpoint follows 3.3–4.1 seconds later, after activity startup and a fixed
1.25-second bridge proof, so controller timing slightly understates
user-perceived time.

The fastest complete run is
[`run-006`](../artifacts/prism-runs/20260823-000937/run-006/prism-controller.trace):

- Controller start: 27.620 s after boot.
- Harness dispatch pass: 39.907 s.
- Root chain pass: 110.699 s.
- Postflight pass: 122.049 s.
- Return-to-Prism command pass: 122.406 s.
- Controller-to-return duration: 94.786 s.

## Exact current chain

### 1. Controller preflight

The controller verifies the boot ID, JobScheduler count, device health,
`update_engine` donor identity, `ueventd`, the `/vendor` label, and absence of a
live rescue module. It then opens the app bridge, creates guarded shell control
files, starts an arm-lock holder, launches the `app_process` shell helper,
starts an independent reboot watchdog, samples a stable Prism process cohort,
and dispatches the harness. The complete flow is in
[`DirectReSukiSuActivation.java`](../app/src/main/java/com/vandam/prism/DirectReSukiSuActivation.java).

The dominant fixed preflight cost is `waitForStableProcess(update_engine)`,
which requires ten seconds with an unchanged PID and start time. Across the 14
runs, controller preflight took 12.186–12.549 seconds.

### 2. Binder object and address acquisition

The harness then performs three dependent acquisitions:

1. It grooms and reclaims event-poll objects, leaks 1,152 records, and analyses
   them to locate a live kernel `file` and `epitem`.
2. It creates a Binder-node cohort, retires references through the vulnerable
   transaction-unwind path, and analyses another 1,152 records to locate the
   controlled `binder_node`.
3. It constructs 1,024 blocked fake-control buffers, selects the exact freed
   buffer, and converts the dangling-node condition into a retained arbitrary
   kernel-read primitive.

This shape follows directly from CVE-2024-46740. The upstream fix explains that
an unchecked raw-data copy can corrupt Binder's offsets, after which unwinding
can decrement arbitrary nodes, release them prematurely, and leave dangling
pointers
([upstream Linux fix](https://github.com/torvalds/linux/commit/4df153652cc46545722879415937582028c18af5),
[Linux CVE announcement](https://lists.openwall.net/linux-cve-announce/2024/09/18/43)).
The affected Android 12/5.10 driver also makes the relevant process, node, and
work queues lock-protected kernel state
([AOSP Android 12/5.10 Binder source](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c)).

### 3. Private credential and target profiling

Once arbitrary read is retained, the app and shell helper authenticate over a
loopback socket. The harness validates a private shell credential, identifies
the current Binder process, adopts the credential and security targets,
profiles the ctlbuf rescue resources, derives the KASLR slide, and publishes a
ReSukiSU stage plan.

The chain has real cross-process serialization here. AOSP specifies that a
synchronous Binder call blocks until its reply, while asynchronous calls on a
single node are serialized even when several Binder threads exist
([AOSP Binder threading](https://source.android.com/docs/core/architecture/ipc/binder-threading),
[AOSP Binder overview](https://source.android.com/docs/core/architecture/ipc/binder-overview)).
Consequently, the service and transaction fan-out cannot all collapse into one
parallel CPU burst.

### 4. Eighteen deferred victims and six guarded writes

The harness launches 18 distinct raw-client services, collects their Binder
pointers and cookies, and caches 18 potential victim nodes. It then requires
six successful controlled writes:

1. Replace the helper `cred` slot.
2. Clear the donor credential repair/link word.
3. Replace the helper `real_cred` slot.
4. Clear the donor credential repair/link word again.
5. Borrow the task-security pointer needed for the ReSukiSU transition.
6. Borrow the module-inode security pointer.

The exact targets and per-step validation are in
[`direct.cpp`](../app/src/main/cpp/direct.cpp). Each attempt retires one raw
client, waits for its process identity to disappear, and then has a fixed
1.5-second deferred-release settlement before touching the dangling Binder
state. A miss is accepted only while `buffer_freed=0`; it releases the fake
spray and consumes another victim.

Across the evidence:

- 84 writes succeeded and 44 victims missed: an effective per-victim success
  rate of 65.6%.
- A run averaged 3.14 misses.
- Only one of 14 runs had no write miss.
- Regression over the 14 runs assigns approximately **3.27 seconds per miss**.

The collection/caching interval before write 1 is also bimodal: 12 runs took
12.75–13.03 seconds, while two took 3.51–3.59 seconds. The approximately
9.3-second difference is genuine and not explained by write misses. It is the
largest unexplained timing opportunity in the current evidence.

### 5. Root window and ReSukiSU load

After write 4, the controller validates and arms a root watchdog. In the root
window it stages the relocated KernelSU module for the observed kernel base,
stops and proves the `update_engine` donor stable, releases writes 5 and 6,
loads the staged module with `finit_module`, hands off through the recognised
manager UID, and proves the ReSukiSU action returned success.

The exact LP3 loader copies and relocates the embedded module, synchronises its
mapping, loads it, waits for KernelSU manager recognition, and grants root; see
[`light-phone-iii.patch`](../resukisu/patches/light-phone-iii.patch). This
segment is not the main bottleneck: the best observed root-window-to-action
duration was 9.428 seconds.

### 6. Normalisation, retirement, and strict postflight

The rescue module repairs seven blocked `sendmsg` workers, restores SELinux
collateral, unloads, resumes the donor, and restores the helper to its original
shell identity. The controller verifies the finalisation, donor-resume, and
normalisation proofs; retires the helper and app-side processes; waits 1.5
seconds for terminal process settlement and another second before native
cleanup; and accepts the exact terminal-clean proof.

Finally, strict postflight proves the exact baseline, waits a deliberately
fixed ten seconds, proves it again, invokes `ksud debug version`, checks jobs
and health, and records a clean receipt. This accounts for almost all of the
observed 11.35–11.52-second postflight interval.

## Timing decomposition

The table uses the minimum and median duration of each independently observed
phase. Minima from different runs are useful as a compositional lower envelope,
but they did not all occur in one run.

| Phase | Minimum | Median | Main cause |
| --- | ---: | ---: | --- |
| Controller preflight | 12.186 s | 12.317 s | Fixed 10-second donor stability proof |
| Harness launch | 0.210 s | 0.247 s | Service dispatch and first checkpoint |
| Epitem acquisition | 7.254 s | 7.454 s | Process death, fixed 1.5-second settle, 1,152-record reclaim and analysis |
| Owner hand-off | 0.461 s | 0.533 s | First-owner cleanup and second-owner bind |
| Binder-node acquisition | 12.073 s | 12.478 s | 64 isolated processes, 1,536 fillers, 1,152 decrements and leak analysis |
| Arbitrary-read acquisition | 3.464 s | 3.550 s | Retirement proof, fixed 1.5-second settle, 1,024-control spray |
| Credential target and security plan | 4.287 s | 4.975 s | Helper handshake, process profiling, KASLR plan |
| Deferred-victim collection | 3.506 s | 12.879 s | Eighteen services, pointer collection and node caching; bimodal |
| Writes 1–4 | 19.334 s | 29.327 s | Four fixed 1.5-second settles plus probabilistic retries |
| Root window, writes 5–6, activation | 9.428 s | 11.591 s | Donor freeze, two settles/writes, module activation |
| Normalisation and terminal cleanup | 3.984 s | 4.222 s | Rescue module, helper/process retirement, fixed 2.5 seconds |
| Result collation | 0.247 s | 0.315 s | Proof serialization and bridge reads |
| Strict postflight | 11.350 s | 11.406 s | Fixed 10-second clean dwell |
| Close and watchdog disarm | 0.248 s | 0.258 s | Receipt, bridge close, watchdog retirement |

Summing the individual minima gives **88.032 seconds** before the final
return-to-Prism command. This is optimistic because those minima came from
different runs.

## Lower-bound derivation

### Safety-preserving current-code estimate

A simple model of the measured root-chain duration is:

```text
chain seconds ~= 77.514 + 3.265 * write misses - 10.564 * fast victim collection
```

The root-mean-square residual is about 2.01 seconds. A zero-miss run with the
fast victim-collection outcome therefore estimates **66.95 seconds** for the
chain. Adding the best measured controller preflight, strict postflight,
bridge/watchdog close, and return command gives approximately **90.8 seconds**.
Because this is an extrapolated combination not present in a single trace, the
honest result is **90–92 seconds**, not a point estimate.

This also agrees with the fastest observed run: 94.786 seconds minus one
modelled 3.27-second miss is 91.52 seconds.

### Explicit code-imposed lower bound

From controller start, the successful path contains at least **34.5 seconds of
unconditional sleeps**:

| Sleep | Total |
| --- | ---: |
| Stable `update_engine` identity | 10.0 s |
| Epitem-client deferred release | 1.5 s |
| Pre-arbitrary-read retirement settle | 1.5 s |
| Six raw-client deferred-release settles | 9.0 s |
| Terminal process retirement settle | 1.5 s |
| Pre-native-cleanup settle | 1.0 s |
| Strict postflight dwell | 10.0 s |
| **Total** | **34.5 s** |

This 34.5 seconds is a true current-code lower bound, but not the full bound:
thousands of Binder operations, service starts, process exits, CPU-affinity
changes, file synchronisations, module relocation/loading, and proof reads must
still execute.

Subtracting all 34.5 seconds from the 90.8-second safety-preserving estimate
produces the approximately **56.3-second unsafe mathematical floor**. It does
not demonstrate that a correct 56-second implementation exists. In particular,
process exit precedes Binder's deferred release work, which is exactly why the
source inserted the 1.5-second settlements.

The top-level activation also waits 1.25 seconds for its bridge proof before
the Direct controller starts. This makes the complete Root-tap path's explicit
sleep floor **35.75 seconds**, and puts the equivalent unsafe user-visible
estimate at roughly **59–60 seconds** rather than 56.3 seconds.

### Why there is no stronger physical/API bound

The current trace records coarse stage boundaries, not the time of individual
Binder ioctls, scheduler wakeups, deferred-work completion, page faults, or
`fsync` operations. The AOSP Binder contract defines synchronous blocking,
asynchronous serialization, and thread-pool behaviour, but no maximum or
minimum latency. Linux likewise provides no timing guarantee for process death,
deferred Binder cleanup, `finit_module`, or module initialisation. A physical
bound would require hardware counters and kernel/user-space tracing of every
dependency, and would still be conditional on CPU frequency, thermal state,
storage state, and scheduler load.

## Where future investigation would pay off

No implementation is proposed here, but the timing evidence ranks the possible
areas clearly:

1. **Explain the 9.3-second deferred-victim bimodality.** It is the largest
   observed non-retry variance and occurs before write 1. A reliable fast path
   would lower both median and floor without weakening the postflight proof.
2. **Reduce miss probability.** The current average of 3.14 misses costs about
   10.3 seconds per run. A zero-miss path is already present, but occurred only
   once in 14 samples.
3. **Replace fixed Binder settlements with positive completion evidence.** The
   epitem, six write-victim, and terminal settlements account for 12 seconds.
   Removing them without a replacement proof is unsafe; adding an observable
   kernel completion condition is the meaningful route.
4. **Reconsider the two 10-second policy dwells separately from the exploit.**
   The donor-stability and postflight waits cost 20 seconds by design. Shorter
   waits would move the user-visible result directly, but change the assurance
   level rather than make the exploit intrinsically faster.
5. **Do not optimise ReSukiSU loading first.** The module stage/load and manager
   hand-off sit inside a roughly 9–12-second root-window segment that also
   contains two guarded writes and donor proofs. It is not where most of the
   minute is spent.

The central conclusion is therefore stable: with the current six-write,
proof-heavy design, **sub-minute completion is outside the defensible envelope**.
Theoretical sub-minute timing appears only after discounting safety settlements,
and a comfortably sub-minute user experience would require a materially
different acquisition/write strategy rather than ordinary micro-optimisation.
