# Standalone C++ chain design

## Objective

Run the existing CVE-2024-46740 chain from pushed artefacts, without installing a
new APK for each iteration. Preserve the accepted allocator geometry, mutation
invariants, rescue plan, strict cleanup proof, and controlled-reboot fail-safe.

The public C++ surface remains one deep operation:

```cpp
RunResult run(const RunConfiguration&, EventSink, void*);
```

The CLI and APK JNI layer are adapters. They must not own exploit state or
reimplement phase transitions.

## Process topology

| Native role | Current Android role | Required property |
| --- | --- | --- |
| Controller | `HarnessService` | Owns the state machine, deadlines, receipts, and fail-safe lease |
| Owner A/B | `OwnerService` and `OwnerService2` | Separate Binder processes; own fragment, controlled, filler, and cohort nodes |
| Epitem client A/B | `BatchClientService` and `BatchClient2Service` | Separate Binder processes; saturate the owner pool, queue the native fragment geometry, then retire exactly |
| Raw target | `RawTargetService` | Owns the controlled raw cohort and all victim nodes |
| Raw clients | `RawBClientService` plus 18 siblings | Separate Binder processes; retain, export, queue, and retire victim references |
| Reference holders | 64 isolated services | Separate Binder processes; retain exact reference counts and publish death receipts |
| Anchor holder | `AnchorHolderService` | Retains the kernel anchor until terminal retirement |
| Credential helper | `ShellBridgeMain` command mode | Supplies the accepted shell/donor identity and guarded privileged action |

Start all independent roles concurrently. Use fixed-size `SOCK_SEQPACKET`
control messages and pidfds for liveness. Do not use files as phase signals.

## Binder bootstrap

The shell SELinux domain can open `/dev/binder`, but cannot add a service to the
system ServiceManager. A direct native broker registration returned `-1` and an
audit denial for `{ add }` on `default_android_service`.

The direct framework-broker probe is also closed. `app_process` can call
ActivityManager, but AMS refuses receiver registration because the process has
no `ProcessRecord`, both with its synthetic application thread and with a null
caller. A package-free multi-process Binder graph therefore has no supported
bootstrap on this production build.

Use the installed APK only as a topology adapter: it starts distinct Binder
processes and hands their exact `IBinder` endpoints to one C++ controller. The
adapter performs no grooming, disclosure, arbitrary read/write, mutation,
cleanup, retry, or safety decision. Convert references at the boundary with
`AIBinder_fromJavaBinder`. The standalone CLI remains the controller and
measurement surface once a topology lease is supplied; the APK JNI entry point
uses the same controller directly. Do not claim a package-free pass, and do not
retry ServiceManager names, Binder devices, or unattached ActivityManager
receivers.

## Internal phase boundaries

1. `Topology`: start roles concurrently, exchange exact Binder references, arm
   pidfds and Binder death barriers.
2. `FileEpitemDisclosure`: reproduce the accepted first disclosure and validate
   every derived address.
3. `BinderNodeDisclosure`: reproduce the second geometry and validate the fake
   node mutation before any credential mutation.
4. `ArbitraryAccess`: construct the accepted stale read and per-victim write
   carriers. Batch-cache all victim nodes in one traversal.
5. `MutationTransaction`: perform the four accepted writes with readback gates.
   A partial mutation immediately transfers ownership to the fail-safe path.
6. `PrivilegedAction`: run the staged ReSukiSU action and accept only its exact
   nonce-bound completion receipt.
7. `Normalisation`: load the exact rescue module, restore helper and donor
   identities, retire every carrier, and produce the strict cleanup receipt.

Only `MutationTransaction` may set `unsafe=true`. Once set, normal return is
forbidden until exact cleanup succeeds or the controlled-reboot lease fires.

## Timing budget

| Phase | Budget |
| --- | ---: |
| Native topology and Binder exchange | 0.75 s |
| First disclosure | 2.00 s |
| Second disclosure and arbitrary-read construction | 2.00 s |
| Four writes including recovered misses | 3.00 s |
| Privileged action | 1.00 s |
| Normalisation, retirement, and strict proof | 1.00 s |
| Total | 9.75 s |

Budgets are acceptance bounds, not waits. Each phase advances on positive
evidence and fails closed at its absolute deadline.

## Reliability rules

- Preserve CPU placement, allocation counts, fresh worker lifetime, and object
  destruction order until a five-boot candidate proves a change.
- Never infer Binder cleanup from elapsed time or PID disappearance alone.
- Require Binder death plus unlink plus exact PID/start-time retirement.
- Retain all-or-nothing validation for disclosed pointers and cached victims.
- Never call `commit_creds()` on the split helper leader.
- Never weaken SELinux, capability, module hash, inode label, nonce, boot ID,
  thermal, battery, postflight, or strict-cleanup gates.
- Never wipe, flash, or write a partition. A controlled `adb reboot` is the only
  recovery action.
