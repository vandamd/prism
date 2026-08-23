# Raw Binder holder allocation research

## Conclusion

Sixty-four calls to `open("/dev/binder")` do create 64 independent
`binder_proc` objects. They therefore create 64 independent `(proc, node)`
`binder_ref` records for the controlled node, just as 64 isolated processes
do. This establishes equivalent Binder ownership, but it does **not** establish
equivalent slab placement.

The most important source-level reason is cache aliasing. On the arm64 layout
used here, `binder_ref` is 120 bytes, `binder_buffer` is 104 bytes, and
`binder_node` is 128 bytes. All three therefore use `kmalloc-128`. The driver
allocates a `binder_buffer` descriptor while constructing every transaction,
then allocates the target's new `binder_ref` objects while translating the
transaction's Binder objects. Creating each raw context also allocates its
initial `binder_buffer` descriptor at `mmap()` and its callback `binder_node`.
Those allocations are not neutral scaffolding: they consume and return objects
from the same slabs whose geometry the disclosure later observes. See the
[`binder_ref` and `binder_node` definitions](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_internal.h),
the [`binder_buffer` definition](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_alloc.h),
and the [`binder_alloc_new_buf_locked()` split allocation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_alloc.c).

The accepted isolated design creates and retires this same-cache state through
64 zygote-created processes, framework bootstraps, Binder pool threads, and
scheduler placements. The raw design creates most of it serially through one
app and a small number of native threads. SLUB serves the fast path from a
per-CPU freelist, so equal object counts with different allocation CPUs,
ordering, and intervening frees need not occupy the same pages or offsets.
The [SLUB allocation fast path](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/mm/slub.c)
explicitly reads the current CPU's `cpu_slab` freelist.

This makes allocator history, allocation CPU, and transaction lifetime more
plausible causes than a missing strong-reference command.

## What an independent `binder_proc` does and does not provide

`binder_open()` allocates a new `binder_proc` on every open and gives it its
own locks, node tree, reference trees, work lists, statistics, and
`binder_alloc`. Repeated opens from the app are permitted even though every
object records the same group leader in `proc->tsk`, the same `proc->pid`, and
the same file credentials. Isolated services instead record distinct group
leaders, PIDs, and credentials. The source only suppresses duplicate per-PID
debugfs entries; it does not merge the `binder_proc` objects. See
[`binder_open()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c)
and the [`binder_proc` definition](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_internal.h).

Each `binder_proc` has independent `refs_by_node` and `refs_by_desc` trees.
`binder_inc_ref_for_node()` looks up `(target_proc, node)`, allocates a new
`binder_ref` with `kzalloc(..., GFP_KERNEL)` when absent, and inserts it into
those per-proc trees. Thus 64 raw contexts can represent the required 64
independent references even though they share a Linux process. The allocation
itself occurs synchronously inside the **sending** thread's Binder ioctl while
`binder_translate_binder()` or `binder_translate_handle()` translates objects
for the target transaction. It is not deferred until the receiver calls
`readStrongBinder()`. See
[`binder_inc_ref_for_node()` and the translation paths](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c).

The practical consequence is:

- The target `binder_proc` determines whether a new reference is needed, its
  handle, trees, and lifetime.
- The current sender task and CPU normally determine which global
  `kmalloc-128` freelist supplies the object.
- A `binder_proc` is not a private slab or slab-allocation arena.

The current raw and isolated spray paths both pin the Harness sender to CPU 2,
so the controlled transaction's new `binder_ref` allocations should start from
the same per-CPU allocation domain. However, the CPU 2 freelist can already be
different because raw context creation, mapping, callback-node creation,
bootstrap transactions, and their frees have a different history from zygote
service creation.

## Shared process state still matters

Every raw mapping has an independent `binder_alloc`, but
`binder_alloc_mmap_handler()` stores the mapping's `vma->vm_mm`. The 64 raw
allocators therefore point into distinct VMAs of the same `mm_struct`; the
isolated allocators point into 64 address spaces. Binder pages are allocated
and inserted while holding that target address space's mmap lock. This changes
page-fault, lock, and scheduling behaviour even when transaction contents are
identical. See
[`binder_mmap()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c)
and [`binder_alloc_mmap_handler()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_alloc.c).

Binder threads are also per `binder_proc` but keyed by `current->pid` and store
the current task. A single native receiver that visits all 64 file descriptors
therefore creates one `binder_thread` in every raw `binder_proc`, all referring
to the same receiver task. The isolated services execute through distinct
tasks, thread pools, transaction stacks, priorities, and scheduler histories.
The driver's target selection, priority inheritance, wake-up, freeze state,
and vendor hooks all receive those different task objects. See
[`binder_get_thread()` and `binder_ioctl()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c).

These process differences are real, but they are mainly indirect explanations
for `binder_ref` placement. The reference allocation uses plain `GFP_KERNEL`,
not `GFP_KERNEL_ACCOUNT` or `__GFP_ACCOUNT`. Android 5.10's memcg slab hook only
charges an object when the allocation has `__GFP_ACCOUNT` or its cache has
`SLAB_ACCOUNT`. Therefore separate isolated-app memory cgroups do not directly
partition or charge these `binder_ref` allocations in the common source. See
the [`GFP_KERNEL` definitions](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/include/linux/gfp.h)
and the [memcg slab hook](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/mm/slab.h).

There is one device-specific caveat: Android common includes vendor hooks at
Binder process, transaction, new-reference, and kmalloc-cache selection seams.
The common source cannot prove that this device has no registered OEM hook
which distinguishes tasks or substitutes a cache. This should be measured,
not assumed.

## Transaction lifetime changes the same cache

Before translating Binder objects, `binder_transaction()` allocates the
target transaction buffer. Splitting a free Binder address range allocates a
new `struct binder_buffer` with `kzalloc(..., GFP_KERNEL)`. Freeing the incoming
buffer can coalesce the range and `kfree()` the redundant descriptor. On arm64,
that descriptor shares `kmalloc-128` with the subsequent `binder_ref` burst.
See
[`binder_alloc_new_buf_locked()` and `binder_free_buf_locked()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_alloc.c).

This explains why the earlier one-way raw path was structurally different:

1. A one-way call sets `TF_ONE_WAY`, has no `from` transaction-stack link,
   uses the target's default priority, consumes asynchronous buffer space, and
   is queued through the node's `has_async_transaction`/`async_todo` rules.
2. Submission can complete while incoming buffers and their `binder_buffer`
   descriptors remain live. A burst across distinct callback nodes can
   therefore allocate most or all references before those descriptors are
   reclaimed.
3. The isolated baseline is serial and synchronous: send one batch, execute
   it, retain proxies, release its incoming buffer, send a reply, then submit
   the next batch.

The current raw implementation has moved to serial synchronous request/reply,
which removes the largest lifetime difference. Kernel synchronous and one-way
queueing are defined in
[`binder_transaction()` and `binder_proc_transaction()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c).

It still does not exactly reproduce Android 14 libbinder's synchronous
ordering. In `IPCThreadState::executeCommand()`, Android 14 explicitly calls
`buffer.setDataSize(0)` **before** `sendReply()`. This queues
`BC_FREE_BUFFER` before `BC_REPLY`; the source comment says this avoids a race
where the client sends another transaction before the old space is freed. The
raw receiver currently writes `BC_REPLY` before `BC_FREE_BUFFER`. Because the
driver can wake the caller while processing `BC_REPLY`, this reversal permits
different interleaving before the buffer descriptor is coalesced and its
temporary Binder-object references are released. See
[`IPCThreadState::executeCommand()`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android14-release/libs/binder/IPCThreadState.cpp).

The raw write-only reply path also leaves its `BR_TRANSACTION_COMPLETE` to be
drained later or discarded at context teardown, whereas libbinder's serving
loop consumes completion work. This is not a `binder_ref` ownership omission,
but it means the surrounding kernel allocation and work lifetime is not yet an
exact match.

## `readStrongBinder()` protocol audit

No reference-count command appears to be missing.

For a received `BINDER_TYPE_HANDLE`, Android 14 performs this sequence:

1. `Parcel::readStrongBinder()` calls `unflattenBinder()`.
2. `unflattenBinder()` calls `ProcessState::getStrongProxyForHandle()`.
3. A new `BpBinder` constructor calls `incWeakHandle()`, which queues
   `BC_INCREFS`.
4. Its first strong userspace reference calls `BpBinder::onFirstRef()`, which
   queues `BC_ACQUIRE`.
5. Releasing the incoming Parcel queues `BC_FREE_BUFFER`.
6. The last strong reference and proxy destruction later queue `BC_RELEASE`
   and `BC_DECREFS`.

See
[`Parcel::unflattenBinder()` and `readStrongBinder()`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android14-release/libs/binder/Parcel.cpp),
[`ProcessState::getStrongProxyForHandle()`](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android14-release/libs/binder/ProcessState.cpp),
[`BpBinder` construction and reference callbacks](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android14-release/libs/binder/BpBinder.cpp),
and the [`IPCThreadState` handle commands](https://android.googlesource.com/platform/frameworks/native/+/refs/heads/android14-release/libs/binder/IPCThreadState.cpp).

The raw holder now sends exactly those ownership commands and pairs them at
teardown. `BC_INCREFS_DONE` and `BC_ACQUIRE_DONE` are not required here: the
driver uses those to acknowledge `BR_INCREFS` and `BR_ACQUIRE` for a process's
**local Binder nodes**, not to retain received remote handles. Death
notification is also not implicit in `readStrongBinder()`; it is requested
only by `linkToDeath()`.

The remaining discrepancy is therefore command ordering and transaction-loop
behaviour, not a missing `readStrongBinder()` ownership primitive. A userspace
`BpBinder` cache is also unnecessary for the kernel layout once the raw
commands have been accepted; it changes userspace lifetime management, not the
existing kernel `binder_ref` fields.

## Ranked explanation for the observed mismatch

1. **Same-cache bootstrap history and CPU placement.** Raw `binder_buffer` and
   callback `binder_node` objects are created serially through one app context;
   isolated equivalents and framework Binder state are created across many
   scheduled processes. These objects share `kmalloc-128` with `binder_ref`.
2. **Transaction sequencing.** The old one-way burst kept a different set of
   buffer descriptors live. The new synchronous path is closer, but reverses
   libbinder's free-before-reply order and does not drain reply completion.
3. **Receiver task and scheduler topology.** One raw receiver task is installed
   into all 64 `binder_proc` thread trees; the baseline has 64 process tasks.
   Allocation and free CPUs can consequently differ even when the sender is
   pinned.
4. **Per-allocator and address-space history.** Raw allocators share one
   `mm_struct`; isolated allocators have separate mappings and mature Binder
   state. This changes mmap locking, Binder-buffer subdivision, and auxiliary
   allocation timing.
5. **Direct memcg separation.** Unlikely in the common source because
   `binder_ref` uses unaccounted `GFP_KERNEL`. Treat an OEM allocator hook as a
   separate, measurable exception.

## Non-mutating experiments

Run these only in the disclosure-only path; none requires a kernel write
primitive or operating the vulnerable unwind.

1. **Record the actual `kmalloc-128` stream.** Trace Binder transactions,
   transaction-buffer release, kmalloc/kfree, and scheduler switches. Correlate
   allocations from `binder_alloc_new_buf_locked()`, `binder_new_node()`, and
   `binder_inc_ref_for_node()` by timestamp, CPU, caller TID, and address. The
   decisive output is the ordered sequence of 104-, 120-, and 128-byte objects
   on each slab page, not only total counts.
2. **Verify command parity.** Trace `binder_command` for one isolated holder and
   one raw holder from receipt through teardown. Confirm
   `BC_INCREFS`, `BC_ACQUIRE`, `BC_FREE_BUFFER`, `BC_REPLY`, and later
   `BC_RELEASE`, `BC_DECREFS`, including their order. Also confirm whether the
   raw context leaves a transaction-complete item unread.
3. **Measure allocation and free CPUs.** Record the Harness sender CPU, raw
   receiver CPU, and each isolated Binder thread CPU for every batch. Do not
   infer the raw receiver affinity from the sender pin. Compare a cohort where
   target processing is observed on CPU 2 with one where it is naturally
   distributed.
4. **Match libbinder ordering only.** Compare the current synchronous raw path
   with a disclosure-only variant whose command order is acquisitions,
   `BC_FREE_BUFFER`, then `BC_REPLY`, and which drains completion. Hold all
   counts, context bootstrap timing, filler order, and CPU policy constant.
5. **Separate process topology from libbinder.** Compare four 64-holder
   cohorts: zygote plus Java read, zygote plus raw JNI protocol, one process
   plus raw contexts, and 64 minimal native processes plus raw contexts. This
   factorial comparison distinguishes task/mm topology from proxy protocol and
   framework bootstrap.
6. **Snapshot per-proc state read-only.** Use Binder debugfs before delivery,
   after acquisition, and after buffer release to count refs, nodes, threads,
   and allocated buffers for every context. The driver intentionally prints
   all same-PID contexts under the shared PID entry. Verify that each design
   adds the expected new refs and identify unrelated long-lived refs.
7. **Check for vendor-cache substitution.** Observe the actual slab cache name
   or allocation trace for `binder_ref`. If it is not the normal
   `kmalloc-128`, investigate the registered Android vendor hook before using
   common-kernel memcg conclusions.

The highest-value next comparison is experiment 4 combined with experiments 1
and 3. It tests the remaining exact libbinder discrepancy while directly
showing whether the controlled references consume the intended per-CPU
freelist positions.
