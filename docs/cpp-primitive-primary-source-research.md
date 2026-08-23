# CVE primitive redesign: primary-source research

## Conclusion

The fastest safety-preserving redesign that the sources support is:

1. Disclose the file, epitem, and a retained Binder node in one 1,152-record
   cohort by splitting the reclaim between `epitem` objects and `binder_ref`
   objects.
2. Batch the CVE decrements inside each failed Binder transaction. The unwind
   loop can process several already-processed offset slots after one overflow
   has rewritten those slots.
3. Borrow only the helper thread's subjective `task->cred`, leaving
   `task->real_cred` on its private shell credential.
4. Keep using the stopped, disposable root donor. Do not point directly at the
   live `ueventd` credential, because every current pointer write also corrupts
   a word at `replacement + 8`.
5. If the device policy permits `ueventd` to use `init_module`, load from a
   userspace image and remove the module-inode label write. Otherwise retain
   `finit_module` and its inode-label carrier.
6. Let the already privileged rescue module validate and restore the donor
   collateral, borrowed subjective credential, SELinux collateral, and all
   poisoned control buffers before the helper can exit or change credentials.

This reduces the terminal mutation from six successful writes to a defensible
minimum of two with `init_module`: helper `cred` pointer, then donor credential
security pointer. It needs three with `finit_module`, adding the inode-security
carrier. These counts assume the rescue module repairs the deliberately
deferred `+8` collateral. A direct one-write borrow of `ueventd->cred` is faster
but is not safety-preserving because it transiently damages a live system
daemon's shared credential.

The first combined disclosure would remove approximately 11 seconds from the
current measured chain. Reducing six serial write successes to two removes four
allocator-sensitive write cycles. Batching the 1,152-node decrement loops can
remove further ioctl and Binder transaction overhead, but the artefacts do not
measure that portion independently. These changes plausibly move the current
approximately 54-second best path into the low-to-mid 30-second range. They do
not, by themselves, justify a sub-10-second claim: the first disclosure,
arbitrary-read establishment and strict controller bookends already consume
most of that budget.

## 1. What the CVE can batch

The upstream fix adds one missing condition,
`object_offset > tr->data_size`, to the raw-copy check. Its commit description
states the resulting primitive precisely: raw data overwrites the offsets
section, failure unwinds through corrupted offsets, and arbitrary Binder nodes
are decremented and prematurely released
([Linux 5.10 stable fix](https://github.com/gregkh/linux/commit/1f33d9f1d9ac3f0129f8508925000900c2fe5bb0)).

Prism's [`send_single_decrement()`](../app/src/main/cpp/direct.cpp#L3595)
uses two offsets. The first processes a valid target handle. The second is
beyond `data_size`; the vulnerable raw copy overwrites the first offset with
the fake Binder object at byte 24. Failure occurs on the second offset, and the
unwind revisits the now-corrupted first slot.

The driver does not impose a one-decrement limit. On failure it passes the
current `buffer_offset` to `binder_transaction_buffer_release()`
([Binder failure path](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c#3761)).
The release routine walks every offset slot before that point and dispatches
each recovered `BINDER_TYPE_BINDER` object to `binder_dec_node()`
([Binder unwind](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c#2058)).

Therefore one transaction can contain `N` valid objects followed by one
out-of-bounds trigger whose raw copy rewrites the preceding `N` offset entries.
The unwind can then decrement `N` selected nodes. This remains the same CVE;
it does not require a second vulnerability.

This supports two optimisations:

- Replace the 1,152 calls in each disclosure's decrement loop with bounded
  batches. Every batch must still return the expected `BR_FAILED_REPLY`, and
  each selected node must have a unique, known pointer/cookie identity.
- Free several write-victim nodes before one tagged control-buffer spray.
  This is safe only if the chain proves an exact one-to-one mapping between
  every freed victim and a distinct retained replacement before using any of
  them. An unmatched freed node is a live dangling reference, so a partial
  batch must force the existing controlled-reboot path.

The CVE itself is not an arbitrary-write primitive. The driver only performs
reference decrements; Prism obtains reads and writes by reclaiming a freed
`binder_node` and exercising fields in the replacement. Batching can amortise
the free/reclaim work, but it cannot remove that typed-reuse step.

## 2. A combined first disclosure is structurally possible

The first phase already frees a controlled `binder_node` cohort and reads the
stale `node->ptr` and `node->cookie` values through pending transactions. It
currently fills the reclaimed pages with epitems and classifies file and
epitem-shaped records in
[`analyseEpitemLeak()`](../app/src/main/cpp/direct.cpp#L7760). The second phase
uses the same record format, but fills it with Binder references; a repeated
`binder_ref->node` value identifies a retained live node in
[`analyseBinderRefLeak()`](../app/src/main/cpp/direct.cpp#L7600).

The relevant layouts support a mixed reclaim:

- `binder_node` is allocated with `kzalloc()` and contains its userspace `ptr`
  and `cookie` fields
  ([allocation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c#905),
  [layout](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_internal.h#236)).
- `binder_ref` is also allocated with `kzalloc()` and contains a kernel
  `binder_node *node`
  ([allocation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder.c#1490),
  [layout](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/drivers/android/binder_internal.h#332)).
- An epitem is at most 128 bytes and comes from the `eventpoll_epi` cache
  ([epitem layout and cache](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/fs/eventpoll.c#140)).

The exact boot image has `CONFIG_SLAB_MERGE_DEFAULT` disabled, so the epitem
reclaim is cross-cache page reuse, not ordinary cache aliasing. A single slab
page cannot simultaneously belong to `eventpoll_epi` and `kmalloc-128`, but a
1,152-object cohort spans many pages. The reclaim can deliberately dedicate
some freed pages to retained epitems and leave others for `binder_ref` objects
that all point to one retained Binder node. The existing analysis only needs
eight or more file/epitem candidates and eight or more repeats of the selected
node, leaving ample population for both.

An actual live `binder_node` placed in a freed slot does not directly disclose
its own kernel address: its `ptr` and `cookie` are the controlled userspace
tokens. The useful mixed object is `binder_ref`, whose `node` member contains
the live kernel pointer. The combined phase should therefore be described and
proved as an epitem-plus-Binder-reference reclaim, not as two objects sharing
one slot.

The optimisation log's S020 result does not refute this design. S020 found no
epitem/file records in three unchanged *second-phase* sprays. It did not split
the much larger first cohort between the two reclaim types. The risk is
allocator geometry, not a source-level impossibility; a safety candidate needs
separate minimum populations, unique classification, retained-lifetime proofs,
and an all-or-nothing receipt before freeing any stale buffer.

## 3. Subjective credentials are sufficient for module-loading checks

Linux explicitly distinguishes the objective and subjective pointers:
`task->real_cred` describes a task when another actor examines or acts on it,
while `task->cred` describes how the current task acts on another object
([`struct cred` documentation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/include/linux/cred.h#90)).
The supported `override_creds()` API changes only `current->cred`, which shows
that this state is intentional kernel semantics rather than an abnormal
combination
([`override_creds()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/cred.c#542)).

The Android 12/5.10 module path uses the subjective credential throughout:

- `may_init_module()` calls `capable(CAP_SYS_MODULE)`
  ([module gate](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3846)).
- `capable()` reaches `security_capable(current_cred(), ...)`
  ([capability path](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/capability.c#364)).
- SELinux `current_sid()` obtains the SID from `current_cred()->security`
  ([SELinux subjective SID](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/include/objsec.h#183)).

Consequently, a helper leader whose `cred` points to the stopped root donor,
and whose donor credential security points to the `ueventd` security blob, has
the capability and SELinux subject needed by `init_module` or `finit_module`.
Its `real_cred` can remain the private shell credential.

This shortcut has important safety conditions:

- A raw pointer write does not perform `override_creds()` reference and
  subscriber accounting. The donor must remain pinned and stopped, the helper
  must not fork, clone, exec or exit, and the rescue module must restore the
  subjective pointer before normal execution resumes.
- `commit_creds()` updates both pointers and has
  `BUG_ON(task->cred != task->real_cred)`
  ([`commit_creds()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/cred.c#427)).
  Restore the private subjective pointer before `setresuid`, `setresgid`, exec,
  or any other path that commits credentials.
- Existing `/proc/<pid>/status` gates will continue to show the objective shell
  UIDs and capabilities because procfs calls `get_task_cred()` and
  `__task_cred()`, both of which select `real_cred`
  ([proc status implementation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/fs/proc/array.c#156)).
  SELinux also implements `/proc/self/attr/current` with `__task_cred()`, so it
  is objective too
  ([SELinux `getprocattr`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#6399)).
  A redesign must replace those root-window observations with positive
  kernel-memory proofs of the intended `cred != real_cred` state and a
  rescue-module receipt; merely deleting the gates would weaken safety.

Keeping the current stopped `update_engine` donor is preferable to borrowing
`ueventd->cred` directly. Prism's write primitive also stores collateral at
`replacement + 8`; for a credential this damages its GID/SUID word. The stopped
donor isolates that damage until rescue. Doing the same to live `ueventd` would
alter a system daemon's shared credential and is not an acceptable fast path.

## 4. `finit_module` and `init_module` are not equivalent LSM routes

Both syscalls first run the same `CAP_SYS_MODULE`/`modules_disabled` gate and
then converge on `load_module()`
([system-call implementations](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#4205)).
Their input-security hooks differ:

| Route | Input hook | Android 12/5.10 SELinux decision |
| --- | --- | --- |
| `finit_module(fd, ...)` | `kernel_read_file_from_fd(..., READING_MODULE)` | Optional `fd:use`, then subject SID to module inode SID, `system:module_load` |
| `init_module(buf, ...)` | `security_kernel_load_data(LOADING_MODULE, true)` | Subject SID to the same subject SID, `system:module_load` |

The exact SELinux implementation documents the distinction in
`selinux_kernel_module_from_file()`: a null file is the `init_module` route;
the file-backed route checks the file security SID and inode security SID
([SELinux module hook](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#4087)).
This is why `init_module` can eliminate Prism's module-inode label write, but
only if the installed policy grants `ueventd` self `system:module_load`. The
existing successful vendor-labelled `finit_module` path proves a different
permission and does not prove that self permission.

The supplied [`boot.img`](/Users/vandam/Downloads/light%20stuff/boot.img)
(SHA-256 `ae2f5a99048d8ed2c9847b14a4d09d385c8dbfc8c849d57d9abb9d544c974868`)
is especially favourable to the memory route. Its embedded IKCONFIG contains:

```text
# CONFIG_SECURITY_LOADPIN is not set
# CONFIG_MODULE_SIG is not set
# CONFIG_IMA is not set
# CONFIG_EVM is not set
```

Thus this exact build has no LoadPin denial of the old in-memory API, no module
signature requirement, and no IMA/EVM appraisal distinction. In a kernel with
enforcing LoadPin, `init_module` would be rejected because it has no file
origin
([LoadPin old-API check](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/loadpin/loadpin.c#121));
that general restriction does not apply to this boot artefact. Both syscalls
would still share signature and ELF validation inside `load_module()` if those
features were enabled
([common loader](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3979)).

The remaining unknown is the exact compiled SELinux allow rule. The safest
decision sequence is therefore:

1. Prove buffered `init_module` for the rescue image while retaining the
   known-good six-write identity and label state.
2. Change the ReSuki loader at source level to use its already-buffered module
   image. Do not repeat S023's hard-coded GOT interposition.
3. Remove the inode-label write only after both module loads and strict cleanup
   succeed through the in-memory route.
4. Only then adopt the subjective-only, two-write terminal sequence.

No implementation or device run was performed for this research.

## 5. An `EACCES` result from `finit_module` is a phase collision

### Finding

On Android 12 common 5.10, `finit_module()` returns each downstream negative
errno unchanged. Therefore, `EACCES` alone does not identify the failing
phase. SELinux can return `-EACCES` before the image is loaded, and a module's
own init function can return the same value after relocation. The syscall has
no phase field
([`finit_module()`](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#4231)).

For the current rescue image, an unchanged `EACCES` is nevertheless strong
evidence of a pre-init security rejection. Its init path and parameter setters
do not return `-EACCES`, and its `stop_machine()` callback returns zero while
reporting validation failures separately
([rescue init](/Users/vandam/Developer/prism/kernel/ctlbuf_rescue/lp3_ctlbuf_rescue.c:1764),
[stop callback](/Users/vandam/Developer/prism/kernel/ctlbuf_rescue/lp3_ctlbuf_rescue.c:939)).
Keep that reserved errno property explicit; otherwise later module changes
will make the result ambiguous again. This conclusion requires the bytes passed
to `finit_module` to match the inspected rescue source; an embedded historical
image can have a different errno map.

### Pre-init audit

The exact path has the following possible outcomes:

| Phase | Can produce `EACCES`? | Relevant detail |
| --- | --- | --- |
| Initial module gate | No | Missing `CAP_SYS_MODULE` or `modules_disabled` returns `EPERM`, not `EACCES` ([gate](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3852)). |
| Descriptor and file read setup | Not by its fixed checks | An unreadable descriptor returns `EBADF`; a non-regular, empty or malformed-size input returns `EINVAL`, `EFBIG`, `ENOMEM` or `EIO` as appropriate ([file reader](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/fs/kernel_read_file.c#35)). |
| SELinux module-file hook | **Yes** | Enforcing SELinux returns `EACCES` for either denied `fd:use` or denied `system:module_load` ([module-file hook](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#4053), [AVC result](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/avc.c#1023)). |
| Actual file read | **Yes** | `kernel_read()` calls `security_file_permission(MAY_READ)`. After an inode relabel, SELinux detects that the open-time inode SID is stale and rechecks `fd:use` plus inode `file:read`; either denial is `EACCES` ([read verification](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/fs/read_write.c#366), [SELinux revalidation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#3590)). |
| Filesystem `read_iter` | Vendor-dependent | The underlying filesystem's negative read result is propagated unchanged. Android common regular-file implementations do not normally return `EACCES` after the LSM check, but a vendor filesystem can do so. |
| IMA/post-read appraisal | Yes when enabled | Enforcing IMA appraisal can return `EACCES` from `ima_post_read_file()` ([IMA post-read hook](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/integrity/ima/ima_main.c#681)). It is compiled out in the supplied kernel. |
| LoadPin and lockdown | No on this path | LoadPin is compiled out, and `CONFIG_MODULE_SIG=n` means this path does not call the module-signature lockdown hook. Android common denials from either subsystem use `EPERM`, not `EACCES` ([LoadPin](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/loadpin/loadpin.c#121), [lockdown](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/lockdown/lockdown.c#83)). |
| Module signature | Not on this build | `CONFIG_MODULE_SIG` is unset. When enabled, the common loader's policy rejection is `EKEYREJECTED`; the normal unsigned/unsupported/unavailable-key cases are not `EACCES` ([signature check](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#2937)). |
| ELF, architecture and vermagic validation | No fixed `EACCES` path | Invalid ELF and wrong architecture return `ENOEXEC`; a vermagic mismatch also returns `ENOEXEC` ([ELF validation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3018), [vermagic check](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3280)). Blacklisting returns `EPERM`. Arm64 relocation/finalisation uses `ENOEXEC`, `ERANGE` or allocation errors, not `EACCES` ([arm64 finalisation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/arch/arm64/kernel/module.c#522)). |
| User copies | No fixed `EACCES` path | `finit_module` reads the image from the file and performs no image `copy_from_user`. Its user argument string can fail with a user-memory or allocation error. The separate `init_module` image copy maps a failed `copy_from_user` to `EFAULT` ([copy path](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3110)). The loader performs no `copy_to_user`. |
| Architecture, livepatch, parameter and notifier callbacks | Callback-dependent | The generic loader propagates errors from its architecture hooks, livepatch callbacks, parameter setters and robust module-notifier chain. A vendor hook or custom callback can therefore manufacture `EACCES`. The exact common arm64 hooks and current rescue setters do not ([parameter propagation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/params.c#115), [coming-module path](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3945)). |

The inode relabel does not update the open file's provenance. SELinux records
`current_sid()` in the file security object when the `struct file` is
allocated, but reads the inode's current SID during module-load and read
checks
([file allocation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#3623),
[open-time inode SID](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/security/selinux/hooks.c#3928)).
Consequently:

- `dup()` or `F_DUPFD` preserves a shell-opened `struct file` and can fail the
  later `ueventd -> shell-fd` `fd:use` check.
- Reopening `/proc/self/fd/<n>` creates a new file security object under the
  current subject and can remove that mismatch.
- Relabelling the inode to `vendor_file` is visible immediately. It must allow
  both `ueventd:system module_load` and the separate `ueventd:file read`
  revalidation; satisfying only `module_load` is insufficient.

### Init and `stop_machine`

The loader emits `module_load` and then calls `do_init_module()`. That function
calls `do_one_initcall(mod->init)` and returns any negative init result
unchanged
([init propagation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#3746),
[load hand-off](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/module.c#4161)).
A module init function may therefore return `-EACCES`; user space receives
`errno == EACCES` exactly as it does for a pre-read SELinux denial.

The arm64 module loader does **not** use `stop_machine()` for module
alternatives. `module_finalize()` calls `apply_alternatives_module()`, which
patches directly; `stop_machine()` is used by the boot-time
`apply_alternatives_all()` path instead
([arm64 module finalisation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/arch/arm64/kernel/module.c#522),
[alternatives paths](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/arch/arm64/kernel/alternative.c#220)).
The current rescue module itself calls `stop_machine()` from its init
function. Generic `stop_machine()` propagates its callback's return value
([implementation](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/kernel/stop_machine.c#606)),
so a callback could cause init to return `EACCES`. The current callback always
returns zero and places its validation errno in `context.error`, which the
module init then returns. Its present validation set contains no `EACCES`.
The module's `copy_to_user()` operations are in module exit, after a successful
load, and cannot explain an `EACCES` from `finit_module`.

### Distinguish the phases without `dmesg`

Raw syscall errno and the absence of `/sys/module/<name>` are insufficient:
both paths leave no live module. Use one of these positive signals:

1. Reserve `EACCES` for pre-init rejection. Require the rescue init,
   load-time parameter setters and any invoked helper to map their failures to
   distinct errno values. This is already true of the current source.
2. For an independent proof, enable the `module:module_load` trace event for
   one isolated attempt, clear its buffer before the call, and correlate the
   event's module name and task with that attempt. The tracepoint is emitted
   immediately before `do_init_module()` and records the module name
   ([tracepoint definition](https://android.googlesource.com/kernel/common/+/refs/heads/android12-5.10/include/trace/events/module.h#31)).
   An `EACCES` with a correlated event came from init. An `EACCES` without one
   occurred earlier, provided trace capture itself is proved healthy.
3. If trace events are unavailable, trace entry to `do_init_module()` with a
   kprobe or function tracer and correlate it with the syscall exit. This has
   the same phase boundary but requires tracing privilege.

The most discriminating next observation is therefore the `module_load`
tracepoint, followed by separate AVC probes for `fd use`, `system module_load`
and `file read`. If probing is unavailable, compare the inherited descriptor
with a freshly reopened descriptor under the same caller SID and inode label;
only the file-object SID should change. Do not infer the stage from `EACCES`
alone.
