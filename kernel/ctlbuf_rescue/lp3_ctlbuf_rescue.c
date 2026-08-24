// SPDX-License-Identifier: GPL-2.0-only

#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/delay.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/sched/task_stack.h>
#include <linux/slab.h>
#include <linux/stop_machine.h>
#include <linux/uaccess.h>
#include <asm/pointer_auth.h>

#define LP3_EXPECTED_REPAIRS 5
#define LP3_CONTROL_SIZE 128
#define LP3_MAX_FRAMES 64
#define LP3_WORKER_COMM "lp3-fake-ctl"

#define LP3_EXPECTED_EP_LINKS 5632
#define LP3_SNAPSHOT_FATAL (-1)
#define LP3_SNAPSHOT_EXACT 0
#define LP3_SNAPSHOT_EXCESS 1
#define LP3_FILE_INODE_OFFSET 0x20UL
#define LP3_FILE_F_OP_OFFSET 0x28UL
#define LP3_FILE_EP_LINKS_OFFSET 0xe0UL
#define LP3_EPITEM_FLLINK_OFFSET 0x58UL
#define LP3_EPITEM_FLLINK_NEXT_OFFSET 0x00UL
#define LP3_EPITEM_FLLINK_PREV_OFFSET 0x08UL
#define LP3_EVENTFD_FOPS_OFFSET 0x02156800UL
#define LP3_TASK_REAL_CRED_OFFSET 0x778UL
#define LP3_TASK_CRED_OFFSET 0x780UL
#define LP3_CRED_USAGE_OFFSET 0x00UL
#define LP3_CRED_UID_OFFSET 0x04UL
#define LP3_CRED_GID_OFFSET 0x10UL
#define LP3_CRED_EUID_OFFSET 0x0cUL
#define LP3_CRED_SUID_OFFSET 0x14UL
#define LP3_CRED_FSUID_OFFSET 0x18UL
#define LP3_CRED_EGID_OFFSET 0x20UL
#define LP3_CRED_SGID_OFFSET 0x24UL
#define LP3_CRED_FSGID_OFFSET 0x28UL
#define LP3_CRED_CAPS_OFFSET 0x38UL
#define LP3_CRED_SECURITY_OFFSET 0x78UL

#define LP3_SENDMSG_OFFSET 0x0129d464UL
#define LP3_SENDMSG_CTLBUF_MOV_OFFSET 0x000000e4UL
#define LP3_SENDMSG_CALL_OFFSET 0x0000023cUL
#define LP3_SENDMSG_RETURN_OFFSET 0x00000240UL
#define LP3_UNIX_DGRAM_OFFSET 0x015139f4UL
#define LP3_UNIX_DGRAM_END_OFFSET 0x015152acUL
#define LP3_SAVED_X23_FP_OFFSET 56UL
#define LP3_RESUME_MAGIC 0x4c5033524553554dULL
#define LP3_RESUME_VERSION 1U
#define LP3_RESUME_COMMIT_XOR 0xa5d91f7462c83be0ULL

struct lp3_resume_record {
	__u64 magic;
	__u64 cookie_hi;
	__u64 cookie_lo;
	__u64 helper_task;
	__u64 donor_task;
	__u64 pre_state;
	__u64 pre_exit_state;
	__u64 post_state;
	__u64 post_exit_state;
	__u64 task_security;
	__u64 task_security_word8;
	__u64 inode_security;
	__u64 inode_security_word8;
	__u32 version;
	__u32 size;
	__s32 helper_pid;
	__s32 donor_pid;
	__s32 donor_tgid;
	__s32 signal;
	__s32 signal_rc;
	__s32 signal_errno;
	__u32 pre_thread_count;
	__u32 pre_stopped_count;
	__u32 post_thread_count;
	__u32 post_stopped_count;
	__u32 stable_samples;
	__u32 labels_restored;
	__u32 resumed;
	__u32 proof;
	__u64 commit;
};

#define LP3_SENDMSG_CTLBUF_MOV_INSN 0xaa0003f7U
#define LP3_SENDMSG_CALL_INSN 0xd63f0300U
#define LP3_SENDMSG_RETURN_INSN 0x3108441fU
#define LP3_UNIX_DGRAM_PAC_INSN 0xd503233fU
#define LP3_UNIX_DGRAM_STACK_INSN 0xd103c3ffU
#define LP3_UNIX_DGRAM_SAVE_X23_INSN 0xa90c5ff8U

struct lp3_repair {
	pid_t tid;
	unsigned long old_ctlbuf;
	void *replacement;
	struct task_struct *task;
	void *stack;
	unsigned long frame_pointer;
	unsigned long slot;
	unsigned int depth;
};

struct lp3_stop_context {
	struct lp3_repair *repairs;
	unsigned int count;
	unsigned long unix_start;
	unsigned long unix_end;
	unsigned long sendmsg_return;
	int error;
	bool patched;
};

static int tids[LP3_EXPECTED_REPAIRS];
static unsigned int tid_count;
module_param_array(tids, int, &tid_count, 0400);

static unsigned long nodes[LP3_EXPECTED_REPAIRS];
static unsigned int node_count;
module_param_array(nodes, ulong, &node_count, 0400);

static unsigned long kernel_base;
module_param(kernel_base, ulong, 0400);

static int expected_tgid;
module_param(expected_tgid, int, 0400);

static int helper_tid;
module_param(helper_tid, int, 0400);

static unsigned long helper_task;
module_param(helper_task, ulong, 0400);

static unsigned long donor_cred;
module_param(donor_cred, ulong, 0400);

static unsigned long private_cred;
module_param(private_cred, ulong, 0400);

static unsigned long donor_security_slot;
module_param(donor_security_slot, ulong, 0400);

static unsigned long donor_security_original;
module_param(donor_security_original, ulong, 0400);

static unsigned long borrowed_task_security;
module_param(borrowed_task_security, ulong, 0400);

static unsigned long borrowed_task_security_word8;
module_param(borrowed_task_security_word8, ulong, 0400);

static unsigned long inode_security_slot;
module_param(inode_security_slot, ulong, 0400);

static unsigned long inode_security_original;
module_param(inode_security_original, ulong, 0400);

static unsigned long borrowed_inode_security;
module_param(borrowed_inode_security, ulong, 0400);

static unsigned long borrowed_inode_security_word8;
module_param(borrowed_inode_security_word8, ulong, 0400);

static bool defer_inode_restore;
module_param(defer_inode_restore, bool, 0400);

/* The finalise record is supplied by the current run.  No value is
 * inferred from the existing arbitrary-read state. */
static unsigned long finalise_owner_task;
module_param_named(owner_task, finalise_owner_task, ulong, 0400);

static int finalise_owner_pid;
module_param_named(owner_pid, finalise_owner_pid, int, 0400);

static int finalise_watched_fd;
module_param_named(watched_fd, finalise_watched_fd, int, 0400);

static int finalise_arbitrary_fd;
module_param_named(arbitrary_fd, finalise_arbitrary_fd, int, 0400);

static int finalise_reference_fd;
module_param_named(reference_fd, finalise_reference_fd, int, 0400);

static unsigned long finalise_watched_file;
module_param_named(watched_file, finalise_watched_file, ulong, 0400);

static unsigned long finalise_watched_inode;
module_param_named(watched_inode, finalise_watched_inode, ulong, 0400);

static unsigned long finalise_arbitrary_file;
module_param_named(arbitrary_file, finalise_arbitrary_file, ulong, 0400);

static unsigned long finalise_arbitrary_inode;
module_param_named(arbitrary_inode, finalise_arbitrary_inode, ulong, 0400);

static unsigned long finalise_reference_file;
module_param_named(reference_file, finalise_reference_file, ulong, 0400);

static unsigned long finalise_reference_inode;
module_param_named(reference_inode, finalise_reference_inode, ulong, 0400);

static unsigned long finalise_watched_fops;
module_param_named(watched_fops, finalise_watched_fops, ulong, 0400);

static unsigned long finalise_arbitrary_fops;
module_param_named(arbitrary_fops, finalise_arbitrary_fops, ulong, 0400);

static unsigned long finalise_reference_fops;
module_param_named(reference_fops, finalise_reference_fops, ulong, 0400);

static unsigned long finalise_selected_epitem;
module_param_named(selected_epitem, finalise_selected_epitem, ulong, 0400);

static unsigned long finalise_expected_fops;
module_param_named(expected_fops, finalise_expected_fops, ulong, 0400);

static unsigned long finalise_donor_task;
module_param_named(donor_task, finalise_donor_task, ulong, 0400);

static unsigned long finalise_donor_real_cred_slot;
module_param_named(donor_real_cred_slot, finalise_donor_real_cred_slot,
			  ulong, 0400);

static unsigned long finalise_donor_cred_slot;
module_param_named(donor_cred_slot, finalise_donor_cred_slot, ulong, 0400);

static int finalise_donor_pid;
module_param_named(donor_pid, finalise_donor_pid, int, 0400);

static unsigned int finalise_donor_usage;
module_param_named(donor_usage, finalise_donor_usage, uint, 0400);

static unsigned int finalise_donor_uid;
module_param_named(donor_uid, finalise_donor_uid, uint, 0400);

static unsigned int finalise_donor_euid;
module_param_named(donor_euid, finalise_donor_euid, uint, 0400);

static unsigned int finalise_donor_suid;
module_param_named(donor_suid, finalise_donor_suid, uint, 0400);

static unsigned int finalise_donor_fsuid;
module_param_named(donor_fsuid, finalise_donor_fsuid, uint, 0400);

static unsigned int finalise_donor_gid;
module_param_named(donor_gid, finalise_donor_gid, uint, 0400);

static unsigned int finalise_donor_egid;
module_param_named(donor_egid, finalise_donor_egid, uint, 0400);

static unsigned int finalise_donor_sgid;
module_param_named(donor_sgid, finalise_donor_sgid, uint, 0400);

static unsigned int finalise_donor_fsgid;
module_param_named(donor_fsgid, finalise_donor_fsgid, uint, 0400);

static unsigned long finalise_donor_caps;
module_param_named(donor_caps, finalise_donor_caps, ulong, 0400);

static unsigned int finalise_donor_sid;
module_param_named(donor_sid, finalise_donor_sid, uint, 0400);

static unsigned long finalise_donor_security;
module_param_named(donor_security, finalise_donor_security, ulong, 0400);

static unsigned int finalise_expected_count = LP3_EXPECTED_EP_LINKS;
module_param(finalise_expected_count, uint, 0400);

static unsigned int repaired_count;
module_param(repaired_count, uint, 0444);

static char repair_status[1024] = "not-started";
module_param_string(repair_status, repair_status, sizeof(repair_status), 0444);

static char finalise_status[4096] = "status=not-started stage=ctlbuf-finalise";
module_param_string(finalise_status, finalise_status, sizeof(finalise_status),
			   0444);

static unsigned int finalise_snapshot_stage;
static unsigned long finalise_snapshot_state;
static int finalise_snapshot_pid;
static int finalise_snapshot_tgid;
static unsigned long finalise_snapshot_real_cred;
static unsigned long finalise_snapshot_cred;
static unsigned long finalise_snapshot_real_slot;
static unsigned long finalise_snapshot_cred_slot;
static unsigned int finalise_snapshot_usage;
static unsigned int finalise_snapshot_file_refs;
static unsigned int finalise_snapshot_open_fds;
static unsigned int finalise_snapshot_max_fds;
static unsigned int finalise_snapshot_ids_mask;
static unsigned long finalise_snapshot_caps;
static unsigned long finalise_snapshot_repair = ~0UL;
static unsigned long finalise_snapshot_security;
static unsigned long finalise_snapshot_security_word8;
static unsigned int finalise_snapshot_sid;

static struct lp3_repair repairs[LP3_EXPECTED_REPAIRS];
static bool carriers_stabilised;
static bool inode_label_restored;
static bool labels_restored;
static bool repair_complete;
static bool finalise_complete;
static unsigned long finalise_successor;
static bool finalise_successor_valid;
static unsigned int finalise_request;
static unsigned int inode_restore_request;
static unsigned long resume_user_addr;
module_param(resume_user_addr, ulong, 0400);

static unsigned int resume_user_size;
module_param(resume_user_size, uint, 0400);

static unsigned long resume_cookie_hi;
module_param(resume_cookie_hi, ulong, 0400);

static unsigned long resume_cookie_lo;
module_param(resume_cookie_lo, ulong, 0400);

static int lp3_finalise_set(const char *value,
				const struct kernel_param *param);
static int lp3_inode_restore_set(const char *value,
				const struct kernel_param *param);
static const struct kernel_param_ops lp3_inode_restore_ops = {
	.set = lp3_inode_restore_set,
	.get = param_get_uint,
};
module_param_cb(inode_restore_request, &lp3_inode_restore_ops,
		&inode_restore_request, 0600);
static const struct kernel_param_ops lp3_finalise_ops = {
		.set = lp3_finalise_set,
		.get = param_get_uint,
};
module_param_cb(finalise_request, &lp3_finalise_ops, &finalise_request, 0200);

static bool lp3_kernel_pointer(unsigned long value)
{
	return value >= 0xffffff8000000000UL;
}

static bool lp3_frame_in_stack(unsigned long stack, unsigned long frame)
{
	if ((frame & 0xfUL) != 0)
		return false;
	if (frame < stack)
		return false;
	return frame <= stack + THREAD_SIZE - 16;
}

static bool lp3_text_matches(void)
{
	unsigned long sendmsg = kernel_base + LP3_SENDMSG_OFFSET;
	unsigned long unix_dgram = kernel_base + LP3_UNIX_DGRAM_OFFSET;

	if (!lp3_kernel_pointer(kernel_base))
		return false;
	return READ_ONCE(*(u32 *)(sendmsg +
			LP3_SENDMSG_CTLBUF_MOV_OFFSET)) ==
			LP3_SENDMSG_CTLBUF_MOV_INSN &&
		READ_ONCE(*(u32 *)(sendmsg + LP3_SENDMSG_CALL_OFFSET)) ==
			LP3_SENDMSG_CALL_INSN &&
		READ_ONCE(*(u32 *)(sendmsg + LP3_SENDMSG_RETURN_OFFSET)) ==
			LP3_SENDMSG_RETURN_INSN &&
		READ_ONCE(*(u32 *)(unix_dgram)) ==
			LP3_UNIX_DGRAM_PAC_INSN &&
		READ_ONCE(*(u32 *)(unix_dgram + 4)) ==
			LP3_UNIX_DGRAM_STACK_INSN &&
		READ_ONCE(*(u32 *)(unix_dgram + 24)) ==
			LP3_UNIX_DGRAM_SAVE_X23_INSN;
}

static int lp3_private_cred_error(void)
{
	const struct cred *cred = (const struct cred *)private_cred;

	if (!lp3_kernel_pointer(private_cred))
		return -EFAULT;
	if (atomic_read(&cred->usage) != 2)
		return -EUSERS;
	if (__kuid_val(cred->uid) != 2000 ||
	    __kuid_val(cred->euid) != 2000 ||
	    __kuid_val(cred->suid) != 2000 ||
	    __kuid_val(cred->fsuid) != 2000)
		return -EUCLEAN;
	if (__kgid_val(cred->gid) != 2000 ||
	    __kgid_val(cred->egid) != 2000 ||
	    __kgid_val(cred->sgid) != 2000 ||
	    __kgid_val(cred->fsgid) != 2000)
		return -ENOTUNIQ;
	if (!cap_isclear(cred->cap_inheritable) ||
	    !cap_isclear(cred->cap_permitted) ||
	    !cap_isclear(cred->cap_effective) ||
	    !cap_isclear(cred->cap_ambient))
		return -EPERM;
	return cred->security != NULL ? 0 : -ENOKEY;
}

static int lp3_equivalent_cred_error(const struct cred *cred,
				     unsigned long expected_cred)
{
	const struct cred *expected = (const struct cred *)expected_cred;
	const struct group_info *groups;
	const struct group_info *private_groups;
	unsigned long security;
	unsigned long expected_security;
	int i;

	if (!lp3_kernel_pointer((unsigned long)cred) ||
	    !lp3_kernel_pointer(expected_cred))
		return -EFAULT;
	if (atomic_read(&cred->usage) < 1)
		return -EUSERS;
	if (!uid_eq(cred->uid, expected->uid) ||
	    !uid_eq(cred->euid, expected->euid) ||
	    !uid_eq(cred->suid, expected->suid) ||
	    !uid_eq(cred->fsuid, expected->fsuid))
		return -EUCLEAN;
	if (!gid_eq(cred->gid, expected->gid) ||
	    !gid_eq(cred->egid, expected->egid) ||
	    !gid_eq(cred->sgid, expected->sgid) ||
	    !gid_eq(cred->fsgid, expected->fsgid))
		return -ENOTUNIQ;
	if (cred->securebits != expected->securebits)
		return -EBADSLT;
	if (cred->user != expected->user)
		return -EMULTIHOP;
	if (cred->user_ns != expected->user_ns)
		return -ENOLINK;
	if (memcmp(&cred->cap_inheritable, &expected->cap_inheritable,
		   sizeof(cred->cap_inheritable)) ||
	    memcmp(&cred->cap_permitted, &expected->cap_permitted,
		   sizeof(cred->cap_permitted)) ||
	    memcmp(&cred->cap_effective, &expected->cap_effective,
		   sizeof(cred->cap_effective)) ||
	    memcmp(&cred->cap_bset, &expected->cap_bset,
		   sizeof(cred->cap_bset)) ||
	    memcmp(&cred->cap_ambient, &expected->cap_ambient,
		   sizeof(cred->cap_ambient)))
		return -EPERM;
	groups = cred->group_info;
	private_groups = expected->group_info;
	if (groups == NULL || private_groups == NULL ||
	    groups->ngroups != private_groups->ngroups)
		return -EMEDIUMTYPE;
	for (i = 0; i < groups->ngroups; ++i) {
		if (!gid_eq(groups->gid[i], private_groups->gid[i]))
			return -EBADRQC;
	}
	security = (unsigned long)cred->security;
	expected_security = (unsigned long)expected->security;
	if (!lp3_kernel_pointer(security) ||
	    !lp3_kernel_pointer(expected_security))
		return -ECHRNG;
	if (READ_ONCE(*(unsigned long *)security) !=
	    READ_ONCE(*(unsigned long *)expected_security) ||
	    READ_ONCE(*(unsigned long *)(security + 8)) !=
	    READ_ONCE(*(unsigned long *)(expected_security + 8)))
		return -ENONET;
	return 0;
}

static struct task_struct *lp3_helper_task_get(void)
{
	struct task_struct *task;
	struct pid *pid;

	if (helper_tid <= 0)
		return NULL;
	pid = find_get_pid(helper_tid);
	if (pid == NULL)
		return NULL;
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (task == NULL)
		return NULL;
	if (task->pid != helper_tid || task->tgid != helper_tid ||
	    (unsigned long)task != helper_task) {
		put_task_struct(task);
		return NULL;
	}
	return task;
}

static int lp3_helper_borrowed_task_error(struct task_struct *task)
{
	if (task == NULL)
		return -EINVAL;
	if (task->pid != helper_tid || task->tgid != helper_tid)
		return -EBADR;
	if ((unsigned long)task != helper_task)
		return -EXDEV;
	if ((unsigned long)READ_ONCE(task->real_cred) != donor_cred)
		return -EHOSTDOWN;
	if ((unsigned long)READ_ONCE(task->cred) != donor_cred)
		return -EBADFD;
	return lp3_private_cred_error();
}

static int lp3_helper_subjective_borrowed_task_error(
	struct task_struct *task)
{
	if (task == NULL)
		return -EINVAL;
	if (task->pid != helper_tid || task->tgid != helper_tid)
		return -ERANGE;
	if ((unsigned long)task != helper_task)
		return -EXDEV;
	if ((unsigned long)READ_ONCE(task->real_cred) != private_cred)
		return -EBADE;
	if ((unsigned long)READ_ONCE(task->cred) != donor_cred)
		return -EBADFD;
	return lp3_private_cred_error();
}

static int lp3_helper_borrowed_error(void)
{
	return lp3_helper_borrowed_task_error(current);
}

static int lp3_loader_and_target_error(void)
{
	struct task_struct *parent = NULL;
	struct task_struct *task;
	int result;

	if (current->pid == current->tgid) {
		if (get_nr_threads(current) != 1)
			return -EMLINK;
		parent = READ_ONCE(current->real_parent);
		if (parent == NULL || parent->tgid != helper_tid)
			return -ECHILD;
		if (parent->pid == helper_tid)
			return -EALREADY;
		if ((unsigned long)READ_ONCE(parent->real_cred) != donor_cred)
			return -EREMOTE;
		if ((unsigned long)READ_ONCE(parent->cred) != donor_cred)
			return -EREMOTEIO;
	} else {
		if (current->tgid != helper_tid)
			return -EPROTO;
		if (current->pid == helper_tid)
			return -EALREADY;
	}
	if ((unsigned long)current->real_cred != donor_cred &&
	    (unsigned long)current->real_cred != private_cred) {
		result = lp3_equivalent_cred_error(current->real_cred,
						  private_cred);
		if (result)
			result = lp3_equivalent_cred_error(current->real_cred,
						  donor_cred);
		if (result)
			return result;
	}
	if ((unsigned long)current->cred != donor_cred) {
		result = lp3_equivalent_cred_error(current->cred, donor_cred);
		if (result)
			return result;
	}
	if ((unsigned long)((const struct cred *)donor_cred)->security !=
	    borrowed_task_security)
		return -EKEYREJECTED;
	task = lp3_helper_task_get();
	if (task == NULL)
		return -ENXIO;
	result = lp3_helper_subjective_borrowed_task_error(task);
	put_task_struct(task);
	return result;
}

static int lp3_normalise_helper_real_cred(void)
{
	struct task_struct *task;
	int result;

	task = lp3_helper_task_get();
	if (task == NULL)
		return -ENODEV;
	result = lp3_helper_subjective_borrowed_task_error(task);
	if (result)
		goto out;
	preempt_disable();
	WRITE_ONCE(*(const struct cred **)&task->real_cred,
		(const struct cred *)donor_cred);
	smp_wmb();
	preempt_enable();
	result = lp3_helper_borrowed_task_error(task);
out:
	put_task_struct(task);
	return result;
}

static bool lp3_helper_is_borrowed(void)
{
	return lp3_helper_borrowed_error() == 0;
}

static int lp3_stabilise_carriers(void)
{
	unsigned long *task_slot = (unsigned long *)donor_security_slot;
	unsigned long *task_word8 =
		(unsigned long *)(borrowed_task_security + 8);
	unsigned long *inode_slot = (unsigned long *)inode_security_slot;
	unsigned long *inode_word8 =
		(unsigned long *)(borrowed_inode_security + 8);

	if (!lp3_kernel_pointer(donor_security_slot) ||
	    !lp3_kernel_pointer(donor_security_original) ||
	    !lp3_kernel_pointer(borrowed_task_security) ||
	    !lp3_kernel_pointer(inode_security_slot) ||
	    !lp3_kernel_pointer(inode_security_original) ||
	    !lp3_kernel_pointer(borrowed_inode_security))
		return -EINVAL;
	if (READ_ONCE(*task_slot) != borrowed_task_security ||
	    READ_ONCE(*task_word8) != donor_security_slot ||
	    READ_ONCE(*inode_slot) != borrowed_inode_security ||
	    READ_ONCE(*inode_word8) != inode_security_slot)
		return -ESTALE;

	WRITE_ONCE(*task_word8, borrowed_task_security_word8);
	WRITE_ONCE(*inode_word8, borrowed_inode_security_word8);
	if (!defer_inode_restore)
		WRITE_ONCE(*inode_slot, inode_security_original);
	smp_wmb();

	if (READ_ONCE(*task_slot) != borrowed_task_security ||
	    READ_ONCE(*task_word8) != borrowed_task_security_word8 ||
	    READ_ONCE(*inode_slot) != (defer_inode_restore ?
			borrowed_inode_security : inode_security_original) ||
	    READ_ONCE(*inode_word8) != borrowed_inode_security_word8) {
		WRITE_ONCE(*task_word8, borrowed_task_security_word8);
		WRITE_ONCE(*inode_word8, borrowed_inode_security_word8);
		WRITE_ONCE(*inode_slot, inode_security_original);
		WRITE_ONCE(*task_slot, donor_security_original);
		smp_wmb();
		if (READ_ONCE(*task_slot) != donor_security_original ||
		    READ_ONCE(*task_word8) != borrowed_task_security_word8 ||
		    READ_ONCE(*inode_slot) != inode_security_original ||
		    READ_ONCE(*inode_word8) != borrowed_inode_security_word8)
			return -EIO;
		labels_restored = true;
		inode_label_restored = true;
		return -EIO;
	}
	inode_label_restored = !defer_inode_restore;
	carriers_stabilised = true;
	return 0;
}

static int lp3_inode_restore_set(const char *value,
				const struct kernel_param *param)
{
	unsigned long *task_slot = (unsigned long *)donor_security_slot;
	unsigned long *task_word8 =
		(unsigned long *)(borrowed_task_security + 8);
	unsigned long *inode_slot = (unsigned long *)inode_security_slot;
	unsigned long *inode_word8 =
		(unsigned long *)(borrowed_inode_security + 8);
	unsigned int request;

	(void)param;
	if (value == NULL || kstrtouint(value, 0, &request) || request != 1 ||
	    inode_restore_request != 0 || !defer_inode_restore ||
	    !carriers_stabilised || labels_restored || inode_label_restored)
		return -EINVAL;
	if (READ_ONCE(*task_slot) != borrowed_task_security ||
	    READ_ONCE(*task_word8) != borrowed_task_security_word8 ||
	    READ_ONCE(*inode_slot) != borrowed_inode_security ||
	    READ_ONCE(*inode_word8) != borrowed_inode_security_word8)
		return -ESTALE;
	WRITE_ONCE(*inode_slot, inode_security_original);
	smp_wmb();
	if (READ_ONCE(*inode_slot) != inode_security_original ||
	    READ_ONCE(*inode_word8) != borrowed_inode_security_word8)
		return -EIO;
	inode_label_restored = true;
	inode_restore_request = request;
	return 0;
}

static int lp3_restore_task_label(void)
{
	unsigned long *task_slot = (unsigned long *)donor_security_slot;
	unsigned long *task_word8 =
		(unsigned long *)(borrowed_task_security + 8);
	unsigned long *inode_slot = (unsigned long *)inode_security_slot;
	unsigned long *inode_word8 =
		(unsigned long *)(borrowed_inode_security + 8);

	bool collateral_valid;

	if (!carriers_stabilised)
		return -ESTALE;
	if (!inode_label_restored &&
	    READ_ONCE(*inode_slot) == borrowed_inode_security &&
	    READ_ONCE(*inode_word8) == borrowed_inode_security_word8) {
		WRITE_ONCE(*inode_slot, inode_security_original);
		smp_wmb();
		inode_label_restored =
			READ_ONCE(*inode_slot) == inode_security_original;
	}
	collateral_valid =
		READ_ONCE(*task_slot) == borrowed_task_security &&
		READ_ONCE(*task_word8) == borrowed_task_security_word8 &&
		READ_ONCE(*inode_slot) == inode_security_original &&
		READ_ONCE(*inode_word8) == borrowed_inode_security_word8;

	WRITE_ONCE(*task_slot, donor_security_original);
	smp_wmb();
	if (!collateral_valid ||
	    READ_ONCE(*task_slot) != donor_security_original ||
	    READ_ONCE(*task_word8) != borrowed_task_security_word8 ||
	    READ_ONCE(*inode_slot) != inode_security_original ||
	    READ_ONCE(*inode_word8) != borrowed_inode_security_word8)
		return -EIO;
	labels_restored = true;
	return 0;
}

static bool lp3_task_label_is_restored(void)
{
	return carriers_stabilised && labels_restored &&
		READ_ONCE(*(unsigned long *)donor_security_slot) ==
			donor_security_original &&
		READ_ONCE(*(unsigned long *)(borrowed_task_security + 8)) ==
			borrowed_task_security_word8 &&
		READ_ONCE(*(unsigned long *)inode_security_slot) ==
			inode_security_original &&
		READ_ONCE(*(unsigned long *)(borrowed_inode_security + 8)) ==
			borrowed_inode_security_word8;
}

static bool lp3_donor_group_state(struct task_struct *leader,
				  unsigned long *leader_state,
				  unsigned long *leader_exit_state,
				  unsigned int *thread_count,
				  unsigned int *stopped_count)
{
	struct task_struct *thread;
	unsigned long state;
	unsigned long exit_state;
	unsigned int count = 0;
	unsigned int stopped = 0;
	bool leader_seen = false;
	bool valid = true;

	if (leader == NULL || leader_state == NULL || leader_exit_state == NULL ||
	    thread_count == NULL || stopped_count == NULL)
		return false;
	rcu_read_lock();
	if (READ_ONCE(leader->pid) != finalise_donor_pid ||
	    READ_ONCE(leader->tgid) != finalise_donor_pid) {
		valid = false;
		goto out;
	}
	state = READ_ONCE(leader->state);
	exit_state = READ_ONCE(leader->exit_state);
	for_each_thread(leader, thread) {
		unsigned long thread_state = READ_ONCE(thread->state);

		if (++count > 4096U || READ_ONCE(thread->exit_state) != 0 ||
		    READ_ONCE(thread->tgid) != finalise_donor_pid) {
			valid = false;
			goto out;
		}
		if (thread == leader)
			leader_seen = true;
		if (thread_state & (TASK_STOPPED | TASK_TRACED))
			++stopped;
	}
	if (!leader_seen || count == 0 || exit_state != 0) {
		valid = false;
		goto out;
	}
	*leader_state = state;
	*leader_exit_state = exit_state;
	*thread_count = count;
	*stopped_count = stopped;
out:
	rcu_read_unlock();
	return valid;
}

static bool lp3_carriers_still_stabilised(void)
{
	return carriers_stabilised && !labels_restored &&
		inode_label_restored &&
		READ_ONCE(*(unsigned long *)donor_security_slot) ==
			borrowed_task_security &&
		READ_ONCE(*(unsigned long *)(borrowed_task_security + 8)) ==
			borrowed_task_security_word8 &&
		READ_ONCE(*(unsigned long *)inode_security_slot) ==
			inode_security_original &&
		READ_ONCE(*(unsigned long *)(borrowed_inode_security + 8)) ==
			borrowed_inode_security_word8;
}

static bool lp3_repairs_still_installed(void)
{
	unsigned int i;

	for (i = 0; i < LP3_EXPECTED_REPAIRS; ++i) {
		if (!lp3_kernel_pointer(repairs[i].slot) ||
		    !lp3_kernel_pointer((unsigned long)repairs[i].replacement) ||
		    READ_ONCE(*(unsigned long *)repairs[i].slot) !=
			    (unsigned long)repairs[i].replacement)
			return false;
	}
	return true;
}

static int lp3_prepare_repairs(void)
{
	unsigned int i;

	if (tid_count != LP3_EXPECTED_REPAIRS ||
	    node_count != LP3_EXPECTED_REPAIRS || expected_tgid <= 0)
		return -EINVAL;

	for (i = 0; i < LP3_EXPECTED_REPAIRS; ++i) {
		struct pid *pid;
		struct task_struct *task;
		unsigned int j;

		if (tids[i] <= 0 || !lp3_kernel_pointer(nodes[i]))
			return -EINVAL;
		for (j = 0; j < i; ++j) {
			if (tids[j] == tids[i] || nodes[j] == nodes[i])
				return -EINVAL;
		}

		pid = find_get_pid(tids[i]);
		if (!pid)
			return -ENOENT;
		task = get_pid_task(pid, PIDTYPE_PID);
		put_pid(pid);
		if (!task)
			return -ECHILD;
		if (task->pid != tids[i] || task->tgid != expected_tgid ||
		    strncmp(task->comm, LP3_WORKER_COMM, TASK_COMM_LEN) != 0) {
			put_task_struct(task);
			return -EINVAL;
		}
		repairs[i].stack = try_get_task_stack(task);
		if (!repairs[i].stack) {
			put_task_struct(task);
			return -EDEADLK;
		}
		repairs[i].tid = tids[i];
		repairs[i].old_ctlbuf = nodes[i];
		repairs[i].task = task;
		repairs[i].replacement = kzalloc(LP3_CONTROL_SIZE, GFP_KERNEL);
		if (!repairs[i].replacement)
			return -ENOMEM;
	}
	return 0;
}

static void lp3_release_repair_refs(bool free_replacements)
{
	unsigned int i;

	for (i = 0; i < LP3_EXPECTED_REPAIRS; ++i) {
		if (free_replacements && repairs[i].replacement)
			kfree(repairs[i].replacement);
		if (repairs[i].stack && repairs[i].task)
			put_task_stack(repairs[i].task);
		if (repairs[i].task)
			put_task_struct(repairs[i].task);
		repairs[i].stack = NULL;
		repairs[i].task = NULL;
		if (free_replacements)
			repairs[i].replacement = NULL;
	}
}

static int lp3_validate_one_stack(struct lp3_stop_context *context,
				  struct lp3_repair *repair)
{
	struct task_struct *task = repair->task;
	unsigned long stack = (unsigned long)repair->stack;
	unsigned long fp = READ_ONCE(task->thread.cpu_context.fp);
	unsigned int depth;
	unsigned int matches = 0;

	if (READ_ONCE(task->state) != TASK_INTERRUPTIBLE ||
	    READ_ONCE(task->on_cpu) != 0 || READ_ONCE(task->on_rq) != 0 ||
	    READ_ONCE(task->exit_state) != 0 || task->pid != repair->tid ||
	    task->tgid != expected_tgid)
		return -EBUSY;

	for (depth = 0; depth < LP3_MAX_FRAMES; ++depth) {
		unsigned long next_fp;
		unsigned long next_pc;
		unsigned long caller_pc;
		unsigned long slot;

		if (!lp3_frame_in_stack(stack, fp))
			break;
		next_fp = READ_ONCE(*(unsigned long *)fp);
		next_pc = ptrauth_strip_insn_pac(
				READ_ONCE(*(unsigned long *)(fp + 8)));
		if (next_fp <= fp)
			break;

		if (next_pc >= context->unix_start &&
		    next_pc < context->unix_end) {
			if (!lp3_frame_in_stack(stack, next_fp))
				return -EINVAL;
			caller_pc = ptrauth_strip_insn_pac(
					READ_ONCE(*(unsigned long *)(next_fp + 8)));
			if (caller_pc != context->sendmsg_return)
				return -EINVAL;
			slot = next_fp + LP3_SAVED_X23_FP_OFFSET;
			if (slot < stack || slot > stack + THREAD_SIZE - 8 ||
			    READ_ONCE(*(unsigned long *)slot) !=
					repair->old_ctlbuf)
				return -ESTALE;
			repair->frame_pointer = next_fp;
			repair->slot = slot;
			repair->depth = depth + 1;
			++matches;
		}
		fp = next_fp;
	}

	return matches == 1 ? 0 : -ENOENT;
}

static int lp3_stop_and_repair(void *data)
{
	struct lp3_stop_context *context = data;
	unsigned int i;

	for (i = 0; i < context->count; ++i) {
		context->error = lp3_validate_one_stack(context,
				&context->repairs[i]);
		if (context->error)
			return 0;
	}

	for (i = 0; i < context->count; ++i)
		WRITE_ONCE(*(unsigned long *)context->repairs[i].slot,
			(unsigned long)context->repairs[i].replacement);
	smp_wmb();
	context->patched = true;
	for (i = 0; i < context->count; ++i) {
		if (READ_ONCE(*(unsigned long *)context->repairs[i].slot) !=
		    (unsigned long)context->repairs[i].replacement) {
			context->error = -EIO;
			return 0;
		}
	}
	return 0;
}

static bool lp3_finalise_kernel_pointer(unsigned long value)
{
	return lp3_kernel_pointer(value) && (value & 0x7UL) == 0;
}

static bool lp3_finalise_read(unsigned long address, unsigned long *value)
{
	if (!lp3_kernel_pointer(address) || value == NULL)
		return false;
	*value = READ_ONCE(*(unsigned long *)address);
	return lp3_kernel_pointer(*value) || *value == 0;
}

static bool lp3_finalise_count_helper_donor_files(unsigned int *matches,
						   unsigned int *open_count,
						   unsigned int *max_fds,
						   unsigned int *usage)
{
	struct files_struct *files = READ_ONCE(current->files);
	struct file *seen[64] = { NULL };
	struct fdtable *fdt;
	unsigned long flags;
	unsigned int fd;
	unsigned int found = 0;
	unsigned int opened = 0;
	bool valid = true;

	if (matches == NULL || open_count == NULL || max_fds == NULL ||
		usage == NULL ||
		current->pid != helper_tid || current->tgid != helper_tid ||
		(unsigned long)current != helper_task || files == NULL)
		return false;
	spin_lock_irqsave(&files->file_lock, flags);
	fdt = files_fdtable(files);
	if (fdt == NULL || fdt->fd == NULL || fdt->open_fds == NULL ||
		fdt->max_fds == 0 || fdt->max_fds > 65536U) {
		valid = false;
		goto out;
	}
	for (fd = 0; fd < fdt->max_fds; ++fd) {
		struct file *file;
		unsigned int index;

		if (!test_bit(fd, fdt->open_fds))
			continue;
		if (++opened > 16384U) {
			valid = false;
			goto out;
		}
		file = READ_ONCE(fdt->fd[fd]);
		if (file == NULL) {
			valid = false;
			goto out;
		}
		if ((unsigned long)READ_ONCE(file->f_cred) != donor_cred)
			continue;
		for (index = 0; index < found; ++index) {
			if (seen[index] == file)
				break;
		}
		if (index != found)
			continue;
		if (found == ARRAY_SIZE(seen)) {
			valid = false;
			goto out;
		}
		seen[found++] = file;
	}
	*usage = (unsigned int)atomic_read(
		&((const struct cred *)donor_cred)->usage);
out:
	*matches = found;
	*open_count = opened;
	*max_fds = fdt != NULL ? fdt->max_fds : 0;
	spin_unlock_irqrestore(&files->file_lock, flags);
	return valid;
}

static int lp3_finalise_donor_snapshot_once(unsigned int *usage,
					      unsigned long *repair,
					      bool require_file_refs)
{
	struct task_struct *task = (struct task_struct *)finalise_donor_task;
	const struct cred *cred;
	unsigned long security;
	unsigned long ids;
	unsigned int expected_usage;
	unsigned int sid;
	bool usage_excess;

	finalise_snapshot_stage = 1;
	finalise_snapshot_state = 0;
	finalise_snapshot_pid = 0;
	finalise_snapshot_tgid = 0;
	finalise_snapshot_real_cred = 0;
	finalise_snapshot_cred = 0;
	finalise_snapshot_real_slot = 0;
	finalise_snapshot_cred_slot = 0;
	finalise_snapshot_usage = 0;
	finalise_snapshot_file_refs = 0;
	finalise_snapshot_open_fds = 0;
	finalise_snapshot_max_fds = 0;
	finalise_snapshot_ids_mask = 0;
	finalise_snapshot_caps = 0;
	finalise_snapshot_repair = ~0UL;
	finalise_snapshot_security = 0;
	finalise_snapshot_security_word8 = 0;
	finalise_snapshot_sid = 0;
	if (usage == NULL || repair == NULL || finalise_donor_pid <= 0 ||
		!lp3_finalise_kernel_pointer((unsigned long)task))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_pid = READ_ONCE(task->pid);
	finalise_snapshot_tgid = READ_ONCE(task->tgid);
	finalise_snapshot_state = READ_ONCE(task->state);
	finalise_snapshot_stage = 2;
	if (finalise_snapshot_pid != finalise_donor_pid ||
		finalise_snapshot_tgid != finalise_donor_pid)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 3;
	if (!(finalise_snapshot_state & TASK_STOPPED))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_real_cred =
		(unsigned long)READ_ONCE(task->real_cred);
	finalise_snapshot_cred = (unsigned long)READ_ONCE(task->cred);
	finalise_snapshot_stage = 4;
	if (!lp3_kernel_pointer(finalise_snapshot_real_cred) ||
		!lp3_kernel_pointer(finalise_snapshot_cred) ||
		finalise_snapshot_real_cred != donor_cred ||
		finalise_snapshot_cred != donor_cred)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 5;
	if (finalise_donor_real_cred_slot !=
			finalise_donor_task + LP3_TASK_REAL_CRED_OFFSET ||
		finalise_donor_cred_slot !=
			finalise_donor_task + LP3_TASK_CRED_OFFSET)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_real_slot = READ_ONCE(
		*(unsigned long *)finalise_donor_real_cred_slot);
	finalise_snapshot_cred_slot = READ_ONCE(
		*(unsigned long *)finalise_donor_cred_slot);
	finalise_snapshot_stage = 6;
	if (finalise_snapshot_real_slot != donor_cred ||
		finalise_snapshot_cred_slot != donor_cred)
		return LP3_SNAPSHOT_FATAL;
	cred = (const struct cred *)donor_cred;
	finalise_snapshot_stage = 7;
	if (!lp3_finalise_count_helper_donor_files(
			&finalise_snapshot_file_refs,
			&finalise_snapshot_open_fds,
			&finalise_snapshot_max_fds,
			&finalise_snapshot_usage))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 8;
	if ((require_file_refs && finalise_snapshot_file_refs == 0) ||
		finalise_snapshot_file_refs > UINT_MAX - finalise_donor_usage)
		return LP3_SNAPSHOT_FATAL;
	expected_usage = finalise_donor_usage + finalise_snapshot_file_refs;
	if (finalise_snapshot_usage < expected_usage)
		return LP3_SNAPSHOT_FATAL;
	usage_excess = finalise_snapshot_usage > expected_usage;
	if (__kuid_val(cred->uid) == finalise_donor_uid)
		finalise_snapshot_ids_mask |= BIT(0);
	if (__kuid_val(cred->euid) == finalise_donor_euid)
		finalise_snapshot_ids_mask |= BIT(1);
	if (__kuid_val(cred->suid) == finalise_donor_suid)
		finalise_snapshot_ids_mask |= BIT(2);
	if (__kuid_val(cred->fsuid) == finalise_donor_fsuid)
		finalise_snapshot_ids_mask |= BIT(3);
	if (__kgid_val(cred->gid) == finalise_donor_gid)
		finalise_snapshot_ids_mask |= BIT(4);
	if (__kgid_val(cred->egid) == finalise_donor_egid)
		finalise_snapshot_ids_mask |= BIT(5);
	if (__kgid_val(cred->sgid) == finalise_donor_sgid)
		finalise_snapshot_ids_mask |= BIT(6);
	if (__kgid_val(cred->fsgid) == finalise_donor_fsgid)
		finalise_snapshot_ids_mask |= BIT(7);
	finalise_snapshot_stage = 9;
	if (finalise_snapshot_ids_mask != 0xffU)
		return LP3_SNAPSHOT_FATAL;
	ids = (unsigned long)cred->cap_effective.cap[0] |
		((unsigned long)cred->cap_effective.cap[1] << 32);
	finalise_snapshot_caps = ids;
	finalise_snapshot_stage = 10;
	if (ids != finalise_donor_caps)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 11;
	if (!lp3_finalise_read((unsigned long)cred + 8, repair))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_repair = *repair;
	finalise_snapshot_stage = 12;
	if (*repair != 0)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 13;
	if (!lp3_finalise_read((unsigned long)cred +
			LP3_CRED_SECURITY_OFFSET, &security))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_security = security;
	finalise_snapshot_stage = 14;
	if (security != finalise_donor_security)
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_stage = 15;
	if (!lp3_kernel_pointer(security))
		return LP3_SNAPSHOT_FATAL;
	finalise_snapshot_security_word8 =
		READ_ONCE(*(unsigned long *)(security + 8));
	sid = READ_ONCE(*(unsigned int *)(security + 4));
	finalise_snapshot_sid = sid;
	finalise_snapshot_stage = 16;
	if (finalise_snapshot_security_word8 !=
			borrowed_task_security_word8 || sid != finalise_donor_sid)
		return LP3_SNAPSHOT_FATAL;
	if (usage_excess) {
		finalise_snapshot_stage = 18;
		return LP3_SNAPSHOT_EXCESS;
	}
	*usage = finalise_snapshot_usage;
	finalise_snapshot_stage = 17;
	return LP3_SNAPSHOT_EXACT;
}

static bool lp3_finalise_donor_snapshot(unsigned int *usage,
					 unsigned long *repair,
					 bool require_file_refs)
{
	unsigned long deadline = jiffies + msecs_to_jiffies(5000);
	unsigned int delay_ms = 10;

	for (;;) {
		int result = lp3_finalise_donor_snapshot_once(
			usage, repair, require_file_refs);

		if (result == LP3_SNAPSHOT_EXACT)
			return true;
		if (result != LP3_SNAPSHOT_EXCESS || time_after_eq(jiffies, deadline))
			return false;
		msleep(delay_ms);
		delay_ms = 50;
	}
}

static struct task_struct *lp3_finalise_owner_task_get(void)
{
	struct pid *pid;
	struct task_struct *task;

	if (finalise_owner_pid <= 0)
		return NULL;
	pid = find_get_pid(finalise_owner_pid);
	if (pid == NULL)
		return NULL;
	task = get_pid_task(pid, PIDTYPE_PID);
	put_pid(pid);
	if (task == NULL)
		return NULL;
	/* Do not dereference the parameter until the PID lookup has pinned a
	 * task.  The pointer comparison binds this run to the recorded task. */
	if ((unsigned long)task != finalise_owner_task ||
		READ_ONCE(task->pid) != finalise_owner_pid ||
		READ_ONCE(task->tgid) != finalise_owner_pid) {
		put_task_struct(task);
		return NULL;
	}
	return task;
}

static bool lp3_finalise_task_files_get(struct task_struct *task,
					       struct file **watched,
					       struct file **arbitrary,
					       struct file **reference)
{
	struct files_struct *files;
	struct fdtable *fdt;
	struct file *found[3] = { NULL, NULL, NULL };
	const int fds[3] = {
		finalise_watched_fd,
		finalise_arbitrary_fd,
		finalise_reference_fd,
	};
	const unsigned long expected[3] = {
		finalise_watched_file,
		finalise_arbitrary_file,
		finalise_reference_file,
	};
	unsigned long flags;
	unsigned int index;
	bool valid = false;

	if (task == NULL || watched == NULL || arbitrary == NULL ||
		reference == NULL)
		return false;
	*watched = NULL;
	*arbitrary = NULL;
	*reference = NULL;
	for (index = 0; index < ARRAY_SIZE(fds); ++index) {
		if (fds[index] < 0 ||
			!lp3_finalise_kernel_pointer(expected[index]))
			return false;
	}
	/* task_lock keeps task->files alive until all three file references are
	 * acquired.  The file-table lock gives one exact descriptor snapshot. */
	task_lock(task);
	files = READ_ONCE(task->files);
	if (files == NULL)
		goto out_task;
	spin_lock_irqsave(&files->file_lock, flags);
	fdt = files_fdtable(files);
	if (fdt == NULL || fdt->fd == NULL || fdt->open_fds == NULL)
		goto out_files;
	for (index = 0; index < ARRAY_SIZE(fds); ++index) {
		if (fds[index] >= fdt->max_fds ||
			!test_bit(fds[index], fdt->open_fds))
			goto out_files;
		found[index] = READ_ONCE(fdt->fd[fds[index]]);
		if (found[index] == NULL ||
			(unsigned long)found[index] != expected[index])
			goto out_files;
	}
	get_file(found[0]);
	get_file(found[1]);
	get_file(found[2]);
	*watched = found[0];
	*arbitrary = found[1];
	*reference = found[2];
	valid = true;
out_files:
	spin_unlock_irqrestore(&files->file_lock, flags);
out_task:
	task_unlock(task);
	return valid;
}

static bool lp3_finalise_file_exact(struct file *file,
					unsigned long expected_file,
					unsigned long expected_inode,
					unsigned long expected_fops)
{
	if (file == NULL || (unsigned long)file != expected_file ||
		!lp3_finalise_kernel_pointer(expected_file) ||
		READ_ONCE(file->f_inode) == NULL ||
		(unsigned long)READ_ONCE(file->f_inode) != expected_inode ||
		(unsigned long)READ_ONCE(file->f_op) != expected_fops ||
		!lp3_finalise_kernel_pointer(expected_inode) ||
		!lp3_finalise_kernel_pointer(expected_fops))
		return false;
	return true;
}

static int lp3_finalise_walk_reverse(unsigned long head,
					unsigned long selected_link,
					unsigned long *successor,
					unsigned long *selected_next,
					unsigned int *count,
					unsigned int *non_selected_forward,
					unsigned int *selected_seen)
{
	unsigned long cursor;
	unsigned long previous = head;
	unsigned int walked = 0;
	int result = -EINVAL;

	if (!lp3_finalise_kernel_pointer(head) ||
		!lp3_finalise_kernel_pointer(selected_link) || successor == NULL ||
		selected_next == NULL || count == NULL || non_selected_forward == NULL ||
		selected_seen == NULL)
		return -EINVAL;
	*successor = 0;
	*selected_next = 0;
	*count = 0;
	*non_selected_forward = 0;
	*selected_seen = 0;
	cursor = READ_ONCE(*(unsigned long *)(head +
		LP3_EPITEM_FLLINK_PREV_OFFSET));
	while (walked < finalise_expected_count && cursor != head) {
		unsigned long prev;
		unsigned long next;

		if (!lp3_finalise_kernel_pointer(cursor))
			goto out;
		prev = READ_ONCE(*(unsigned long *)
			(cursor + LP3_EPITEM_FLLINK_PREV_OFFSET));
		next = READ_ONCE(*(unsigned long *)
			(cursor + LP3_EPITEM_FLLINK_NEXT_OFFSET));
		if (!lp3_finalise_kernel_pointer(prev) ||
			!lp3_finalise_kernel_pointer(next))
			goto out;
		if (cursor == selected_link) {
			/* The selected link is deliberately corrupt before the write;
			 * validate the reverse edge without dereferencing its bad next. */
			if (READ_ONCE(*(unsigned long *)
					(prev + LP3_EPITEM_FLLINK_NEXT_OFFSET)) != cursor)
				goto out;
			*successor = previous;
			*selected_next = next;
			++*selected_seen;
		} else {
			if ((prev != selected_link && READ_ONCE(*(unsigned long *)
					(prev + LP3_EPITEM_FLLINK_NEXT_OFFSET)) != cursor) ||
				READ_ONCE(*(unsigned long *)
					(next + LP3_EPITEM_FLLINK_PREV_OFFSET)) != cursor)
				goto out;
			++*non_selected_forward;
		}
		++walked;
		previous = cursor;
		cursor = prev;
	}
	if (walked != finalise_expected_count || cursor != head ||
		*selected_seen != 1 || !lp3_finalise_kernel_pointer(*successor))
		goto out;
	*count = walked;
	result = 0;
out:
	*count = walked;
	return result;
}

static int lp3_finalise_walk_forward(unsigned long head,
					unsigned int *count,
					unsigned int *reverse_relationships)
{
	unsigned long cursor;
	unsigned long previous = head;
	unsigned int walked = 0;
	int result = -EINVAL;

	if (!lp3_finalise_kernel_pointer(head) || count == NULL ||
		reverse_relationships == NULL)
		return -EINVAL;
	*count = 0;
	*reverse_relationships = 0;
	cursor = READ_ONCE(*(unsigned long *)(head +
		LP3_EPITEM_FLLINK_NEXT_OFFSET));
	while (walked < finalise_expected_count && cursor != head) {
		unsigned long prev;
		unsigned long next;

		if (!lp3_finalise_kernel_pointer(cursor))
			goto out;
		prev = READ_ONCE(*(unsigned long *)
			(cursor + LP3_EPITEM_FLLINK_PREV_OFFSET));
		next = READ_ONCE(*(unsigned long *)
			(cursor + LP3_EPITEM_FLLINK_NEXT_OFFSET));
		if (!lp3_finalise_kernel_pointer(prev) ||
			!lp3_finalise_kernel_pointer(next) || prev != previous ||
			READ_ONCE(*(unsigned long *)
				(prev + LP3_EPITEM_FLLINK_NEXT_OFFSET)) != cursor ||
			READ_ONCE(*(unsigned long *)
				(next + LP3_EPITEM_FLLINK_PREV_OFFSET)) != cursor)
			goto out;
		++walked;
		++*reverse_relationships;
		previous = cursor;
		cursor = next;
	}
	if (walked != finalise_expected_count || cursor != head ||
		READ_ONCE(*(unsigned long *)(head +
			LP3_EPITEM_FLLINK_PREV_OFFSET)) != previous)
		goto out;
	*count = walked;
	result = 0;
out:
	*count = walked;
	return result;
}

static int lp3_finalise_set_status(const char *reason, int error,
					unsigned int donor_a, unsigned int donor_b,
					unsigned long pre_inode,
					unsigned long pre_next,
					unsigned long successor,
					unsigned int reverse_count,
					unsigned int forward_count,
					unsigned int non_selected_forward,
					unsigned int reverse_relationships,
					unsigned long post_link,
					unsigned long final_post_link,
					unsigned int restored_link,
					unsigned int restored_inode,
					unsigned int forward_cycle,
					unsigned int reverse_cycle,
					unsigned int readbacks)
{
	scnprintf(finalise_status, sizeof(finalise_status),
		"status=%s stage=ctlbuf-finalise reason=%s error=%d"
		" helper_pid=%d helper_task=0x%lx helper_borrowed=%d"
		" owner_task=0x%lx owner_pid=%d watched_fd=%d arbitrary_fd=%d"
		" reference_fd=%d watched_file=0x%lx watched_inode=0x%lx"
		" arbitrary_file=0x%lx arbitrary_inode=0x%lx"
		" reference_file=0x%lx reference_inode=0x%lx"
		" watched_fops=0x%lx arbitrary_fops=0x%lx reference_fops=0x%lx"
		" selected_epitem=0x%lx expected_fops=0x%lx expected_count=%u reverse_count=%u"
		" forward_count=%u non_selected_forward=%u"
		" reverse_relationships=%u pre_inode=0x%lx pre_next=0x%lx"
		" successor=0x%lx post_link=0x%lx final_post_link=0x%lx"
		" restored_link=%u restored_inode=%u"
		" restored_inode_value=0x%lx restored_inode_source=reference"
		" forward_cycle=%u reverse_cycle=%u readbacks=%u"
		" donor_task=0x%lx donor_pid=%d donor_real_cred_slot=0x%lx"
		" donor_cred_slot=0x%lx donor_cred=0x%lx"
		" donor_usage=%u donor_uid=%u donor_euid=%u donor_suid=%u"
		" donor_fsuid=%u donor_gid=%u donor_egid=%u donor_sgid=%u"
		" donor_fsgid=%u donor_caps=0x%lx donor_sid=%u donor_repair=0x0"
		" donor_frozen=%u donor_snapshot_a=%u donor_snapshot_b=%u"
		" donor_snapshot_stage=%u donor_state=0x%lx"
		" donor_observed_pid=%d donor_observed_tgid=%d"
		" donor_observed_real_cred=0x%lx donor_observed_cred=0x%lx"
		" donor_observed_real_slot=0x%lx donor_observed_cred_slot=0x%lx"
		" donor_observed_usage=%u donor_file_refs=%u"
		" donor_open_fds=%u donor_max_fds=%u donor_ids_mask=0x%x"
		" donor_observed_caps=0x%lx donor_observed_repair=0x%lx"
		" donor_observed_security=0x%lx"
		" donor_observed_security_word8=0x%lx donor_observed_sid=%u"
		" list_exact=%u proof=%u",
		(finalise_complete ? "pass" : "fail"), reason, error,
		helper_tid, helper_task, lp3_helper_is_borrowed() ? 1 : 0,
		finalise_owner_task, finalise_owner_pid, finalise_watched_fd,
		finalise_arbitrary_fd, finalise_reference_fd, finalise_watched_file,
		finalise_watched_inode, finalise_arbitrary_file,
		finalise_arbitrary_inode, finalise_reference_file,
		finalise_reference_inode, finalise_watched_fops,
		finalise_arbitrary_fops, finalise_reference_fops,
		finalise_selected_epitem, finalise_expected_fops,
		finalise_expected_count, reverse_count,
		forward_count, non_selected_forward, reverse_relationships,
		pre_inode, pre_next, successor, post_link, final_post_link,
		restored_link, restored_inode,
		finalise_reference_inode,
		forward_cycle, reverse_cycle, readbacks, finalise_donor_task,
		finalise_donor_pid, finalise_donor_real_cred_slot,
		finalise_donor_cred_slot, donor_cred, finalise_donor_usage,
		finalise_donor_uid, finalise_donor_euid, finalise_donor_suid,
		finalise_donor_fsuid, finalise_donor_gid, finalise_donor_egid,
		finalise_donor_sgid, finalise_donor_fsgid, finalise_donor_caps,
		finalise_donor_sid, (donor_a == 1 && donor_b == 1) ? 1 : 0,
		donor_a, donor_b, finalise_snapshot_stage,
		finalise_snapshot_state, finalise_snapshot_pid,
		finalise_snapshot_tgid, finalise_snapshot_real_cred,
		finalise_snapshot_cred, finalise_snapshot_real_slot,
		finalise_snapshot_cred_slot, finalise_snapshot_usage,
		finalise_snapshot_file_refs, finalise_snapshot_open_fds,
		finalise_snapshot_max_fds, finalise_snapshot_ids_mask,
		finalise_snapshot_caps,
		finalise_snapshot_repair, finalise_snapshot_security,
		finalise_snapshot_security_word8, finalise_snapshot_sid,
		reverse_count == finalise_expected_count ? 1 : 0,
		finalise_complete ? 1 : 0);
	return finalise_complete ? 0 : error;
}

static int lp3_run_finalise(void)
{
	struct task_struct *owner = NULL;
	struct file *watched = NULL;
	struct file *arbitrary = NULL;
	struct file *reference = NULL;
	unsigned long watched_head = 0;
	unsigned long selected_link = 0;
	unsigned long successor = 0;
	unsigned long final_successor = 0;
	unsigned long pre_inode = 0;
	unsigned long pre_next = 0;
	unsigned long replacement_inode = 0;
	unsigned long post_link = 0;
	unsigned long final_post_link = 0;
	unsigned long flags = 0;
	unsigned int donor_a = 0;
	unsigned int donor_b = 0;
	unsigned int reverse_count = 0;
	unsigned int forward_count = 0;
	unsigned int non_selected_forward = 0;
	unsigned int reverse_relationships = 0;
	unsigned int selected_seen = 0;
	unsigned int restored_link = 0;
	unsigned int restored_inode = 0;
	unsigned int forward_cycle = 0;
	unsigned int reverse_cycle = 0;
	unsigned int readbacks = 0;
	unsigned int usage_a = 0;
	unsigned int usage_b = 0;
	unsigned int file_refs_a = 0;
	bool watched_locked = false;
	bool success = false;
	int error = -EINVAL;

	finalise_complete = false;
	finalise_successor_valid = false;
	finalise_successor = 0;
	if (finalise_owner_pid <= 0 || finalise_owner_pid == helper_tid ||
		current->pid != helper_tid || current->tgid != helper_tid ||
		(unsigned long)current != helper_task ||
		lp3_helper_borrowed_error() ||
		!lp3_finalise_kernel_pointer(finalise_owner_task) ||
		finalise_expected_fops == 0 ||
		finalise_watched_fops != finalise_expected_fops ||
		finalise_arbitrary_fops != finalise_expected_fops ||
		finalise_reference_fops != finalise_expected_fops ||
		(finalise_expected_count != 1 &&
		 finalise_expected_count != LP3_EXPECTED_EP_LINKS))
		goto fail;
	owner = lp3_finalise_owner_task_get();
	if (owner == NULL)
		goto fail;
	if (!lp3_finalise_task_files_get(owner, &watched, &arbitrary,
		&reference))
		goto fail;
	watched_head = finalise_watched_file + LP3_FILE_EP_LINKS_OFFSET;
	selected_link = finalise_selected_epitem + LP3_EPITEM_FLLINK_OFFSET;
	if (!lp3_finalise_kernel_pointer(watched_head) ||
		!lp3_finalise_kernel_pointer(selected_link))
		goto fail;
	if (!lp3_finalise_donor_snapshot(
			&usage_a, &replacement_inode, true))
		goto fail;
	donor_a = 1;
	file_refs_a = finalise_snapshot_file_refs;
	if (!donor_a || !lp3_finalise_donor_snapshot(
			&usage_b, &replacement_inode, true))
		goto fail;
	donor_b = usage_b == usage_a &&
		finalise_snapshot_file_refs == file_refs_a ? 1 : 0;
	if (!donor_b)
		goto fail;

	/* The watched file lock is the only lock held during the complete
	 * topology transaction.  Walkers are bounded by the exact list count
	 * and validate both list relationships, so they need no scratch memory. */
	spin_lock_irqsave(&watched->f_lock, flags);
	watched_locked = true;
	if (!lp3_finalise_file_exact(watched, finalise_watched_file,
			finalise_watched_inode, finalise_watched_fops) ||
		!lp3_finalise_file_exact(arbitrary, finalise_arbitrary_file,
			finalise_arbitrary_inode, finalise_arbitrary_fops) ||
		!lp3_finalise_file_exact(reference, finalise_reference_file,
			finalise_reference_inode, finalise_reference_fops) ||
		watched == arbitrary || watched == reference || arbitrary == reference ||
		finalise_watched_inode != finalise_reference_inode ||
		!lp3_finalise_kernel_pointer(watched_head) ||
		!lp3_finalise_kernel_pointer(selected_link) ||
		!lp3_finalise_read(finalise_arbitrary_file + LP3_FILE_INODE_OFFSET,
			&pre_inode) ||
		pre_inode != finalise_selected_epitem + 0x50UL)
		goto fail;
	if (lp3_finalise_walk_reverse(watched_head, selected_link, &successor,
		&pre_next, &reverse_count, &non_selected_forward, &selected_seen) ||
		reverse_count != finalise_expected_count ||
		non_selected_forward != finalise_expected_count - 1 ||
		selected_seen != 1 ||
		pre_next != finalise_arbitrary_file + LP3_FILE_INODE_OFFSET)
		goto fail;
	WRITE_ONCE(*(unsigned long *)(selected_link +
		LP3_EPITEM_FLLINK_NEXT_OFFSET), successor);
	smp_wmb();
	post_link = READ_ONCE(*(unsigned long *)(selected_link +
		LP3_EPITEM_FLLINK_NEXT_OFFSET));
	restored_link = post_link == successor ? 1 : 0;
	if (!restored_link)
		goto fail;
	WRITE_ONCE(*(unsigned long *)(finalise_arbitrary_file +
		LP3_FILE_INODE_OFFSET), finalise_reference_inode);
	smp_wmb();
	if (READ_ONCE(*(unsigned long *)(finalise_arbitrary_file +
		LP3_FILE_INODE_OFFSET)) != finalise_reference_inode)
		goto fail;
	restored_inode = 1;
	if (lp3_finalise_walk_forward(watched_head, &forward_count,
		&reverse_relationships) || forward_count != finalise_expected_count ||
		reverse_relationships != finalise_expected_count)
		goto fail;
	forward_cycle = 1;
	if (lp3_finalise_walk_reverse(watched_head, selected_link,
		&final_successor, &final_post_link, &reverse_count, &non_selected_forward,
		&selected_seen) || reverse_count != finalise_expected_count ||
		selected_seen != 1 ||
		non_selected_forward != finalise_expected_count - 1 ||
		final_successor != successor)
		goto fail;
	reverse_cycle = 1;
	if (!lp3_finalise_read(finalise_arbitrary_file + LP3_FILE_INODE_OFFSET,
		&replacement_inode) || replacement_inode != finalise_reference_inode ||
		final_post_link != successor)
		goto fail;
	readbacks = final_post_link == successor ? 1 : 0;
	if (!readbacks)
		goto fail;
	success = true;
	finalise_complete = true;
	finalise_successor = successor;
	finalise_successor_valid = true;
fail:
	if (watched_locked)
		spin_unlock_irqrestore(&watched->f_lock, flags);
	if (reference != NULL)
		fput(reference);
	if (arbitrary != NULL)
		fput(arbitrary);
	if (watched != NULL)
		fput(watched);
	if (owner != NULL)
		put_task_struct(owner);
	return lp3_finalise_set_status(success ? "none" : "validation",
		success ? 0 : error, donor_a, donor_b,
		pre_inode, pre_next, successor, reverse_count, forward_count,
		non_selected_forward, reverse_relationships, post_link,
		final_post_link, restored_link, restored_inode, forward_cycle,
		reverse_cycle, readbacks);
}

static bool lp3_finalise_state_revalidates(void)
{
	struct task_struct *owner = NULL;
	struct file *watched = NULL;
	struct file *arbitrary = NULL;
	struct file *reference = NULL;
	unsigned long watched_head = 0;
	unsigned long selected_link = 0;
	unsigned long successor = 0;
	unsigned long selected_next = 0;
	unsigned long inode = 0;
	unsigned long flags = 0;
	unsigned int reverse_count = 0;
	unsigned int forward_count = 0;
	unsigned int non_selected_forward = 0;
	unsigned int reverse_relationships = 0;
	unsigned int selected_seen = 0;
	bool watched_locked = false;
	bool valid = false;

	if (!finalise_complete || !finalise_successor_valid ||
		!lp3_finalise_kernel_pointer(finalise_owner_task))
		goto out;
	owner = lp3_finalise_owner_task_get();
	if (owner == NULL)
		goto out;
	if (!lp3_finalise_task_files_get(owner, &watched, &arbitrary,
		&reference))
		goto out;
	watched_head = finalise_watched_file + LP3_FILE_EP_LINKS_OFFSET;
	selected_link = finalise_selected_epitem + LP3_EPITEM_FLLINK_OFFSET;
	spin_lock_irqsave(&watched->f_lock, flags);
	watched_locked = true;
	if (!lp3_finalise_file_exact(watched, finalise_watched_file,
			finalise_watched_inode, finalise_watched_fops) ||
		!lp3_finalise_file_exact(arbitrary, finalise_arbitrary_file,
			finalise_reference_inode, finalise_arbitrary_fops) ||
		!lp3_finalise_file_exact(reference, finalise_reference_file,
			finalise_reference_inode, finalise_reference_fops) ||
		finalise_watched_inode != finalise_reference_inode ||
		watched == arbitrary || watched == reference ||
		arbitrary == reference ||
		!lp3_finalise_kernel_pointer(watched_head) ||
		!lp3_finalise_kernel_pointer(selected_link) ||
		!lp3_finalise_read(finalise_arbitrary_file +
			LP3_FILE_INODE_OFFSET, &inode) ||
		inode != finalise_reference_inode ||
		lp3_finalise_walk_forward(watched_head, &forward_count,
			&reverse_relationships) ||
		forward_count != finalise_expected_count ||
		reverse_relationships != finalise_expected_count ||
		lp3_finalise_walk_reverse(watched_head, selected_link, &successor,
			&selected_next,
			&reverse_count, &non_selected_forward, &selected_seen) ||
		reverse_count != finalise_expected_count ||
		non_selected_forward != finalise_expected_count - 1 ||
		selected_seen != 1 || successor != finalise_successor ||
		selected_next != finalise_successor)
		goto out;
	valid = true;
out:
	if (watched_locked)
		spin_unlock_irqrestore(&watched->f_lock, flags);
	if (reference != NULL)
		fput(reference);
	if (arbitrary != NULL)
		fput(arbitrary);
	if (watched != NULL)
		fput(watched);
	if (owner != NULL)
		put_task_struct(owner);
	return valid;
}

static int lp3_finalise_set(const char *value,
				const struct kernel_param *param)
{
	unsigned int request;
	int result;

	(void)param;
	if (value == NULL || kstrtouint(value, 0, &request) || request != 1 ||
		finalise_request != 0)
		return -EINVAL;
	finalise_request = request;
	result = lp3_run_finalise();
	if (result)
		return 0;
	return 0;
}

static int __init lp3_ctlbuf_rescue_init(void)
{
	struct lp3_stop_context context = {
		.repairs = repairs,
		.count = LP3_EXPECTED_REPAIRS,
		.unix_start = kernel_base + LP3_UNIX_DGRAM_OFFSET,
		.unix_end = kernel_base + LP3_UNIX_DGRAM_END_OFFSET,
		.sendmsg_return = kernel_base + LP3_SENDMSG_OFFSET +
			LP3_SENDMSG_RETURN_OFFSET,
	};
	int result;

	BUILD_BUG_ON(sizeof(struct lp3_resume_record) != 176);
	BUILD_BUG_ON(offsetof(struct lp3_resume_record, commit) != 168);

	strscpy(repair_status, "validating", sizeof(repair_status));
	if (!lp3_text_matches())
		return -EILSEQ;
	result = lp3_loader_and_target_error();
	if (result)
		return result == -ESRCH ? -ENXIO :
			result == -EINVAL ? -EUCLEAN : result;
	result = lp3_stabilise_carriers();
	if (result)
		return result == -ESRCH ? -ENODEV :
			result == -EINVAL ? -EREMOTEIO : result;
	result = lp3_normalise_helper_real_cred();
	if (result == -ESRCH)
		result = -EOWNERDEAD;
	else if (result == -EINVAL)
		result = -EPROTO;
	if (result)
		goto fail;
	result = lp3_prepare_repairs();
	if (result == -ESRCH)
		result = -EIDRM;
	else if (result == -EINVAL)
		result = -ENOTUNIQ;
	if (result)
		goto fail;
	result = stop_machine(lp3_stop_and_repair, &context, NULL);
	if (result || context.error) {
		result = result == -ESRCH ? -ENOMSG : result;
		context.error = context.error == -ESRCH ?
			-EBADMSG : context.error;
		if (result == -EINVAL)
			result = -EBADR;
		if (context.error == -EINVAL)
			context.error = -EBADR;
		result = result ? result : context.error;
		goto fail;
	}
	repaired_count = LP3_EXPECTED_REPAIRS;
	repair_complete = true;
	{
		size_t used = scnprintf(repair_status, sizeof(repair_status),
				"status=pass count=%u", repaired_count);
		unsigned int i;

		for (i = 0; i < LP3_EXPECTED_REPAIRS &&
		     used < sizeof(repair_status); ++i) {
			used += scnprintf(repair_status + used,
					sizeof(repair_status) - used,
					" e%u=%d/0x%lx/0x%lx/0x%lx/%u",
					i, repairs[i].tid, repairs[i].old_ctlbuf,
					repairs[i].slot,
					(unsigned long)repairs[i].replacement,
					repairs[i].depth);
		}
	}
	lp3_release_repair_refs(false);
	return 0;

fail:
	strscpy(repair_status, "failed", sizeof(repair_status));
	lp3_release_repair_refs(!context.patched);
	if (lp3_restore_task_label())
		return -EIO;
	return result;
}

static void __exit lp3_ctlbuf_rescue_exit(void)
{
	struct lp3_resume_record record = { 0 };
	const struct cred *private = (const struct cred *)private_cred;
	struct pid *pid = NULL;
	struct task_struct *task = NULL;
	unsigned int donor_usage = 0;
	unsigned long donor_repair = ~0UL;
	unsigned long state_before = 0;
	unsigned long exit_state_before = 0;
	unsigned long state_after = 0;
	unsigned long exit_state_after = 0;
	unsigned int before_threads = 0;
	unsigned int before_stopped = 0;
	unsigned int after_threads = 0;
	unsigned int after_stopped = 0;
	unsigned int stable_samples = 0;
	unsigned int last_threads = 0;
	unsigned long deadline;
	int signal_result = -1;
	int signal_errno = 0;
	bool resumed = false;
	bool donor_baseline = finalise_complete &&
		lp3_finalise_donor_snapshot(
			&donor_usage, &donor_repair, false) &&
		donor_repair == 0;
	bool finalise_revalidated = lp3_finalise_state_revalidates();
	bool buffer_valid = resume_user_size == sizeof(record) &&
		resume_user_addr >= 4096UL &&
		resume_user_addr <= ULONG_MAX - sizeof(record) &&
		(resume_cookie_hi != 0 || resume_cookie_lo != 0) &&
		access_ok((void __user *)resume_user_addr, resume_user_size);
	bool ready = lp3_carriers_still_stabilised() && repair_complete &&
		repaired_count == LP3_EXPECTED_REPAIRS &&
		lp3_repairs_still_installed() && lp3_helper_is_borrowed() &&
		finalise_revalidated && donor_baseline && buffer_valid;

	record.magic = LP3_RESUME_MAGIC;
	record.cookie_hi = resume_cookie_hi;
	record.cookie_lo = resume_cookie_lo;
	record.helper_task = (unsigned long)current;
	record.donor_task = finalise_donor_task;
	record.version = LP3_RESUME_VERSION;
	record.size = sizeof(record);
	record.helper_pid = current->pid;
	record.donor_pid = finalise_donor_pid;
	record.donor_tgid = finalise_donor_pid;
	record.signal = SIGCONT;
	record.signal_rc = -1;

	if (!ready) {
		goto publish;
	}
	pid = find_get_pid(finalise_donor_pid);
	if (pid == NULL)
		goto publish;
	task = get_pid_task(pid, PIDTYPE_PID);
	if (task == NULL || (unsigned long)task != finalise_donor_task ||
	    READ_ONCE(task->pid) != finalise_donor_pid ||
	    READ_ONCE(task->tgid) != finalise_donor_pid)
		goto publish;
	record.donor_task = (unsigned long)task;
	record.donor_pid = READ_ONCE(task->pid);
	record.donor_tgid = READ_ONCE(task->tgid);
	if (!lp3_donor_group_state(task, &state_before, &exit_state_before,
				   &before_threads,
				   &before_stopped) || before_threads == 0 ||
	    before_stopped != before_threads ||
	    !(state_before & (TASK_STOPPED | TASK_TRACED)))
		goto publish;
	if (lp3_restore_task_label() || !lp3_task_label_is_restored())
		goto publish;
	signal_result = kill_pid(pid, SIGCONT, 0);
	if (signal_result != 0) {
		signal_errno = signal_result < 0 ? -signal_result : EIO;
		goto publish;
	}
	deadline = jiffies + msecs_to_jiffies(5000);
	for (;;) {
		bool observed = lp3_donor_group_state(
			task, &state_after, &exit_state_after,
			&after_threads, &after_stopped);

		if (observed && after_threads > 0 && after_stopped == 0 &&
		    !(state_after & (TASK_STOPPED | TASK_TRACED))) {
			if (after_threads == last_threads)
				++stable_samples;
			else {
				last_threads = after_threads;
				stable_samples = 1;
			}
			if (stable_samples == 2)
				break;
		} else {
			stable_samples = 0;
			last_threads = 0;
		}
		if (time_after_eq(jiffies, deadline)) {
			goto publish;
		}
		msleep(50);
	}
	resumed = lp3_task_label_is_restored();
	if (!resumed)
		goto publish;

publish:
	if (carriers_stabilised && !labels_restored)
		lp3_restore_task_label();
	record.pre_state = state_before;
	record.pre_exit_state = exit_state_before;
	record.post_state = state_after;
	record.post_exit_state = exit_state_after;
	record.task_security = READ_ONCE(
		*(unsigned long *)donor_security_slot);
	record.task_security_word8 = READ_ONCE(
		*(unsigned long *)(borrowed_task_security + 8));
	record.inode_security = READ_ONCE(
		*(unsigned long *)inode_security_slot);
	record.inode_security_word8 = READ_ONCE(
		*(unsigned long *)(borrowed_inode_security + 8));
	record.signal_rc = signal_result;
	record.signal_errno = signal_errno;
	record.pre_thread_count = before_threads;
	record.pre_stopped_count = before_stopped;
	record.post_thread_count = after_threads;
	record.post_stopped_count = after_stopped;
	record.stable_samples = stable_samples;
	record.labels_restored = lp3_task_label_is_restored() ? 1U : 0U;
	record.resumed = resumed ? 1U : 0U;
	record.proof = resumed && signal_result == 0 && signal_errno == 0 &&
		record.labels_restored == 1U && record.pre_exit_state == 0 &&
		record.post_exit_state == 0 && before_threads > 0 &&
		before_stopped == before_threads && after_threads > 0 &&
		after_stopped == 0 && stable_samples == 2 ? 1U : 0U;
	record.commit = LP3_RESUME_MAGIC ^ resume_cookie_hi ^
		resume_cookie_lo ^ finalise_donor_task ^ LP3_RESUME_COMMIT_XOR;
	if (buffer_valid && copy_to_user(
			(void __user *)resume_user_addr, &record,
			offsetof(struct lp3_resume_record, commit)) == 0)
		(void)copy_to_user(
			(void __user *)(resume_user_addr +
				offsetof(struct lp3_resume_record, commit)),
			&record.commit, sizeof(record.commit));
	if (task != NULL)
		put_task_struct(task);
	if (pid != NULL)
		put_pid(pid);
	if (!lp3_task_label_is_restored() || !lp3_helper_is_borrowed())
		return;
	strscpy(repair_status, "restoring-helper", sizeof(repair_status));
	preempt_disable();
	WRITE_ONCE(*(const struct cred **)&current->real_cred, private);
	WRITE_ONCE(*(const struct cred **)&current->cred, private);
	smp_wmb();
	preempt_enable();
}

module_init(lp3_ctlbuf_rescue_init);
module_exit(lp3_ctlbuf_rescue_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Light Phone III terminal ctl_buf ownership repair");
MODULE_AUTHOR("light-side-of-the-moon");
