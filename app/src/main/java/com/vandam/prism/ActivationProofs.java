package com.vandam.prism;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/** Strict parsers for the successful direct activation cleanup proofs. */
final class ActivationProofs {
    private static final BigInteger ZERO = BigInteger.ZERO;
    private static final BigInteger ONE = BigInteger.ONE;
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger SIX = BigInteger.valueOf(6);
    private static final BigInteger SEVEN = BigInteger.valueOf(7);
    private static final BigInteger TWELVE = BigInteger.valueOf(12);
    private static final BigInteger EIGHTEEN = BigInteger.valueOf(18);
    private static final BigInteger UINT32_MAX = new BigInteger("ffffffff", 16);
    private static final BigInteger RESUME_MAGIC =
            new BigInteger("4c5033524553554d", 16);
    private static final BigInteger RESUME_COMMIT_MASK =
            new BigInteger("a5d91f7462c83be0", 16);

    private static final Pattern DECIMAL = Pattern.compile("-?[0-9]+");
    private static final Pattern UNSIGNED_DECIMAL = Pattern.compile("[0-9]+");
    private static final Pattern POSITIVE_DECIMAL = Pattern.compile("[1-9][0-9]*");
    private static final Pattern HEX = Pattern.compile("0x[0-9a-f]+");
    private static final Pattern LOWER_HEX_32 = Pattern.compile("[0-9a-f]{32}");
    private static final Pattern BOOT_ID = Pattern.compile(
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                    + "[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern HOST_STATE =
            Pattern.compile("[1-9][0-9]*:[A-Za-z]");
    private static final Pattern TOKEN_FIELD_NAME =
            Pattern.compile("[a-z][a-z0-9_]*");
    private static final Pattern ISSUE_STRING =
            Pattern.compile("[A-Za-z0-9_.:-]+");
    private static final Pattern ISSUE_ORDER =
            Pattern.compile("[A-Za-z0-9_.:,-]+");
    private static final Pattern PROGRESS_MARKER =
            Pattern.compile("[A-Za-z0-9_.-]+");
    private static final Pattern WHITESPACE = Pattern.compile("\\s+");
    private static final Pattern LINE_BREAK = Pattern.compile("\\R");

    private static final Map<String, String> TERMINAL_CLEANUP_FIXED_FIELDS =
            fixedFields(
                    "status", "pass",
                    "stage", "terminal-cleanup",
                    "outcome", "clean",
                    "reason", "none");

    private static final Set<String> TERMINAL_CLEANUP_INTEGER_FIELDS = setOf(
            "reboot_required",
            "durable",
            "sequence_complete",
            "required_writes",
            "successful_writes",
            "internal_write_misses",
            "used_victims",
            "helper_pid",
            "helper_probe",
            "helper_probe_errno",
            "helper_retired",
            "helper_unlinked",
            "helper_unlink_samples",
            "helper_slots_restored",
            "helper_refs_retired",
            "donor_proof_sequence",
            "donor_proof_valid",
            "donor_proof_consumed",
            "donor_live_before",
            "donor_live_before_stage",
            "donor_live_a_stage",
            "donor_live_b_stage",
            "donor_slots",
            "donor_baseline",
            "baseline_usage",
            "observed_usage",
            "donor_live_pre_snapshot_2",
            "donor_live_pre_snapshot_2_stage",
            "donor_snapshot_stage",
            "donor_complete_samples",
            "donor_preexit_refs_valid",
            "donor_preexit_usage",
            "preexit_refs_valid",
            "preexit_usage",
            "final_usage",
            "preexit_delta",
            "donor_refs_retired",
            "collateral_restored",
            "collateral_retired",
            "normalisation_uid",
            "normalisation_gid",
            "final_shell_identity",
            "retained_read_buffers",
            "watchdog_tid",
            "joined",
            "tid_gone",
            "uid_result",
            "gid_result",
            "shell",
            "ctlbuf_repaired",
            "module_loaded",
            "module_unloaded",
            "module_finalised",
            "finalise_proof",
            "donor_frozen",
            "donor_resumed",
            "donor_resume_pid",
            "donor_resume_result",
            "donor_resume_errno",
            "resume_version",
            "resume_size",
            "resume_helper_pid",
            "resume_donor_tgid",
            "resume_signal",
            "resume_before_threads",
            "resume_before_stopped",
            "resume_after_threads",
            "resume_after_stopped",
            "resume_stable_samples",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof",
            "host_donor_pid",
            "host_donor_start_time",
            "host_donor_samples",
            "credential_target_death",
            "poisoned_sprays",
            "spray_active",
            "spray_expected",
            "sprays_retired",
            "binder_controlled_unlinks",
            "binder_objects_retired",
            "raw_target_pid",
            "raw_target_probe",
            "raw_target_probe_errno",
            "raw_target_retired",
            "owner_pid",
            "owner_probe",
            "owner_probe_errno",
            "owner_retired",
            "anchor_pid",
            "anchor_probe",
            "anchor_probe_errno",
            "anchor_retired",
            "isolated_total",
            "isolated_retired",
            "primitive_fds",
            "fake_node_fds",
            "native_fds_retired",
            "watchdogs_retired");

    private static final Set<String> TERMINAL_CLEANUP_HEX_FIELDS = setOf(
            "helper_proc",
            "donor_real_cred",
            "donor_cred",
            "donor_repair",
            "collateral",
            "resume_magic",
            "resume_cookie_hi",
            "resume_cookie_lo",
            "resume_helper_task",
            "resume_donor_task",
            "resume_before_state",
            "resume_before_exit_state",
            "resume_after_state",
            "resume_after_exit_state",
            "resume_task_security",
            "resume_task_security_word8",
            "resume_inode_security",
            "resume_inode_security_word8",
            "resume_commit");

    private static final Set<String> TERMINAL_CLEANUP_STRING_FIELDS = setOf(
            "host_donor_tids", "host_donor_states");

    private static final Set<String> TERMINAL_CLEANUP_BINARY_ONE_FIELDS = setOf(
            "durable",
            "sequence_complete",
            "helper_retired",
            "helper_slots_restored",
            "helper_refs_retired",
            "donor_proof_valid",
            "donor_proof_consumed",
            "donor_live_before",
            "donor_slots",
            "donor_baseline",
            "donor_live_pre_snapshot_2",
            "donor_preexit_refs_valid",
            "donor_refs_retired",
            "normalisation_uid",
            "normalisation_gid",
            "final_shell_identity",
            "ctlbuf_repaired",
            "module_loaded",
            "module_unloaded",
            "module_finalised",
            "finalise_proof",
            "donor_frozen",
            "donor_resumed",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof",
            "credential_target_death",
            "sprays_retired",
            "binder_objects_retired",
            "raw_target_retired",
            "owner_retired",
            "anchor_retired",
            "native_fds_retired",
            "watchdogs_retired");

    private static final String[] CTLBUF_FINALISE_FIELDS = {
            "status",
            "stage",
            "reason",
            "error",
            "helper_pid",
            "helper_task",
            "helper_borrowed",
            "owner_task",
            "owner_pid",
            "watched_fd",
            "arbitrary_fd",
            "reference_fd",
            "watched_file",
            "watched_inode",
            "arbitrary_file",
            "arbitrary_inode",
            "reference_file",
            "reference_inode",
            "watched_fops",
            "arbitrary_fops",
            "reference_fops",
            "selected_epitem",
            "expected_fops",
            "expected_count",
            "reverse_count",
            "forward_count",
            "non_selected_forward",
            "reverse_relationships",
            "pre_inode",
            "pre_next",
            "successor",
            "post_link",
            "final_post_link",
            "restored_link",
            "restored_inode",
            "restored_inode_value",
            "restored_inode_source",
            "forward_cycle",
            "reverse_cycle",
            "readbacks",
            "donor_task",
            "donor_pid",
            "donor_real_cred_slot",
            "donor_cred_slot",
            "donor_cred",
            "donor_usage",
            "donor_uid",
            "donor_euid",
            "donor_suid",
            "donor_fsuid",
            "donor_gid",
            "donor_egid",
            "donor_sgid",
            "donor_fsgid",
            "donor_caps",
            "donor_sid",
            "donor_repair",
            "donor_frozen",
            "donor_snapshot_a",
            "donor_snapshot_b",
            "donor_snapshot_stage",
            "donor_state",
            "donor_observed_pid",
            "donor_observed_tgid",
            "donor_observed_real_cred",
            "donor_observed_cred",
            "donor_observed_real_slot",
            "donor_observed_cred_slot",
            "donor_observed_usage",
            "donor_file_refs",
            "donor_open_fds",
            "donor_max_fds",
            "donor_ids_mask",
            "donor_observed_caps",
            "donor_observed_repair",
            "donor_observed_security",
            "donor_observed_security_word8",
            "donor_observed_sid",
            "list_exact",
            "proof"
    };

    private static final Set<String> CTLBUF_FINALISE_DECIMAL_FIELDS = setOf(
            "error",
            "helper_pid",
            "helper_borrowed",
            "owner_pid",
            "watched_fd",
            "arbitrary_fd",
            "reference_fd",
            "expected_count",
            "reverse_count",
            "forward_count",
            "non_selected_forward",
            "reverse_relationships",
            "restored_link",
            "restored_inode",
            "forward_cycle",
            "reverse_cycle",
            "readbacks",
            "donor_pid",
            "donor_usage",
            "donor_uid",
            "donor_euid",
            "donor_suid",
            "donor_fsuid",
            "donor_gid",
            "donor_egid",
            "donor_sgid",
            "donor_fsgid",
            "donor_sid",
            "donor_frozen",
            "donor_snapshot_a",
            "donor_snapshot_b",
            "donor_snapshot_stage",
            "donor_observed_pid",
            "donor_observed_tgid",
            "donor_observed_usage",
            "donor_file_refs",
            "donor_open_fds",
            "donor_max_fds",
            "donor_observed_sid",
            "list_exact",
            "proof");

    private static final Set<String> CTLBUF_FINALISE_TEXT_FIELDS = setOf(
            "status", "stage", "reason", "restored_inode_source");

    private static final Set<String> CTLBUF_FINALISE_HEX_FIELDS =
            difference(CTLBUF_FINALISE_FIELDS, CTLBUF_FINALISE_DECIMAL_FIELDS,
                    CTLBUF_FINALISE_TEXT_FIELDS);

    private static final Set<String> CTLBUF_FINALISE_NON_POINTER_HEX_FIELDS = setOf(
            "donor_caps",
            "donor_repair",
            "donor_state",
            "donor_ids_mask",
            "donor_observed_caps",
            "donor_observed_repair",
            "donor_observed_security_word8");

    private static final String[] DONOR_RESUME_FIELDS = {
            "status",
            "stage",
            "magic",
            "version",
            "size",
            "cookie_hi",
            "cookie_lo",
            "helper_task",
            "helper_pid",
            "donor_task",
            "donor_pid",
            "donor_tgid",
            "signal",
            "signal_result",
            "signal_errno",
            "before_state",
            "before_exit_state",
            "before_threads",
            "before_stopped",
            "after_state",
            "after_exit_state",
            "after_threads",
            "after_stopped",
            "stable_samples",
            "task_security",
            "task_security_word8",
            "inode_security",
            "inode_security_word8",
            "labels_restored",
            "resumed",
            "proof",
            "commit"
    };

    private static final Set<String> DONOR_RESUME_HEX_FIELDS = setOf(
            "magic",
            "cookie_hi",
            "cookie_lo",
            "helper_task",
            "donor_task",
            "before_state",
            "before_exit_state",
            "after_state",
            "after_exit_state",
            "task_security",
            "task_security_word8",
            "inode_security",
            "inode_security_word8",
            "commit");

    private static final String[] NORMALISATION_FIELDS = {
            "status",
            "stage",
            "watchdog_tid",
            "joined",
            "tid_gone",
            "uid_result",
            "gid_result",
            "shell",
            "ctlbuf_repaired",
            "module_loaded",
            "module_unloaded",
            "module_finalised",
            "finalise_proof",
            "donor_frozen",
            "donor_resumed",
            "donor_resume_pid",
            "donor_resume_result",
            "donor_resume_errno",
            "resume_magic",
            "resume_version",
            "resume_size",
            "resume_cookie_hi",
            "resume_cookie_lo",
            "resume_helper_task",
            "resume_helper_pid",
            "resume_donor_task",
            "resume_donor_tgid",
            "resume_signal",
            "resume_before_state",
            "resume_before_exit_state",
            "resume_before_threads",
            "resume_before_stopped",
            "resume_after_state",
            "resume_after_exit_state",
            "resume_after_threads",
            "resume_after_stopped",
            "resume_stable_samples",
            "resume_task_security",
            "resume_task_security_word8",
            "resume_inode_security",
            "resume_inode_security_word8",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof",
            "resume_commit"
    };

    private static final String[] NORMALISATION_RESUME_FIELDS = {
            "resume_magic",
            "resume_version",
            "resume_size",
            "resume_cookie_hi",
            "resume_cookie_lo",
            "resume_helper_task",
            "resume_helper_pid",
            "resume_donor_task",
            "resume_donor_tgid",
            "resume_signal",
            "resume_before_state",
            "resume_before_exit_state",
            "resume_before_threads",
            "resume_before_stopped",
            "resume_after_state",
            "resume_after_exit_state",
            "resume_after_threads",
            "resume_after_stopped",
            "resume_stable_samples",
            "resume_task_security",
            "resume_task_security_word8",
            "resume_inode_security",
            "resume_inode_security_word8",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof",
            "resume_commit"
    };

    private static final String[] DONOR_RESUME_BINDING_FIELDS = {
            "magic",
            "version",
            "size",
            "cookie_hi",
            "cookie_lo",
            "helper_task",
            "helper_pid",
            "donor_task",
            "donor_tgid",
            "signal",
            "before_state",
            "before_exit_state",
            "before_threads",
            "before_stopped",
            "after_state",
            "after_exit_state",
            "after_threads",
            "after_stopped",
            "stable_samples",
            "task_security",
            "task_security_word8",
            "inode_security",
            "inode_security_word8",
            "labels_restored",
            "resumed",
            "proof",
            "commit"
    };

    private static final Set<String> NORMALISATION_HEX_FIELDS = setOf(
            "resume_magic",
            "resume_cookie_hi",
            "resume_cookie_lo",
            "resume_helper_task",
            "resume_donor_task",
            "resume_before_state",
            "resume_before_exit_state",
            "resume_after_state",
            "resume_after_exit_state",
            "resume_task_security",
            "resume_task_security_word8",
            "resume_inode_security",
            "resume_inode_security_word8",
            "resume_commit");

    private static final Set<String> NORMALISATION_POSITIVE_FIELDS = setOf(
            "watchdog_tid",
            "donor_resume_pid",
            "resume_helper_pid",
            "resume_donor_tgid",
            "resume_before_threads",
            "resume_before_stopped",
            "resume_after_threads");

    private static final Set<String> NORMALISATION_UNSIGNED_FIELDS = setOf(
            "resume_version",
            "resume_size",
            "resume_signal",
            "resume_after_stopped",
            "resume_stable_samples");

    private static final Set<String> NORMALISATION_SIGNED_FIELDS = setOf(
            "uid_result",
            "gid_result",
            "donor_resume_result",
            "donor_resume_errno");

    private static final Set<String> NORMALISATION_BOOLEAN_FIELDS = setOf(
            "joined",
            "tid_gone",
            "shell",
            "ctlbuf_repaired",
            "module_loaded",
            "module_unloaded",
            "module_finalised",
            "finalise_proof",
            "donor_frozen",
            "donor_resumed",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof");

    private static final String[] NORMALISATION_TERMINAL_FIELDS = {
            "watchdog_tid",
            "joined",
            "tid_gone",
            "uid_result",
            "gid_result",
            "shell",
            "ctlbuf_repaired",
            "module_loaded",
            "module_unloaded",
            "module_finalised",
            "finalise_proof",
            "donor_frozen",
            "donor_resumed",
            "donor_resume_pid",
            "donor_resume_result",
            "donor_resume_errno",
            "resume_magic",
            "resume_version",
            "resume_size",
            "resume_cookie_hi",
            "resume_cookie_lo",
            "resume_helper_task",
            "resume_helper_pid",
            "resume_donor_task",
            "resume_donor_tgid",
            "resume_signal",
            "resume_before_state",
            "resume_before_exit_state",
            "resume_before_threads",
            "resume_before_stopped",
            "resume_after_state",
            "resume_after_exit_state",
            "resume_after_threads",
            "resume_after_stopped",
            "resume_stable_samples",
            "resume_task_security",
            "resume_task_security_word8",
            "resume_inode_security",
            "resume_inode_security_word8",
            "resume_labels_restored",
            "resume_resumed",
            "resume_proof",
            "resume_commit"
    };

    private static final String[] CREDENTIAL_TARGET_DEATH_FIELDS = {
            "status",
            "stage",
            "pid",
            "start_time",
            "boot_id",
            "binder_handle",
            "callback",
            "one_shot"
    };

    private static final Set<String> PROCESS_TEARDOWN_FIELDS = setOf(
            "version",
            "reason",
            "nonce",
            "boot_id",
            "helper_pid",
            "helper_start",
            "harness_pid",
            "harness_start",
            "raw_target_pid",
            "raw_target_start",
            "raw_client_pid",
            "raw_client_start");

    private static final String[] PROCESS_TEARDOWN_IDENTITY_FIELDS = {
            "harness_pid",
            "harness_start",
            "raw_target_pid",
            "raw_target_start",
            "raw_client_pid",
            "raw_client_start"
    };

    private static final String[] INITIAL_MISS_PREPARE_FIELDS = {
            "status",
            "stage",
            "node",
            "file",
            "epitem",
            "raw_pointer",
            "raw_cookie",
            "next",
            "pprev",
            "decrements",
            "expected_decrements",
            "epitems",
            "probe_epitems",
            "control_blocks",
            "expected_blocks",
            "prefilled",
            "coordinator_cpu",
            "restored_cpu2",
            "thread_created",
            "thread_joined",
            "go_issued",
            "thread_exited",
            "join_timed_out",
            "join_result",
            "quarantined",
            "fd_closed",
            "write_attempted",
            "write_rc",
            "write_errno",
            "write_consumed",
            "write_read_consumed",
            "write_expected",
            "write_enter_cpu",
            "write_return_cpu",
            "tid",
            "generation",
            "staged_generation",
            "generation_captured",
            "generation_valid",
            "expected",
            "staged_expected",
            "staged_active",
            "staged_wake",
            "staged_state2",
            "staged_stable",
            "global_published",
            "all_entered",
            "all_state2",
            "blocked",
            "read_rc",
            "read_errno",
            "read_consumed",
            "read_write_consumed",
            "read_enter_cpu",
            "read_return_cpu",
            "read_tid",
            "poll_rc",
            "poll_errno",
            "poll_revents",
            "read_first",
            "read_second",
            "read_responses",
            "noop",
            "failed_reply",
            "dead_reply",
            "unexpected",
            "malformed",
            "exact_read",
            "retirement_before_go",
            "retirement_after_write",
            "gate_error",
            "gate_free",
            "gate_read",
            "gate_unlinked_free",
            "gate_unlinked_read",
            "reboot_required"
    };

    private static final String[] INITIAL_MISS_OBSERVATION_FIELDS = {
            "status",
            "stage",
            "victim",
            "buffer",
            "ptr",
            "cookie",
            "worker_index",
            "raw_index",
            "exact_payload",
            "buffer_freed",
            "polling",
            "wait_cpu",
            "read_calls",
            "responses",
            "transactions",
            "last_response",
            "last_code",
            "flags",
            "data_size",
            "offsets_size",
            "refs_before_transaction",
            "victim_refs_before_transaction",
            "victim_ref_count",
            "last_ref_ptr",
            "last_ref_cookie",
            "order"
    };

    private static final Set<String> INITIAL_MISS_HEX_FIELDS = setOf(
            "node",
            "file",
            "epitem",
            "raw_pointer",
            "raw_cookie",
            "next",
            "pprev",
            "generation",
            "read_first",
            "read_second",
            "buffer",
            "ptr",
            "cookie",
            "last_response",
            "last_code",
            "refs_before_transaction",
            "flags",
            "victim_refs_before_transaction",
            "last_ref_ptr",
            "last_ref_cookie",
            "initial",
            "expected",
            "cred");

    private static final Map<String, BigInteger> INITIAL_MISS_PREPARE_EXACT =
            fixedNumbers(
                    "decrements", 1,
                    "expected_decrements", 1,
                    "epitems", 5632,
                    "probe_epitems", 4096,
                    "control_blocks", 1024,
                    "expected_blocks", 1024,
                    "coordinator_cpu", 1,
                    "restored_cpu2", 1,
                    "thread_created", 1,
                    "thread_joined", 1,
                    "go_issued", 1,
                    "thread_exited", 1,
                    "join_timed_out", 0,
                    "join_result", 0,
                    "quarantined", 0,
                    "fd_closed", 1,
                    "write_attempted", 1,
                    "write_rc", 0,
                    "write_errno", 0,
                    "write_read_consumed", 0,
                    "write_enter_cpu", 2,
                    "write_return_cpu", 2,
                    "generation_captured", 1,
                    "generation_valid", 1,
                    "expected", 1024,
                    "staged_expected", 32,
                    "staged_active", 32,
                    "staged_wake", 1,
                    "staged_state2", 32,
                    "staged_stable", 1,
                    "global_published", 1,
                    "all_entered", 1,
                    "all_state2", 1024,
                    "blocked", 1024,
                    "read_rc", 0,
                    "read_errno", 0,
                    "read_write_consumed", 0,
                    "read_enter_cpu", 1,
                    "read_return_cpu", 1,
                    "poll_rc", 1,
                    "poll_errno", 0,
                    "poll_revents", 1,
                    "read_responses", 2,
                    "noop", 1,
                    "failed_reply", 1,
                    "dead_reply", 0,
                    "unexpected", 0,
                    "malformed", 0,
                    "exact_read", 1,
                    "retirement_before_go", 0,
                    "retirement_after_write", 0,
                    "gate_error", 0,
                    "gate_free", 1,
                    "gate_read", 1,
                    "gate_unlinked_free", 0,
                    "gate_unlinked_read", 0,
                    "reboot_required", 0);

    private static final String[] INITIAL_MISS_PREPARE_POSITIVE_FIELDS = {
            "node",
            "file",
            "epitem",
            "raw_pointer",
            "raw_cookie",
            "next",
            "pprev",
            "generation",
            "tid",
            "staged_generation",
            "read_tid"
    };

    private static final Map<String, BigInteger> INITIAL_MISS_OBSERVATION_EXACT =
            fixedNumbers(
                    "victim", 0,
                    "exact_payload", 0,
                    "buffer_freed", 0,
                    "polling", 1,
                    "worker_index", -1);

    private static final String INITIAL_MISS_FIRST_PREFIX =
            "status=miss stage=unlink-observe safe_no_free=0 "
                    + "teardown_required=1 teardown_signal=pass ";

    private static final String INITIAL_MISS_RESPONSE_ORDER =
            "1:0x720c,1:0x80107207,1:0x80107208,1:0x80107207,"
                    + "1:0x80107208,2:0x720c,2:0x80107207,2:0x80107208";

    private static final String[] INITIAL_MISS_PROGRESS_TAIL = {
            "arbitrary-read-start",
            "isolated-retirement-proof-pass",
            "arbitrary-read-reclaim-armed",
            "arbitrary-read-prepared",
            "arbitrary-read-proc-teardown-required"
    };

    private static final String[] INITIAL_MISS_FORBIDDEN_PROGRESS_PREFIXES = {
            "arbitrary-read-free-",
            "arbitrary-read-handoff",
            "arbitrary-read-retained",
            "root-mutation",
            "root-write-",
            "root-window-"
    };

    private static final Set<String> SAFE_MISS_MARKERS = setOf(
            "epitem-reader-failed",
            "epitem-reclaim-failed",
            "epitem-analysis-failed",
            "node-analysis-failed",
            "arbitrary-read-observe-miss-safe");

    private static final String[] SAFE_MISS_FORBIDDEN_PROGRESS_PREFIXES = {
            "arbitrary-read-free-",
            "arbitrary-read-handoff",
            "arbitrary-read-retained",
            "private-credential-",
            "root-mutation",
            "root-write-",
            "root-window-",
            "cred-quarantine-"
    };

    private ActivationProofs() {}

    static CtlbufFinaliseProof parseCtlbufFinalise(String value) {
        Map<String, String> raw = parseOrderedFields(value, CTLBUF_FINALISE_FIELDS);
        if (raw == null
                || !"pass".equals(raw.get("status"))
                || !"ctlbuf-finalise".equals(raw.get("stage"))
                || !"none".equals(raw.get("reason"))
                || !"reference".equals(raw.get("restored_inode_source"))) {
            return null;
        }
        ProofFields fields = parseNumbers(
                raw, CTLBUF_FINALISE_DECIMAL_FIELDS, CTLBUF_FINALISE_HEX_FIELDS);
        if (fields == null) {
            return null;
        }
        for (String name : CTLBUF_FINALISE_HEX_FIELDS) {
            if (!CTLBUF_FINALISE_NON_POINTER_HEX_FIELDS.contains(name)
                    && is(fields, name, ZERO)) {
                return null;
            }
        }
        Set<BigInteger> fileDescriptors = new HashSet<>(Arrays.asList(
                number(fields, "watched_fd"),
                number(fields, "arbitrary_fd"),
                number(fields, "reference_fd")));
        BigInteger expectedCount = number(fields, "expected_count");
        boolean expectedCountSupported = expectedCount.equals(ONE) ||
                expectedCount.equals(BigInteger.valueOf(5632));
        if (!is(fields, "error", ZERO)
                || !positive(fields, "helper_pid")
                || !is(fields, "helper_borrowed", ONE)
                || !positive(fields, "owner_pid")
                || !positive(fields, "donor_pid")
                || negative(fields, "watched_fd")
                || negative(fields, "arbitrary_fd")
                || negative(fields, "reference_fd")
                || fileDescriptors.size() != 3
                || same(fields, "watched_file", "arbitrary_file")
                || same(fields, "watched_file", "reference_file")
                || same(fields, "arbitrary_file", "reference_file")
                || !same(fields, "watched_inode", "reference_inode")
                || !same(fields, "watched_fops", "arbitrary_fops")
                || !same(fields, "watched_fops", "reference_fops")
                || !same(fields, "watched_fops", "expected_fops")
                || !equalsAdded(fields, "arbitrary_inode", "selected_epitem", 0x50)
                || !same(fields, "pre_inode", "arbitrary_inode")
                || !equalsAdded(fields, "pre_next", "arbitrary_file", 0x20)
                || !same(fields, "restored_inode_value", "reference_inode")
                || !expectedCountSupported
                || !number(fields, "reverse_count").equals(expectedCount)
                || !number(fields, "forward_count").equals(expectedCount)
                || !number(fields, "non_selected_forward").equals(
                        expectedCount.subtract(ONE))
                || !number(fields, "reverse_relationships").equals(expectedCount)
                || !same(fields, "post_link", "successor")
                || !same(fields, "final_post_link", "successor")
                || !is(fields, "restored_link", ONE)
                || !is(fields, "restored_inode", ONE)
                || !is(fields, "forward_cycle", ONE)
                || !is(fields, "reverse_cycle", ONE)
                || !is(fields, "readbacks", ONE)
                || !positive(fields, "donor_usage")
                || greaterThan(fields, "donor_usage", UINT32_MAX)
                || is(fields, "donor_caps", ZERO)
                || is(fields, "donor_sid", ZERO)
                || !is(fields, "donor_repair", ZERO)
                || !is(fields, "donor_frozen", ONE)
                || !is(fields, "donor_snapshot_a", ONE)
                || !is(fields, "donor_snapshot_b", ONE)
                || !is(fields, "donor_snapshot_stage", 17)
                || !number(fields, "donor_state").and(FOUR).equals(FOUR)
                || !same(fields, "donor_observed_pid", "donor_pid")
                || !same(fields, "donor_observed_tgid", "donor_pid")
                || !same(fields, "donor_observed_real_cred", "donor_cred")
                || !same(fields, "donor_observed_cred", "donor_cred")
                || !same(fields, "donor_observed_real_slot", "donor_cred")
                || !same(fields, "donor_observed_cred_slot", "donor_cred")
                || !between(fields, "donor_file_refs", 1, 64)
                || !between(fields, "donor_open_fds", 0, 16384)
                || !between(fields, "donor_max_fds", 1, 65536)
                || greaterThan(fields, "donor_file_refs", "donor_open_fds")
                || greaterThan(fields, "donor_open_fds", "donor_max_fds")
                || number(fields, "donor_file_refs").compareTo(
                        UINT32_MAX.subtract(number(fields, "donor_usage"))) > 0
                || !between(fields, "donor_observed_usage", ZERO, UINT32_MAX)
                || !number(fields, "donor_observed_usage").equals(
                        number(fields, "donor_usage").add(
                                number(fields, "donor_file_refs")))
                || !is(fields, "donor_ids_mask", 0xff)
                || !same(fields, "donor_observed_caps", "donor_caps")
                || !is(fields, "donor_observed_repair", ZERO)
                || is(fields, "donor_observed_security", ZERO)
                || !is(fields, "donor_observed_security_word8", ZERO)
                || !same(fields, "donor_observed_sid", "donor_sid")
                || !is(fields, "list_exact", ONE)
                || !is(fields, "proof", ONE)) {
            return null;
        }
        return new CtlbufFinaliseProof(fields);
    }

    static DonorResumeProof parseDonorResume(String value) {
        Map<String, String> raw = parseOrderedFields(value, DONOR_RESUME_FIELDS);
        if (raw == null
                || !"pass".equals(raw.get("status"))
                || !"donor-resume".equals(raw.get("stage"))) {
            return null;
        }
        Set<String> decimalFields = difference(
                DONOR_RESUME_FIELDS,
                DONOR_RESUME_HEX_FIELDS,
                setOf("status", "stage"));
        ProofFields fields = parseNumbers(raw, decimalFields, DONOR_RESUME_HEX_FIELDS);
        if (fields == null) {
            return null;
        }
        BigInteger commit = number(fields, "magic")
                .xor(number(fields, "cookie_hi"))
                .xor(number(fields, "cookie_lo"))
                .xor(number(fields, "donor_task"))
                .xor(RESUME_COMMIT_MASK);
        if (!is(fields, "magic", RESUME_MAGIC)
                || !is(fields, "version", ONE)
                || !is(fields, "size", 176)
                || is(fields, "helper_task", ZERO)
                || !positive(fields, "helper_pid")
                || is(fields, "donor_task", ZERO)
                || !positive(fields, "donor_pid")
                || !same(fields, "donor_tgid", "donor_pid")
                || !is(fields, "signal", EIGHTEEN)
                || !is(fields, "signal_result", ZERO)
                || !is(fields, "signal_errno", ZERO)
                || number(fields, "before_state").and(TWELVE).equals(ZERO)
                || !is(fields, "before_exit_state", ZERO)
                || !between(fields, "before_threads", 1, 4096)
                || !same(fields, "before_stopped", "before_threads")
                || !number(fields, "after_state").and(TWELVE).equals(ZERO)
                || !is(fields, "after_exit_state", ZERO)
                || !between(fields, "after_threads", 1, 4096)
                || !is(fields, "after_stopped", ZERO)
                || !is(fields, "stable_samples", TWO)
                || is(fields, "task_security", ZERO)
                || is(fields, "inode_security", ZERO)
                || !is(fields, "labels_restored", ONE)
                || !is(fields, "resumed", ONE)
                || !is(fields, "proof", ONE)
                || !number(fields, "commit").equals(commit)) {
            return null;
        }
        return new DonorResumeProof(fields);
    }

    static NormalisationProof parseNormalisation(String value) {
        Map<String, String> raw = parseOrderedFields(value, NORMALISATION_FIELDS);
        if (raw == null
                || !"pass".equals(raw.get("status"))
                || !"credential-normalisation".equals(raw.get("stage"))) {
            return null;
        }
        Map<String, BigInteger> numbers = new HashMap<>();
        for (String name : NORMALISATION_FIELDS) {
            if ("status".equals(name) || "stage".equals(name)) {
                continue;
            }
            Pattern format;
            int radix;
            if (NORMALISATION_HEX_FIELDS.contains(name)) {
                format = HEX;
                radix = 16;
            } else if (NORMALISATION_POSITIVE_FIELDS.contains(name)) {
                format = POSITIVE_DECIMAL;
                radix = 10;
            } else if (NORMALISATION_UNSIGNED_FIELDS.contains(name)) {
                format = UNSIGNED_DECIMAL;
                radix = 10;
            } else if (NORMALISATION_SIGNED_FIELDS.contains(name)) {
                format = DECIMAL;
                radix = 10;
            } else if (NORMALISATION_BOOLEAN_FIELDS.contains(name)) {
                format = Pattern.compile("[01]");
                radix = 10;
            } else {
                return null;
            }
            BigInteger parsed = parseNumber(raw.get(name), format, radix);
            if (parsed == null) {
                return null;
            }
            numbers.put(name, parsed);
        }
        ProofFields fields = new ProofFields(raw, numbers);
        if (!is(fields, "joined", ONE)
                || !is(fields, "tid_gone", ONE)
                || !is(fields, "uid_result", ZERO)
                || !is(fields, "gid_result", ZERO)
                || !is(fields, "shell", ONE)
                || !is(fields, "ctlbuf_repaired", ONE)
                || !is(fields, "module_loaded", ONE)
                || !is(fields, "module_unloaded", ONE)
                || !is(fields, "module_finalised", ONE)
                || !is(fields, "finalise_proof", ONE)
                || !is(fields, "donor_frozen", ONE)
                || !is(fields, "donor_resumed", ONE)
                || !is(fields, "donor_resume_result", ZERO)
                || !is(fields, "donor_resume_errno", ZERO)) {
            return null;
        }
        return new NormalisationProof(fields);
    }

    static CredentialTargetDeathProof parseCredentialTargetDeath(String value) {
        Map<String, String> raw = parseOrderedFields(value, CREDENTIAL_TARGET_DEATH_FIELDS);
        if (raw == null
                || !"pass".equals(raw.get("status"))
                || !"credential-target-death".equals(raw.get("stage"))
                || !POSITIVE_DECIMAL.matcher(raw.get("pid")).matches()
                || !UNSIGNED_DECIMAL.matcher(raw.get("start_time")).matches()
                || !BOOT_ID.matcher(raw.get("boot_id")).matches()
                || !POSITIVE_DECIMAL.matcher(raw.get("binder_handle")).matches()
                || !"1".equals(raw.get("callback"))
                || !"1".equals(raw.get("one_shot"))) {
            return null;
        }
        Map<String, BigInteger> numbers = new HashMap<>();
        numbers.put("pid", new BigInteger(raw.get("pid")));
        numbers.put("start_time", new BigInteger(raw.get("start_time")));
        numbers.put("binder_handle", new BigInteger(raw.get("binder_handle")));
        return new CredentialTargetDeathProof(new ProofFields(raw, numbers));
    }

    static ProcessTeardownProof parseProcessTeardownToken(String value) {
        Map<String, String> fields = parseProcessTeardownFields(value);
        return fields == null ? null : new ProcessTeardownProof(fields);
    }

    static InitialAcquisitionMissProof parseInitialAcquisitionMiss(
            String result, String progress, String tokenValue) {
        ProcessTeardownProof token = parseProcessTeardownToken(tokenValue);
        if (token == null || !token.hasInitialAcquisitionMissShape()) {
            return null;
        }
        RootChain root = parseRootChain(result);
        if (root == null
                || !"miss".equals(root.status)
                || !"miss".equals(root.nodeStatus)
                || !"status=miss stage=root-unlink".equals(root.nodePrefix)
                || !root.nodeTail.isEmpty()) {
            return null;
        }
        ProofFields prepare = validateInitialMissPrepare(
                parseIssueRecord(root.prepare, INITIAL_MISS_PREPARE_FIELDS));
        if (prepare == null) {
            return null;
        }
        BracketSpan observationSpan = bracketSpan(root.first, "observation");
        if (observationSpan == null
                || !root.first.substring(0, observationSpan.start)
                        .equals(INITIAL_MISS_FIRST_PREFIX)
                || observationSpan.end != root.first.length()) {
            return null;
        }
        String observationValue = root.first.substring(
                observationSpan.start + "observation=[".length(),
                observationSpan.end - 1);
        ProofFields observation = validateInitialMissObservation(
                parseIssueRecord(observationValue, INITIAL_MISS_OBSERVATION_FIELDS),
                prepare);
        if (observation == null
                || !same(observation, "ptr", prepare, "raw_pointer")
                || !same(observation, "cookie", prepare, "raw_cookie")) {
            return null;
        }
        List<String> progressNames = parseProgress(progress);
        if (!hasExactInitialMissTail(progressNames)
                || hasForbiddenInitialMissProgress(progressNames)) {
            return null;
        }
        return new InitialAcquisitionMissProof(token);
    }

    static SafeAcquisitionMissProof parseSafeAcquisitionMiss(
            String result, String progress) {
        if (result == null || result.length() > 256 * 1024 ||
                result.indexOf('\n') >= 0 || result.indexOf('\r') >= 0 ||
                result.indexOf('\0') >= 0) {
            return null;
        }
        List<String> markers = parseProgress(progress);
        if (markers == null || markers.isEmpty()) {
            return null;
        }
        String terminal = markers.get(markers.size() - 1);
        if (!SAFE_MISS_MARKERS.contains(terminal) ||
                Collections.frequency(markers, terminal) != 1) {
            return null;
        }
        for (String marker : markers) {
            for (String prefix : SAFE_MISS_FORBIDDEN_PROGRESS_PREFIXES) {
                if (marker.startsWith(prefix)) {
                    return null;
                }
            }
            if (!"arbitrary-read-observe-miss-safe".equals(terminal) &&
                    marker.startsWith("arbitrary-read-")) {
                return null;
            }
        }

        String rootPrefix = "status=miss stage=root-chain ";
        if (!result.startsWith(rootPrefix)) {
            return null;
        }
        if (terminal.startsWith("epitem-")) {
            BracketSpan epitem = bracketSpan(result, "epitem");
            if (epitem == null || epitem.start != rootPrefix.length() ||
                    epitem.end != result.length()) {
                return null;
            }
            String value = result.substring(
                    epitem.start + "epitem=[".length(), epitem.end - 1);
            boolean shape;
            if ("epitem-reclaim-failed".equals(terminal)) {
                shape = value.startsWith("status=fail stage=epitem-leak ");
            } else if ("epitem-analysis-failed".equals(terminal)) {
                shape = value.startsWith("status=miss stage=epitem-leak ");
            } else {
                shape = value.startsWith("status=fail ") ||
                        value.startsWith("status=miss ");
            }
            return shape ? new SafeAcquisitionMissProof(terminal) : null;
        }
        if ("node-analysis-failed".equals(terminal)) {
            BracketSpan epitem = bracketSpan(result, "epitem");
            BracketSpan node = bracketSpan(result, "node");
            if (epitem == null || node == null ||
                    epitem.start != rootPrefix.length() ||
                    node.start != epitem.end + 1 ||
                    !" ".equals(result.substring(epitem.end, node.start)) ||
                    node.end != result.length()) {
                return null;
            }
            String epitemValue = result.substring(
                    epitem.start + "epitem=[".length(), epitem.end - 1);
            String nodeValue = result.substring(
                    node.start + "node=[".length(), node.end - 1);
            BracketSpan analysis = bracketSpan(nodeValue, "analysis");
            boolean shape = epitemValue.startsWith(
                            "status=pass stage=epitem-leak ") &&
                    nodeValue.startsWith("status=miss stage=node-address ") &&
                    analysis != null && analysis.end == nodeValue.length() &&
                    nodeValue.substring(
                            analysis.start + "analysis=[".length(),
                            analysis.end - 1).startsWith("status=miss ");
            return shape ? new SafeAcquisitionMissProof(terminal) : null;
        }

        RootChain root = parseRootChain(result);
        ProofFields prepare = root == null ? null : validateInitialMissPrepare(
                parseIssueRecord(root.prepare, INITIAL_MISS_PREPARE_FIELDS));
        if (root == null || prepare == null ||
                !"miss".equals(root.status) ||
                !"miss".equals(root.nodeStatus) ||
                !root.first.startsWith(
                        "status=miss stage=unlink-observe safe_no_free=1 " +
                                "teardown_required=0 " +
                                "teardown_signal=not-requested ")) {
            return null;
        }
        BracketSpan observation = bracketSpan(root.first, "observation");
        if (observation == null || observation.end != root.first.length()) {
            return null;
        }
        String observationValue = root.first.substring(
                observation.start + "observation=[".length(),
                observation.end - 1);
        return observationValue.startsWith("status=miss stage=fake-node-check ") &&
                observationValue.contains(" exact_payload=0") &&
                observationValue.contains(" buffer_freed=0")
                ? new SafeAcquisitionMissProof(terminal)
                : null;
    }

    static TerminalCleanupProof parseTerminalCleanup(String value) {
        Map<String, String> raw = parseUnorderedFields(value);
        if (raw == null) {
            return null;
        }
        Set<String> expected = new HashSet<>(TERMINAL_CLEANUP_FIXED_FIELDS.keySet());
        expected.addAll(TERMINAL_CLEANUP_INTEGER_FIELDS);
        expected.addAll(TERMINAL_CLEANUP_HEX_FIELDS);
        expected.addAll(TERMINAL_CLEANUP_STRING_FIELDS);
        if (!raw.keySet().equals(expected)) {
            return null;
        }
        for (Map.Entry<String, String> fixed : TERMINAL_CLEANUP_FIXED_FIELDS.entrySet()) {
            if (!fixed.getValue().equals(raw.get(fixed.getKey()))) {
                return null;
            }
        }
        ProofFields fields = parseNumbers(
                raw, TERMINAL_CLEANUP_INTEGER_FIELDS, TERMINAL_CLEANUP_HEX_FIELDS);
        if (fields == null) {
            return null;
        }
        for (String name : TERMINAL_CLEANUP_BINARY_ONE_FIELDS) {
            if (!is(fields, name, ONE)) {
                return null;
            }
        }
        if (!is(fields, "reboot_required", ZERO)
                || !zeroOrOne(fields, "collateral_restored")
                || !zeroOrOne(fields, "collateral_retired")
                || !number(fields, "collateral_restored")
                        .add(number(fields, "collateral_retired")).equals(ONE)
                || !validHostDonorState(
                        raw.get("host_donor_tids"), raw.get("host_donor_states"))
                || !is(fields, "required_writes", SIX)
                || !is(fields, "successful_writes", SIX)
                || number(fields, "used_victims").compareTo(
                        number(fields, "successful_writes")) < 0
                || negative(fields, "internal_write_misses")
                || !positive(fields, "helper_pid")
                || !is(fields, "helper_probe", -1)
                || !is(fields, "helper_probe_errno", 3)
                || !is(fields, "helper_proc", ZERO)
                || !is(fields, "helper_unlinked", ZERO)
                || !is(fields, "helper_unlink_samples", ZERO)
                || !positive(fields, "donor_proof_sequence")
                || is(fields, "donor_real_cred", ZERO)
                || !same(fields, "donor_real_cred", "donor_cred")
                || !is(fields, "donor_live_before_stage", SEVEN)
                || !is(fields, "donor_live_a_stage", SEVEN)
                || !is(fields, "donor_live_b_stage", SEVEN)
                || !is(fields, "donor_live_pre_snapshot_2_stage", SEVEN)
                || !is(fields, "donor_snapshot_stage", 15)
                || !is(fields, "donor_repair", ZERO)
                || !is(fields, "donor_complete_samples", TWO)
                || !positive(fields, "baseline_usage")
                || !same(fields, "observed_usage", "baseline_usage")
                || !equalsAdded(fields, "donor_preexit_usage", "baseline_usage", 2)
                || !is(fields, "preexit_refs_valid", ONE)
                || !equalsAdded(fields, "preexit_usage", "baseline_usage", 2)
                || !same(fields, "final_usage", "baseline_usage")
                || !is(fields, "preexit_delta", TWO)
                || !is(fields, "retained_read_buffers", ZERO)
                || !positive(fields, "watchdog_tid")
                || same(fields, "watchdog_tid", "helper_pid")
                || !positive(fields, "donor_resume_pid")
                || !is(fields, "donor_resume_result", ZERO)
                || !is(fields, "donor_resume_errno", ZERO)
                || !is(fields, "resume_magic", RESUME_MAGIC)
                || !is(fields, "resume_version", ONE)
                || !is(fields, "resume_size", 176)
                || is(fields, "resume_helper_task", ZERO)
                || !same(fields, "resume_helper_pid", "helper_pid")
                || is(fields, "resume_donor_task", ZERO)
                || !same(fields, "resume_donor_tgid", "donor_resume_pid")
                || !is(fields, "resume_signal", EIGHTEEN)
                || number(fields, "resume_before_state").and(TWELVE).equals(ZERO)
                || !is(fields, "resume_before_exit_state", ZERO)
                || !between(fields, "resume_before_threads", 1, 4096)
                || !same(fields, "resume_before_stopped", "resume_before_threads")
                || !number(fields, "resume_after_state").and(TWELVE).equals(ZERO)
                || !is(fields, "resume_after_exit_state", ZERO)
                || !between(fields, "resume_after_threads", 1, 4096)
                || !is(fields, "resume_after_stopped", ZERO)
                || !is(fields, "resume_stable_samples", TWO)
                || is(fields, "resume_task_security", ZERO)
                || !is(fields, "resume_task_security_word8", ZERO)
                || is(fields, "resume_inode_security", ZERO)
                || !is(fields, "resume_inode_security_word8", ZERO)
                || !number(fields, "resume_commit").equals(resumeCommit(fields))
                || !same(fields, "host_donor_pid", "donor_resume_pid")
                || !positive(fields, "host_donor_start_time")
                || !is(fields, "host_donor_samples", TWO)
                || !is(fields, "joined", ONE)
                || !is(fields, "tid_gone", ONE)
                || !is(fields, "uid_result", ZERO)
                || !is(fields, "gid_result", ZERO)
                || !is(fields, "shell", ONE)
                || !is(fields, "poisoned_sprays", ZERO)
                || !is(fields, "spray_active", ZERO)
                || !is(fields, "spray_expected", ZERO)
                || !is(fields, "binder_controlled_unlinks", SEVEN)
                || !positive(fields, "raw_target_pid")
                || !is(fields, "raw_target_probe", -1)
                || !is(fields, "raw_target_probe_errno", 3)
                || !positive(fields, "owner_pid")
                || !is(fields, "owner_probe", -1)
                || !is(fields, "owner_probe_errno", 3)
                || !positive(fields, "anchor_pid")
                || !is(fields, "anchor_probe", -1)
                || !is(fields, "anchor_probe_errno", 3)
                || !is(fields, "isolated_total", 64)
                || !is(fields, "isolated_retired", 64)
                || !is(fields, "primitive_fds", ZERO)
                || !is(fields, "fake_node_fds", ZERO)) {
            return null;
        }
        return new TerminalCleanupProof(fields);
    }

    static final class CtlbufFinaliseProof {
        private final ProofFields fields;

        private CtlbufFinaliseProof(ProofFields fields) {
            this.fields = fields;
        }

        boolean bindsTo(int helperPid, int donorPid) {
            return is(fields, "helper_pid", helperPid)
                    && is(fields, "donor_pid", donorPid);
        }
    }

    static final class DonorResumeProof {
        private final ProofFields fields;

        private DonorResumeProof(ProofFields fields) {
            this.fields = fields;
        }

        boolean bindsTo(
                String nonce,
                int helperPid,
                int donorPid,
                CtlbufFinaliseProof finalise) {
            if (nonce == null || !LOWER_HEX_32.matcher(nonce).matches()
                    || finalise == null) {
                return false;
            }
            BigInteger expectedHigh = new BigInteger(nonce.substring(0, 16), 16);
            BigInteger expectedLow = new BigInteger(nonce.substring(16), 16);
            return is(fields, "cookie_hi", expectedHigh)
                    && is(fields, "cookie_lo", expectedLow)
                    && is(fields, "helper_pid", helperPid)
                    && is(fields, "donor_pid", donorPid)
                    && same(fields, "helper_task", finalise.fields, "helper_task")
                    && same(fields, "donor_task", finalise.fields, "donor_task");
        }
    }

    static final class NormalisationProof {
        private final ProofFields fields;

        private NormalisationProof(ProofFields fields) {
            this.fields = fields;
        }

        boolean bindsTo(
                int watchdogTid,
                int helperPid,
                int donorPid,
                DonorResumeProof resume) {
            if (resume == null
                    || !is(fields, "watchdog_tid", watchdogTid)
                    || is(fields, "watchdog_tid", helperPid)
                    || !is(fields, "donor_resume_pid", donorPid)) {
                return false;
            }
            for (int index = 0; index < NORMALISATION_RESUME_FIELDS.length; index++) {
                if (!same(
                        fields,
                        NORMALISATION_RESUME_FIELDS[index],
                        resume.fields,
                        DONOR_RESUME_BINDING_FIELDS[index])) {
                    return false;
                }
            }
            return true;
        }

        String resumeGateFields() {
            StringBuilder result = new StringBuilder();
            for (String name : NORMALISATION_RESUME_FIELDS) {
                if (result.length() > 0) {
                    result.append(' ');
                }
                result.append(name).append('=').append(fields.raw.get(name));
            }
            return result.toString();
        }
    }

    static final class CredentialTargetDeathProof {
        private final ProofFields fields;

        private CredentialTargetDeathProof(ProofFields fields) {
            this.fields = fields;
        }

        boolean bindsTo(int helperPid, String helperStartTime, String bootId) {
            BigInteger expectedStart = parseNumber(
                    helperStartTime, UNSIGNED_DECIMAL, 10);
            return expectedStart != null
                    && is(fields, "pid", helperPid)
                    && is(fields, "start_time", expectedStart)
                    && fields.raw.get("boot_id").equals(bootId);
        }
    }

    static final class ProcessTeardownProof {
        private final Map<String, String> fields;

        private ProcessTeardownProof(Map<String, String> fields) {
            this.fields = Collections.unmodifiableMap(new LinkedHashMap<>(fields));
        }

        boolean bindsTo(
                String nonce,
                String bootId,
                int helperPid,
                String helperStartTime) {
            if (!hasInitialAcquisitionMissShape()
                    || !fields.get("nonce").equals(nonce)
                    || !fields.get("boot_id").equals(bootId)
                    || !fields.get("helper_pid").equals(Integer.toString(helperPid))
                    || !fields.get("helper_start").equals(helperStartTime)) {
                return false;
            }
            return true;
        }

        TokenProcessIdentity harness() {
            return identity("harness");
        }

        TokenProcessIdentity rawTarget() {
            return identity("raw_target");
        }

        TokenProcessIdentity rawClient() {
            return identity("raw_client");
        }

        String bootId() {
            return fields.get("boot_id");
        }

        private TokenProcessIdentity identity(String name) {
            return new TokenProcessIdentity(
                    fields.get(name + "_pid"), fields.get(name + "_start"));
        }

        private boolean hasInitialAcquisitionMissShape() {
            if (!"1".equals(fields.get("version"))
                    || !"initial-acquisition-miss".equals(fields.get("reason"))) {
                return false;
            }
            for (String name : PROCESS_TEARDOWN_IDENTITY_FIELDS) {
                if (!POSITIVE_DECIMAL.matcher(fields.get(name)).matches()) {
                    return false;
                }
            }
            return true;
        }
    }

    static final class InitialAcquisitionMissProof {
        private final ProcessTeardownProof token;

        private InitialAcquisitionMissProof(ProcessTeardownProof token) {
            this.token = token;
        }

        boolean bindsTo(
                String nonce,
                String bootId,
                int helperPid,
                String helperStartTime) {
            return token.bindsTo(nonce, bootId, helperPid, helperStartTime);
        }

        TokenProcessIdentity harness() {
            return token.harness();
        }

        TokenProcessIdentity rawTarget() {
            return token.rawTarget();
        }

        TokenProcessIdentity rawClient() {
            return token.rawClient();
        }
    }

    static final class SafeAcquisitionMissProof {
        private final String marker;

        private SafeAcquisitionMissProof(String marker) {
            this.marker = marker;
        }

        String marker() {
            return marker;
        }
    }

    static final class TokenProcessIdentity {
        private final String pid;
        private final String startTime;

        private TokenProcessIdentity(String pid, String startTime) {
            this.pid = pid;
            this.startTime = startTime;
        }

        String pid() {
            return pid;
        }

        String startTime() {
            return startTime;
        }

        boolean bindsTo(int expectedPid, String expectedStartTime) {
            return pid.equals(Integer.toString(expectedPid))
                    && startTime.equals(expectedStartTime);
        }
    }

    static final class TerminalCleanupProof {
        private final ProofFields fields;

        private TerminalCleanupProof(ProofFields fields) {
            this.fields = fields;
        }

        boolean bindsTo(
                int helperPid,
                int donorPid,
                String donorStartTime,
                String donorTids,
                String donorStates,
                NormalisationProof normalisation) {
            BigInteger expectedStart = parseNumber(
                    donorStartTime, UNSIGNED_DECIMAL, 10);
            if (normalisation == null
                    || expectedStart == null
                    || !is(fields, "helper_pid", helperPid)
                    || !is(fields, "host_donor_pid", donorPid)
                    || !is(fields, "host_donor_start_time", expectedStart)
                    || !fields.raw.get("host_donor_tids").equals(donorTids)
                    || !fields.raw.get("host_donor_states").equals(donorStates)) {
                return false;
            }
            for (String name : NORMALISATION_TERMINAL_FIELDS) {
                if (!same(fields, name, normalisation.fields, name)) {
                    return false;
                }
            }
            return true;
        }
    }

    private static RootChain parseRootChain(String value) {
        if (value == null) {
            return null;
        }
        BracketSpan nodeSpan = bracketSpan(value, "node");
        if (nodeSpan == null || nodeSpan.end != value.length()) {
            return null;
        }
        String outer = stripWhitespace(value.substring(0, nodeSpan.start));
        BracketSpan epitemSpan = bracketSpan(outer, "epitem");
        if (epitemSpan == null || epitemSpan.end != outer.length()) {
            return null;
        }
        String outerPrefix = stripWhitespace(
                outer.substring(0, epitemSpan.start)
                        + outer.substring(epitemSpan.end));
        ProofFields outerRecord = parseIssueRecord(
                outerPrefix, new String[] {"status", "stage"});
        if (outerRecord == null || !"root-chain".equals(outerRecord.raw.get("stage"))) {
            return null;
        }
        String status = outerRecord.raw.get("status");
        String expectedOuterPrefix = "status=" + status + " stage=root-chain";
        if (!outer.substring(0, epitemSpan.start).equals(expectedOuterPrefix + " ")) {
            return null;
        }

        String node = value.substring(
                nodeSpan.start + "node=[".length(), nodeSpan.end - 1);
        BracketSpan prepareSpan = bracketSpan(node, "prepare");
        BracketSpan firstSpan = bracketSpan(node, "first");
        if (prepareSpan == null || firstSpan == null) {
            return null;
        }
        String expectedNodePrefix = "status=" + status + " stage=root-unlink";
        if (!node.substring(0, prepareSpan.start).equals(expectedNodePrefix + " ")
                || prepareSpan.end > firstSpan.start
                || !node.substring(prepareSpan.end, firstSpan.start).equals(" ")) {
            return null;
        }
        String nodePrefix = stripWhitespace(node.substring(0, prepareSpan.start));
        if (!nodePrefix.equals(expectedNodePrefix)) {
            return null;
        }
        int nodeStatusEnd = nodePrefix.indexOf(' ');
        if (nodeStatusEnd < 0) {
            return null;
        }
        String nodeStatus = nodePrefix.substring(0, nodeStatusEnd);
        String nodeTail = node.substring(firstSpan.end);
        if (!nodeTail.isEmpty()) {
            return null;
        }
        return new RootChain(
                status,
                nodeStatus.substring("status=".length()),
                nodePrefix,
                nodeTail,
                node.substring(
                        prepareSpan.start + "prepare=[".length(),
                        prepareSpan.end - 1),
                node.substring(
                        firstSpan.start + "first=[".length(),
                        firstSpan.end - 1));
    }

    private static ProofFields parseIssueRecord(String value, String[] names) {
        Map<String, String> raw = parseOrderedFields(value, names);
        if (raw == null) {
            return null;
        }
        boolean prepareRecord = Arrays.asList(names).contains("staged_expected");
        Map<String, BigInteger> numbers = new HashMap<>();
        for (String name : names) {
            String fieldValue = raw.get(name);
            if ("status".equals(name) || "stage".equals(name) || "order".equals(name)) {
                Pattern format = "order".equals(name) ? ISSUE_ORDER : ISSUE_STRING;
                if (!format.matcher(fieldValue).matches()) {
                    return null;
                }
                continue;
            }
            boolean hexadecimal = INITIAL_MISS_HEX_FIELDS.contains(name)
                    && !("expected".equals(name) && prepareRecord);
            BigInteger parsed = parseNumber(
                    fieldValue, hexadecimal ? HEX : DECIMAL, hexadecimal ? 16 : 10);
            if (parsed == null) {
                return null;
            }
            numbers.put(name, parsed);
        }
        return new ProofFields(raw, numbers);
    }

    private static ProofFields validateInitialMissPrepare(ProofFields record) {
        if (record == null
                || !"pass".equals(record.raw.get("status"))
                || !"arb-read-prepare".equals(record.raw.get("stage"))) {
            return null;
        }
        for (Map.Entry<String, BigInteger> entry : INITIAL_MISS_PREPARE_EXACT.entrySet()) {
            if (!is(record, entry.getKey(), entry.getValue())) {
                return null;
            }
        }
        for (String name : INITIAL_MISS_PREPARE_POSITIVE_FIELDS) {
            if (!positive(record, name)) {
                return null;
            }
        }
        if (!same(record, "write_consumed", "write_expected")
                || !is(record, "write_expected", 68)
                || !is(record, "read_consumed", 8)
                || !is(record, "read_first", 0x720c)
                || !is(record, "read_second", 0x7211)
                || !same(record, "read_tid", "tid")) {
            return null;
        }
        return record;
    }

    private static ProofFields validateInitialMissObservation(
            ProofFields record, ProofFields prepare) {
        if (record == null
                || !"miss".equals(record.raw.get("status"))
                || !"fake-node-check".equals(record.raw.get("stage"))) {
            return null;
        }
        for (Map.Entry<String, BigInteger> entry
                : INITIAL_MISS_OBSERVATION_EXACT.entrySet()) {
            if (!is(record, entry.getKey(), entry.getValue())) {
                return null;
            }
        }
        BigInteger addressLimit = ONE.shiftLeft(39);
        BigInteger buffer = number(record, "buffer");
        BigInteger pointer = number(record, "ptr");
        BigInteger cookie = number(record, "cookie");
        if (buffer.signum() <= 0
                || buffer.compareTo(addressLimit) >= 0
                || !buffer.mod(BigInteger.valueOf(8)).equals(ZERO)
                || pointer.signum() < 0
                || pointer.compareTo(addressLimit) >= 0
                || !pointer.mod(BigInteger.valueOf(8)).equals(ZERO)
                || cookie.signum() < 0
                || cookie.compareTo(addressLimit) >= 0
                || !cookie.mod(BigInteger.valueOf(8)).equals(ZERO)
                || !is(record, "wait_cpu", ONE)
                || !number(record, "raw_index").equals(
                        pointer.and(BigInteger.valueOf(0x3ff)))
                || !is(record, "transactions", ONE)
                || !is(record, "last_response", 0x80407202L)
                || !is(record, "last_code", 0x4266)
                || !is(record, "flags", ZERO)
                || !is(record, "data_size", ZERO)
                || !is(record, "offsets_size", ZERO)
                || !is(record, "victim_refs_before_transaction", ZERO)
                || !is(record, "victim_ref_count", ZERO)) {
            return null;
        }
        boolean zeroPair = pointer.equals(ZERO) && cookie.equals(ZERO);
        boolean preparedPair = pointer.equals(number(prepare, "raw_pointer"))
                && cookie.equals(number(prepare, "raw_cookie"));
        if (!is(record, "read_calls", 17)
                || !is(record, "responses", 81)
                || !is(record, "refs_before_transaction", TWELVE)
                || !(zeroPair || preparedPair)
                || !number(record, "last_ref_ptr").equals(
                        number(prepare, "raw_pointer").subtract(
                                BigInteger.valueOf(0x308)))
                || !number(record, "last_ref_cookie").equals(
                        number(prepare, "raw_cookie").subtract(
                                BigInteger.valueOf(0xa0)))
                || !INITIAL_MISS_RESPONSE_ORDER.equals(record.raw.get("order"))) {
            return null;
        }
        return record;
    }

    private static BracketSpan bracketSpan(String value, String name) {
        if (value == null) {
            return null;
        }
        String marker = name + "=[";
        int start = -1;
        int searchFrom = 0;
        while (searchFrom <= value.length() - marker.length()) {
            int candidate = value.indexOf(marker, searchFrom);
            if (candidate < 0) {
                break;
            }
            if (start >= 0) {
                return null;
            }
            start = candidate;
            searchFrom = candidate + 1;
        }
        if (start < 0) {
            return null;
        }
        int depth = 1;
        for (int index = start + marker.length(); index < value.length(); index++) {
            char character = value.charAt(index);
            if (character == '[') {
                depth++;
            } else if (character == ']') {
                depth--;
                if (depth == 0) {
                    return new BracketSpan(start, index + 1);
                }
            }
        }
        return null;
    }

    private static List<String> parseProgress(String value) {
        if (value == null) {
            return null;
        }
        List<String> names = new ArrayList<>();
        BigInteger previousTime = BigInteger.valueOf(-1);
        for (String line : LINE_BREAK.split(value)) {
            int position = 0;
            while (position < line.length() && isWhitespace(line.charAt(position))) {
                position++;
            }
            int timestampEnd = position;
            while (timestampEnd < line.length()
                    && !isWhitespace(line.charAt(timestampEnd))) {
                timestampEnd++;
            }
            if (position == timestampEnd) {
                return null;
            }
            int detailStart = timestampEnd;
            while (detailStart < line.length()
                    && isWhitespace(line.charAt(detailStart))) {
                detailStart++;
            }
            if (detailStart == timestampEnd || detailStart == line.length()) {
                return null;
            }
            String timestampValue = line.substring(position, timestampEnd);
            if (!UNSIGNED_DECIMAL.matcher(timestampValue).matches()) {
                return null;
            }
            BigInteger timestamp = new BigInteger(timestampValue);
            String detail = line.substring(detailStart);
            int markerEnd = 0;
            while (markerEnd < detail.length()
                    && !isWhitespace(detail.charAt(markerEnd))) {
                markerEnd++;
            }
            String marker = detail.substring(0, markerEnd);
            if (timestamp.compareTo(previousTime) < 0
                    || !PROGRESS_MARKER.matcher(marker).matches()
                    || detail.indexOf('\0') >= 0
                    || detail.indexOf('\r') >= 0) {
                return null;
            }
            previousTime = timestamp;
            names.add(marker);
        }
        return names;
    }

    private static boolean hasExactInitialMissTail(List<String> names) {
        if (names == null) {
            return false;
        }
        int start = names.indexOf(INITIAL_MISS_PROGRESS_TAIL[0]);
        if (start < 0 || names.size() - start != INITIAL_MISS_PROGRESS_TAIL.length) {
            return false;
        }
        for (int index = 0; index < INITIAL_MISS_PROGRESS_TAIL.length; index++) {
            if (!INITIAL_MISS_PROGRESS_TAIL[index].equals(names.get(start + index))) {
                return false;
            }
        }
        return true;
    }

    private static boolean hasForbiddenInitialMissProgress(List<String> names) {
        if (names == null) {
            return true;
        }
        for (String marker : names) {
            for (String prefix : INITIAL_MISS_FORBIDDEN_PROGRESS_PREFIXES) {
                if (marker.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static ProofFields parseNumbers(
            Map<String, String> raw,
            Set<String> decimalFields,
            Set<String> hexFields) {
        Map<String, BigInteger> numbers = new HashMap<>();
        for (String name : decimalFields) {
            BigInteger parsed = parseNumber(raw.get(name), DECIMAL, 10);
            if (parsed == null) {
                return null;
            }
            numbers.put(name, parsed);
        }
        for (String name : hexFields) {
            BigInteger parsed = parseNumber(raw.get(name), HEX, 16);
            if (parsed == null) {
                return null;
            }
            numbers.put(name, parsed);
        }
        return new ProofFields(raw, numbers);
    }

    private static BigInteger parseNumber(String value, Pattern format, int radix) {
        if (value == null || !format.matcher(value).matches()) {
            return null;
        }
        String digits = radix == 16 ? value.substring(2) : value;
        try {
            return new BigInteger(digits, radix);
        } catch (NumberFormatException exception) {
            return null;
        }
    }

    private static Map<String, String> parseOrderedFields(String value, String[] names) {
        if (value == null || value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return null;
        }
        String[] tokens = value.split(" ", -1);
        if (tokens.length != names.length) {
            return null;
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (int index = 0; index < names.length; index++) {
            String token = tokens[index];
            int separator = token.indexOf('=');
            if (separator < 1
                    || separator == token.length() - 1
                    || !names[index].equals(token.substring(0, separator))) {
                return null;
            }
            result.put(names[index], token.substring(separator + 1));
        }
        return result;
    }

    private static Map<String, String> parseUnorderedFields(String value) {
        if (value == null) {
            return null;
        }
        String stripped = stripWhitespace(value);
        if (stripped.isEmpty()) {
            return null;
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (String token : WHITESPACE.split(stripped)) {
            int separator = token.indexOf('=');
            if (separator < 1 || separator == token.length() - 1) {
                return null;
            }
            String key = token.substring(0, separator);
            if (result.containsKey(key)) {
                return null;
            }
            result.put(key, token.substring(separator + 1));
        }
        return result;
    }

    private static Map<String, String> parseProcessTeardownFields(String value) {
        if (value == null) {
            return null;
        }
        String stripped = stripWhitespace(value);
        if (stripped.isEmpty()) {
            return null;
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (String token : WHITESPACE.split(stripped)) {
            int separator = token.indexOf('=');
            if (separator < 1
                    || separator != token.lastIndexOf('=')
                    || separator == token.length() - 1) {
                return null;
            }
            String name = token.substring(0, separator);
            if (!TOKEN_FIELD_NAME.matcher(name).matches() || result.containsKey(name)) {
                return null;
            }
            result.put(name, token.substring(separator + 1));
        }
        return result.keySet().equals(PROCESS_TEARDOWN_FIELDS) ? result : null;
    }

    private static String stripWhitespace(String value) {
        int start = 0;
        int end = value.length();
        while (start < end && isWhitespace(value.charAt(start))) {
            start++;
        }
        while (end > start && isWhitespace(value.charAt(end - 1))) {
            end--;
        }
        return value.substring(start, end);
    }

    private static boolean isWhitespace(char value) {
        return Character.isWhitespace(value) || Character.isSpaceChar(value);
    }

    private static boolean validHostDonorState(String tidsValue, String statesValue) {
        String[] tids = tidsValue.split(",", -1);
        String[] states = statesValue.split(",", -1);
        if (tids.length == 0 || tids.length != states.length) {
            return false;
        }
        for (int index = 0; index < tids.length; index++) {
            if (!POSITIVE_DECIMAL.matcher(tids[index]).matches()
                    || !HOST_STATE.matcher(states[index]).matches()) {
                return false;
            }
            int separator = states[index].indexOf(':');
            String stateTid = states[index].substring(0, separator);
            char state = states[index].charAt(separator + 1);
            if (!stateTid.equals(tids[index]) || state == 'T' || state == 't') {
                return false;
            }
        }
        return true;
    }

    private static BigInteger resumeCommit(ProofFields fields) {
        return number(fields, "resume_magic")
                .xor(number(fields, "resume_cookie_hi"))
                .xor(number(fields, "resume_cookie_lo"))
                .xor(number(fields, "resume_donor_task"))
                .xor(RESUME_COMMIT_MASK);
    }

    private static BigInteger number(ProofFields fields, String name) {
        return fields.numbers.get(name);
    }

    private static boolean is(ProofFields fields, String name, long value) {
        return is(fields, name, BigInteger.valueOf(value));
    }

    private static boolean is(ProofFields fields, String name, BigInteger value) {
        return value.equals(number(fields, name));
    }

    private static boolean same(ProofFields fields, String first, String second) {
        return number(fields, first).equals(number(fields, second));
    }

    private static boolean same(
            ProofFields first,
            String firstName,
            ProofFields second,
            String secondName) {
        return number(first, firstName).equals(number(second, secondName));
    }

    private static boolean positive(ProofFields fields, String name) {
        return number(fields, name).signum() > 0;
    }

    private static boolean negative(ProofFields fields, String name) {
        return number(fields, name).signum() < 0;
    }

    private static boolean zeroOrOne(ProofFields fields, String name) {
        return is(fields, name, ZERO) || is(fields, name, ONE);
    }

    private static boolean between(ProofFields fields, String name, long low, long high) {
        return between(fields, name, BigInteger.valueOf(low), BigInteger.valueOf(high));
    }

    private static boolean between(
            ProofFields fields, String name, BigInteger low, BigInteger high) {
        BigInteger value = number(fields, name);
        return value.compareTo(low) >= 0 && value.compareTo(high) <= 0;
    }

    private static boolean greaterThan(ProofFields fields, String name, BigInteger value) {
        return number(fields, name).compareTo(value) > 0;
    }

    private static boolean greaterThan(ProofFields fields, String first, String second) {
        return number(fields, first).compareTo(number(fields, second)) > 0;
    }

    private static boolean equalsAdded(
            ProofFields fields, String result, String source, long amount) {
        return number(fields, result).equals(
                number(fields, source).add(BigInteger.valueOf(amount)));
    }

    private static Map<String, String> fixedFields(String... entries) {
        Map<String, String> result = new LinkedHashMap<>();
        for (int index = 0; index < entries.length; index += 2) {
            result.put(entries[index], entries[index + 1]);
        }
        return Collections.unmodifiableMap(result);
    }

    private static Map<String, BigInteger> fixedNumbers(Object... entries) {
        Map<String, BigInteger> result = new LinkedHashMap<>();
        for (int index = 0; index < entries.length; index += 2) {
            result.put(
                    (String) entries[index],
                    BigInteger.valueOf(((Number) entries[index + 1]).longValue()));
        }
        return Collections.unmodifiableMap(result);
    }

    private static Set<String> setOf(String... values) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(values)));
    }

    @SafeVarargs
    private static Set<String> difference(
            String[] values, Set<String>... excludedSets) {
        Set<String> result = new HashSet<>(Arrays.asList(values));
        for (Set<String> excluded : excludedSets) {
            result.removeAll(excluded);
        }
        return Collections.unmodifiableSet(result);
    }

    private static final class BracketSpan {
        final int start;
        final int end;

        BracketSpan(int start, int end) {
            this.start = start;
            this.end = end;
        }
    }

    private static final class RootChain {
        final String status;
        final String nodeStatus;
        final String nodePrefix;
        final String nodeTail;
        final String prepare;
        final String first;

        RootChain(
                String status,
                String nodeStatus,
                String nodePrefix,
                String nodeTail,
                String prepare,
                String first) {
            this.status = status;
            this.nodeStatus = nodeStatus;
            this.nodePrefix = nodePrefix;
            this.nodeTail = nodeTail;
            this.prepare = prepare;
            this.first = first;
        }
    }

    private static final class ProofFields {
        final Map<String, String> raw;
        final Map<String, BigInteger> numbers;

        ProofFields(Map<String, String> raw, Map<String, BigInteger> numbers) {
            this.raw = Collections.unmodifiableMap(new LinkedHashMap<>(raw));
            this.numbers = Collections.unmodifiableMap(new HashMap<>(numbers));
        }
    }
}
