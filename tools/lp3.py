#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///

"""Guarded host controller for the known Light Phone III build."""

from __future__ import annotations

import argparse
import errno
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PROFILE_PATH = ROOT / "app/src/main/assets/device_profiles.json"
APK_PATH = ROOT / "app/build/outputs/apk/debug/app-debug.apk"
PACKAGE = "com.vandam.prism"
LINUX_SIGCONT = 18
HELPER_CLASS = "com.vandam.prism.ShellBridgeMain"
HELPER_LOG = "/data/local/tmp/light-side-of-the-moon-helper.log"
PARTITION_BACKUP_RESULT = (
    "/data/local/tmp/light-side-partition-backup.result"
)
PARTITION_WATCHDOG_PID = (
    "/data/local/tmp/light-side-partition-watchdog.pid"
)
PARTITION_BACKUPS = {
    "frp": "/data/local/tmp/frp.img",
    "devinfo": "/data/local/tmp/devinfo.img",
    "deviceinfo": "/data/local/tmp/deviceinfo.img",
    "abl_a": "/data/local/tmp/abl_a.img",
    "abl_b": "/data/local/tmp/abl_b.img",
}
PARTITION_LIMIT = 134_217_728
PARTITION_SIGNAL_PORT = 47392
SU_COMMAND_PORT = 47393
SU_TOKEN_PATH = "/data/local/tmp/light-side-su.token"
SU_ARM_PATH = "/data/local/tmp/light-side-su.arm"
ROOT_WATCHDOG_ARM_PATH = (
    "/data/local/tmp/light-side-root-watchdog.arm"
)
NORMALISE_WAITING_PATH = "/data/local/tmp/light-side-normalise.waiting"
JOB_STORE_REPAIR_RESULT = (
    "/data/local/tmp/light-side-jobstore-repair.result"
)
JOB_STORE_COMMIT = "/data/local/tmp/light-side-jobstore-repair.commit"
JOB_STORE_BACKUPS = {
    "jobs.xml": "/data/local/tmp/light-side-jobs.xml",
    "jobs.xml.bak": "/data/local/tmp/light-side-jobs.xml.bak",
    "jobs_1000.xml": "/data/local/tmp/light-side-jobs_1000.xml",
    "jobs_1000.xml.bak": "/data/local/tmp/light-side-jobs_1000.xml.bak",
}
SAFE_FAST_RESET_MARKERS = {
    "epitem-reader-failed",
    "epitem-reclaim-failed",
    "epitem-analysis-failed",
    "node-analysis-failed",
    "arbitrary-read-observe-miss-safe",
}
SAFE_CLEAN_REBOOT_MARKERS = {
    "direct-security-target-failed",
}
SAFE_NODE_ANALYSIS_MISS_MARKER = "node-analysis-failed"
SAFE_EXACT_MISS_MARKER = "arbitrary-read-observe-miss-safe"
PROC_TEARDOWN_MARKER = "arbitrary-read-proc-teardown-required"
SU_IDENTITY_COMMAND = "__LP3_IDENTITY__"
RESUKISU_PROBE_COMMAND = "__LP3_RESUKISU_PROBE__"
RESUKISU_ACTIVATE_COMMAND = "__LP3_RESUKISU_ACTIVATE__"
RESUKISU_PACKAGE = "com.resukisu.resukisu"
RESUKISU_PATH = "/data/local/tmp/lp3-resukisu-ksud"
KERNEL_LINK_BASE = 0xFFFFFFC008000000
KASLR_ALIGNMENT = 0x200000
RESUKISU_SHA256 = (
    "7765acff69651e31629433fa6095a41b7ca034b62e17f9180c2a820b1f177483"
)
ISSUE_2_QUALIFICATION_RUNS = 10
ISSUE_2_CLASSIFIER_VERSION = 2
ISSUE_2_MAX_EXCLUSIONS = 10
ISSUE_2_MAX_ATTEMPTS = 20
ISSUE_2_BR_NOOP = 0x720C
ISSUE_2_BR_FAILED_REPLY = 0x7211
# The initial controlled transaction is reported as a BR_TRANSACTION command
# with the binder transaction payload size encoded in the command value.
ISSUE_2_INITIAL_LAST_RESPONSE = 0x80407202
ISSUE_2_COHORT_MISS_RESPONSE_ORDER = (
    "1:0x720c,1:0x80107207,1:0x80107208,1:0x80107207,"
    "1:0x80107208,2:0x720c,2:0x80107207,2:0x80107208"
)
HELPER_NAMESPACE_NAMES = (
    "cgroup",
    "mnt",
    "net",
    "time",
    "time_for_children",
    "uts",
)
POST_CLEAN_DWELL_SECONDS = 10
BOOT_ID_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}"
)
TERMINAL_CLEANUP_FIXED_FIELDS = {
    "status": "pass",
    "stage": "terminal-cleanup",
    "outcome": "clean",
    "reason": "none",
}
TERMINAL_CLEANUP_INTEGER_FIELDS = {
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
    "watchdogs_retired",
}
TERMINAL_CLEANUP_HEX_FIELDS = {
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
    "resume_commit",
}

TERMINAL_CLEANUP_STRING_FIELDS = {
    "host_donor_tids",
    "host_donor_states",
}

CTLBUF_DONOR_RESUME_FIELDS = (
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
    "commit",
)

CTLBUF_DONOR_RESUME_HEX_FIELDS = {
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
    "commit",
}

CTLBUF_FINALISE_FIELDS = (
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
    "proof",
)
CTLBUF_FINALISE_DECIMAL_FIELDS = {
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
    "proof",
}
CTLBUF_FINALISE_HEX_FIELDS = {
    name
    for name in CTLBUF_FINALISE_FIELDS
    if name not in CTLBUF_FINALISE_DECIMAL_FIELDS
    and name not in {"status", "stage", "reason", "restored_inode_source"}
}


def parse_ctlbuf_finalise_status(
    value: str,
) -> dict[str, int | str] | None:
    """Parse the exact one-shot module finalisation proof."""
    if "\n" in value or "\r" in value:
        return None
    tokens = value.split(" ")
    if len(tokens) != len(CTLBUF_FINALISE_FIELDS):
        return None
    raw: dict[str, str] = {}
    for token, name in zip(tokens, CTLBUF_FINALISE_FIELDS, strict=True):
        key, separator, field_value = token.partition("=")
        if separator != "=" or key != name or not field_value:
            return None
        raw[name] = field_value
    if (
        raw["status"] != "pass"
        or raw["stage"] != "ctlbuf-finalise"
        or raw["reason"] != "none"
        or raw["restored_inode_source"] != "reference"
    ):
        return None
    parsed: dict[str, int | str] = {
        "status": raw["status"],
        "stage": raw["stage"],
        "reason": raw["reason"],
        "restored_inode_source": raw["restored_inode_source"],
    }
    for name in CTLBUF_FINALISE_DECIMAL_FIELDS:
        if re.fullmatch(r"-?\d+", raw[name]) is None:
            return None
        parsed[name] = int(raw[name])
    for name in CTLBUF_FINALISE_HEX_FIELDS:
        if re.fullmatch(r"0x[0-9a-f]+", raw[name]) is None:
            return None
        parsed[name] = int(raw[name], 16)

    expected_count = parsed["expected_count"]
    pointer_fields = {
        name for name in CTLBUF_FINALISE_HEX_FIELDS
        if name not in {
            "donor_caps",
            "donor_repair",
            "donor_state",
            "donor_ids_mask",
            "donor_observed_caps",
            "donor_observed_repair",
            "donor_observed_security_word8",
        }
    }
    if any(parsed[name] == 0 for name in pointer_fields):
        return None
    if (
        parsed["error"] != 0
        or parsed["helper_pid"] <= 0
        or parsed["helper_borrowed"] != 1
        or parsed["owner_pid"] <= 0
        or parsed["donor_pid"] <= 0
        or parsed["watched_fd"] < 0
        or parsed["arbitrary_fd"] < 0
        or parsed["reference_fd"] < 0
        or len({
            parsed["watched_fd"],
            parsed["arbitrary_fd"],
            parsed["reference_fd"],
        }) != 3
        or parsed["watched_file"] in {
            parsed["arbitrary_file"],
            parsed["reference_file"],
        }
        or parsed["arbitrary_file"] == parsed["reference_file"]
        or parsed["watched_inode"] != parsed["reference_inode"]
        or parsed["watched_fops"] != parsed["arbitrary_fops"]
        or parsed["watched_fops"] != parsed["reference_fops"]
        or parsed["watched_fops"] != parsed["expected_fops"]
        or parsed["arbitrary_inode"]
        != parsed["selected_epitem"] + 0x50
        or parsed["pre_inode"] != parsed["arbitrary_inode"]
        or parsed["pre_next"] != parsed["arbitrary_file"] + 0x20
        or parsed["restored_inode_value"] != parsed["reference_inode"]
        or expected_count not in {1, 5632}
        or parsed["reverse_count"] != expected_count
        or parsed["forward_count"] != expected_count
        or parsed["non_selected_forward"] != expected_count - 1
        or parsed["reverse_relationships"] != expected_count
        or parsed["post_link"] != parsed["successor"]
        or parsed["final_post_link"] != parsed["successor"]
        or parsed["restored_link"] != 1
        or parsed["restored_inode"] != 1
        or parsed["forward_cycle"] != 1
        or parsed["reverse_cycle"] != 1
        or parsed["readbacks"] != 1
        or parsed["donor_usage"] <= 0
        or parsed["donor_usage"] > 0xFFFFFFFF
        or parsed["donor_caps"] == 0
        or parsed["donor_sid"] == 0
        or parsed["donor_repair"] != 0
        or parsed["donor_frozen"] != 1
        or parsed["donor_snapshot_a"] != 1
        or parsed["donor_snapshot_b"] != 1
        or parsed["donor_snapshot_stage"] != 17
        or parsed["donor_state"] & 4 != 4
        or parsed["donor_observed_pid"] != parsed["donor_pid"]
        or parsed["donor_observed_tgid"] != parsed["donor_pid"]
        or parsed["donor_observed_real_cred"] != parsed["donor_cred"]
        or parsed["donor_observed_cred"] != parsed["donor_cred"]
        or parsed["donor_observed_real_slot"] != parsed["donor_cred"]
        or parsed["donor_observed_cred_slot"] != parsed["donor_cred"]
        or not 1 <= parsed["donor_file_refs"] <= 64
        or not 0 <= parsed["donor_open_fds"] <= 16384
        or not 1 <= parsed["donor_max_fds"] <= 65536
        or parsed["donor_file_refs"] > parsed["donor_open_fds"]
        or parsed["donor_open_fds"] > parsed["donor_max_fds"]
        or parsed["donor_file_refs"] > 0xFFFFFFFF - parsed["donor_usage"]
        or not 0 <= parsed["donor_observed_usage"] <= 0xFFFFFFFF
        or parsed["donor_observed_usage"]
        != parsed["donor_usage"] + parsed["donor_file_refs"]
        or parsed["donor_ids_mask"] != 0xFF
        or parsed["donor_observed_caps"] != parsed["donor_caps"]
        or parsed["donor_observed_repair"] != 0
        or parsed["donor_observed_security"] == 0
        or parsed["donor_observed_security_word8"] != 0
        or parsed["donor_observed_sid"] != parsed["donor_sid"]
        or parsed["list_exact"] != 1
        or parsed["proof"] != 1
    ):
        return None
    return parsed


def parse_ctlbuf_donor_resume_status(
    value: str,
) -> dict[str, int | str] | None:
    """Parse the committed module-exit donor-resume record."""
    if "\n" in value or "\r" in value:
        return None
    tokens = value.split(" ")
    if len(tokens) != len(CTLBUF_DONOR_RESUME_FIELDS):
        return None
    raw: dict[str, str] = {}
    for token, name in zip(
        tokens, CTLBUF_DONOR_RESUME_FIELDS, strict=True
    ):
        key, separator, field_value = token.partition("=")
        if separator != "=" or key != name or not field_value:
            return None
        raw[name] = field_value
    if raw["status"] != "pass" or raw["stage"] != "donor-resume":
        return None
    parsed: dict[str, int | str] = {
        "status": raw["status"],
        "stage": raw["stage"],
    }
    for name in CTLBUF_DONOR_RESUME_FIELDS[2:]:
        if name in CTLBUF_DONOR_RESUME_HEX_FIELDS:
            if re.fullmatch(r"0x[0-9a-f]+", raw[name]) is None:
                return None
            parsed[name] = int(raw[name], 16)
        else:
            if re.fullmatch(r"-?\d+", raw[name]) is None:
                return None
            parsed[name] = int(raw[name])
    if (
        parsed["magic"] != 0x4C5033524553554D
        or parsed["version"] != 1
        or parsed["size"] != 176
        or parsed["helper_task"] == 0
        or parsed["helper_pid"] <= 0
        or parsed["donor_task"] == 0
        or parsed["donor_pid"] <= 0
        or parsed["donor_tgid"] != parsed["donor_pid"]
        or parsed["signal"] != LINUX_SIGCONT
        or parsed["signal_result"] != 0
        or parsed["signal_errno"] != 0
        or parsed["before_state"] & 0xC == 0
        or parsed["before_exit_state"] != 0
        or not 1 <= parsed["before_threads"] <= 4096
        or parsed["before_stopped"] != parsed["before_threads"]
        or parsed["after_state"] & 0xC != 0
        or parsed["after_exit_state"] != 0
        or not 1 <= parsed["after_threads"] <= 4096
        or parsed["after_stopped"] != 0
        or parsed["stable_samples"] != 2
        or parsed["task_security"] == 0
        or parsed["inode_security"] == 0
        or parsed["labels_restored"] != 1
        or parsed["resumed"] != 1
        or parsed["proof"] != 1
        or parsed["commit"]
        != (
            parsed["magic"]
            ^ parsed["cookie_hi"]
            ^ parsed["cookie_lo"]
            ^ parsed["donor_task"]
            ^ 0xA5D91F7462C83BE0
        )
    ):
        return None
    return parsed


def parse_terminal_cleanup_result(
    value: str,
) -> dict[str, int | str] | None:
    """Parse the only terminal cleanup record that can end a root lease."""
    raw_fields: dict[str, str] = {}
    for token in value.split():
        key, separator, field_value = token.partition("=")
        if (
            not separator
            or not key
            or not field_value
            or key in raw_fields
        ):
            return None
        raw_fields[key] = field_value
    expected = (
        set(TERMINAL_CLEANUP_FIXED_FIELDS)
        | TERMINAL_CLEANUP_INTEGER_FIELDS
        | TERMINAL_CLEANUP_HEX_FIELDS
        | TERMINAL_CLEANUP_STRING_FIELDS
    )
    if set(raw_fields) != expected:
        return None
    if any(
        raw_fields.get(key) != expected_value
        for key, expected_value in TERMINAL_CLEANUP_FIXED_FIELDS.items()
    ):
        return None

    parsed: dict[str, int | str] = {}
    for key in TERMINAL_CLEANUP_INTEGER_FIELDS:
        field_value = raw_fields[key]
        if re.fullmatch(r"-?\d+", field_value) is None:
            return None
        parsed[key] = int(field_value)
    for key in TERMINAL_CLEANUP_HEX_FIELDS:
        field_value = raw_fields[key]
        if re.fullmatch(r"0x[0-9a-f]+", field_value) is None:
            return None
        parsed[key] = int(field_value, 16)
    for key in TERMINAL_CLEANUP_STRING_FIELDS:
        parsed[key] = raw_fields[key]

    binary_one = {
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
        "watchdogs_retired",
    }
    if any(parsed[key] != 1 for key in binary_one):
        return None
    if parsed["reboot_required"] != 0:
        return None
    if parsed["collateral_restored"] not in {0, 1}:
        return None
    if parsed["collateral_retired"] not in {0, 1}:
        return None
    if parsed["collateral_restored"] + parsed["collateral_retired"] != 1:
        return None
    host_tids = str(parsed["host_donor_tids"]).split(",")
    host_states = str(parsed["host_donor_states"]).split(",")
    if (
        not host_tids
        or len(host_tids) != len(host_states)
        or any(re.fullmatch(r"[1-9]\d*", tid) is None for tid in host_tids)
        or any(
            re.fullmatch(r"[1-9]\d*:[A-Za-z]", state) is None
            for state in host_states
        )
        or any(
            state.split(":", 1)[0] != tid
            or state.rsplit(":", 1)[1] in {"T", "t"}
            for tid, state in zip(host_tids, host_states, strict=True)
        )
    ):
        return None
    if (
        parsed["required_writes"] != 6
        or parsed["successful_writes"] != 6
        or parsed["used_victims"] < parsed["successful_writes"]
        or parsed["internal_write_misses"] < 0
        or parsed["helper_pid"] <= 0
        or parsed["helper_probe"] != -1
        or parsed["helper_probe_errno"] != errno.ESRCH
        or parsed["helper_proc"] != 0
        or parsed["helper_unlinked"] != 0
        or parsed["helper_unlink_samples"] != 0
        or parsed["donor_proof_sequence"] <= 0
        or parsed["donor_real_cred"] == 0
        or parsed["donor_real_cred"] != parsed["donor_cred"]
        or parsed["donor_live_before_stage"] != 7
        or parsed["donor_live_a_stage"] != 7
        or parsed["donor_live_b_stage"] != 7
        or parsed["donor_live_pre_snapshot_2_stage"] != 7
        or parsed["donor_snapshot_stage"] != 15
        or parsed["donor_repair"] != 0
        or parsed["donor_complete_samples"] != 2
        or parsed["baseline_usage"] <= 0
        or parsed["observed_usage"] != parsed["baseline_usage"]
        or parsed["donor_preexit_usage"] != parsed["baseline_usage"] + 2
        or parsed["preexit_refs_valid"] != 1
        or parsed["preexit_usage"] != parsed["baseline_usage"] + 2
        or parsed["final_usage"] != parsed["baseline_usage"]
        or parsed["preexit_delta"] != 2
        or parsed["retained_read_buffers"] != 0
        or parsed["watchdog_tid"] <= 0
        or parsed["watchdog_tid"] == parsed["helper_pid"]
        or parsed["donor_resume_pid"] <= 0
        or parsed["donor_resume_result"] != 0
        or parsed["donor_resume_errno"] != 0
        or parsed["resume_magic"] != 0x4C5033524553554D
        or parsed["resume_version"] != 1
        or parsed["resume_size"] != 176
        or parsed["resume_helper_task"] == 0
        or parsed["resume_helper_pid"] != parsed["helper_pid"]
        or parsed["resume_donor_task"] == 0
        or parsed["resume_donor_tgid"] != parsed["donor_resume_pid"]
        or parsed["resume_signal"] != LINUX_SIGCONT
        or parsed["resume_before_state"] & 0xC == 0
        or parsed["resume_before_exit_state"] != 0
        or not 1 <= parsed["resume_before_threads"] <= 4096
        or parsed["resume_before_stopped"]
        != parsed["resume_before_threads"]
        or parsed["resume_after_state"] & 0xC != 0
        or parsed["resume_after_exit_state"] != 0
        or not 1 <= parsed["resume_after_threads"] <= 4096
        or parsed["resume_after_stopped"] != 0
        or parsed["resume_stable_samples"] != 2
        or parsed["resume_task_security"] == 0
        or parsed["resume_task_security_word8"] != 0
        or parsed["resume_inode_security"] == 0
        or parsed["resume_inode_security_word8"] != 0
        or parsed["resume_commit"]
        != (
            parsed["resume_magic"]
            ^ parsed["resume_cookie_hi"]
            ^ parsed["resume_cookie_lo"]
            ^ parsed["resume_donor_task"]
            ^ 0xA5D91F7462C83BE0
        )
        or parsed["host_donor_pid"] != parsed["donor_resume_pid"]
        or parsed["host_donor_start_time"] <= 0
        or parsed["host_donor_samples"] != 2
        or parsed["joined"] != 1
        or parsed["tid_gone"] != 1
        or parsed["uid_result"] != 0
        or parsed["gid_result"] != 0
        or parsed["shell"] != 1
        or parsed["poisoned_sprays"] != 0
        or parsed["spray_active"] != 0
        or parsed["spray_expected"] != 0
        or parsed["binder_controlled_unlinks"] != 7
        or parsed["raw_target_pid"] <= 0
        or parsed["raw_target_probe"] != -1
        or parsed["raw_target_probe_errno"] != errno.ESRCH
        or parsed["owner_pid"] <= 0
        or parsed["owner_probe"] != -1
        or parsed["owner_probe_errno"] != errno.ESRCH
        or parsed["anchor_pid"] <= 0
        or parsed["anchor_probe"] != -1
        or parsed["anchor_probe_errno"] != errno.ESRCH
        or parsed["isolated_total"] != 64
        or parsed["isolated_retired"] != 64
        or parsed["primitive_fds"] != 0
        or parsed["fake_node_fds"] != 0
    ):
        return None
    return parsed


def parse_partition_backup_result(
    value: str,
) -> dict[str, tuple[int, str]] | None:
    fields = value.split()
    if fields[:2] != ["status=pass", "stage=partition-backup"]:
        return None
    if len(fields) != len(PARTITION_BACKUPS) + 2:
        return None
    parsed: dict[str, tuple[int, str]] = {}
    for name, field in zip(PARTITION_BACKUPS, fields[2:], strict=True):
        prefix = f"{name}="
        if not field.startswith(prefix):
            return None
        parts = field.removeprefix(prefix).split(":")
        if len(parts) != 2 or not parts[0].isdigit():
            return None
        size = int(parts[0])
        digest = parts[1]
        if (
            size < 1
            or size > PARTITION_LIMIT
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        ):
            return None
        parsed[name] = (size, digest)
    return parsed


class ControllerError(RuntimeError):
    pass


class SameBootRetryRequired(ControllerError):
    pass


ISSUE_2_ARTIFACT_SECTIONS = (
    "host",
    "result",
    "recovery",
    "cleanup",
    "cleanup stage",
    "donor retirement proof",
    "ctlbuf rescue plan",
    "ctlbuf finalise proof",
    "progress",
    "command output",
    "helper log",
    "JobStore before",
    "JobStore after",
    "thermal before",
    "thermal after",
)
ISSUE_2_HOST_FIELDS = (
    "boot_id",
    "start_boot_id",
    "end_boot_id",
    "same_boot",
    "helper_pid",
    "security_process",
    "security_pid",
    "security_start_time",
    "security_target_stable",
    "root_window_seen",
    "root_window_validated",
    "helper_uid",
    "helper_gid",
    "helper_context",
    "helper_cap_eff",
    "root_action",
    "root_action_validated",
    "root_action_result",
    "root_command_exit",
    "su_command_remote_port",
    "su_forward_local_port",
    "su_forward_mapping",
    "su_protocol_phase",
    "root_watchdog_nonce",
    "root_watchdog_helper_start",
    "command_watchdog_signalled",
    "command_watchdog_tid",
    "internal_write_misses",
    "cleanup_verified",
    "strict_success",
    "mutation_possible",
    "kernel_mutation_observed",
    "post_clean_dwell_seconds",
    "post_clean_dwell_complete",
    "unsafe_state",
    "unsafe_reason",
    "recovery_state",
    "proc_teardown_proof",
    "cred_quarantine_pass",
    "planned_reboot",
    "reboot_confirmed",
    "controller_error",
    "run_id",
    "run_metadata",
    "profile_start",
    "profile_end",
    "health_before",
    "health_after",
)
ISSUE_2_RESULT_PREPARE_FIELDS = (
    "status", "stage", "node", "file", "epitem", "raw_pointer",
    "raw_cookie", "next", "pprev", "decrements", "expected_decrements",
    "epitems", "probe_epitems", "control_blocks", "expected_blocks",
    "prefilled",
    "coordinator_cpu", "restored_cpu2", "thread_created", "thread_joined",
    "go_issued", "thread_exited", "join_timed_out", "join_result",
    "quarantined", "fd_closed", "write_attempted", "write_rc",
    "write_errno", "write_consumed", "write_read_consumed", "write_expected",
    "write_enter_cpu", "write_return_cpu", "tid", "generation",
    "staged_generation", "generation_captured", "generation_valid", "expected",
    "staged_expected", "staged_active", "staged_wake", "staged_state2",
    "staged_stable", "global_published", "all_entered", "all_state2", "blocked",
    "read_rc", "read_errno", "read_consumed", "read_write_consumed",
    "read_enter_cpu", "read_return_cpu", "read_tid", "poll_rc", "poll_errno",
    "poll_revents", "read_first", "read_second", "read_responses", "noop",
    "failed_reply", "dead_reply", "unexpected", "malformed", "exact_read",
    "retirement_before_go", "retirement_after_write", "gate_error", "gate_free",
    "gate_read", "gate_unlinked_free", "gate_unlinked_read", "reboot_required",
)
ISSUE_2_RESULT_COMPLETE_FIELDS = (
    "status", "stage", "worker", "released", "expected_release", "poison",
    "initial", "expected", "matching_files", "selected_fd",
    "selected_watched_fd", "candidates",
    "handoff", "pre_free_indexed", "post_free_node_read", "retained_worker",
    "canonical", "original_owner", "one_poison",
    "acknowledged", "reboot_required", "cred", "uid", "gid", "ids_valid",
)
ISSUE_2_OBSERVATION_FIELDS = (
    "status", "stage", "victim", "buffer", "ptr", "cookie", "worker_index",
    "raw_index", "exact_payload", "buffer_freed", "polling", "wait_cpu",
    "read_calls", "responses", "transactions", "last_response", "last_code",
    "flags", "data_size", "offsets_size", "refs_before_transaction",
    "victim_refs_before_transaction", "victim_ref_count", "last_ref_ptr",
    "last_ref_cookie", "order",
)
ISSUE_2_HEX_FIELDS = {
    "node", "file", "epitem", "raw_pointer", "raw_cookie", "next", "pprev",
    "generation", "read_first", "read_second", "buffer", "ptr", "cookie",
    "last_response", "last_code", "refs_before_transaction",
    "flags", "victim_refs_before_transaction",
    "last_ref_ptr", "last_ref_cookie", "initial", "expected", "cred",
}


def _issue_2_sections(path: Path) -> dict[str, str] | None:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    if not text or "\x00" in text or len(text) > 16 * 1024 * 1024:
        return None
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("--- ") and line.endswith(" ---"):
            name = line[4:-4]
            if name not in ISSUE_2_ARTIFACT_SECTIONS or name in sections:
                return None
            sections[name] = []
            current = name
            continue
        if current is None:
            return None
        sections[current].append(line)
    if tuple(sections) != ISSUE_2_ARTIFACT_SECTIONS:
        return None
    return {name: "\n".join(sections[name]) for name in sections}


def _issue_2_pairs(value: str) -> dict[str, str] | None:
    parsed: dict[str, str] = {}
    for line in value.splitlines():
        if not line or "=" not in line:
            return None
        key, field_value = line.split("=", 1)
        if (
            re.fullmatch(r"[a-z][a-z0-9_]*", key) is None
            or not field_value
            or key in parsed
        ):
            return None
        parsed[key] = field_value
    return parsed


def _issue_2_record(
    value: str,
    fields: tuple[str, ...],
    string_fields: set[str] | None = None,
) -> dict[str, int | str] | None:
    if "\n" in value or "\r" in value:
        return None
    tokens = value.split(" ")
    if len(tokens) != len(fields) or any(not token for token in tokens):
        return None
    strings = string_fields or {"status", "stage", "order"}
    parsed: dict[str, int | str] = {}
    for token, name in zip(tokens, fields, strict=True):
        key, separator, field_value = token.partition("=")
        if key != name or separator != "=" or not field_value:
            return None
        if name in strings:
            pattern = (
                r"[A-Za-z0-9_.:,-]+"
                if name == "order"
                else r"[A-Za-z0-9_.:-]+"
            )
            if re.fullmatch(pattern, field_value) is None:
                return None
            parsed[name] = field_value
        elif name in ISSUE_2_HEX_FIELDS and not (
            name == "expected" and "staged_expected" in fields
        ):
            if re.fullmatch(r"0x[0-9a-f]+", field_value) is None:
                return None
            parsed[name] = int(field_value, 16)
        else:
            if re.fullmatch(r"-?\d+", field_value) is None:
                return None
            parsed[name] = int(field_value)
    return parsed


def _issue_2_bracket_span(value: str, name: str) -> tuple[int, int] | None:
    marker = name + "=["
    starts = [index for index in range(len(value))
              if value.startswith(marker, index)]
    if len(starts) != 1:
        return None
    start = starts[0]
    depth = 1
    index = start + len(marker)
    while index < len(value):
        if value[index] == "[":
            depth += 1
        elif value[index] == "]":
            depth -= 1
            if depth == 0:
                return start, index + 1
        index += 1
    return None


def _issue_2_bracket(value: str, name: str) -> str | None:
    span = _issue_2_bracket_span(value, name)
    if span is None:
        return None
    start, end = span
    marker_length = len(name) + 2
    return value[start + marker_length:end - 1]


def _issue_2_without_brackets(
    value: str, names: tuple[str, ...]
) -> str | None:
    result = value
    for name in names:
        span = _issue_2_bracket_span(result, name)
        if span is None:
            return None
        start, end = span
        result = (result[:start] + result[end:]).strip()
    return result


def _issue_2_root_chain(value: str) -> dict[str, str] | None:
    """Parse the root-chain -> node[root-unlink] result envelope."""
    node_span = _issue_2_bracket_span(value, "node")
    if node_span is None:
        return None
    node_start, node_end = node_span
    if value[node_end:]:
        return None
    outer = value[:node_start].strip()
    epitem_span = _issue_2_bracket_span(outer, "epitem")
    if epitem_span is None:
        return None
    epitem_start, epitem_end = epitem_span
    if outer[epitem_end:]:
        return None
    outer_prefix = (
        outer[:epitem_start] + outer[epitem_end:]
    ).strip()
    outer_record = _issue_2_record(
        outer_prefix, ("status", "stage"), {"status", "stage"}
    )
    if outer_record is None or outer_record["stage"] != "root-chain":
        return None
    expected_outer_prefix = (
        f"status={outer_record['status']} stage=root-chain"
    )
    if outer[:epitem_start] != expected_outer_prefix + " ":
        return None
    node = value[node_start + len("node=["):node_end - 1]
    prepare_span = _issue_2_bracket_span(node, "prepare")
    first_span = _issue_2_bracket_span(node, "first")
    if prepare_span is None or first_span is None:
        return None
    prepare_start, prepare_end = prepare_span
    first_start, first_end = first_span
    expected_node_prefix = (
        f"status={outer_record['status']} stage=root-unlink"
    )
    if node[:prepare_start] != expected_node_prefix + " ":
        return None
    if prepare_end > first_start or node[prepare_end:first_start] != " ":
        return None
    node_prefix = node[:prepare_start].strip()
    if node_prefix != expected_node_prefix:
        return None
    node_status, node_stage = node_prefix.split(" ", 1)
    node_tail = node[first_end:]
    if node_tail:
        return None
    return {
        "status": str(outer_record["status"]),
        "node_status": node_status.removeprefix("status="),
        "node_prefix": node_prefix,
        "node_tail": node_tail,
        "prepare": node[prepare_start + len("prepare=["):prepare_end - 1],
        "first": node[first_start + len("first=["):first_end - 1],
    }


def _issue_2_validate_prepare(
    record: dict[str, int | str] | None,
) -> dict[str, int | str] | None:
    if record is None or record["status"] != "pass" or record["stage"] != (
        "arb-read-prepare"
    ):
        return None
    exact = {
        "decrements": 1,
        "expected_decrements": 1,
        "epitems": 5632,
        "probe_epitems": 4096,
        "control_blocks": 1024,
        "expected_blocks": 1024,
        "coordinator_cpu": 1,
        "restored_cpu2": 1,
        "thread_created": 1,
        "thread_joined": 1,
        "go_issued": 1,
        "thread_exited": 1,
        "join_timed_out": 0,
        "join_result": 0,
        "quarantined": 0,
        "fd_closed": 1,
        "write_attempted": 1,
        "write_rc": 0,
        "write_errno": 0,
        "write_read_consumed": 0,
        "write_enter_cpu": 2,
        "write_return_cpu": 2,
        "generation_captured": 1,
        "generation_valid": 1,
        "expected": 1024,
        "staged_expected": 32,
        "staged_active": 32,
        "staged_wake": 1,
        "staged_state2": 32,
        "staged_stable": 1,
        "global_published": 1,
        "all_entered": 1,
        "all_state2": 1024,
        "blocked": 1024,
        "read_rc": 0,
        "read_errno": 0,
        "read_write_consumed": 0,
        "read_enter_cpu": 1,
        "read_return_cpu": 1,
        "poll_rc": 1,
        "poll_errno": 0,
        "poll_revents": 1,
        "read_responses": 2,
        "noop": 1,
        "failed_reply": 1,
        "dead_reply": 0,
        "unexpected": 0,
        "malformed": 0,
        "exact_read": 1,
        "retirement_before_go": 0,
        "retirement_after_write": 0,
        "gate_error": 0,
        "gate_free": 1,
        "gate_read": 1,
        "gate_unlinked_free": 0,
        "gate_unlinked_read": 0,
        "reboot_required": 0,
    }
    if any(record.get(name) != value for name, value in exact.items()):
        return None
    for name in (
        "node", "file", "epitem", "raw_pointer", "raw_cookie", "next",
        "pprev", "generation", "tid", "staged_generation", "read_tid",
    ):
        if not isinstance(record.get(name), int) or int(record[name]) <= 0:
            return None
    if (
        record["write_consumed"] != record["write_expected"]
        or record["write_expected"] != 68
        or record["read_consumed"] != 8
        or record["read_first"] != ISSUE_2_BR_NOOP
        or record["read_second"] != ISSUE_2_BR_FAILED_REPLY
        or record["read_tid"] != record["tid"]
    ):
        return None
    return record


def _issue_2_validate_observation(
    record: dict[str, int | str] | None,
    prepare: dict[str, int | str],
) -> dict[str, int | str] | None:
    if record is None or record["status"] != "miss" or record["stage"] != (
        "fake-node-check"
    ):
        return None
    exact = {
        "victim": 0,
        "exact_payload": 0,
        "buffer_freed": 0,
        "polling": 1,
        "worker_index": -1,
    }
    if any(record.get(name) != value for name, value in exact.items()):
        return None
    if (
        not isinstance(record.get("buffer"), int)
        or not 0 < int(record["buffer"]) < (1 << 39)
        or int(record["buffer"]) % 8 != 0
        or not isinstance(record.get("ptr"), int)
        or not 0 <= int(record["ptr"]) < (1 << 39)
        or int(record["ptr"]) % 8 != 0
        or not isinstance(record.get("cookie"), int)
        or not 0 <= int(record["cookie"]) < (1 << 39)
        or int(record["cookie"]) % 8 != 0
        or record.get("wait_cpu") != 1
        or record.get("raw_index") != (int(record["ptr"]) & 0x3ff)
        or record.get("transactions") != 1
        or record.get("last_response") != ISSUE_2_INITIAL_LAST_RESPONSE
        or record.get("last_code") != 0x4266
        or record.get("flags") != 0
        or record.get("data_size") != 0
        or record.get("offsets_size") != 0
        or record.get("victim_refs_before_transaction") != 0
        or record.get("victim_ref_count") != 0
    ):
        return None
    observed_pair = (int(record["ptr"]), int(record["cookie"]))
    prepared_pair = (
        int(prepare["raw_pointer"]), int(prepare["raw_cookie"])
    )
    cohort_shape = (
        record.get("read_calls") == 17
        and record.get("responses") == 81
        and record.get("refs_before_transaction") == 0xC
        and observed_pair in ((0, 0), prepared_pair)
        and record.get("last_ref_ptr")
        == int(prepare["raw_pointer"]) - 0x308
        and record.get("last_ref_cookie")
        == int(prepare["raw_cookie"]) - 0xA0
        and record.get("order") == ISSUE_2_COHORT_MISS_RESPONSE_ORDER
    )
    if not cohort_shape:
        return None
    return record


def _issue_2_validate_complete(
    record: dict[str, int | str] | None,
    *,
    replacement_miss: bool,
) -> dict[str, int | str] | None:
    if record is None or record["stage"] != "arb-read-complete":
        return None
    if replacement_miss:
        return None
    exact = {
        "status": "pass",
        "poison": 1,
        "handoff": 1,
        "pre_free_indexed": 1,
        "post_free_node_read": 0,
        "canonical": 1,
        "original_owner": 1,
        "one_poison": 1,
        "acknowledged": 1,
        "reboot_required": 0,
        "ids_valid": 1,
    }
    if any(record.get(name) != value for name, value in exact.items()):
        return None
    if (
        not isinstance(record.get("worker"), int)
        or not 0 <= int(record["worker"]) < 1024
        or record.get("retained_worker") != record["worker"]
        or record["released"] != record["expected_release"]
        or record["released"] != 0
        or record["initial"] != record["expected"]
        or record["matching_files"] != 1
        or not isinstance(record.get("selected_fd"), int)
        or int(record["selected_fd"]) < 0
        or not isinstance(record.get("selected_watched_fd"), int)
        or int(record["selected_watched_fd"]) < 0
        or not isinstance(record.get("candidates"), int)
        or int(record["candidates"]) < 1
        or record["cred"] == 0
        or record["uid"] < 0
        or record["gid"] < 0
    ):
        return None
    return record


def _issue_2_progress(value: str) -> list[str] | None:
    names: list[str] = []
    previous_time = -1
    for line in value.splitlines():
        parts = line.split(None, 1)
        if len(parts) != 2 or re.fullmatch(r"\d+", parts[0]) is None:
            return None
        timestamp = int(parts[0])
        marker = parts[1].split(None, 1)[0]
        if timestamp < previous_time or re.fullmatch(
                r"[A-Za-z0-9_.-]+", marker) is None:
            return None
        if "\x00" in parts[1] or "\r" in parts[1]:
            return None
        previous_time = timestamp
        names.append(marker)
    return names


def _issue_2_has_order(names: list[str], required: tuple[str, ...]) -> bool:
    position = -1
    for marker in required:
        try:
            position = names.index(marker, position + 1)
        except ValueError:
            return False
    return True


def _issue_2_validate_metadata(
    sections: dict[str, str],
    *,
    expected_boot_id: str,
    qualification_id: str,
    run_index: int,
    attempt_index: int,
    accepted: bool,
) -> dict[str, str] | None:
    host = _issue_2_pairs(sections["host"])
    recovery = _issue_2_pairs(sections["recovery"])
    if host is None or recovery is None or set(host) != set(
            ISSUE_2_HOST_FIELDS) or set(recovery) != {"state", "error"}:
        return None
    boot_id = host["boot_id"]
    start_boot_id = host["start_boot_id"]
    end_boot_id = host["end_boot_id"]
    if (
        BOOT_ID_PATTERN.fullmatch(boot_id) is None
        or boot_id != expected_boot_id
        or start_boot_id != expected_boot_id
        or end_boot_id != "unknown"
        and BOOT_ID_PATTERN.fullmatch(end_boot_id) is None
    ):
        return None
    try:
        metadata = json.loads(host["run_metadata"])
        profile_start = json.loads(host["profile_start"])
        profile_end = (
            None if host["profile_end"] == "unavailable"
            else json.loads(host["profile_end"])
        )
        health_before = json.loads(host["health_before"])
        health_after = json.loads(host["health_after"])
        proc_teardown_proof = (
            None
            if host["proc_teardown_proof"] == "none"
            else json.loads(host["proc_teardown_proof"])
        )
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    expected_metadata = {
        "mode": "issue-2-qualification",
        "qualification_id": qualification_id,
        "run_index": run_index,
        "attempt_index": attempt_index,
        "run_total": ISSUE_2_QUALIFICATION_RUNS,
        "clean_boot_id": expected_boot_id,
        "host_retries_allowed": 0,
        "host_retries_used": 0,
        "terminal_cleanup_requested": 1,
        "credential_layout_config_verified": 1,
    }
    if metadata != expected_metadata or not isinstance(profile_start, dict):
        return None
    if (
        not isinstance(profile_end, dict)
        or set(profile_start) != {
            "serial", "profile", "expected_properties",
            "observed_properties", "kernel_release", "page_size",
        }
        or set(profile_end) != set(profile_start)
        or profile_end["profile"] != profile_start["profile"]
        or profile_end["expected_properties"]
        != profile_start["expected_properties"]
        or not isinstance(health_before, dict)
        or not isinstance(health_after, dict)
        or set(health_before) != {
            "registered_jobs", "thermal_status", "battery_c", "cpu_max_c"
        }
        or set(health_after) != set(health_before)
        or not health_is_normal(health_before)
        or not health_is_normal(health_after)
    ):
        return None
    serial = profile_start.get("serial")
    if not isinstance(serial, str) or not serial:
        return None
    decimal_names = (
        "same_boot", "helper_pid", "security_pid", "security_target_stable",
        "security_start_time", "root_watchdog_helper_start",
        "root_window_seen", "root_window_validated", "root_action_validated",
        "root_command_exit", "su_command_remote_port", "su_forward_local_port",
        "command_watchdog_signalled", "command_watchdog_tid",
        "internal_write_misses", "cleanup_verified", "strict_success",
        "mutation_possible", "kernel_mutation_observed",
        "post_clean_dwell_seconds", "post_clean_dwell_complete", "unsafe_state",
        "cred_quarantine_pass", "planned_reboot", "reboot_confirmed",
    )
    values: dict[str, int] = {}
    for name in decimal_names:
        if re.fullmatch(r"-?\d+", host[name]) is None:
            return None
        values[name] = int(host[name])
    common = (
        host["root_action"] == "direct-su"
        and host["root_command_exit"] == "0"
        and host["mutation_possible"] == "1"
        and host["kernel_mutation_observed"] == "1"
        and host["unsafe_state"] == "0"
        and host["controller_error"] == "none"
        and host["recovery_state"] == recovery["state"]
        and recovery["error"] == "none"
    )
    if not common:
        return None
    if (
        host["security_process"] != "update_engine"
        or any(
            not value
            for value in (
                host["helper_uid"], host["helper_gid"],
                host["helper_context"], host["helper_cap_eff"],
                host["root_watchdog_nonce"], host["run_id"],
            )
        )
        or re.fullmatch(r"[0-9a-f]{32}", host["root_watchdog_nonce"])
        is None
        or values["helper_pid"] <= 0
        or values["security_pid"] <= 0
        or values["security_start_time"] <= 0
        or values["root_watchdog_helper_start"] <= 0
        or values["security_target_stable"] != 1
        or values["su_command_remote_port"] != SU_COMMAND_PORT
        or values["post_clean_dwell_seconds"] != POST_CLEAN_DWELL_SECONDS
        or values["cred_quarantine_pass"] != 0
        or values["internal_write_misses"] < 0
        or host["unsafe_reason"] != "none"
        or re.fullmatch(r"[A-Za-z0-9_.:-]+", host["run_id"]) is None
    ):
        return None
    if accepted:
        if (
            values["same_boot"] != 1
            or end_boot_id != expected_boot_id
            or recovery["state"] != "not-required"
            or values["root_window_seen"] != 1
            or values["root_window_validated"] != 1
            or values["root_action_validated"] != 1
            or values["planned_reboot"] != 0
            or values["reboot_confirmed"] != 0
            or values["strict_success"] != 1
            or values["cleanup_verified"] != 1
            or values["post_clean_dwell_complete"] != 1
            or host["root_action_result"]
            != "status=pass stage=direct-su root=pass exit=0"
            or host["su_protocol_phase"] != "complete"
            or host["helper_uid"] != "0 0 0 0"
            or host["helper_gid"] != "0 0 0 0"
            or host["helper_context"] != "u:r:update_engine:s0"
            or host["helper_cap_eff"] != "000001ffffffffff"
            or values["su_forward_local_port"] <= 0
            or host["su_forward_mapping"] != (
                f"{serial} tcp:{values['su_forward_local_port']} "
                f"tcp:{SU_COMMAND_PORT}"
            )
            or values["command_watchdog_signalled"] != 1
            or values["command_watchdog_tid"] <= 0
            or profile_end != profile_start
            or proc_teardown_proof is not None
        ):
            return None
    else:
        common_miss = (
            values["root_window_seen"] != 0
            or values["root_window_validated"] != 0
            or values["root_action_validated"] != 0
            or values["strict_success"] != 0
            or values["cleanup_verified"] != 0
            or host["root_action_result"] != "none"
            or host["su_protocol_phase"] != "arm-lock-ready"
            or host["helper_uid"] != "unknown"
            or host["helper_gid"] != "unknown"
            or host["helper_context"] != "unknown"
            or host["helper_cap_eff"] != "unknown"
            or values["su_forward_local_port"] != 0
            or host["su_forward_mapping"] != "none"
            or values["command_watchdog_signalled"] != 0
            or values["command_watchdog_tid"] != 0
        )
        reboot_recovery = (
            values["same_boot"] == 0
            and BOOT_ID_PATTERN.fullmatch(end_boot_id) is not None
            and end_boot_id != start_boot_id
            and recovery["state"] == "clean-reboot-confirmed"
            and values["planned_reboot"] == 1
            and values["reboot_confirmed"] == 1
        )
        process_teardown_recovery = (
            values["same_boot"] == 1
            and end_boot_id == start_boot_id
            and recovery["state"] == "same-boot-proc-teardown-confirmed"
            and values["planned_reboot"] == 0
            and values["reboot_confirmed"] == 0
            and profile_end == profile_start
            and isinstance(proc_teardown_proof, dict)
        )
        if process_teardown_recovery:
            proof = proc_teardown_proof
            proof_token = proof.get("token")
            old_processes = proof.get("old_processes")
            new_processes = proof.get("new_processes")
            process_teardown_recovery = (
                set(proof) == {
                    "version", "token", "start_boot_id", "end_boot_id",
                    "security_pid", "security_start", "old_processes",
                    "new_processes", "helper_absent", "profile_equal",
                    "token_consumed",
                }
                and proof["version"] == 1
                and proof["start_boot_id"] == expected_boot_id
                and proof["end_boot_id"] == expected_boot_id
                and proof["security_pid"] == values["security_pid"]
                and proof["security_start"] == host["security_start_time"]
                and proof["helper_absent"] == 1
                and proof["profile_equal"] == 1
                and proof["token_consumed"] == 1
                and isinstance(proof_token, dict)
                and proof_token.get("nonce") == host["root_watchdog_nonce"]
                and proof_token.get("boot_id") == expected_boot_id
                and proof_token.get("helper_pid") == host["helper_pid"]
                and proof_token.get("helper_start")
                    == host["root_watchdog_helper_start"]
                and isinstance(old_processes, dict)
                and isinstance(new_processes, dict)
                and all(
                    old_processes.get(proof_token.get(pid_name))
                    == proof_token.get(start_name)
                    for pid_name, start_name in (
                        ("harness_pid", "harness_start"),
                        ("raw_target_pid", "raw_target_start"),
                        ("raw_client_pid", "raw_client_start"),
                    )
                )
                and not any(
                    new_processes.get(pid) == start
                    for pid, start in old_processes.items()
                )
            )
        if common_miss or not (
            reboot_recovery or process_teardown_recovery
        ):
            return None
    return {
        "boot_id": boot_id,
        "start_boot_id": start_boot_id,
        "recovery_boot_id": end_boot_id,
        "recovery_state": recovery["state"],
        "strict_success": host["strict_success"],
    }


def parse_issue_2_artifact_v1(
    path: Path,
    *,
    expected_boot_id: str,
    qualification_id: str,
    run_index: int,
    attempt_index: int,
) -> dict[str, Any] | None:
    sections = _issue_2_sections(path)
    if sections is None:
        return None
    names = _issue_2_progress(sections["progress"])
    if names is None:
        return None
    result = sections["result"]
    root = _issue_2_root_chain(result)
    if root is None:
        return None
    prepare_text = root["prepare"]
    first_text = root["first"]
    prepare = _issue_2_validate_prepare(_issue_2_record(
        prepare_text, ISSUE_2_RESULT_PREPARE_FIELDS
    ))
    metadata = _issue_2_validate_metadata(
        sections,
        expected_boot_id=expected_boot_id,
        qualification_id=qualification_id,
        run_index=run_index,
        attempt_index=attempt_index,
        accepted=False,
    )
    if prepare is None or metadata is None:
        return None
    return {
        "sections": sections,
        "progress": names,
        "result": result,
        "root": root,
        "prepare": prepare,
        "first": first_text,
        "metadata": metadata,
    }


def classify_issue_2_artifact_v1(
    path: Path,
    *,
    expected_boot_id: str,
    qualification_id: str,
    run_index: int,
    attempt_index: int,
) -> dict[str, Any] | None:
    parsed = parse_issue_2_artifact_v1(
        path,
        expected_boot_id=expected_boot_id,
        qualification_id=qualification_id,
        run_index=run_index,
        attempt_index=attempt_index,
    )
    if parsed is None:
        return None
    result = parsed["result"]
    root = parsed["root"]
    prepare = parsed["prepare"]
    names = parsed["progress"]
    first = parsed["first"]
    observation_span = _issue_2_bracket_span(first, "observation")
    observation_text = None
    initial_wrapper = False
    process_teardown_wrapper = False
    if observation_span is not None:
        observation_start, observation_end = observation_span
        wrapper_prefix = first[:observation_start]
        process_teardown_wrapper = wrapper_prefix == (
            "status=miss stage=unlink-observe safe_no_free=0 "
            "teardown_required=1 teardown_signal=pass "
        )
        initial_wrapper = (
            wrapper_prefix in {
                "status=miss stage=unlink-observe safe_no_free=0 ",
                "status=miss stage=unlink-observe safe_no_free=0 "
                "teardown_required=1 teardown_signal=pass ",
            }
            and first[observation_end:] == ""
        )
        if initial_wrapper:
            observation_text = first[
                observation_start + len("observation=["):
                observation_end - 1
            ]
    if initial_wrapper and observation_text is not None:
        observation = _issue_2_validate_observation(
            _issue_2_record(observation_text, ISSUE_2_OBSERVATION_FIELDS),
            prepare,
        )
        if (
            root["status"] == "miss"
            and root["node_status"] == "miss"
            and root["node_prefix"] == "status=miss stage=root-unlink"
            and not root["node_tail"]
            and observation is not None
            and (
                not process_teardown_wrapper
                or (
                    observation["ptr"] == prepare["raw_pointer"]
                    and observation["cookie"] == prepare["raw_cookie"]
                )
            )
            and "arbitrary-read-start" in names
            and names[names.index("arbitrary-read-start"):]
            == (
                [
                    "arbitrary-read-start",
                    "isolated-retirement-proof-pass",
                    "arbitrary-read-reclaim-armed",
                    "arbitrary-read-prepared",
                    PROC_TEARDOWN_MARKER,
                ]
                if process_teardown_wrapper
                else [
                    "arbitrary-read-start",
                    "isolated-retirement-proof-pass",
                    "arbitrary-read-reclaim-armed",
                    "arbitrary-read-prepared",
                    "arbitrary-read-failed",
                ]
            )
            and not any(
                marker.startswith(("private-", "root-write-", "root-mutation",
                                   "root-window-"))
                for marker in names
            )
            and not any(
                marker.startswith((
                    "arbitrary-read-free-",
                    "arbitrary-read-handoff",
                    "arbitrary-read-retained",
                    "arbitrary-read-safe-to-active",
                    "handoff",
                    "root-window-",
                ))
                for marker in names
            )
        ):
            return {"kind": "initial-unlink-observe", **parsed}
    complete = _issue_2_validate_complete(
        _issue_2_record(first, ISSUE_2_RESULT_COMPLETE_FIELDS),
        replacement_miss=True,
    )
    if (
        root["status"] == "miss"
        and root["node_status"] == "miss"
        and root["node_prefix"] == "status=miss stage=root-unlink"
        and not root["node_tail"]
        and complete is not None
        and "arbitrary-read-start" in names
        and names[names.index("arbitrary-read-start"):]
        == [
            "arbitrary-read-start",
            "isolated-retirement-proof-pass",
            "arbitrary-read-reclaim-armed",
            "arbitrary-read-prepared",
            "arbitrary-read-free-start",
            "arbitrary-read-safe-to-active",
            "arbitrary-read-retained",
            "arbitrary-read-free-pass",
            "root-window-reboot-required",
            "arbitrary-read-failed",
        ]
        and not any(
            marker.startswith(("private-", "root-write-", "root-mutation"))
            for marker in names
        )
        and not any(
            marker.startswith("root-window-")
            and marker != "root-window-reboot-required"
            for marker in names
        )
        and names.count("root-window-reboot-required") == 1
        and names.index("root-window-reboot-required") == (
            names.index("arbitrary-read-start") + 8
        )
    ):
        return {"kind": "replacement-arb-read-complete", **parsed}
    return None


def validate_issue_2_accepted_artifact_v2(
    path: Path,
    *,
    expected_boot_id: str,
    qualification_id: str,
    run_index: int,
    attempt_index: int,
) -> dict[str, Any] | None:
    sections = _issue_2_sections(path)
    if sections is None:
        return None
    metadata = _issue_2_validate_metadata(
        sections,
        expected_boot_id=expected_boot_id,
        qualification_id=qualification_id,
        run_index=run_index,
        attempt_index=attempt_index,
        accepted=True,
    )
    names = _issue_2_progress(sections["progress"])
    if metadata is None or names is None:
        return None

    result = sections["result"]
    node_span = _issue_2_bracket_span(result, "node")
    if (
        node_span is None
        or not result.startswith("status=pass stage=root-chain ")
        or node_span[0] == 0
        or result[node_span[0] - 1] != " "
        or result[node_span[1]:]
    ):
        return None
    node = result[node_span[0] + len("node=["):node_span[1] - 1]
    if not node.startswith("status=pass stage=root-unlink "):
        return None
    prepare_text = _issue_2_bracket(node, "prepare")
    complete_text = _issue_2_bracket(node, "first")
    prepare = _issue_2_validate_prepare(_issue_2_record(
        prepare_text or "", ISSUE_2_RESULT_PREPARE_FIELDS
    ))
    complete = _issue_2_validate_complete(
        _issue_2_record(
            complete_text or "", ISSUE_2_RESULT_COMPLETE_FIELDS
        ),
        replacement_miss=False,
    )
    if prepare is None or complete is None:
        return None

    required_order = (
        "root-flow-start",
        "device-gate-pass",
        "arbitrary-read-start",
        "isolated-retirement-proof-pass",
        "arbitrary-read-reclaim-armed",
        "arbitrary-read-prepared",
        "arbitrary-read-free-start",
        "arbitrary-read-safe-to-active",
        "arbitrary-read-retained",
        "arbitrary-read-free-pass",
        "arbitrary-read-pass",
        "private-credential-request-ready",
        "private-credential-signal-pass",
        "private-credential-pass",
        "current-proc-pass",
        "helper-target-pass",
        "direct-security-target-pass",
        "root-mutation-start",
        "root-window-ready",
        "root-window-action-pass",
        "ctlbuf-donor-freeze-ready",
        "ctlbuf-donor-freeze-pass",
        "ctlbuf-rescue-plan-ready",
        "helper-normalisation-arm-ready",
        "helper-retirement-arm-ready",
        "terminal-donor-retirement-proof-start",
        "terminal-donor-retirement-proof-pass",
        "terminal-java-retirement-start",
        "terminal-raw-target-retired",
        "terminal-owner-retired",
        "terminal-process-identities-retired",
        "terminal-process-retirement-settled",
        "terminal-java-retirement-pass",
        "native-terminal-cleanup-start",
        "terminal-cleanup-pass",
    )
    unique_markers = (
        "arbitrary-read-free-start",
        "arbitrary-read-safe-to-active",
        "arbitrary-read-retained",
        "arbitrary-read-free-pass",
        "arbitrary-read-pass",
        "root-window-ready",
        "root-window-action-pass",
        "terminal-cleanup-pass",
    )
    forbidden_markers = {
        "arbitrary-read-failed",
        "arbitrary-read-handoff-failed",
        "root-window-reboot-required",
        "root-write-incomplete",
        "terminal-cleanup-failed",
    }
    if (
        not _issue_2_has_order(names, required_order)
        or any(names.count(marker) != 1 for marker in unique_markers)
        or forbidden_markers.intersection(names)
    ):
        return None

    host = _issue_2_pairs(sections["host"])
    if host is None:
        return None
    command_pattern = re.compile(
        r"LP3_SU_IDENTITY status=pass stage=command-root-watchdog "
        rf"pid={re.escape(host['helper_pid'])} tid=[1-9][0-9]* "
        r"uid=0,0,0 gid=0,0,0 fsuid=0 fsgid=0 "
        r"cap_eff=000001ffffffffff"
    )
    if command_pattern.fullmatch(sections["command output"].strip()) is None:
        return None
    helper_log = sections["helper log"]
    if (
        " private_credential=0 private_credential_errno=0 "
        not in helper_log
        or "BRIDGE_COMMAND_NORMALISED " not in helper_log
        or "uid_result=0 gid_result=0 shell=1 ctlbuf_repaired=1"
        not in helper_log
    ):
        return None
    return {
        "metadata": metadata,
        "prepare": prepare,
        "complete": complete,
        "progress": names,
    }

def command(
    arguments: list[str],
    *,
    check: bool = True,
    timeout: float | None = None,
) -> str:
    try:
        result = subprocess.run(
            arguments,
            cwd=ROOT,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exception:
        raise ControllerError(
            f"command timed out: {' '.join(arguments)}"
        ) from exception
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise ControllerError(
            f"command failed ({result.returncode}): {' '.join(arguments)}"
            + (f"\n{detail}" if detail else "")
        )
    return result.stdout.strip()


def adb(
    serial: str,
    *arguments: str,
    check: bool = True,
    timeout: float = 120,
) -> str:
    return command(
        ["adb", "-s", serial, *arguments],
        check=check,
        timeout=timeout,
    )


def process_start_time(serial: str, pid: str) -> str:
    value = adb(
        serial,
        "exec-out",
        "cat",
        f"/proc/{pid}/stat",
        check=False,
    )
    close = value.rfind(")")
    if close < 0:
        return ""
    fields = value[close + 1:].split()
    return fields[19] if len(fields) > 19 and fields[19].isdigit() else ""


def stop_su_arm_holder(
    serial: str,
    holder_pid: int,
    sleep_seconds: int,
) -> bool:
    if holder_pid <= 0:
        return True
    command_line = adb(
        serial,
        "exec-out",
        "cat",
        f"/proc/{holder_pid}/cmdline",
        check=False,
        timeout=15,
    ).replace("\x00", " ").strip()
    fields = command_line.split()
    if (
        len(fields) != 2
        or Path(fields[0]).name != "sleep"
        or fields[1] != str(sleep_seconds)
    ):
        return False
    adb(
        serial,
        "shell",
        "kill",
        str(holder_pid),
        check=False,
        timeout=15,
    )
    return True


def cleanup_su_setup(
    serial: str,
    holder_pid: int,
    holder_seconds: int,
    forward_port: int,
    *,
    kill_bridge: bool,
) -> None:
    try:
        stop_su_arm_holder(serial, holder_pid, holder_seconds)
    except BaseException:
        pass
    if kill_bridge:
        try:
            adb(
                serial,
                "shell",
                "pkill",
                "-f",
                HELPER_CLASS,
                check=False,
                timeout=15,
            )
        except BaseException:
            pass
    if forward_port:
        try:
            adb(
                serial,
                "forward",
                "--remove",
                f"tcp:{forward_port}",
                check=False,
                timeout=15,
            )
        except BaseException:
            pass
    try:
        adb(
            serial,
            "shell",
            "rm",
            "-f",
            SU_TOKEN_PATH,
            SU_ARM_PATH,
            ROOT_WATCHDOG_ARM_PATH,
            NORMALISE_WAITING_PATH,
            check=False,
            timeout=15,
        )
    except BaseException:
        pass


def load_profile() -> dict[str, Any]:
    root = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    profiles = root.get("profiles", [])
    if len(profiles) != 1:
        raise ControllerError("the profile file must contain one target")
    return profiles[0]


def select_serial(requested: str | None) -> str:
    if requested:
        if adb(requested, "get-state") != "device":
            raise ControllerError(f"device {requested} is not ready")
        return requested
    lines = command(["adb", "devices"]).splitlines()[1:]
    devices = [line.split()[0] for line in lines if line.endswith("\tdevice")]
    if len(devices) != 1:
        raise ControllerError("connect one device or use --serial")
    return devices[0]


def properties(serial: str, names: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    requested = set(names)
    for line in adb(serial, "shell", "getprop").splitlines():
        name, separator, value = line[1:].partition("]: [")
        if separator and name in requested and value.endswith("]"):
            values[name] = value[:-1]
    return values


def expected_properties(profile: dict[str, Any]) -> dict[str, str]:
    product = profile["product"]
    system = profile["system"]
    boot = profile["required_boot_state"]
    return {
        "ro.product.device": product["device"],
        "ro.product.model": product["model"],
        "ro.product.manufacturer": product["manufacturer"],
        "ro.product.board": product["board"],
        "ro.board.platform": product["platform"],
        "ro.hardware": product["hardware"],
        "ro.soc.model": product["soc_model"],
        "ro.soc.manufacturer": product["soc_manufacturer"],
        "ro.build.display.id": system["display_id"],
        "ro.build.id": system["build_id"],
        "ro.build.version.incremental": system["incremental"],
        "ro.build.version.release": system["release"],
        "ro.build.version.sdk": str(system["sdk"]),
        "ro.build.version.security_patch": system["security_patch"],
        "ro.build.fingerprint": system["fingerprint"],
        "ro.boot.verifiedbootstate": boot["verified_boot"],
        "ro.boot.flash.locked": "1" if boot["flash_locked"] else "0",
        "ro.boot.vbmeta.device_state": "locked",
        "ro.virtual_ab.enabled": str(boot["virtual_ab"]).lower(),
        "ro.boot.dynamic_partitions": str(boot["dynamic_partitions"]).lower(),
    }


def device_profile_snapshot(
    serial: str,
    profile: dict[str, Any],
) -> dict[str, Any]:
    expected = expected_properties(profile)
    return {
        "serial": serial,
        "profile": profile,
        "expected_properties": expected,
        "observed_properties": properties(serial, list(expected)),
        "kernel_release": adb(serial, "shell", "uname", "-r"),
        "page_size": adb(serial, "shell", "getconf", "PAGESIZE"),
    }


def verify(serial: str, profile: dict[str, Any]) -> None:
    kernel = profile["kernel"]
    expected = expected_properties(profile)
    actual = properties(serial, list(expected))
    mismatches = [
        name for name, value in expected.items() if actual.get(name) != value
    ]
    kernel_release = adb(serial, "shell", "uname", "-r")
    if kernel_release != kernel["release"]:
        mismatches.append("kernel.release")
    page_size = adb(serial, "shell", "getconf", "PAGESIZE")
    if page_size != str(kernel["page_size"]):
        mismatches.append("kernel.page_size")
    if mismatches:
        raise ControllerError("unsupported device: " + ", ".join(mismatches))


def write_private_control_file(
    serial: str,
    name: str,
    value: str,
) -> None:
    if re.fullmatch(r"[a-z0-9.-]+", name) is None or "\n" in value:
        raise ControllerError("invalid private control-file value")
    final_path = "files/" + name
    temporary_path = "files/." + name + ".tmp"
    script = " && ".join([
        "umask 077",
        "rm -f " + shlex.quote(temporary_path),
        (
            "printf '%s\\n' " + shlex.quote(value) + " > "
            + shlex.quote(temporary_path)
        ),
        "sync " + shlex.quote(temporary_path),
        (
            "mv -f " + shlex.quote(temporary_path) + " "
            + shlex.quote(final_path)
        ),
        "sync files",
    ])
    adb(
        serial,
        "shell",
        "run-as " + shlex.quote(PACKAGE) + " sh -c " + shlex.quote(script),
    )


def read_health_evidence(serial: str) -> dict[str, Any]:
    jobs = adb(serial, "shell", "dumpsys", "jobscheduler")
    job_match = re.search(r"^Registered (\d+) jobs:$", jobs, re.MULTILINE)
    thermal = adb(serial, "shell", "dumpsys", "thermalservice")
    thermal_status = re.search(
        r"^Thermal Status: (\d+)$", thermal, re.MULTILINE
    )
    battery = re.search(
        r"mValue=([0-9.]+), mType=2, mName=battery", thermal
    )
    cpu_values = [
        float(value)
        for value in re.findall(
            r"mValue=([0-9.]+), mType=0, mName=CPU\d+", thermal
        )
    ]
    return {
        "registered_jobs": (
            int(job_match.group(1)) if job_match is not None else None
        ),
        "thermal_status": (
            int(thermal_status.group(1))
            if thermal_status is not None
            else None
        ),
        "battery_c": (
            float(battery.group(1)) if battery is not None else None
        ),
        "cpu_max_c": max(cpu_values) if cpu_values else None,
        "jobscheduler": jobs,
        "thermalservice": thermal,
    }


def health_summary(evidence: dict[str, Any]) -> str:
    return json.dumps(
        {
            key: evidence[key]
            for key in (
                "registered_jobs",
                "thermal_status",
                "battery_c",
                "cpu_max_c",
            )
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def health_is_normal(evidence: dict[str, Any]) -> bool:
    jobs = evidence["registered_jobs"]
    status = evidence["thermal_status"]
    battery = evidence["battery_c"]
    cpu = evidence["cpu_max_c"]
    return (
        isinstance(jobs, int)
        and jobs < 1000
        and status == 0
        and isinstance(battery, float)
        and battery < 42
        and isinstance(cpu, float)
        and cpu < 65
    )


def verify_terminal_cleanup_kernel_config(
    serial: str,
    profile: dict[str, Any],
) -> None:
    config = adb(
        serial,
        "exec-out",
        "sh",
        "-c",
        "zcat /proc/config.gz",
        check=False,
    )
    lines = set(config.splitlines())
    if "# CONFIG_DEBUG_CREDENTIALS is not set" not in lines:
        raise ControllerError(
            "terminal cleanup needs CONFIG_DEBUG_CREDENTIALS disabled"
        )
    if not {"CONFIG_KEYS=y", "CONFIG_SECURITY=y"}.issubset(lines):
        raise ControllerError(
            "terminal cleanup needs CONFIG_KEYS and CONFIG_SECURITY"
        )
    enabled_randstruct = {
        line
        for line in lines
        if re.fullmatch(
            r"CONFIG_[A-Z0-9_]*RANDSTRUCT[A-Z0-9_]*=(?:y|m)", line
        )
    }
    if not config.startswith("#") or enabled_randstruct:
        raise ControllerError(
            "terminal cleanup needs an exact non-randomised kernel layout"
        )
    expected_layout = {
        "task_real_cred_offset": "0x778",
        "task_cred_offset": "0x780",
        "cred_security_offset": "0x78",
        "cred_user_offset": "0x80",
        "cred_user_ns_offset": "0x88",
        "cred_group_info_offset": "0x90",
        "cred_rcu_offset": "0x98",
        "debug_credentials": False,
        "randstruct": False,
        "ucounts_present": False,
        "shell_securebits": 47,
    }
    if profile["kernel"].get("credential_layout") != expected_layout:
        raise ControllerError(
            "terminal cleanup credential layout profile is not exact"
        )


def probe(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    print(
        f"PASS {profile['id']} serial={serial} "
        f"firmware={profile['system']['display_id']} "
        f"kernel={profile['kernel']['release']}"
    )


def build() -> None:
    command([str(ROOT / "gradlew"), "assembleDebug", "--console=plain"])
    if not APK_PATH.is_file():
        raise ControllerError("Gradle did not create the APK")
    print(f"PASS built {APK_PATH}")


def install(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    if not APK_PATH.is_file():
        build()
    output = adb(serial, "install", "-r", str(APK_PATH))
    if "Success" not in output:
        raise ControllerError("ADB did not confirm the install")
    adb(serial, "shell", "sync")
    print(f"PASS installed {PACKAGE} on {serial}")


def clean_reboot(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    boot_id = adb(serial, "shell", "cat", "/proc/sys/kernel/random/boot_id")
    if re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
        r"[0-9a-f]{4}-[0-9a-f]{12}",
        boot_id,
    ) is None:
        raise ControllerError("the initial boot ID is invalid")
    adb(serial, "reboot")
    wait_for_android(serial, previous_boot_id=boot_id)
    verify(serial, profile)
    print(f"PASS clean reboot completed on {serial}")


def wait_for_android(
    serial: str,
    timeout: int = 240,
    previous_boot_id: str | None = None,
) -> None:
    deadline = time.monotonic() + timeout
    attempt = 0
    while time.monotonic() < deadline:
        if attempt % 5 == 0:
            adb(
                serial,
                "shell",
                "input",
                "keyevent",
                "KEYCODE_WAKEUP",
                check=False,
            )
            adb(
                serial,
                "shell",
                "wm",
                "dismiss-keyguard",
                check=False,
            )
        completed = adb(
            serial,
            "shell",
            "getprop",
            "sys.boot_completed",
            check=False,
        )
        package_path = adb(
            serial,
            "shell",
            "pm",
            "path",
            PACKAGE,
            check=False,
        )
        current_boot_id = adb(
            serial,
            "shell",
            "cat",
            "/proc/sys/kernel/random/boot_id",
            check=False,
        )
        valid_boot_id = re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}",
            current_boot_id,
        ) is not None
        changed_boot = valid_boot_id and (
            previous_boot_id is None or current_boot_id != previous_boot_id
        )
        if (
            changed_boot
            and completed == "1"
            and package_path.startswith("package:")
        ):
            adb(
                serial,
                "shell",
                "input",
                "keyevent",
                "KEYCODE_SLEEP",
                check=False,
            )
            return
        attempt += 1
        time.sleep(2)
    raise ControllerError("Android did not finish booting with the app installed")


def status(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    package_path = adb(serial, "shell", "pm", "path", PACKAGE, check=False)
    result = adb(
        serial,
        "exec-out",
        "run-as",
        PACKAGE,
        "cat",
        "files/direct.result",
        check=False,
    )
    print("installed=" + ("yes" if package_path.startswith("package:") else "no"))
    if not result:
        print("result=none")
    else:
        first = result.splitlines()[0]
        state = "pass" if first.startswith("status=pass") else "not-pass"
        stage = "unknown"
        marker = "stage="
        if marker in first:
            stage = first.split(marker, 1)[1].split(None, 1)[0]
        print(f"result={state} stage={stage} bytes={len(result.encode())}")


def app_preflight(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    package_path = adb(serial, "shell", "pm", "path", PACKAGE, check=False)
    if not package_path.startswith("package:"):
        raise ControllerError("install the app before app-preflight")
    adb(
        serial,
        "shell",
        "run-as",
        PACKAGE,
        "rm",
        "-f",
        "files/direct.result",
    )
    adb(
        serial,
        "shell",
        "am",
        "start-foreground-service",
        "--user",
        "0",
        "-n",
        f"{PACKAGE}/.HarnessService",
        "--es",
        "stage",
        "preflight",
    )
    result = ""
    for _ in range(50):
        result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/direct.result",
            check=False,
        )
        if result.startswith("status="):
            break
        time.sleep(0.1)
    if not result.startswith("status=pass stage=device-gate"):
        raise ControllerError("app preflight failed: " + (result or "no result"))
    print("PASS " + result.strip())


def package_pids(serial: str) -> list[int]:
    processes = adb(serial, "shell", "ps", "-A", "-o", "PID,NAME")
    pids: list[int] = []
    for line in processes.splitlines()[1:]:
        fields = line.split(None, 1)
        if len(fields) != 2 or not fields[0].isdigit():
            continue
        if fields[1] == PACKAGE or fields[1].startswith(PACKAGE + ":"):
            pids.append(int(fields[0]))
    return pids


def package_process_identities(serial: str) -> dict[int, str]:
    identities: dict[int, str] = {}
    for pid in package_pids(serial):
        start_time = process_start_time(serial, str(pid))
        if not start_time:
            raise ControllerError(
                f"package process identity is unavailable: pid={pid}"
            )
        identities[pid] = start_time
    return identities


def parse_proc_teardown_token(value: str) -> dict[str, str] | None:
    fields: dict[str, str] = {}
    for token in value.split():
        if token.count("=") != 1:
            return None
        name, field_value = token.split("=", 1)
        if (
            re.fullmatch(r"[a-z][a-z0-9_]*", name) is None
            or not field_value
            or name in fields
        ):
            return None
        fields[name] = field_value
    expected = {
        "version", "reason", "nonce", "boot_id", "helper_pid",
        "helper_start", "harness_pid", "harness_start",
        "raw_target_pid", "raw_target_start", "raw_client_pid",
        "raw_client_start",
    }
    return fields if set(fields) == expected else None


def recover_stale_proc_teardown(
    serial: str,
    profile: dict[str, Any],
    boot_id: str,
) -> str:
    token_script = (
        "if test -f files/proc-teardown.token; then "
        "cat files/proc-teardown.token; else echo absent; fi"
    )
    token_text = adb(
        serial,
        "shell",
        "run-as " + shlex.quote(PACKAGE) + " sh -c "
        + shlex.quote(token_script),
        check=False,
    ).strip()
    if token_text == "absent":
        return boot_id
    token = parse_proc_teardown_token(token_text)
    if token is not None and token["boot_id"] != boot_id:
        return boot_id
    print("RECOVER stale process-teardown token requires a clean reboot")
    clean_reboot(serial, profile)
    recovered_boot_id = adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    )
    if recovered_boot_id == boot_id:
        raise ControllerError("stale process teardown recovery did not reboot")
    return recovered_boot_id


def validate_proc_teardown_request(
    result: str,
    progress: str,
    token_text: str,
    *,
    boot_id: str,
    bridge_nonce: str,
    helper_pid: int,
    helper_start_time: str,
) -> dict[str, str] | None:
    token = parse_proc_teardown_token(token_text)
    if token is None or token != {
        **token,
        "version": "1",
        "reason": "initial-acquisition-miss",
        "nonce": bridge_nonce,
        "boot_id": boot_id,
        "helper_pid": str(helper_pid),
        "helper_start": helper_start_time,
    }:
        return None
    identity_fields = (
        "harness_pid", "harness_start", "raw_target_pid",
        "raw_target_start", "raw_client_pid", "raw_client_start",
    )
    if any(re.fullmatch(r"[1-9][0-9]*", token[name]) is None
           for name in identity_fields):
        return None
    root = _issue_2_root_chain(result)
    if root is None:
        return None
    prepare = _issue_2_validate_prepare(_issue_2_record(
        root["prepare"], ISSUE_2_RESULT_PREPARE_FIELDS
    ))
    first = root["first"]
    prefix = (
        "status=miss stage=unlink-observe safe_no_free=0 "
        "teardown_required=1 teardown_signal=pass "
    )
    observation_span = _issue_2_bracket_span(first, "observation")
    if (
        root["status"] != "miss"
        or root["node_status"] != "miss"
        or root["node_prefix"] != "status=miss stage=root-unlink"
        or root["node_tail"]
        or prepare is None
        or observation_span is None
        or first[:observation_span[0]] != prefix
        or first[observation_span[1]:]
    ):
        return None
    observation = _issue_2_validate_observation(_issue_2_record(
        first[
            observation_span[0] + len("observation=["):
            observation_span[1] - 1
        ],
        ISSUE_2_OBSERVATION_FIELDS,
    ), prepare)
    if (
        observation is None
        or observation["ptr"] != prepare["raw_pointer"]
        or observation["cookie"] != prepare["raw_cookie"]
    ):
        return None
    names = _issue_2_progress(progress)
    expected_tail = [
        "arbitrary-read-start",
        "isolated-retirement-proof-pass",
        "arbitrary-read-reclaim-armed",
        "arbitrary-read-prepared",
        PROC_TEARDOWN_MARKER,
    ]
    if (
        names is None
        or "arbitrary-read-start" not in names
        or names[names.index("arbitrary-read-start"):] != expected_tail
        or any(marker.startswith((
            "arbitrary-read-free-", "arbitrary-read-handoff",
            "arbitrary-read-retained", "root-mutation", "root-write-",
            "root-window-",
        )) for marker in names)
    ):
        return None
    return token


def same_boot_process_teardown_reset(
    serial: str,
    profile: dict[str, Any],
    *,
    result: str,
    progress: str,
    token_text: str,
    boot_id: str,
    bridge_nonce: str,
    helper_pid: int,
    helper_start_time: str,
    helper_command_line: str,
    holder_pid: int,
    holder_seconds: int,
    security_process: str,
    security_pid: str,
    security_start_time: str,
    profile_start: dict[str, Any],
) -> dict[str, Any]:
    verify(serial, profile)
    token = validate_proc_teardown_request(
        result,
        progress,
        token_text,
        boot_id=boot_id,
        bridge_nonce=bridge_nonce,
        helper_pid=helper_pid,
        helper_start_time=helper_start_time,
    )
    if token is None:
        raise ControllerError("process teardown proof is invalid")
    current_boot_id = adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    )
    if current_boot_id != boot_id:
        raise ControllerError("the boot changed before process teardown")
    identities = package_process_identities(serial)
    time.sleep(0.1)
    if package_process_identities(serial) != identities:
        raise ControllerError("package process identities are not stable")
    required_identities = {
        int(token["harness_pid"]): token["harness_start"],
        int(token["raw_target_pid"]): token["raw_target_start"],
        int(token["raw_client_pid"]): token["raw_client_start"],
    }
    if (
        len(required_identities) != 3
        or any(identities.get(pid) != start
               for pid, start in required_identities.items())
    ):
        raise ControllerError("the teardown token process binding is invalid")
    current_helper_start = process_start_time(serial, str(helper_pid))
    current_helper_command = adb(
        serial,
        "exec-out",
        "cat",
        f"/proc/{helper_pid}/cmdline",
        check=False,
    ).replace("\x00", " ").strip()
    if (
        current_helper_start != helper_start_time
        or current_helper_command != helper_command_line
        or HELPER_CLASS not in current_helper_command
    ):
        raise ControllerError("the teardown helper identity is invalid")
    free_script = (
        "if test \"$(cat files/controlled-free.enable.0 2>/dev/null)\" "
        "= 0 && ! test -e files/controlled-free.result.0; then "
        "echo armed-zero; else echo invalid; fi"
    )
    free_state = adb(
        serial,
        "shell",
        "run-as " + shlex.quote(PACKAGE) + " sh -c "
        + shlex.quote(free_script),
        check=False,
    )
    if free_state != "armed-zero":
        raise ControllerError("the controlled free gate is not safely armed")
    if not stop_su_arm_holder(serial, holder_pid, holder_seconds):
        raise ControllerError("the command arm holder identity changed")
    adb(serial, "shell", "am", "force-stop", "--user", "0", PACKAGE)
    deadline = time.monotonic() + 20
    empty_samples = 0
    while time.monotonic() < deadline:
        current = package_process_identities(serial)
        old_live = any(
            current.get(pid) == start for pid, start in identities.items()
        )
        if not current and not old_live:
            empty_samples += 1
            if empty_samples == 2:
                break
        else:
            empty_samples = 0
        time.sleep(0.2)
    if empty_samples != 2:
        raise ControllerError("package process teardown did not complete")
    adb(serial, "shell", "kill", str(helper_pid), check=False)
    helper_deadline = time.monotonic() + 10
    while (
        time.monotonic() < helper_deadline
        and process_start_time(serial, str(helper_pid)) == helper_start_time
    ):
        time.sleep(0.05)
    if process_start_time(serial, str(helper_pid)) == helper_start_time:
        raise ControllerError("the shell helper did not stop")
    cleanup_su_setup(
        serial, 0, holder_seconds, 0, kill_bridge=False
    )
    time.sleep(3)
    if adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    ) != boot_id:
        raise ControllerError("the device restarted during process teardown")
    if (
        adb(serial, "shell", "pidof", security_process, check=False).split()
        != [security_pid]
        or process_start_time(serial, security_pid) != security_start_time
    ):
        raise ControllerError("the credential donor changed during teardown")
    verify(serial, profile)
    if device_profile_snapshot(serial, profile) != profile_start:
        raise ControllerError("the device profile changed during teardown")
    app_preflight(serial, profile)
    new_identities = package_process_identities(serial)
    if any(
        new_identities.get(pid) == start for pid, start in identities.items()
    ):
        raise ControllerError("an old package process survived preflight")
    final_boot_id = adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    )
    final_security_pids = adb(
        serial, "shell", "pidof", security_process, check=False
    ).split()
    final_security_start = process_start_time(serial, security_pid)
    final_helper_start = process_start_time(serial, str(helper_pid))
    final_helper_processes = adb(
        serial, "shell", "ps", "-A", "-o", "PID,ARGS", check=False
    )
    final_profile = device_profile_snapshot(serial, profile)
    if (
        final_boot_id != boot_id
        or final_security_pids != [security_pid]
        or final_security_start != security_start_time
        or final_helper_start
        or HELPER_CLASS in final_helper_processes
        or final_profile != profile_start
    ):
        raise ControllerError("post-preflight teardown proof failed")
    token_cleanup_script = (
        "rm -f files/proc-teardown.token && "
        "if test -e files/proc-teardown.token; then echo present; "
        "else echo absent; fi"
    )
    token_state = adb(
        serial,
        "shell",
        "run-as " + shlex.quote(PACKAGE) + " sh -c "
        + shlex.quote(token_cleanup_script),
        check=False,
    )
    if token_state != "absent":
        raise ControllerError("the verified process teardown token remained")
    adb(serial, "shell", "input", "keyevent", "KEYCODE_SLEEP", check=False)
    return {
        "version": 1,
        "token": token,
        "start_boot_id": boot_id,
        "end_boot_id": final_boot_id,
        "security_pid": int(security_pid),
        "security_start": security_start_time,
        "old_processes": {
            str(pid): start for pid, start in sorted(identities.items())
        },
        "new_processes": {
            str(pid): start for pid, start in sorted(new_identities.items())
        },
        "helper_absent": 1,
        "profile_equal": 1,
        "token_consumed": 1,
    }


def safe_retry_marker(serial: str) -> str:
    progress = adb(
        serial,
        "exec-out",
        "run-as",
        PACKAGE,
        "cat",
        "files/chain.progress",
        check=False,
    )
    lines = progress.splitlines()
    last_marker = (
        lines[-1].split(None, 1)[1]
        if lines and " " in lines[-1]
        else ""
    )
    if last_marker not in SAFE_FAST_RESET_MARKERS | SAFE_CLEAN_REBOOT_MARKERS:
        raise ControllerError(
            "fast reset refused after unsafe or unknown marker: "
            + (last_marker or "missing")
        )
    if last_marker in SAFE_CLEAN_REBOOT_MARKERS:
        result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/direct.result",
            check=False,
        )
        observed_markers = {
            line.split(None, 1)[1]
            for line in lines
            if " " in line
        }
        safe_result = (
            result.startswith("status=miss stage=root-chain")
            and "stage=direct-security-target" in result
            and " root-mutation-start" not in progress
            and "root-mutation-start" not in observed_markers
        )
        if not safe_result:
            raise ControllerError(
                "clean reboot retry refused because the pre-write proof "
                "is incomplete"
            )
    elif last_marker in {
        SAFE_NODE_ANALYSIS_MISS_MARKER,
        SAFE_EXACT_MISS_MARKER,
    }:
        result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/direct.result",
            check=False,
        )
        observed_markers = {
            line.split(None, 1)[1]
            for line in lines
            if " " in line
        }
        if last_marker == SAFE_NODE_ANALYSIS_MISS_MARKER:
            unsafe_progress = {
                "arbitrary-read-start",
                "arbitrary-read-prepared",
                "arbitrary-read-prepare-failed",
                "arbitrary-read-rearmed",
                "arbitrary-read-rearm-failed",
                "arbitrary-read-free-start",
                "arbitrary-read-free-pass",
                "arbitrary-read-pass",
            }
            safe_result = (
                result.startswith((
                    "status=miss stage=primitive-probe",
                    "status=miss stage=root-chain",
                ))
                and "analysis=[status=miss stage=binder-ref-leak" in result
            )
        else:
            unsafe_progress = {
                "arbitrary-read-rearmed",
                "arbitrary-read-rearm-failed",
                "arbitrary-read-free-start",
                "arbitrary-read-free-pass",
                "arbitrary-read-pass",
            }
            safe_result = (
                result.startswith((
                    "status=miss stage=primitive-probe",
                    "status=miss stage=root-chain",
                ))
                and "stage=unlink-observe safe_no_free=1" in result
                and "exact_payload=0" in result
                and "buffer_freed=0" in result
            )
        if not safe_result or observed_markers & unsafe_progress:
            raise ControllerError(
                "fast reset refused because the no-free proof is incomplete"
            )
    return last_marker


def fast_reset(serial: str, profile: dict[str, Any]) -> None:
    verify(serial, profile)
    boot_id = adb(serial, "shell", "cat", "/proc/sys/kernel/random/boot_id")
    last_marker = safe_retry_marker(serial)

    adb(serial, "shell", "am", "force-stop", "--user", "0", PACKAGE)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and package_pids(serial):
        time.sleep(0.2)
    remaining = package_pids(serial)
    if remaining:
        raise ControllerError("package processes did not stop: " + str(remaining))

    time.sleep(3)
    current_boot_id = adb(
        serial,
        "shell",
        "cat",
        "/proc/sys/kernel/random/boot_id",
    )
    if current_boot_id != boot_id:
        raise ControllerError("the device restarted during fast reset")
    app_preflight(serial, profile)
    adb(serial, "shell", "input", "keyevent", "KEYCODE_SLEEP", check=False)
    print(f"PASS fast reset completed after {last_marker}")


def pull_job_store_backups(
    serial: str,
    boot_id: str,
    result: str,
) -> Path:
    fields = {
        field.split("=", 1)[0]: field.split("=", 1)[1]
        for field in result.split()
        if "=" in field
    }
    download_dir = Path.home() / "Downloads"
    destination = download_dir / f"light-side-jobstore-backup-{boot_id}"
    if destination.exists():
        raise ControllerError(f"refusing to replace {destination}")
    temporary = Path(tempfile.mkdtemp(
        prefix=".light-side-jobstore-backup-",
        dir=download_dir,
    ))
    copied = 0
    for name, remote in JOB_STORE_BACKUPS.items():
        description = fields.get(name)
        if description == "missing":
            continue
        if description is None or ":" not in description:
            raise ControllerError(f"missing backup metadata for {name}")
        size_text, expected_digest = description.split(":", 1)
        if not size_text.isdigit() or not re.fullmatch(
            r"[0-9a-f]{64}", expected_digest
        ):
            raise ControllerError(f"invalid backup metadata for {name}")
        local = temporary / name
        adb(serial, "pull", remote, str(local))
        digest_state = hashlib.sha256()
        with local.open("rb") as source:
            while block := source.read(1024 * 1024):
                digest_state.update(block)
        digest = digest_state.hexdigest()
        if local.stat().st_size != int(size_text) or digest != expected_digest:
            raise ControllerError(f"backup validation failed for {name}")
        copied += 1
    if copied == 0:
        raise ControllerError("the root helper found no JobStore files")
    os.rename(temporary, destination)
    return destination


def primitive_probe(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    stage: str = "primitive-probe",
    root_action: str | None = None,
    root_command: str | None = None,
    run_metadata: dict[str, str | int] | None = None,
    artifact_sink: list[Path] | None = None,
    expected_boot_id: str | None = None,
) -> int:
    root_mode = stage == "root-chain"
    if root_action and not root_mode:
        raise ControllerError("a root action needs the root chain")
    verify(serial, profile)
    boot_id = adb(serial, "shell", "cat", "/proc/sys/kernel/random/boot_id")
    if BOOT_ID_PATTERN.fullmatch(boot_id) is None:
        raise ControllerError("the initial boot ID is invalid")
    boot_id = recover_stale_proc_teardown(serial, profile, boot_id)
    if expected_boot_id is not None and boot_id != expected_boot_id:
        raise ControllerError(
            "the initial boot ID does not match the expected clean boot: "
            f"expected={expected_boot_id} actual={boot_id}"
        )
    profile_start = device_profile_snapshot(serial, profile)
    health_before = read_health_evidence(serial)
    metadata = dict(run_metadata or {})
    run_id = str(metadata.get(
        "run_id",
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f"),
    ))
    package_path = adb(serial, "shell", "pm", "path", PACKAGE, check=False)
    if not package_path.startswith("package:"):
        raise ControllerError("install the app before primitive-probe")
    apk = package_path.removeprefix("package:").strip()
    job_store_repair = root_action == "jobstore-repair"
    direct_root_probe = root_action == "direct-root-probe"
    direct_su = root_action == "direct-su"
    deferred_resukisu_activate = direct_su and root_command.startswith(
        f"{RESUKISU_ACTIVATE_COMMAND}:"
    )
    clean_direct_su = direct_su and (
        root_command == SU_IDENTITY_COMMAND
        or root_command.startswith(f"{RESUKISU_PROBE_COMMAND}:")
        or root_command.startswith(f"{RESUKISU_ACTIVATE_COMMAND}:")
    )
    if clean_direct_su:
        verify_terminal_cleanup_kernel_config(serial, profile)
    metadata["terminal_cleanup_requested"] = 1 if clean_direct_su else 0
    metadata["credential_layout_config_verified"] = (
        1 if clean_direct_su else 0
    )
    partition_backup_action = root_action == "partition-backup"
    direct_init_cred = False
    direct_security_repair = direct_su or partition_backup_action
    direct_security_cred = (
        job_store_repair
        or direct_root_probe
        or direct_security_repair
    )
    security_process = (
        "system_server"
        if job_store_repair or direct_root_probe
        else "android.hardware.boot@1.2-service"
        if partition_backup_action
        else "update_engine"
    )
    security_status_name = (
        "boot@1.2-servic"
        if partition_backup_action
        else security_process
    )
    security_context = (
        "u:r:system_server:s0"
        if security_process == "system_server"
        else "u:r:hal_bootctl_default:s0"
        if partition_backup_action
        else "u:r:update_engine:s0"
    )
    root_window_context = (
        "u:r:kernel:s0" if direct_init_cred else security_context
    )
    security_uid = "1000" if security_process == "system_server" else "0"
    security_pids = adb(
        serial, "shell", "pidof", security_process
    ).split()
    if len(security_pids) != 1 or not security_pids[0].isdigit():
        raise ControllerError(
            f"{security_process} does not have one process"
        )
    stable_since = time.monotonic()
    stable_deadline = stable_since + 60
    while True:
        now = time.monotonic()
        if now >= stable_deadline:
            raise ControllerError(f"{security_process} did not become stable")
        if stable_since is not None and now - stable_since >= 10:
            break
        time.sleep(1)
        current_security_pids = adb(
            serial,
            "shell",
            "pidof",
            security_process,
            check=False,
        ).split()
        valid_pid = (
            len(current_security_pids) == 1
            and current_security_pids[0].isdigit()
        )
        if not valid_pid:
            security_pids = current_security_pids
            stable_since = None
        elif current_security_pids != security_pids or stable_since is None:
            security_pids = current_security_pids
            stable_since = time.monotonic()
    security_pid = security_pids[0]
    security_pid_value = int(security_pid)
    security_start_time = process_start_time(serial, security_pid)
    if not security_start_time:
        raise ControllerError(
            f"{security_process} start time is unavailable"
        )
    security_status = adb(
        serial,
        "exec-out",
        "cat",
        f"/proc/{security_pid}/status",
    )
    observed_security_context = adb(
        serial,
        "exec-out",
        "cat",
        f"/proc/{security_pid}/attr/current",
    ).strip("\x00\r\n ")
    status_fields = {
        line.split(":", 1)[0]: line.split(":", 1)[1].split()
        for line in security_status.splitlines()
        if ":" in line
    }
    if (
        status_fields.get("Name") != [security_status_name]
        or status_fields.get("Uid") != [security_uid] * 4
        or status_fields.get("Gid") != [security_uid] * 4
        or observed_security_context != security_context
    ):
        raise ControllerError(f"{security_process} identity gate failed")
    if security_process != "system_server" and (
        int(status_fields.get("CapEff", ["0"])[0], 16) & (1 << 22)
    ) == 0:
        raise ControllerError(f"{security_process} capability gate failed")
    ueventd_pid = ""
    ueventd_start_time = ""
    if clean_direct_su:
        if "lp3_ctlbuf_rescue" in adb(
            serial, "shell", "ls", "/sys/module"
        ).split():
            raise ControllerError("the ctlbuf rescue module is already live")
        vendor_context = adb(
            serial,
            "shell",
            "ls",
            "-Zd",
            "/vendor",
        ).split()[0]
        if vendor_context != "u:object_r:vendor_file:s0":
            raise ControllerError("the /vendor label is not vendor_file")
        ueventd_pids = adb(serial, "shell", "pidof", "ueventd").split()
        if len(ueventd_pids) != 1 or not ueventd_pids[0].isdigit():
            raise ControllerError("ueventd does not have one process")
        ueventd_pid = ueventd_pids[0]
        ueventd_start_time = process_start_time(serial, ueventd_pid)
        if not ueventd_start_time:
            raise ControllerError("ueventd start time is unavailable")
        ueventd_status = adb(
            serial, "exec-out", "cat", f"/proc/{ueventd_pid}/status"
        )
        ueventd_fields = {
            line.split(":", 1)[0]: line.split(":", 1)[1].split()
            for line in ueventd_status.splitlines()
            if ":" in line
        }
        ueventd_context = adb(
            serial,
            "exec-out",
            "cat",
            f"/proc/{ueventd_pid}/attr/current",
        ).strip("\x00\r\n ")
        if (
            ueventd_fields.get("Name") != ["ueventd"]
            or ueventd_fields.get("Uid") != ["0"] * 4
            or ueventd_fields.get("Gid") != ["0"] * 4
            or ueventd_fields.get("Seccomp") != ["0"]
            or ueventd_context != "u:r:ueventd:s0"
            or (
                int(ueventd_fields.get("CapEff", ["0"])[0], 16)
                & (1 << 16)
            ) == 0
        ):
            raise ControllerError("ueventd module-load identity gate failed")
    process_list = adb(serial, "shell", "ps", "-A", "-o", "PID,ARGS")
    existing = [
        line for line in process_list.splitlines()
        if HELPER_CLASS in line and "sh -c" not in line
    ]
    if existing:
        raise ControllerError("a shell bridge is already running")

    adb(
        serial,
        "shell",
        "run-as",
        PACKAGE,
        "rm",
        "-f",
        "files/direct.result",
        "files/chain.progress",
        "files/root-action.done",
        "files/root-action-security.done",
        "files/root-write-arm.done",
        "files/root-watchdog-arm.done",
        "files/private-credential.request",
        "files/private-credential-arm.done",
        "files/helper-normalised.done",
        "files/helper-retired.done",
        "files/credential-target-death.result",
        "files/ctlbuf-finalise.result",
        "files/ctlbuf-donor-frozen.done",
        "files/terminal-cleanup.result",
        "files/ctlbuf-rescue-plan.result",
        "files/resukisu-stage.plan",
        "files/terminal-cleanup.stage",
        "files/terminal-donor-retirement.result",
        "files/proc-teardown.token",
    )
    helper_mode = "hold"
    action_forward_port = 0
    su_forward_mapping = "none"
    su_protocol_phase = "not-applicable"
    su_token = ""
    su_command_socket: socket.socket | None = None
    partition_signal_socket: socket.socket | None = None
    native_normalisation_record: dict[str, int | str] | None = None
    su_arm_holder_pid = 0
    su_arm_holder_seconds = max(timeout + 600, 3600)
    bridge_nonce = secrets.token_hex(16)
    su_armed_marker = f"BRIDGE_COMMAND_ARMED nonce={bridge_nonce}"
    su_listening_marker = f"BRIDGE_COMMAND_LISTENING nonce={bridge_nonce}"
    su_buffered_marker = f"BRIDGE_COMMAND_BUFFERED nonce={bridge_nonce}"
    su_private_waiting_prefix = (
        f"BRIDGE_COMMAND_PRIVATE_CREDENTIAL_WAITING nonce={bridge_nonce} "
    )
    su_private_prefix = (
        f"BRIDGE_COMMAND_PRIVATE_CREDENTIAL nonce={bridge_nonce} "
        "state=[status=pass stage=private-shell-credential "
    )
    su_normalised_prefix = (
        f"BRIDGE_COMMAND_NORMALISED nonce={bridge_nonce} "
        "state=[status=pass stage=credential-normalisation "
    )
    su_finalise_prefix = (
        f"BRIDGE_COMMAND_CTLBUF_FINALISED nonce={bridge_nonce} "
        "state=["
    )
    su_donor_resume_prefix = (
        f"BRIDGE_COMMAND_CTLBUF_DONOR_RESUME_STATE nonce={bridge_nonce} "
        "state=["
    )
    partition_authenticated_marker = (
        f"BRIDGE_PARTITION_AUTHENTICATED nonce={bridge_nonce}"
    )
    partition_armed_marker = (
        f"BRIDGE_PARTITION_ARMED nonce={bridge_nonce}"
    )
    partition_watchdog_prefix = (
        f"BRIDGE_PARTITION_ROOT_WATCHDOG_READY nonce={bridge_nonce} tid="
    )
    partition_watchdog_invalid = (
        f"BRIDGE_PARTITION_ROOT_WATCHDOG_INVALID nonce={bridge_nonce}"
    )
    command_watchdog_prefix = (
        f"BRIDGE_COMMAND_ROOT_WATCHDOG_READY nonce={bridge_nonce} tid="
    )
    command_watchdog_invalid = (
        f"BRIDGE_COMMAND_ROOT_WATCHDOG_INVALID nonce={bridge_nonce}"
    )
    if root_action == "partition-backup":
        helper_mode = "hold-partition-backup-hal"
        remote_files = [
            PARTITION_BACKUP_RESULT,
            PARTITION_WATCHDOG_PID,
            *PARTITION_BACKUPS.values(),
        ]
        adb(serial, "shell", "rm", "-f", *remote_files)
        adb(
            serial,
            "shell",
            "touch",
            PARTITION_BACKUP_RESULT,
            *PARTITION_BACKUPS.values(),
        )
        adb(
            serial,
            "shell",
            "chmod",
            "600",
            PARTITION_BACKUP_RESULT,
            *PARTITION_BACKUPS.values(),
        )
        forwarded = command([
            "adb",
            "-s",
            serial,
            "forward",
            "tcp:0",
            f"tcp:{PARTITION_SIGNAL_PORT}",
        ])
        if not forwarded.isdigit():
            raise ControllerError("ADB did not allocate a backup signal port")
        action_forward_port = int(forwarded)
    elif root_action == "jobstore-repair":
        helper_mode = "hold-jobstore-repair"
        remote_files = [
            JOB_STORE_REPAIR_RESULT,
            JOB_STORE_COMMIT,
            *JOB_STORE_BACKUPS.values(),
        ]
        adb(serial, "shell", "rm", "-f", *remote_files)
        adb(serial, "shell", "touch", *remote_files)
        adb(serial, "shell", "chmod", "600", *remote_files)
    elif root_action == "direct-root-probe":
        helper_mode = "hold-system-server"
    elif root_action == "direct-su":
        su_protocol_phase = "setup"
        if not root_command:
            raise ControllerError("lp3 su needs a non-empty command")
        command_bytes = root_command.encode("utf-8")
        if len(command_bytes) > 65_536:
            raise ControllerError("lp3 su command exceeds 64 KiB")
        helper_mode = (
            "hold-command-server-clean"
            if clean_direct_su
            else "hold-command-server"
        )
        su_token = secrets.token_hex(32)
        try:
            adb(
                serial,
                "shell",
                "rm",
                "-f",
                SU_TOKEN_PATH,
                SU_ARM_PATH,
                ROOT_WATCHDOG_ARM_PATH,
                NORMALISE_WAITING_PATH,
            )
            with tempfile.NamedTemporaryFile() as token_file:
                token_file.write(su_token.encode("ascii"))
                token_file.flush()
                adb(serial, "push", token_file.name, SU_TOKEN_PATH)
            adb(serial, "shell", "chmod", "600", SU_TOKEN_PATH)
            adb(serial, "shell", "touch", SU_ARM_PATH)
            adb(serial, "shell", "chmod", "600", SU_ARM_PATH)
            holder = adb(
                serial,
                "shell",
                "nohup sh -c 'exec <"
                f"{SU_ARM_PATH}; flock -x 0; exec sleep "
                f"{su_arm_holder_seconds}' >/dev/null 2>&1 & echo $!",
            )
            if not holder.isdigit():
                raise ControllerError("lp3 su could not start the arm lock")
            su_arm_holder_pid = int(holder)
            for _ in range(50):
                held = adb(
                    serial,
                    "shell",
                    f"sh -c 'exec <{SU_ARM_PATH}; "
                    "flock -n -x 0'; echo $?",
                )
                if held.strip().endswith("1"):
                    break
                time.sleep(0.02)
            else:
                raise ControllerError(
                    "lp3 su arm lock did not become ready"
                )
            su_protocol_phase = "arm-lock-ready"
        except BaseException:
            cleanup_su_setup(
                serial,
                su_arm_holder_pid,
                su_arm_holder_seconds,
                action_forward_port,
                kill_bridge=False,
            )
            raise
    elif root_action:
        raise ControllerError(f"unknown root action: {root_action}")
    inner = " ".join(
        [
            f"CLASSPATH={shlex.quote(apk)}",
            "exec",
            "/system/bin/app_process",
            "/system/bin",
            HELPER_CLASS,
            shlex.quote(apk),
            security_pids[0],
            helper_mode,
            bridge_nonce,
        ]
    )
    launch = (
        f"nohup setsid sh -c {shlex.quote(inner)} "
        f">{shlex.quote(HELPER_LOG)} 2>&1 </dev/null &"
    )
    helper_pid = 0
    helper_start_time = ""
    helper_command_line = ""
    try:
        adb(serial, "shell", "rm", "-f", HELPER_LOG)
        adb(serial, "shell", "touch", HELPER_LOG)
        adb(serial, "shell", "chmod", "600", HELPER_LOG)
        adb(serial, "shell", launch)
        ready_pattern = re.compile(
            rf"BRIDGE_READY nonce={re.escape(bridge_nonce)} pid=(\d+)"
        )
        for _ in range(100):
            helper_output = adb(
                serial,
                "shell",
                "cat",
                HELPER_LOG,
                check=False,
            )
            match = ready_pattern.search(helper_output)
            if match:
                helper_pid = int(match.group(1))
                break
            time.sleep(0.1)
        if helper_pid == 0:
            raise ControllerError("the shell bridge did not become ready")
        helper_start_time = process_start_time(serial, str(helper_pid))
        helper_command_line = adb(
            serial,
            "exec-out",
            "cat",
            f"/proc/{helper_pid}/cmdline",
            check=False,
        ).replace("\x00", " ").strip()
        if not helper_start_time or HELPER_CLASS not in helper_command_line:
            raise ControllerError("the shell bridge identity is invalid")
        if partition_backup_action:
            partition_signal_socket = socket.create_connection(
                ("127.0.0.1", action_forward_port),
                timeout=10,
            )
            partition_signal_socket.settimeout(100)
            partition_signal_socket.sendall(
                bridge_nonce.encode("ascii") + b"\n"
            )
            authenticated_deadline = time.monotonic() + 10
            while time.monotonic() < authenticated_deadline:
                helper_output = adb(
                    serial,
                    "shell",
                    "cat",
                    HELPER_LOG,
                    check=False,
                )
                if (
                    partition_authenticated_marker
                    in helper_output.splitlines()
                ):
                    break
                time.sleep(0.05)
            else:
                raise ControllerError(
                    "partition writer did not authenticate as shell"
                )
    except BaseException:
        if partition_signal_socket is not None:
            try:
                partition_signal_socket.close()
            except OSError:
                pass
            partition_signal_socket = None
        if su_command_socket is not None:
            try:
                su_command_socket.close()
            except OSError:
                pass
            su_command_socket = None
        if action_forward_port:
            adb(
                serial,
                "forward",
                "--remove",
                f"tcp:{action_forward_port}",
                check=False,
            )
        if partition_backup_action and helper_pid:
            current_boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
                check=False,
            )
            current_helper_start = process_start_time(
                serial, str(helper_pid)
            )
            current_helper_command = adb(
                serial,
                "exec-out",
                "cat",
                f"/proc/{helper_pid}/cmdline",
                check=False,
            ).replace("\x00", " ").strip()
            if (
                current_boot_id == boot_id
                and current_helper_start == helper_start_time
                and current_helper_command == helper_command_line
            ):
                adb(
                    serial,
                    "shell",
                    "kill",
                    str(helper_pid),
                    check=False,
                )
        if su_token:
            cleanup_su_setup(
                serial,
                su_arm_holder_pid,
                su_arm_holder_seconds,
                action_forward_port,
                kill_bridge=True,
            )
        raise
    started = time.monotonic()
    result = ""
    rebooted = False
    target_restarted = False
    root_window_seen = False
    root_window_validated = False
    root_action_validated = root_action is None
    root_action_result = ""
    root_cleanup_result = ""
    cleanup_stage = ""
    donor_retirement_result = ""
    ctlbuf_rescue_plan_result = ""
    ctlbuf_finalise_result = ""
    root_command_output = ""
    root_command_exit = 0
    resukisu_action_proof_valid = True
    resukisu_kernel_base = 0
    root_action_signalled = False
    su_arm_signalled = False
    private_credential_signalled = False
    command_watchdog_signalled = False
    command_watchdog_tid = 0
    helper_tids_before_root: set[int] = set()
    helper_shell_baseline: dict[str, list[str]] = {}
    helper_shell_context = ""
    helper_shell_namespaces: dict[str, str] = {}
    partition_watchdog_signalled = False
    partition_watchdog_tid = 0
    observed_helper_uid = ""
    observed_helper_gid = ""
    observed_helper_context = ""
    observed_helper_capability = ""
    planned_reboot = False
    immediate_reboot = False
    probe_exception: BaseException | None = None
    job_store_backup_path: Path | None = None
    last_progress = ""
    live_progress = ""
    kernel_mutation_observed = False
    mutation_possible = False
    cleanup_claimed_clean = False
    cleanup_proof: dict[str, int] | None = None
    terminal_native_binding = False
    post_clean_dwell_complete = False
    unsafe_state = False
    unsafe_reason = ""
    end_boot_id = ""
    profile_end: dict[str, Any] | None = None
    health_after: dict[str, Any] | None = None
    helper_output = ""
    proc_teardown_recovered = False
    proc_teardown_token = ""
    proc_teardown_proof: dict[str, Any] | None = None
    try:
        service_arguments = [
            "shell",
            "am",
            "start-foreground-service",
            "--user",
            "0",
            "-n",
            f"{PACKAGE}/.HarnessService",
            "--es",
            "stage",
            stage,
        ]
        if root_action:
            service_arguments.extend([
                "--ez",
                "restore-after-action",
                "false",
            ])
        if direct_init_cred:
            service_arguments.extend([
                "--ez",
                "direct-init-cred",
                "true",
            ])
        if direct_security_cred:
            service_arguments.extend([
                "--ez",
                "direct-security-cred",
                "true",
            ])
        if direct_security_repair:
            service_arguments.extend([
                "--ez",
                "direct-security-repair",
                "true",
                "--es",
                "root-watchdog-nonce",
                bridge_nonce,
                "--es",
                "root-watchdog-helper-pid",
                str(helper_pid),
                "--es",
                "root-watchdog-helper-start",
                helper_start_time,
                "--es",
                "root-watchdog-boot-id",
                boot_id,
            ])
        if root_action == "direct-su":
            service_arguments.extend([
                "--ez",
                "process-teardown-supported",
                "true",
            ])
        if clean_direct_su:
            service_arguments.extend([
                "--ez",
                "direct-terminal-cleanup",
                "true",
                "--es",
                "ctlbuf-ueventd-pid",
                ueventd_pid,
                "--es",
                "ctlbuf-donor-pid",
                security_pid,
                "--es",
                "ctlbuf-donor-start",
                security_start_time,
            ])
        if deferred_resukisu_activate:
            service_arguments.extend([
                "--ez",
                "direct-action-after-security-swap",
                "true",
            ])
        if partition_backup_action:
            service_arguments.extend([
                "--ez",
                "direct-cred-quarantine",
                "true",
            ])
        mutation_possible = root_mode
        adb(serial, *service_arguments)
        next_notice = 30
        next_boot_check = 5
        while time.monotonic() - started < timeout:
            result = adb(
                serial,
                "exec-out",
                "run-as",
                PACKAGE,
                "cat",
                "files/direct.result",
                check=False,
            )
            if root_mode and not root_window_seen:
                live_progress = adb(
                    serial,
                    "exec-out",
                    "run-as",
                    PACKAGE,
                    "cat",
                    "files/chain.progress",
                    check=False,
                )
                if live_progress:
                    last_progress = live_progress
                    kernel_mutation_observed = (
                        kernel_mutation_observed
                        or " arbitrary-read-reclaim-armed" in live_progress
                        or " arbitrary-read-free-start" in live_progress
                        or " root-mutation-start" in live_progress
                    )
                elif mutation_possible:
                    transport_deadline = time.monotonic() + 15
                    transport_recovered = False
                    while time.monotonic() < transport_deadline:
                        if adb(
                            serial,
                            "get-state",
                            check=False,
                            timeout=2,
                        ) == "device":
                            recovered_boot_id = adb(
                                serial,
                                "shell",
                                "cat",
                                "/proc/sys/kernel/random/boot_id",
                                check=False,
                                timeout=2,
                            )
                            if recovered_boot_id and (
                                    recovered_boot_id != boot_id):
                                rebooted = True
                                break
                            recovered_progress = adb(
                                serial,
                                "exec-out",
                                "run-as",
                                PACKAGE,
                                "cat",
                                "files/chain.progress",
                                check=False,
                                timeout=2,
                            )
                            if (recovered_boot_id == boot_id and
                                    recovered_progress):
                                live_progress = recovered_progress
                                last_progress = recovered_progress
                                kernel_mutation_observed = (
                                    kernel_mutation_observed
                                    or " arbitrary-read-reclaim-armed"
                                    in live_progress
                                    or " arbitrary-read-free-start"
                                    in live_progress
                                    or " root-mutation-start"
                                    in live_progress
                                )
                                transport_recovered = True
                                break
                        time.sleep(0.5)
                    if rebooted:
                        break
                    if not transport_recovered:
                        unsafe_state = True
                        unsafe_reason = "adb-lost-after-root-dispatch"
                        raise ControllerError(
                            "unsafe state: ADB was lost after root dispatch"
                        )
                if (
                    direct_su
                    and not su_arm_signalled
                    and " root-write-arm-ready" in live_progress
                    and su_command_socket is not None
                ):
                    adb(
                        serial,
                        "shell",
                        "run-as",
                        PACKAGE,
                        "touch",
                        "files/root-write-arm.done",
                    )
                    su_arm_signalled = True
                if (
                    direct_su
                    and su_command_socket is None
                    and (
                        " root-write-arm-ready" in live_progress
                        or clean_direct_su
                        and not private_credential_signalled
                        and " arbitrary-read-retained" in live_progress
                        and " arbitrary-read-pass" in live_progress
                        and " private-credential-request-ready"
                        in live_progress
                    )
                ):
                    if clean_direct_su:
                        expected_private_request = " ".join([
                            f"nonce={bridge_nonce}",
                            f"helper_pid={helper_pid}",
                            f"helper_start_time={helper_start_time}",
                            f"main_tid={helper_pid}",
                            f"boot_id={boot_id}",
                        ])
                        private_request = adb(
                            serial,
                            "exec-out",
                            "run-as",
                            PACKAGE,
                            "cat",
                            "files/private-credential.request",
                            check=False,
                        ).strip()
                        leader_status = adb(
                            serial,
                            "exec-out",
                            "cat",
                            f"/proc/{helper_pid}/task/{helper_pid}/status",
                            check=False,
                        )
                        leader_fields = {
                            line.split(":", 1)[0]:
                                line.split(":", 1)[1].split()
                            for line in leader_status.splitlines()
                            if ":" in line
                        }
                        if (
                            private_request != expected_private_request
                            or leader_fields.get("Tgid")
                            != [str(helper_pid)]
                            or process_start_time(serial, str(helper_pid))
                            != helper_start_time
                            or adb(
                                serial,
                                "exec-out",
                                "cat",
                                f"/proc/{helper_pid}/cmdline",
                                check=False,
                            ).replace("\x00", " ").strip()
                            != helper_command_line
                            or adb(
                                serial,
                                "shell",
                                "cat",
                                "/proc/sys/kernel/random/boot_id",
                                check=False,
                            ) != boot_id
                        ):
                            raise ControllerError(
                                "lp3 private credential request binding failed"
                            )
                    helper_output = adb(
                        serial,
                        "shell",
                        "cat",
                        HELPER_LOG,
                        check=False,
                    )
                    if su_armed_marker in helper_output.splitlines():
                        raise ControllerError(
                            "lp3 su helper armed before host release"
                        )
                    if not stop_su_arm_holder(
                        serial,
                        su_arm_holder_pid,
                        su_arm_holder_seconds,
                    ):
                        raise ControllerError(
                            "lp3 su arm holder identity changed"
                        )
                    su_arm_holder_pid = 0
                    armed_deadline = time.monotonic() + 10
                    while time.monotonic() < armed_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        if su_armed_marker in helper_output.splitlines():
                            break
                        time.sleep(0.05)
                    else:
                        raise ControllerError(
                            "lp3 su helper did not acknowledge arm"
                        )
                    listening_deadline = time.monotonic() + 10
                    while time.monotonic() < listening_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        if su_listening_marker in helper_output.splitlines():
                            break
                        time.sleep(0.05)
                    else:
                        raise ControllerError(
                            "lp3 su protocol phase=listening-marker timed out"
                        )
                    su_protocol_phase = "forward-create"
                    try:
                        forwarded = adb(
                            serial,
                            "forward",
                            "tcp:0",
                            f"tcp:{SU_COMMAND_PORT}",
                        )
                    except ControllerError as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=forward-create failed"
                        ) from exception
                    if not forwarded.isdigit() or int(forwarded) <= 0:
                        raise ControllerError(
                            "lp3 su protocol phase=forward-create returned "
                            "an invalid local port"
                        )
                    action_forward_port = int(forwarded)
                    expected_forward = (
                        serial,
                        f"tcp:{action_forward_port}",
                        f"tcp:{SU_COMMAND_PORT}",
                    )
                    su_forward_mapping = " ".join(expected_forward)
                    su_protocol_phase = "forward-verify"
                    try:
                        forward_list = adb(
                            serial,
                            "forward",
                            "--list",
                        )
                    except ControllerError as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=forward-verify could not "
                            "read the forward list"
                        ) from exception
                    forward_rows = [
                        tuple(line.split())
                        for line in forward_list.splitlines()
                        if line.strip()
                    ]
                    if forward_rows.count(expected_forward) != 1:
                        raise ControllerError(
                            "lp3 su protocol phase=forward-verify did not "
                            "find the exact serial/local/remote mapping"
                        )
                    su_protocol_phase = "socket-connect"
                    try:
                        su_command_socket = socket.create_connection(
                            ("127.0.0.1", action_forward_port),
                            timeout=10,
                        )
                    except OSError as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=socket-connect failed"
                        ) from exception
                    su_command_socket.settimeout(10)
                    su_protocol_phase = "request-send"
                    try:
                        su_command_socket.sendall(
                            su_token.encode("ascii")
                            + b"\n"
                            + len(command_bytes).to_bytes(4, "big")
                            + command_bytes
                        )
                    except OSError as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=request-send failed"
                        ) from exception
                    su_protocol_phase = "auth-ack-read"
                    expected_auth_ack = (
                        b"LP3_SU_AUTH_" + su_token.encode("ascii") + b"=1\n"
                    )
                    auth_ack = bytearray()
                    try:
                        while len(auth_ack) < len(expected_auth_ack):
                            item = su_command_socket.recv(1)
                            if not item:
                                raise ControllerError(
                                    "lp3 su protocol phase=auth-ack-read "
                                    "closed before the ACK"
                                )
                            auth_ack.extend(item)
                            if item == b"\n":
                                break
                    except socket.timeout as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=auth-ack-read timed out"
                        ) from exception
                    except OSError as exception:
                        raise ControllerError(
                            "lp3 su protocol phase=auth-ack-read failed"
                        ) from exception
                    su_protocol_phase = "auth-ack-validate"
                    if bytes(auth_ack) != expected_auth_ack:
                        raise ControllerError(
                            "lp3 su protocol phase=auth-ack-validate "
                            "received an invalid ACK"
                        )
                    su_command_socket.settimeout(100)
                    su_protocol_phase = "request-authenticated"
                    if clean_direct_su:
                        private_waiting = (
                            su_private_waiting_prefix
                            + f"pid={helper_pid} "
                            + f"start={helper_start_time} "
                            + f"tid={helper_pid} boot_id={boot_id}"
                        )
                        waiting_deadline = time.monotonic() + 10
                        while time.monotonic() < waiting_deadline:
                            helper_output = adb(
                                serial,
                                "shell",
                                "cat",
                                HELPER_LOG,
                                check=False,
                            )
                            if private_waiting in helper_output.splitlines():
                                break
                            time.sleep(0.05)
                        else:
                            raise ControllerError(
                                "lp3 clean helper did not wait for the split"
                            )
                        private_deadline = time.monotonic() + 10
                        private_line = ""
                        while time.monotonic() < private_deadline:
                            helper_output = adb(
                                serial,
                                "shell",
                                "cat",
                                HELPER_LOG,
                                check=False,
                            )
                            private_line = next((
                                line
                                for line in helper_output.splitlines()
                                if line.startswith(su_private_prefix)
                            ), "")
                            if private_line:
                                break
                            time.sleep(0.05)
                        expected_private_line = (
                            f"{su_private_prefix}leader=1 "
                            f"pid={helper_pid} tid={helper_pid} "
                            "securebits_before=47 "
                            "securebits_before_errno=0 ambient_cap=0 "
                            "ambient_before=0 ambient_before_errno=0 "
                            "ambient_lower=0 ambient_lower_errno=0 "
                            "private_credential=0 "
                            "private_credential_errno=0 "
                            "ambient_after=0 ambient_after_errno=0 "
                            "securebits_after=47 "
                            "securebits_after_errno=0 "
                            "shell_before=1 shell_after=1]"
                        )
                        if private_line != expected_private_line:
                            raise ControllerError(
                                "lp3 clean helper split identity is invalid"
                            )
                    buffered_deadline = time.monotonic() + 10
                    while time.monotonic() < buffered_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        if su_buffered_marker in helper_output.splitlines():
                            break
                        time.sleep(0.05)
                    else:
                        raise ControllerError(
                            "lp3 su protocol phase=command-buffered-marker "
                            "timed out"
                        )
                    su_protocol_phase = "command-buffered"
                    if clean_direct_su:
                        helper_lines = helper_output.splitlines()
                        if not any(
                            line.startswith(su_private_prefix)
                            for line in helper_lines
                        ):
                            raise ControllerError(
                                "lp3 clean helper did not create a private cred"
                            )
                        helper_tids_before_root = {
                            int(tid)
                            for tid in adb(
                                serial,
                                "shell",
                                "ls",
                                f"/proc/{helper_pid}/task",
                            ).split()
                            if tid.isdigit()
                        }
                        baseline_status = adb(
                            serial,
                            "exec-out",
                            "cat",
                            f"/proc/{helper_pid}/status",
                        )
                        helper_shell_baseline = {
                            line.split(":", 1)[0]:
                                line.split(":", 1)[1].split()
                            for line in baseline_status.splitlines()
                            if ":" in line
                        }
                        helper_shell_context = adb(
                            serial,
                            "exec-out",
                            "cat",
                            f"/proc/{helper_pid}/attr/current",
                        ).strip("\x00\r\n ")
                        helper_namespace_names = tuple(sorted(adb(
                            serial,
                            "shell",
                            "ls",
                            "-1",
                            f"/proc/{helper_pid}/ns",
                        ).split()))
                        helper_shell_namespaces = {
                            name: adb(
                                serial,
                                "shell",
                                "readlink",
                                f"/proc/{helper_pid}/ns/{name}",
                            )
                            for name in HELPER_NAMESPACE_NAMES
                        }
                        if (
                            len(helper_tids_before_root) < 3
                            or helper_pid not in helper_tids_before_root
                            or helper_shell_baseline.get("Uid")
                            != ["2000"] * 4
                            or helper_shell_baseline.get("Gid")
                            != ["2000"] * 4
                            or helper_shell_context != "u:r:shell:s0"
                            or helper_namespace_names
                            != tuple(sorted(HELPER_NAMESPACE_NAMES))
                            or any(
                                not value
                                for value in helper_shell_namespaces.values()
                            )
                            or process_start_time(serial, str(helper_pid))
                            != helper_start_time
                            or adb(
                                serial,
                                "exec-out",
                                "cat",
                                f"/proc/{helper_pid}/cmdline",
                                check=False,
                            ).replace("\x00", " ").strip()
                            != helper_command_line
                            or adb(
                                serial,
                                "shell",
                                "cat",
                                "/proc/sys/kernel/random/boot_id",
                                check=False,
                            ) != boot_id
                        ):
                            raise ControllerError(
                                "lp3 private shell baseline is invalid"
                            )
                        write_private_control_file(
                            serial,
                            "private-credential-arm.done",
                            " ".join([
                                f"nonce={bridge_nonce}",
                                f"helper_pid={helper_pid}",
                                "helper_start_time="
                                f"{helper_start_time}",
                                f"main_tid={helper_pid}",
                                f"boot_id={boot_id}",
                                "host_helper_identity=1",
                            ]),
                        )
                        private_credential_signalled = True
                    if " root-write-arm-ready" in live_progress:
                        adb(
                            serial,
                            "shell",
                            "run-as",
                            PACKAGE,
                            "touch",
                            "files/root-write-arm.done",
                        )
                        su_arm_signalled = True
                if (
                    direct_su
                    and not command_watchdog_signalled
                    and " root-watchdog-arm-ready" in live_progress
                ):
                    if su_command_socket is None:
                        raise ControllerError(
                            "lp3 su watchdog arm transport is missing"
                        )
                    su_command_socket.sendall(b"\x04")
                    watchdog_deadline = time.monotonic() + 45
                    while time.monotonic() < watchdog_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        helper_lines = helper_output.splitlines()
                        if any(
                            line.startswith(command_watchdog_invalid)
                            for line in helper_lines
                        ):
                            raise ControllerError(
                                "lp3 su root watchdog identity failed"
                            )
                        watchdog_line = next(
                            (
                                line
                                for line in helper_lines
                                if line.startswith(command_watchdog_prefix)
                            ),
                            "",
                        )
                        match = re.fullmatch(
                            re.escape(command_watchdog_prefix)
                            + r"(\d+) identity=\[status=pass"
                            r" stage=command-root-watchdog pid=(\d+)"
                            r" tid=(\d+) uid=0,0,0 gid=0,0,0"
                            r" fsuid=0 fsgid=0 cap_eff=([0-9a-f]{16})\]",
                            watchdog_line,
                        )
                        expected_cap_eff = (
                            status_fields.get("CapEff", [""])[0]
                            .lower()
                            .zfill(16)
                        )
                        if (
                            match
                            and int(match.group(1)) == int(match.group(3))
                            and int(match.group(2)) == helper_pid
                            and match.group(4) == expected_cap_eff
                        ):
                            command_watchdog_tid = int(match.group(1))
                            break
                        time.sleep(0.05)
                    else:
                        leader_wchan = adb(
                            serial,
                            "shell",
                            "cat",
                            f"/proc/{helper_pid}/task/{helper_pid}/wchan",
                            check=False,
                        ).strip()
                        leader_syscall = adb(
                            serial,
                            "shell",
                            "cat",
                            f"/proc/{helper_pid}/task/{helper_pid}/syscall",
                            check=False,
                        ).strip()
                        raise ControllerError(
                            "lp3 su root watchdog did not become ready "
                            f"leader_wchan={leader_wchan or 'unavailable'} "
                            f"leader_syscall={leader_syscall or 'unavailable'}"
                        )
                    watchdog_status = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/task/"
                        f"{command_watchdog_tid}/status",
                        check=False,
                    )
                    watchdog_context = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/task/"
                        f"{command_watchdog_tid}/attr/current",
                        check=False,
                    ).strip("\x00\r\n ")
                    watchdog_fields = {
                        line.split(":", 1)[0]:
                        line.split(":", 1)[1].split()
                        for line in watchdog_status.splitlines()
                        if ":" in line
                    }
                    current_helper_tids = {
                        int(tid)
                        for tid in adb(
                            serial,
                            "shell",
                            "ls",
                            f"/proc/{helper_pid}/task",
                            check=False,
                        ).split()
                        if tid.isdigit()
                    }
                    if (
                        watchdog_fields.get("Tgid") != [str(helper_pid)]
                        or watchdog_fields.get("Uid") != ["0"] * 4
                        or watchdog_fields.get("Gid") != ["0"] * 4
                        or watchdog_fields.get("CapEff")
                        != status_fields.get("CapEff")
                        or watchdog_context != security_context
                        or (
                            clean_direct_su
                            and current_helper_tids
                            != helper_tids_before_root
                            | {command_watchdog_tid}
                        )
                        or process_start_time(serial, security_pid)
                        != security_start_time
                        or process_start_time(serial, str(helper_pid))
                        != helper_start_time
                        or adb(
                            serial,
                            "shell",
                            "cat",
                            "/proc/sys/kernel/random/boot_id",
                            check=False,
                        ) != boot_id
                    ):
                        raise ControllerError(
                            "lp3 su root watchdog host gate failed"
                        )
                    write_private_control_file(
                        serial,
                        "root-watchdog-arm.done",
                        " ".join([
                            f"nonce={bridge_nonce}",
                            f"helper_pid={helper_pid}",
                            f"helper_start_time={helper_start_time}",
                            f"watchdog_tid={command_watchdog_tid}",
                            f"boot_id={boot_id}",
                            "host_helper_identity=1",
                        ]),
                    )
                    command_watchdog_signalled = True
                if (
                    partition_backup_action
                    and not su_arm_signalled
                    and " root-write-arm-ready" in live_progress
                ):
                    if partition_signal_socket is None:
                        raise ControllerError(
                            "partition writer connection was lost"
                        )
                    partition_signal_socket.sendall(b"\x00")
                    armed_deadline = time.monotonic() + 10
                    while time.monotonic() < armed_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        if partition_armed_marker in helper_output.splitlines():
                            break
                        time.sleep(0.05)
                    else:
                        raise ControllerError(
                            "partition helper did not arm containment"
                        )
                    adb(
                        serial,
                        "shell",
                        "run-as",
                        PACKAGE,
                        "touch",
                        "files/root-write-arm.done",
                    )
                    su_arm_signalled = True
                if (
                    partition_backup_action
                    and not partition_watchdog_signalled
                    and " root-watchdog-arm-ready" in live_progress
                ):
                    watchdog_deadline = time.monotonic() + 45
                    while time.monotonic() < watchdog_deadline:
                        helper_output = adb(
                            serial,
                            "shell",
                            "cat",
                            HELPER_LOG,
                            check=False,
                        )
                        helper_lines = helper_output.splitlines()
                        if any(
                            line.startswith(partition_watchdog_invalid)
                            for line in helper_lines
                        ):
                            raise ControllerError(
                                "partition root watchdog identity failed"
                            )
                        watchdog_line = next(
                            (
                                line
                                for line in helper_lines
                                if line.startswith(
                                    partition_watchdog_prefix
                                )
                            ),
                            "",
                        )
                        match = re.fullmatch(
                            re.escape(partition_watchdog_prefix)
                            + r"(\d+) identity=\[status=pass .+\]",
                            watchdog_line,
                        )
                        if match:
                            partition_watchdog_tid = int(match.group(1))
                            break
                        time.sleep(0.05)
                    else:
                        raise ControllerError(
                            "partition root watchdog did not become ready"
                        )
                    watchdog_status = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/task/"
                        f"{partition_watchdog_tid}/status",
                        check=False,
                    )
                    watchdog_context = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/task/"
                        f"{partition_watchdog_tid}/attr/current",
                        check=False,
                    ).strip("\x00\r\n ")
                    watchdog_fields = {
                        line.split(":", 1)[0]:
                        line.split(":", 1)[1].split()
                        for line in watchdog_status.splitlines()
                        if ":" in line
                    }
                    if (
                        watchdog_fields.get("Tgid") != [str(helper_pid)]
                        or watchdog_fields.get("Uid") != ["0"] * 4
                        or watchdog_fields.get("Gid") != ["0"] * 4
                        or watchdog_fields.get("CapEff")
                        != status_fields.get("CapEff")
                        or watchdog_context != security_context
                        or process_start_time(serial, security_pid)
                        != security_start_time
                        or process_start_time(serial, str(helper_pid))
                        != helper_start_time
                        or adb(
                            serial,
                            "shell",
                            "cat",
                            "/proc/sys/kernel/random/boot_id",
                            check=False,
                        ) != boot_id
                    ):
                        raise ControllerError(
                            "partition root watchdog host gate failed"
                        )
                    write_private_control_file(
                        serial,
                        "root-watchdog-arm.done",
                        " ".join([
                            f"nonce={bridge_nonce}",
                            f"helper_pid={helper_pid}",
                            f"helper_start_time={helper_start_time}",
                            f"watchdog_tid={partition_watchdog_tid}",
                            f"boot_id={boot_id}",
                            "host_helper_identity=1",
                        ]),
                    )
                    partition_watchdog_signalled = True
                if (
                    " root-window-ready" in live_progress
                    and not root_action_signalled
                ):
                    root_window_seen = True
                    helper_status = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/status",
                        check=False,
                    )
                    helper_context = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/attr/current",
                        check=False,
                    ).strip("\x00\r\n ")
                    window_security_pids = adb(
                        serial,
                        "shell",
                        "pidof",
                        security_process,
                        check=False,
                    ).split()
                    window_security_start_time = process_start_time(
                        serial, security_pid
                    )
                    helper_fields = {
                        line.split(":", 1)[0]:
                            line.split(":", 1)[1].split()
                        for line in helper_status.splitlines()
                        if ":" in line
                    }
                    observed_helper_uid = " ".join(
                        helper_fields.get("Uid", [])
                    )
                    observed_helper_gid = " ".join(
                        helper_fields.get("Gid", [])
                    )
                    observed_helper_context = helper_context
                    observed_helper_capability = " ".join(
                        helper_fields.get("CapEff", [])
                    )
                    if direct_init_cred:
                        expected_helper_ids = ["0"] * 4
                    elif direct_security_cred:
                        expected_helper_ids = [security_uid] * 4
                    else:
                        expected_helper_ids = [
                            "2000", "2000", "2000", security_uid
                        ]
                    helper_capability = int(
                        helper_fields.get("CapEff", ["0"])[0], 16
                    )
                    expected_capability = int(
                        status_fields.get("CapEff", ["0"])[0], 16
                    )
                    root_window_validated = (
                        helper_fields.get("Uid") == expected_helper_ids
                        and helper_fields.get("Gid") == expected_helper_ids
                        and helper_context == root_window_context
                        and window_security_pids == [security_pid]
                        and window_security_start_time == security_start_time
                        and (
                            not direct_security_cred
                            or helper_capability == expected_capability
                        )
                    )
                    try:
                        if root_action == "partition-backup":
                            if root_window_validated:
                                if partition_signal_socket is None:
                                    raise ControllerError(
                                        "partition writer is not connected"
                                    )
                                partition_signal_socket.sendall(b"\x01")
                                action_deadline = time.monotonic() + 90
                                while time.monotonic() < action_deadline:
                                    root_action_result = adb(
                                        serial,
                                        "exec-out",
                                        "cat",
                                        PARTITION_BACKUP_RESULT,
                                        check=False,
                                    ).strip()
                                    if root_action_result.startswith("status="):
                                        break
                                    time.sleep(0.2)
                                root_action_validated = (
                                    parse_partition_backup_result(
                                        root_action_result
                                    )
                                    is not None
                                )
                            else:
                                root_action_result = (
                                    "status=fail stage=partition-backup "
                                    "reason=root-window-invalid"
                                )
                        elif root_action == "jobstore-repair":
                            if root_window_validated:
                                action_deadline = time.monotonic() + 120
                                while time.monotonic() < action_deadline:
                                    root_action_result = adb(
                                        serial,
                                        "exec-out",
                                        "cat",
                                        JOB_STORE_REPAIR_RESULT,
                                        check=False,
                                    ).strip()
                                    if root_action_result.startswith("status="):
                                        break
                                    time.sleep(0.2)
                                if root_action_result.startswith(
                                    "status=ready stage=jobstore-backup"
                                ):
                                    job_store_backup_path = (
                                        pull_job_store_backups(
                                            serial, boot_id,
                                            root_action_result,
                                        )
                                    )
                                    adb(
                                        serial,
                                        "shell",
                                        f"printf 2 > {JOB_STORE_COMMIT}",
                                    )
                                    action_deadline = time.monotonic() + 30
                                    while time.monotonic() < action_deadline:
                                        root_action_result = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            JOB_STORE_REPAIR_RESULT,
                                            check=False,
                                        ).strip()
                                        if root_action_result.startswith(
                                            "status=pass"
                                        ) or root_action_result.startswith(
                                            "status=fail"
                                        ):
                                            break
                                        time.sleep(0.1)
                                root_action_validated = (
                                    root_action_result.startswith(
                                        "status=pass stage=jobstore-repair"
                                    )
                                    and job_store_backup_path is not None
                                )
                                immediate_reboot = root_action_validated
                            else:
                                root_action_result = (
                                    "status=fail stage=jobstore-repair "
                                    "reason=root-window-invalid"
                                )
                        elif root_action == "direct-su":
                            if root_window_validated:
                                if su_command_socket is None:
                                    raise ControllerError(
                                        "lp3 su command bridge is not connected"
                                    )
                                su_protocol_phase = "root-dispatch"
                                su_command_socket.sendall(b"\x02")
                                output = bytearray()
                                response_match = None
                                response_pattern = re.compile(
                                    rb"(?:^|\n)LP3_SU_(EXIT|ERROR)_"
                                    + su_token.encode("ascii")
                                    + rb"=([^\n]+)\n$"
                                )
                                while True:
                                    block = su_command_socket.recv(65_536)
                                    if not block:
                                        break
                                    output.extend(block)
                                    if len(output) > 16 * 1024 * 1024:
                                        raise ControllerError(
                                            "lp3 su output exceeded 16 MiB"
                                        )
                                    response_match = response_pattern.search(
                                        output
                                    )
                                    if response_match:
                                        break
                                if response_match is None:
                                    raise ControllerError(
                                        "lp3 su command protocol failed"
                                    )
                                su_protocol_phase = "response-validated"
                                response_kind = response_match.group(1)
                                response_value = response_match.group(2)
                                root_command_output = bytes(
                                    output[:response_match.start()]
                                ).decode(
                                    "utf-8", errors="replace"
                                ).rstrip("\n")
                                if clean_direct_su:
                                    expected_cap_eff = (
                                        status_fields.get("CapEff", [""])[0]
                                        .lower()
                                        .zfill(16)
                                    )
                                    identity_match = re.match(
                                        r"LP3_SU_IDENTITY status=pass"
                                        r" stage=command-root-watchdog"
                                        r" pid=(\d+) tid=(\d+)"
                                        r" uid=0,0,0 gid=0,0,0"
                                        r" fsuid=0 fsgid=0"
                                        r" cap_eff=([0-9a-f]{16})(?:\n|$)",
                                        root_command_output,
                                    )
                                    if (
                                        identity_match is None
                                        or int(identity_match.group(1))
                                        != helper_pid
                                        or int(identity_match.group(2))
                                        != command_watchdog_tid
                                        or identity_match.group(3)
                                        != expected_cap_eff
                                    ):
                                        raise ControllerError(
                                            "lp3 su identity proof is invalid"
                                        )
                                    if root_command != SU_IDENTITY_COMMAND:
                                        action = (
                                            "activate"
                                            if root_command.startswith(
                                                RESUKISU_ACTIVATE_COMMAND
                                            )
                                            else "probe"
                                        )
                                        expected_action = (
                                            "LP3_RESUKISU status=ready "
                                            "stage=resukisu-action "
                                            "action=activate"
                                            if deferred_resukisu_activate
                                            else
                                            "LP3_RESUKISU status=pass "
                                            "stage=resukisu-action "
                                            f"action={action} exit=0 errno=0"
                                        )
                                        if expected_action not in (
                                            root_command_output.splitlines()
                                        ):
                                            resukisu_action_proof_valid = False
                                if response_kind == b"EXIT" and (
                                    response_value.isdigit()
                                ):
                                    root_command_exit = int(response_value)
                                    root_action_result = (
                                        "status="
                                        + (
                                            "pass"
                                            if root_command_exit == 0
                                            and resukisu_action_proof_valid
                                            else "command-fail"
                                        )
                                        + " stage=direct-su root=pass exit="
                                        f"{root_command_exit}"
                                    )
                                    root_action_validated = (
                                        root_command_exit == 0
                                        and resukisu_action_proof_valid
                                    )
                                else:
                                    reason = response_value.decode(
                                        "ascii", errors="replace"
                                    )
                                    root_action_result = (
                                        "status=fail stage=direct-su reason="
                                        + reason
                                    )
                                if deferred_resukisu_activate:
                                    stage_plan = adb(
                                        serial,
                                        "exec-out",
                                        "run-as",
                                        PACKAGE,
                                        "cat",
                                        "files/resukisu-stage.plan",
                                    ).strip()
                                    stage_plan_match = re.fullmatch(
                                        r"status=pass "
                                        r"stage=resukisu-stage-plan "
                                        rf"nonce={re.escape(bridge_nonce)} "
                                        r"kernel_base=0x([0-9a-f]+) "
                                        r"kaslr_slide=0x([0-9a-f]+)",
                                        stage_plan,
                                    )
                                    if stage_plan_match is None:
                                        raise ControllerError(
                                            "lp3 ReSukiSU staging plan is "
                                            "invalid"
                                        )
                                    resukisu_kernel_base = int(
                                        stage_plan_match.group(1), 16
                                    )
                                    resukisu_slide = int(
                                        stage_plan_match.group(2), 16
                                    )
                                    if (
                                        resukisu_kernel_base
                                        < KERNEL_LINK_BASE
                                        or resukisu_kernel_base
                                        >= 1 << 64
                                        or resukisu_kernel_base
                                        & (KASLR_ALIGNMENT - 1)
                                        or resukisu_slide
                                        != resukisu_kernel_base
                                        - KERNEL_LINK_BASE
                                        or resukisu_slide
                                        & (KASLR_ALIGNMENT - 1)
                                    ):
                                        raise ControllerError(
                                            "lp3 ReSukiSU kernel base is "
                                            "invalid"
                                        )
                                    su_command_socket.sendall(
                                        b"\x08"
                                        + resukisu_kernel_base.to_bytes(
                                            8, "big"
                                        )
                                    )
                                    stage_output = bytearray()
                                    stage_pattern = re.compile(
                                        rb"(?:^|\n)LP3_SU_STAGE_"
                                        + su_token.encode("ascii")
                                        + rb"=(\d+)\n$"
                                    )
                                    stage_match = None
                                    while True:
                                        block = su_command_socket.recv(65_536)
                                        if not block:
                                            break
                                        stage_output.extend(block)
                                        if len(stage_output) > 65_536:
                                            raise ControllerError(
                                                "lp3 ReSukiSU staging "
                                                "response exceeded 64 KiB"
                                            )
                                        stage_match = stage_pattern.search(
                                            stage_output
                                        )
                                        if stage_match:
                                            break
                                    if stage_match is None:
                                        raise ControllerError(
                                            "lp3 ReSukiSU staging response "
                                            "is invalid"
                                        )
                                    stage_result = bytes(
                                        stage_output[:stage_match.start()]
                                    ).decode(
                                        "utf-8", errors="replace"
                                    ).rstrip("\n")
                                    expected_stage_result = (
                                        "LP3_RESUKISU_STAGE status=pass "
                                        "stage=resukisu-stage result=0 "
                                        "relocation=0 kernel_base="
                                        f"0x{resukisu_kernel_base:x} "
                                        "kaslr_slide="
                                        f"0x{resukisu_slide:x}"
                                    )
                                    if (
                                        int(stage_match.group(1)) != 0
                                        or stage_result
                                        != expected_stage_result
                                    ):
                                        raise ControllerError(
                                            "lp3 ReSukiSU staging failed: "
                                            + (stage_result or "no result")
                                        )
                                    root_command_output = "\n".join(
                                        part for part in (
                                            root_command_output,
                                            stage_result,
                                        ) if part
                                    )
                                if clean_direct_su:
                                    waiting_deadline = time.monotonic() + 10
                                    expected_waiting = (
                                        f"nonce={bridge_nonce} "
                                        f"pid={helper_pid} tid={helper_pid}"
                                    )
                                    while time.monotonic() < waiting_deadline:
                                        waiting_state = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            NORMALISE_WAITING_PATH,
                                            check=False,
                                        ).strip()
                                        if waiting_state == expected_waiting:
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 helper native wait did not arm"
                                        )
                                adb(
                                    serial,
                                    "shell",
                                    "run-as",
                                    PACKAGE,
                                    "touch",
                                    "files/root-action.done",
                                )
                                root_action_signalled = True
                                if clean_direct_su:
                                    su_command_socket.sendall(b"\x05")
                                    signalled_marker = (
                                        "BRIDGE_COMMAND_CTLBUF_DONOR_SIGNALLED "
                                        f"nonce={bridge_nonce} "
                                        f"pid={security_pid}"
                                    )
                                    signalled_prefix = (
                                        "BRIDGE_COMMAND_CTLBUF_DONOR_SIGNALLED "
                                    )
                                    freeze_deadline = time.monotonic() + 15
                                    while time.monotonic() < freeze_deadline:
                                        helper_output = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            HELPER_LOG,
                                            check=False,
                                        )
                                        helper_lines = helper_output.splitlines()
                                        if any(
                                            line.startswith(
                                                command_watchdog_invalid
                                            )
                                            for line in helper_lines
                                        ):
                                            raise ControllerError(
                                                "lp3 donor signal protocol "
                                                "failed"
                                            )
                                        signalled_lines = [
                                            line for line in helper_lines
                                            if line.startswith(signalled_prefix)
                                        ]
                                        if (
                                            len(signalled_lines) > 1
                                            or (
                                                signalled_lines
                                                and signalled_lines[0]
                                                != signalled_marker
                                            )
                                        ):
                                            raise ControllerError(
                                                "lp3 donor signal identity "
                                                "failed"
                                            )
                                        if signalled_marker in helper_lines:
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 donor process signal timed out"
                                        )
                                    freeze_deadline = time.monotonic() + 15
                                    previous_task_ids: set[int] | None = None
                                    stable_task_samples = 0
                                    while time.monotonic() < freeze_deadline:
                                        task_listing = adb(
                                            serial,
                                            "exec-out",
                                            "ls",
                                            f"/proc/{security_pid}/task",
                                            check=False,
                                        )
                                        task_tokens = task_listing.split()
                                        task_ids = {
                                            int(token)
                                            for token in task_tokens
                                            if token.isdigit() and int(token) > 0
                                        }
                                        sample_valid = bool(task_ids) and len(
                                            task_ids
                                        ) == len(task_tokens)
                                        if sample_valid:
                                            for tid in sorted(task_ids):
                                                task_status = adb(
                                                    serial,
                                                    "exec-out",
                                                    "cat",
                                                    f"/proc/{security_pid}/"
                                                    f"task/{tid}/status",
                                                    check=False,
                                                )
                                                task_fields = {
                                                    line.split(":", 1)[0]:
                                                    line.split(":", 1)[1].split()
                                                    for line in
                                                    task_status.splitlines()
                                                    if ":" in line
                                                }
                                                if (
                                                    task_fields.get("Tgid")
                                                    != [security_pid]
                                                    or task_fields.get(
                                                        "State", [""]
                                                    )[0] not in {"T", "t"}
                                                ):
                                                    sample_valid = False
                                                    break
                                        sample_start_time = (
                                            process_start_time(
                                                serial, security_pid
                                            )
                                            if sample_valid else ""
                                        )
                                        sample_context = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{security_pid}/attr/current",
                                            check=False,
                                        ).strip("\x00\r\n ")
                                        sample_boot_id = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            "/proc/sys/kernel/random/boot_id",
                                            check=False,
                                        )
                                        sample_valid = sample_valid and (
                                            sample_start_time
                                            == security_start_time
                                            and sample_context
                                            == security_context
                                            and sample_boot_id == boot_id
                                        )
                                        if sample_valid and task_ids == (
                                                previous_task_ids or set()):
                                            stable_task_samples += 1
                                        elif sample_valid:
                                            stable_task_samples = 1
                                        else:
                                            stable_task_samples = 0
                                        previous_task_ids = (
                                            task_ids if sample_valid else None
                                        )
                                        if stable_task_samples >= 2:
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 signalled donor identity "
                                            "failed"
                                        )
                                    su_command_socket.sendall(b"\x06")
                                    frozen_marker = (
                                        "BRIDGE_COMMAND_CTLBUF_DONOR_FROZEN "
                                        f"nonce={bridge_nonce} "
                                        f"pid={security_pid}"
                                    )
                                    frozen_prefix = (
                                        "BRIDGE_COMMAND_CTLBUF_DONOR_FROZEN "
                                    )
                                    freeze_deadline = time.monotonic() + 15
                                    while time.monotonic() < freeze_deadline:
                                        helper_output = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            HELPER_LOG,
                                            check=False,
                                        )
                                        helper_lines = helper_output.splitlines()
                                        if any(
                                            line.startswith(
                                                command_watchdog_invalid
                                            )
                                            for line in helper_lines
                                        ):
                                            raise ControllerError(
                                                "lp3 donor freeze protocol "
                                                "failed"
                                            )
                                        frozen_lines = [
                                            line for line in helper_lines
                                            if line.startswith(frozen_prefix)
                                        ]
                                        if (
                                            len(frozen_lines) > 1
                                            or (
                                                frozen_lines
                                                and frozen_lines[0]
                                                != frozen_marker
                                            )
                                        ):
                                            raise ControllerError(
                                                "lp3 donor frozen identity "
                                                "failed"
                                            )
                                        if frozen_marker in helper_lines:
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 donor frozen confirmation "
                                            "timed out"
                                        )
                                    write_private_control_file(
                                        serial,
                                        "ctlbuf-donor-frozen.done",
                                        " ".join([
                                            f"nonce={bridge_nonce}",
                                            f"donor_pid={security_pid}",
                                            "donor_start_time="
                                            f"{security_start_time}",
                                            f"boot_id={boot_id}",
                                            "host_donor_frozen=1",
                                        ]),
                                    )
                                    if deferred_resukisu_activate:
                                        security_ready_deadline = (
                                            time.monotonic() + 90
                                        )
                                        while (
                                            time.monotonic()
                                            < security_ready_deadline
                                        ):
                                            live_progress = adb(
                                                serial,
                                                "exec-out",
                                                "run-as",
                                                PACKAGE,
                                                "cat",
                                                "files/chain.progress",
                                                check=False,
                                            )
                                            if (
                                                " root-window-security-ready"
                                                in live_progress
                                            ):
                                                break
                                            time.sleep(0.05)
                                        else:
                                            raise ControllerError(
                                                "lp3 ReSukiSU security "
                                                "window did not arm"
                                            )
                                        helper_security_status = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/status",
                                            check=False,
                                        )
                                        watchdog_security_status = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/task/"
                                            f"{command_watchdog_tid}/status",
                                            check=False,
                                        )
                                        helper_security_fields = {
                                            line.split(":", 1)[0]:
                                            line.split(":", 1)[1].split()
                                            for line in
                                            helper_security_status.splitlines()
                                            if ":" in line
                                        }
                                        watchdog_security_fields = {
                                            line.split(":", 1)[0]:
                                            line.split(":", 1)[1].split()
                                            for line in
                                            watchdog_security_status.splitlines()
                                            if ":" in line
                                        }
                                        helper_security_context = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/attr/current",
                                            check=False,
                                        ).strip("\x00\r\n ")
                                        watchdog_security_context = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/task/"
                                            f"{command_watchdog_tid}/attr/current",
                                            check=False,
                                        ).strip("\x00\r\n ")
                                        if (
                                            helper_security_fields.get("Uid")
                                            != ["0"] * 4
                                            or helper_security_fields.get(
                                                "Gid"
                                            ) != ["0"] * 4
                                            or helper_security_fields.get(
                                                "CapEff"
                                            ) != [expected_cap_eff]
                                            or watchdog_security_fields.get(
                                                "Tgid"
                                            ) != [str(helper_pid)]
                                            or watchdog_security_fields.get(
                                                "Uid"
                                            ) != ["0"] * 4
                                            or watchdog_security_fields.get(
                                                "Gid"
                                            ) != ["0"] * 4
                                            or watchdog_security_fields.get(
                                                "CapEff"
                                            ) != [expected_cap_eff]
                                            or helper_security_context
                                            != "u:r:ueventd:s0"
                                            or watchdog_security_context
                                            != "u:r:ueventd:s0"
                                            or process_start_time(
                                                serial, security_pid
                                            ) != security_start_time
                                            or process_start_time(
                                                serial, str(helper_pid)
                                            ) != helper_start_time
                                            or adb(
                                                serial,
                                                "shell",
                                                "cat",
                                                "/proc/sys/kernel/random/"
                                                "boot_id",
                                                check=False,
                                            ) != boot_id
                                        ):
                                            raise ControllerError(
                                                "lp3 ReSukiSU ueventd "
                                                "identity gate failed"
                                            )
                                        su_command_socket.sendall(b"\x07")
                                        final_output = bytearray()
                                        final_pattern = re.compile(
                                            rb"(?:^|\n)LP3_SU_FINAL_"
                                            + su_token.encode("ascii")
                                            + rb"=(\d+)\n$"
                                        )
                                        final_match = None
                                        while True:
                                            block = su_command_socket.recv(
                                                65_536
                                            )
                                            if not block:
                                                break
                                            final_output.extend(block)
                                            if len(final_output) > 1_048_576:
                                                raise ControllerError(
                                                    "lp3 ReSukiSU response "
                                                    "exceeded 1 MiB"
                                                )
                                            final_match = final_pattern.search(
                                                final_output
                                            )
                                            if final_match:
                                                break
                                        if final_match is None:
                                            raise ControllerError(
                                                "lp3 ReSukiSU final response "
                                                "is invalid"
                                            )
                                        final_action_output = bytes(
                                            final_output[
                                                :final_match.start()
                                            ]
                                        ).decode(
                                            "utf-8", errors="replace"
                                        ).rstrip("\n")
                                        final_action_line = (
                                            "LP3_RESUKISU status=pass "
                                            "stage=resukisu-action "
                                            "action=activate exit=0 errno=0"
                                        )
                                        final_exit = int(
                                            final_match.group(1)
                                        )
                                        resukisu_action_proof_valid = (
                                            final_exit == 0
                                            and final_action_output
                                            == final_action_line
                                        )
                                        root_command_output = "\n".join(
                                            part for part in (
                                                root_command_output,
                                                final_action_output,
                                            ) if part
                                        )
                                        root_command_exit = final_exit
                                        root_action_validated = (
                                            resukisu_action_proof_valid
                                        )
                                        root_action_result = (
                                            "status="
                                            + (
                                                "pass"
                                                if root_action_validated
                                                else "command-fail"
                                            )
                                            + " stage=direct-su root=pass "
                                            f"exit={root_command_exit}"
                                        )
                                        write_private_control_file(
                                            serial,
                                            "root-action-security.done",
                                            " ".join([
                                                f"nonce={bridge_nonce}",
                                                f"helper_pid={helper_pid}",
                                                "helper_start_time="
                                                f"{helper_start_time}",
                                                "watchdog_tid="
                                                f"{command_watchdog_tid}",
                                                f"boot_id={boot_id}",
                                                "host_helper_identity=1",
                                            ]),
                                        )
                                    normalise_deadline = time.monotonic() + 90
                                    while time.monotonic() < normalise_deadline:
                                        live_progress = adb(
                                            serial,
                                            "exec-out",
                                            "run-as",
                                            PACKAGE,
                                            "cat",
                                            "files/chain.progress",
                                            check=False,
                                        )
                                        if (
                                            " helper-normalisation-arm-ready"
                                            in live_progress
                                        ):
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 clean helper restore did not arm"
                                        )
                                    rescue_plan = adb(
                                        serial,
                                        "exec-out",
                                        "run-as",
                                        PACKAGE,
                                        "cat",
                                        "files/ctlbuf-rescue.plan",
                                    ).strip()
                                    rescue_prefix = (
                                        "status=pass "
                                        "stage=ctlbuf-rescue-plan "
                                        f"nonce={bridge_nonce} "
                                        "module_sha256="
                                        "2b4e520b65f252c1c7a51c303f8bc228"
                                        "663f6804cbca00f2ebc6005c9a9f26f8 "
                                        "params="
                                    )
                                    rescue_bytes = rescue_plan.encode("utf-8")
                                    rescue_kernel_base_match = re.search(
                                        r"(?:^| )kernel_base="
                                        r"0x([0-9a-f]+)(?: |$)",
                                        rescue_plan,
                                    )
                                    if (
                                        not rescue_plan.startswith(
                                            rescue_prefix
                                        )
                                        or "\n" in rescue_plan
                                        or "\r" in rescue_plan
                                        or not 1 <= len(rescue_bytes) <= 3072
                                        or deferred_resukisu_activate and (
                                            rescue_kernel_base_match is None
                                            or int(
                                                rescue_kernel_base_match.group(
                                                    1
                                                ),
                                                16,
                                            ) != resukisu_kernel_base
                                        )
                                    ):
                                        raise ControllerError(
                                            "lp3 ctlbuf rescue plan is invalid"
                                        )
                                    su_command_socket.sendall(
                                        b"\x03"
                                        + len(rescue_bytes).to_bytes(
                                            4, "big"
                                        )
                                        + rescue_bytes
                                    )
                                    helper_deadline = time.monotonic() + 60
                                    finalise_status: str | None = None
                                    finalise_record = None
                                    finalise_seen = False
                                    donor_resume_record = None
                                    normalisation_pattern = re.compile(
                                        re.escape(su_normalised_prefix)
                                        + r"watchdog_tid=(?P<tid>[1-9]\d*) "
                                        r"joined=(?P<joined>[01]) "
                                        r"tid_gone=(?P<tid_gone>[01]) "
                                        r"uid_result=(?P<uid>-?\d+) "
                                        r"gid_result=(?P<gid>-?\d+) "
                                        r"shell=(?P<shell>[01]) "
                                        r"ctlbuf_repaired="
                                        r"(?P<ctlbuf_repaired>[01]) "
                                        r"module_loaded="
                                        r"(?P<module_loaded>[01]) "
                                        r"module_unloaded="
                                        r"(?P<module_unloaded>[01]) "
                                        r"module_finalised="
                                        r"(?P<module_finalised>[01]) "
                                        r"finalise_proof="
                                        r"(?P<finalise_proof>[01]) "
                                        r"donor_frozen="
                                        r"(?P<donor_frozen>[01]) "
                                        r"donor_resumed="
                                        r"(?P<donor_resumed>[01]) "
                                        r"donor_resume_pid="
                                        r"(?P<donor_resume_pid>[1-9]\d*) "
                                        r"donor_resume_result="
                                        r"(?P<donor_resume_result>-?\d+) "
                                        r"donor_resume_errno="
                                        r"(?P<donor_resume_errno>-?\d+) "
                                        r"resume_magic=(?P<resume_magic>0x[0-9a-f]+) "
                                        r"resume_version=(?P<resume_version>\d+) "
                                        r"resume_size=(?P<resume_size>\d+) "
                                        r"resume_cookie_hi=(?P<resume_cookie_hi>0x[0-9a-f]+) "
                                        r"resume_cookie_lo=(?P<resume_cookie_lo>0x[0-9a-f]+) "
                                        r"resume_helper_task=(?P<resume_helper_task>0x[0-9a-f]+) "
                                        r"resume_helper_pid=(?P<resume_helper_pid>[1-9]\d*) "
                                        r"resume_donor_task=(?P<resume_donor_task>0x[0-9a-f]+) "
                                        r"resume_donor_tgid=(?P<resume_donor_tgid>[1-9]\d*) "
                                        r"resume_signal=(?P<resume_signal>\d+) "
                                        r"resume_before_state=(?P<resume_before_state>0x[0-9a-f]+) "
                                        r"resume_before_exit_state=(?P<resume_before_exit_state>0x[0-9a-f]+) "
                                        r"resume_before_threads=(?P<resume_before_threads>[1-9]\d*) "
                                        r"resume_before_stopped=(?P<resume_before_stopped>[1-9]\d*) "
                                        r"resume_after_state=(?P<resume_after_state>0x[0-9a-f]+) "
                                        r"resume_after_exit_state=(?P<resume_after_exit_state>0x[0-9a-f]+) "
                                        r"resume_after_threads=(?P<resume_after_threads>[1-9]\d*) "
                                        r"resume_after_stopped=(?P<resume_after_stopped>\d+) "
                                        r"resume_stable_samples=(?P<resume_stable_samples>\d+) "
                                        r"resume_task_security=(?P<resume_task_security>0x[0-9a-f]+) "
                                        r"resume_task_security_word8=(?P<resume_task_security_word8>0x[0-9a-f]+) "
                                        r"resume_inode_security=(?P<resume_inode_security>0x[0-9a-f]+) "
                                        r"resume_inode_security_word8=(?P<resume_inode_security_word8>0x[0-9a-f]+) "
                                        r"resume_labels_restored=(?P<resume_labels_restored>[01]) "
                                        r"resume_resumed=(?P<resume_resumed>[01]) "
                                        r"resume_proof=(?P<resume_proof>[01]) "
                                        r"resume_commit=(?P<resume_commit>0x[0-9a-f]+)\]"
                                    )
                                    normalisation_match = None
                                    while time.monotonic() < helper_deadline:
                                        helper_output = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            HELPER_LOG,
                                            check=False,
                                        )
                                        normalised_line = next((
                                            line
                                            for line in helper_output.splitlines()
                                            if line.startswith(
                                                su_normalised_prefix
                                            )
                                        ), "")
                                        normalisation_match = (
                                            normalisation_pattern.fullmatch(
                                                normalised_line
                                            )
                                        )
                                        normalisation_resume_valid = False
                                        finalise_lines = [
                                            line for line in
                                            helper_output.splitlines()
                                            if line.startswith(
                                                su_finalise_prefix
                                            )
                                        ]
                                        if len(finalise_lines) > 1:
                                            raise ControllerError(
                                                "lp3 module finalise marker "
                                                "was repeated"
                                            )
                                        if finalise_lines:
                                            finalise_line = finalise_lines[0]
                                            if not finalise_line.endswith("]"):
                                                raise ControllerError(
                                                    "lp3 module finalise "
                                                    "marker was truncated"
                                                )
                                            finalise_state = finalise_line[
                                                len(su_finalise_prefix):-1
                                            ]
                                            finalise_record = (
                                                parse_ctlbuf_finalise_status(
                                                    finalise_state
                                                )
                                            )
                                            if finalise_record is None:
                                                raise ControllerError(
                                                    "lp3 module finalise "
                                                    "proof is invalid"
                                                )
                                            finalise_status = finalise_state
                                            finalise_seen = True
                                        donor_resume_lines = [
                                            line
                                            for line in
                                            helper_output.splitlines()
                                            if line.startswith(
                                                su_donor_resume_prefix
                                            )
                                        ]
                                        if len(donor_resume_lines) > 1:
                                            raise ControllerError(
                                                "lp3 donor resume marker "
                                                "was repeated"
                                            )
                                        if donor_resume_lines:
                                            donor_resume_line = (
                                                donor_resume_lines[0]
                                            )
                                            if not donor_resume_line.endswith(
                                                "]"
                                            ):
                                                raise ControllerError(
                                                    "lp3 donor resume marker "
                                                    "was truncated"
                                                )
                                            donor_resume_record = (
                                                parse_ctlbuf_donor_resume_status(
                                                    donor_resume_line[
                                                        len(
                                                            su_donor_resume_prefix
                                                        ):-1
                                                    ]
                                                )
                                            )
                                            if (
                                                donor_resume_record is None
                                                or donor_resume_record[
                                                    "cookie_hi"
                                                ]
                                                != int(
                                                    bridge_nonce[:16], 16
                                                )
                                                or donor_resume_record[
                                                    "cookie_lo"
                                                ]
                                                != int(
                                                    bridge_nonce[16:], 16
                                                )
                                                or donor_resume_record[
                                                    "helper_pid"
                                                ]
                                                != helper_pid
                                                or donor_resume_record[
                                                    "donor_pid"
                                                ]
                                                != security_pid_value
                                            ):
                                                raise ControllerError(
                                                    "lp3 donor resume proof "
                                                    "is invalid"
                                                )
                                            if (
                                                finalise_record is not None
                                                and (
                                                    donor_resume_record[
                                                        "helper_task"
                                                    ]
                                                    != finalise_record[
                                                        "helper_task"
                                                    ]
                                                    or donor_resume_record[
                                                        "donor_task"
                                                    ]
                                                    != finalise_record[
                                                        "donor_task"
                                                    ]
                                                )
                                            ):
                                                raise ControllerError(
                                                    "lp3 donor resume proof "
                                                    "is invalid"
                                                )
                                        if (
                                            normalisation_match is not None
                                            and donor_resume_record is not None
                                        ):
                                            resume_field_map = {
                                                "resume_magic": "magic",
                                                "resume_version": "version",
                                                "resume_size": "size",
                                                "resume_cookie_hi": "cookie_hi",
                                                "resume_cookie_lo": "cookie_lo",
                                                "resume_helper_task": "helper_task",
                                                "resume_helper_pid": "helper_pid",
                                                "resume_donor_task": "donor_task",
                                                "resume_donor_tgid": "donor_tgid",
                                                "resume_signal": "signal",
                                                "resume_before_state": "before_state",
                                                "resume_before_exit_state": "before_exit_state",
                                                "resume_before_threads": "before_threads",
                                                "resume_before_stopped": "before_stopped",
                                                "resume_after_state": "after_state",
                                                "resume_after_exit_state": "after_exit_state",
                                                "resume_after_threads": "after_threads",
                                                "resume_after_stopped": "after_stopped",
                                                "resume_stable_samples": "stable_samples",
                                                "resume_task_security": "task_security",
                                                "resume_task_security_word8": "task_security_word8",
                                                "resume_inode_security": "inode_security",
                                                "resume_inode_security_word8": "inode_security_word8",
                                                "resume_labels_restored": "labels_restored",
                                                "resume_resumed": "resumed",
                                                "resume_proof": "proof",
                                                "resume_commit": "commit",
                                            }
                                            normalisation_resume_valid = all(
                                                int(
                                                    normalisation_match.group(
                                                        native_name
                                                    ),
                                                    0,
                                                )
                                                == donor_resume_record[
                                                    record_name
                                                ]
                                                for native_name, record_name in
                                                resume_field_map.items()
                                            )
                                        if (
                                            normalisation_match is not None
                                            and normalisation_match.group(
                                                "joined"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "tid_gone"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "uid"
                                            ) == "0"
                                            and normalisation_match.group(
                                                "gid"
                                            ) == "0"
                                            and normalisation_match.group(
                                                "shell"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "ctlbuf_repaired"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "module_loaded"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "module_unloaded"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "module_finalised"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "finalise_proof"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "donor_frozen"
                                            ) == "1"
                                            and normalisation_match.group(
                                                "donor_resumed"
                                            ) == "1"
                                            and int(
                                                normalisation_match.group(
                                                    "donor_resume_pid"
                                            )
                                            ) == security_pid_value
                                            and normalisation_match.group(
                                                "donor_resume_result"
                                            ) == "0"
                                            and normalisation_match.group(
                                                "donor_resume_errno"
                                            ) == "0"
                                            and int(
                                                normalisation_match.group(
                                                    "tid"
                                                )
                                            ) != helper_pid
                                            and int(
                                                normalisation_match.group(
                                                    "tid"
                                                )
                                            ) == command_watchdog_tid
                                            and finalise_seen
                                            and normalisation_resume_valid
                                        ):
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 helper did not normalise"
                                        )
                                    native_normalisation_record = {
                                        "watchdog_tid": int(
                                            normalisation_match.group("tid")
                                        ),
                                        "joined": int(
                                            normalisation_match.group("joined")
                                        ),
                                        "tid_gone": int(
                                            normalisation_match.group(
                                                "tid_gone"
                                            )
                                        ),
                                        "uid_result": int(
                                            normalisation_match.group("uid")
                                        ),
                                        "gid_result": int(
                                            normalisation_match.group("gid")
                                        ),
                                        "shell": int(
                                            normalisation_match.group("shell")
                                        ),
                                        "ctlbuf_repaired": int(
                                            normalisation_match.group(
                                                "ctlbuf_repaired"
                                            )
                                        ),
                                        "module_loaded": int(
                                            normalisation_match.group(
                                                "module_loaded"
                                            )
                                        ),
                                        "module_unloaded": int(
                                            normalisation_match.group(
                                                "module_unloaded"
                                            )
                                        ),
                                        "module_finalised": int(
                                            normalisation_match.group(
                                                "module_finalised"
                                            )
                                        ),
                                        "finalise_proof": int(
                                            normalisation_match.group(
                                                "finalise_proof"
                                            )
                                        ),
                                        "donor_frozen": int(
                                            normalisation_match.group(
                                                "donor_frozen"
                                            )
                                        ),
                                        "donor_resumed": int(
                                            normalisation_match.group(
                                                "donor_resumed"
                                            )
                                        ),
                                        "donor_resume_pid": int(
                                            normalisation_match.group(
                                                "donor_resume_pid"
                                            )
                                        ),
                                        "donor_resume_result": int(
                                            normalisation_match.group(
                                                "donor_resume_result"
                                            )
                                        ),
                                        "donor_resume_errno": int(
                                            normalisation_match.group(
                                                "donor_resume_errno"
                                            )
                                        ),
                                    }
                                    native_normalisation_record.update({
                                        native_name: int(
                                            normalisation_match.group(
                                                native_name
                                            ),
                                            0,
                                        )
                                        for native_name in resume_field_map
                                    })
                                    if finalise_status is None:
                                        raise ControllerError(
                                            "lp3 module finalise proof is "
                                            "missing"
                                        )
                                    ctlbuf_finalise_result = finalise_status
                                    write_private_control_file(
                                        serial,
                                        "ctlbuf-finalise.result",
                                        finalise_status,
                                    )
                                    final_status = adb(
                                        serial,
                                        "exec-out",
                                        "cat",
                                        f"/proc/{helper_pid}/status",
                                    )
                                    final_fields = {
                                        line.split(":", 1)[0]:
                                            line.split(":", 1)[1].split()
                                        for line in final_status.splitlines()
                                        if ":" in line
                                    }
                                    identity_fields = (
                                        "Uid", "Gid", "Groups", "CapInh",
                                        "CapPrm", "CapEff", "CapBnd",
                                        "CapAmb", "NoNewPrivs", "Seccomp",
                                        "Seccomp_filters",
                                    )
                                    final_context = adb(
                                        serial,
                                        "exec-out",
                                        "cat",
                                        f"/proc/{helper_pid}/attr/current",
                                    ).strip("\x00\r\n ")
                                    final_namespaces = {
                                        name: adb(
                                            serial,
                                            "shell",
                                            "readlink",
                                            f"/proc/{helper_pid}/ns/{name}",
                                        )
                                        for name in helper_shell_namespaces
                                    }
                                    final_tids = {
                                        int(tid)
                                        for tid in adb(
                                            serial,
                                            "shell",
                                            "ls",
                                            f"/proc/{helper_pid}/task",
                                        ).split()
                                        if tid.isdigit()
                                    }
                                    resumed_donor_valid = False
                                    resumed_task_ids: set[int] | None = None
                                    resumed_state_letters: dict[int, str] = {}
                                    resumed_samples = 0
                                    resume_deadline = time.monotonic() + 5
                                    while time.monotonic() < resume_deadline:
                                        task_tokens = adb(
                                            serial,
                                            "exec-out",
                                            "ls",
                                            f"/proc/{security_pid}/task",
                                            check=False,
                                        ).split()
                                        task_ids = {
                                            int(token)
                                            for token in task_tokens
                                            if token.isdigit()
                                            and int(token) > 0
                                        }
                                        sample_valid = bool(task_ids) and (
                                            len(task_ids) == len(task_tokens)
                                        )
                                        sample_state_letters: dict[int, str] = {}
                                        if sample_valid:
                                            for tid in sorted(task_ids):
                                                task_status = adb(
                                                    serial,
                                                    "exec-out",
                                                    "cat",
                                                    f"/proc/{security_pid}/"
                                                    f"task/{tid}/status",
                                                    check=False,
                                                )
                                                task_fields = {
                                                    line.split(":", 1)[0]:
                                                    line.split(
                                                        ":", 1
                                                    )[1].split()
                                                    for line in
                                                    task_status.splitlines()
                                                    if ":" in line
                                                }
                                                state_letter = task_fields.get(
                                                    "State", [""]
                                                )[0]
                                                if (
                                                    task_fields.get("Tgid")
                                                    != [security_pid]
                                                    or not state_letter
                                                    or state_letter
                                                    in {"T", "t"}
                                                ):
                                                    sample_valid = False
                                                    break
                                                sample_state_letters[tid] = (
                                                    state_letter
                                                )
                                        sample_valid = sample_valid and (
                                            process_start_time(
                                                serial, security_pid
                                            )
                                            == security_start_time
                                            and adb(
                                                serial,
                                                "exec-out",
                                                "cat",
                                                f"/proc/{security_pid}/"
                                                "attr/current",
                                                check=False,
                                            ).strip("\x00\r\n ")
                                            == security_context
                                            and adb(
                                                serial,
                                                "shell",
                                                "cat",
                                                "/proc/sys/kernel/random/"
                                                "boot_id",
                                                check=False,
                                            )
                                            == boot_id
                                        )
                                        if sample_valid and task_ids == (
                                            resumed_task_ids or set()
                                        ):
                                            resumed_samples += 1
                                        elif sample_valid:
                                            resumed_samples = 1
                                        else:
                                            resumed_samples = 0
                                        resumed_task_ids = (
                                            task_ids if sample_valid else None
                                        )
                                        if resumed_samples >= 2:
                                            resumed_donor_valid = True
                                            resumed_state_letters = (
                                                sample_state_letters
                                            )
                                            break
                                        time.sleep(0.05)
                                    native_normalisation_record.update({
                                        "host_donor_pid": security_pid_value,
                                        "host_donor_start_time":
                                            int(security_start_time),
                                        "host_donor_tids": ",".join(
                                            str(tid)
                                            for tid in sorted(
                                                resumed_state_letters
                                            )
                                        ),
                                        "host_donor_states": ",".join(
                                            f"{tid}:"
                                            f"{resumed_state_letters[tid]}"
                                            for tid in sorted(
                                                resumed_state_letters
                                            )
                                        ),
                                        "host_donor_samples":
                                            resumed_samples,
                                    })
                                    changed_identity_fields = [
                                        key for key in identity_fields
                                        if final_fields.get(key)
                                        != helper_shell_baseline.get(key)
                                    ]
                                    changed_namespaces = [
                                        key for key in helper_shell_namespaces
                                        if final_namespaces.get(key)
                                        != helper_shell_namespaces.get(key)
                                    ]
                                    added_tids = (
                                        final_tids - helper_tids_before_root
                                    )
                                    removed_tids = (
                                        helper_tids_before_root - final_tids
                                    )
                                    additional_shell_threads_valid = True
                                    for tid in sorted(added_tids):
                                        thread_status = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/task/"
                                            f"{tid}/status",
                                            check=False,
                                        )
                                        thread_fields = {
                                            line.split(
                                                ":", 1
                                            )[0]: line.split(
                                                ":", 1
                                            )[1].split()
                                            for line in
                                            thread_status.splitlines()
                                            if ":" in line
                                        }
                                        thread_context = adb(
                                            serial,
                                            "exec-out",
                                            "cat",
                                            f"/proc/{helper_pid}/task/"
                                            f"{tid}/attr/current",
                                            check=False,
                                        ).strip("\x00\r\n ")
                                        if (
                                            thread_fields.get("Tgid")
                                            != [str(helper_pid)]
                                            or any(
                                                thread_fields.get(key)
                                                != helper_shell_baseline.get(
                                                    key
                                                )
                                                for key in identity_fields
                                            )
                                            or thread_context
                                            != helper_shell_context
                                        ):
                                            additional_shell_threads_valid = (
                                                False
                                            )
                                            break
                                    helper_start_changed = (
                                        process_start_time(
                                            serial, str(helper_pid)
                                        ) != helper_start_time
                                    )
                                    ueventd_start_changed = (
                                        process_start_time(
                                            serial, ueventd_pid
                                        ) != ueventd_start_time
                                    )
                                    rescue_live = (
                                        "lp3_ctlbuf_rescue" in adb(
                                            serial,
                                            "shell",
                                            "ls",
                                            "/sys/module",
                                        ).split()
                                    )
                                    boot_changed = adb(
                                        serial,
                                        "shell",
                                        "cat",
                                        "/proc/sys/kernel/random/boot_id",
                                    ) != boot_id
                                    if (
                                        changed_identity_fields
                                        or final_context
                                        != helper_shell_context
                                        or changed_namespaces
                                        or removed_tids
                                        or not additional_shell_threads_valid
                                        or helper_start_changed
                                        or ueventd_start_changed
                                        or not resumed_donor_valid
                                        or rescue_live
                                        or boot_changed
                                    ):
                                        raise ControllerError(
                                            "lp3 final shell identity changed: "
                                            f"fields={changed_identity_fields} "
                                            "context="
                                            f"{final_context != helper_shell_context} "
                                            f"namespaces={changed_namespaces} "
                                            "tids_added="
                                            f"{sorted(added_tids)} "
                                            "tids_removed="
                                            f"{sorted(removed_tids)} "
                                            "tids_shell="
                                            f"{additional_shell_threads_valid} "
                                            f"helper_start={helper_start_changed} "
                                            f"ueventd_start={ueventd_start_changed} "
                                            f"donor={not resumed_donor_valid} "
                                            f"rescue={rescue_live} "
                                            f"boot={boot_changed}"
                                        )
                                    resume_gate_fields = [
                                        f"{name}=0x{native_normalisation_record[name]:x}"
                                        if name in {
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
                                            "resume_commit",
                                        }
                                        else f"{name}={native_normalisation_record[name]}"
                                        for name in (
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
                                            "resume_commit",
                                            "host_donor_pid",
                                            "host_donor_start_time",
                                            "host_donor_tids",
                                            "host_donor_states",
                                            "host_donor_samples",
                                        )
                                    ]
                                    write_private_control_file(
                                        serial,
                                        "helper-normalised.done",
                                        " ".join([
                                            f"nonce={bridge_nonce}",
                                            f"helper_pid={helper_pid}",
                                            "helper_start_time="
                                            f"{helper_start_time}",
                                            f"boot_id={boot_id}",
                                            "watchdog_tid="
                                            f"{native_normalisation_record['watchdog_tid']}",
                                            "joined="
                                            f"{native_normalisation_record['joined']}",
                                            "tid_gone="
                                            f"{native_normalisation_record['tid_gone']}",
                                            "uid_result="
                                            f"{native_normalisation_record['uid_result']}",
                                            "gid_result="
                                            f"{native_normalisation_record['gid_result']}",
                                            "shell="
                                            f"{native_normalisation_record['shell']}",
                                            "ctlbuf_repaired="
                                            f"{native_normalisation_record['ctlbuf_repaired']}",
                                            "module_loaded="
                                            f"{native_normalisation_record['module_loaded']}",
                                            "module_unloaded="
                                            f"{native_normalisation_record['module_unloaded']}",
                                            "module_finalised="
                                            f"{native_normalisation_record['module_finalised']}",
                                            "finalise_proof="
                                            f"{native_normalisation_record['finalise_proof']}",
                                            "donor_frozen="
                                            f"{native_normalisation_record['donor_frozen']}",
                                            "donor_resumed="
                                            f"{native_normalisation_record['donor_resumed']}",
                                            "donor_resume_pid="
                                            f"{native_normalisation_record['donor_resume_pid']}",
                                            "donor_resume_result="
                                            f"{native_normalisation_record['donor_resume_result']}",
                                            "donor_resume_errno="
                                            f"{native_normalisation_record['donor_resume_errno']}",
                                            *resume_gate_fields,
                                            "host_helper_identity=1",
                                        ]),
                                    )
                                    retire_deadline = time.monotonic() + 30
                                    while time.monotonic() < retire_deadline:
                                        live_progress = adb(
                                            serial,
                                            "exec-out",
                                            "run-as",
                                            PACKAGE,
                                            "cat",
                                            "files/chain.progress",
                                            check=False,
                                        )
                                        if " helper-retirement-arm-ready" in (
                                            live_progress
                                        ):
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 helper retirement did not arm"
                                        )
                                    su_command_socket.sendall(b"\x01")
                                    exit_deadline = time.monotonic() + 15
                                    while time.monotonic() < exit_deadline:
                                        if not process_start_time(
                                            serial, str(helper_pid)
                                        ):
                                            break
                                        time.sleep(0.05)
                                    else:
                                        raise ControllerError(
                                            "lp3 helper did not retire"
                                        )
                                    write_private_control_file(
                                        serial,
                                        "helper-retired.done",
                                        " ".join([
                                            f"nonce={bridge_nonce}",
                                            f"helper_pid={helper_pid}",
                                            "helper_start_time="
                                            f"{helper_start_time}",
                                            f"boot_id={boot_id}",
                                            "watchdog_tid="
                                            f"{native_normalisation_record['watchdog_tid']}",
                                            "joined="
                                            f"{native_normalisation_record['joined']}",
                                            "tid_gone="
                                            f"{native_normalisation_record['tid_gone']}",
                                            "uid_result="
                                            f"{native_normalisation_record['uid_result']}",
                                            "gid_result="
                                            f"{native_normalisation_record['gid_result']}",
                                            "shell="
                                            f"{native_normalisation_record['shell']}",
                                            "ctlbuf_repaired="
                                            f"{native_normalisation_record['ctlbuf_repaired']}",
                                            "module_loaded="
                                            f"{native_normalisation_record['module_loaded']}",
                                            "module_unloaded="
                                            f"{native_normalisation_record['module_unloaded']}",
                                            "module_finalised="
                                            f"{native_normalisation_record['module_finalised']}",
                                            "finalise_proof="
                                            f"{native_normalisation_record['finalise_proof']}",
                                            "donor_frozen="
                                            f"{native_normalisation_record['donor_frozen']}",
                                            "donor_resumed="
                                            f"{native_normalisation_record['donor_resumed']}",
                                            "donor_resume_pid="
                                            f"{native_normalisation_record['donor_resume_pid']}",
                                            "donor_resume_result="
                                            f"{native_normalisation_record['donor_resume_result']}",
                                            "donor_resume_errno="
                                            f"{native_normalisation_record['donor_resume_errno']}",
                                            *resume_gate_fields,
                                            "helper_retired=1",
                                            "host_helper_identity=1",
                                        ]),
                                    )
                                cleanup_deadline = time.monotonic() + 180
                                cleanup_boot_check = time.monotonic()
                                while time.monotonic() < cleanup_deadline:
                                    observed_cleanup_stage = adb(
                                        serial,
                                        "exec-out",
                                        "run-as",
                                        PACKAGE,
                                        "cat",
                                        "files/terminal-cleanup.stage",
                                        check=False,
                                    ).strip()
                                    if re.fullmatch(
                                            r"[a-z0-9-]+",
                                            observed_cleanup_stage):
                                        cleanup_stage = observed_cleanup_stage
                                    if time.monotonic() >= cleanup_boot_check:
                                        cleanup_boot_id = adb(
                                            serial,
                                            "shell",
                                            "cat",
                                            "/proc/sys/kernel/random/boot_id",
                                            check=False,
                                        ).strip()
                                        if BOOT_ID_PATTERN.fullmatch(
                                                cleanup_boot_id) is None:
                                            unsafe_state = True
                                            unsafe_reason = (
                                                "boot-id-invalid-during-"
                                                "terminal-cleanup"
                                            )
                                            raise ControllerError(
                                                "unsafe state: the boot ID "
                                                "is invalid during terminal "
                                                "cleanup"
                                            )
                                        if cleanup_boot_id != boot_id:
                                            rebooted = True
                                            end_boot_id = cleanup_boot_id
                                            target_restarted = False
                                            raise ControllerError(
                                                "the device rebooted during "
                                                "terminal cleanup"
                                            )
                                        cleanup_boot_check = (
                                            time.monotonic() + 1
                                        )
                                    root_cleanup_result = adb(
                                        serial,
                                        "exec-out",
                                        "run-as",
                                        PACKAGE,
                                        "cat",
                                        "files/terminal-cleanup.result",
                                        check=False,
                                    ).strip()
                                    observed_donor_retirement = adb(
                                        serial,
                                        "exec-out",
                                        "run-as",
                                        PACKAGE,
                                        "cat",
                                        "files/terminal-donor-retirement.result",
                                        check=False,
                                    ).strip()
                                    if observed_donor_retirement:
                                        donor_retirement_result = (
                                            observed_donor_retirement
                                        )
                                    if observed_donor_retirement.startswith(
                                            "status=fail"):
                                        raise ControllerError(
                                            "lp3 su terminal donor proof "
                                            "failed"
                                        )
                                    if root_cleanup_result.startswith("status="):
                                        break
                                    time.sleep(0.05)
                                cleanup_proof = parse_terminal_cleanup_result(
                                    root_cleanup_result
                                )
                                if cleanup_proof is not None:
                                    if cleanup_proof["helper_pid"] != helper_pid:
                                        raise ControllerError(
                                            "lp3 su terminal cleanup helper "
                                            "identity changed"
                                        )
                                    terminal_native_binding = (
                                        native_normalisation_record is not None
                                        and all(
                                            cleanup_proof[field] == value
                                            for field, value in (
                                                native_normalisation_record
                                            ).items()
                                        )
                                    )
                                    if not terminal_native_binding:
                                        raise ControllerError(
                                            "lp3 su native watchdog proof "
                                            "changed"
                                        )
                                    cleanup_claimed_clean = True
                                elif (
                                    root_cleanup_result.startswith(
                                        "status=reboot-required "
                                        "stage=terminal-cleanup "
                                    )
                                    and "outcome=incomplete"
                                    in root_cleanup_result
                                    and "reboot_required=1"
                                    in root_cleanup_result
                                    and "durable=1"
                                    in root_cleanup_result
                                ):
                                    planned_reboot = True
                                else:
                                    raise ControllerError(
                                        "lp3 su terminal cleanup state is "
                                        "missing or invalid"
                                    )
                                if not clean_direct_su:
                                    try:
                                        su_command_socket.sendall(b"\x01")
                                    except OSError:
                                        if not cleanup_claimed_clean:
                                            raise
                                su_command_socket.close()
                                su_command_socket = None
                                su_protocol_phase = "complete"
                            else:
                                root_action_result = (
                                    "status=fail stage=direct-su "
                                    "reason=root-window-invalid"
                                )
                        else:
                            root_action_validated = root_window_validated
                    finally:
                        if not immediate_reboot and not root_action_signalled:
                            adb(
                                serial,
                                "shell",
                                "run-as",
                                PACKAGE,
                                "touch",
                                "files/root-action.done",
                            )
                            root_action_signalled = True
                    if immediate_reboot:
                        adb(serial, "reboot", check=False)
                        planned_reboot = True
                        break
            if result.startswith("status="):
                break
            elapsed = int(time.monotonic() - started)
            if elapsed >= next_boot_check:
                current_boot_id = adb(
                    serial,
                    "shell",
                    "cat",
                    "/proc/sys/kernel/random/boot_id",
                    check=False,
                )
                if not current_boot_id:
                    time.sleep(2)
                    current_boot_id = adb(
                        serial,
                        "shell",
                        "cat",
                        "/proc/sys/kernel/random/boot_id",
                        check=False,
                    )
                valid_current_boot = re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                    r"[0-9a-f]{4}-[0-9a-f]{12}",
                    current_boot_id,
                ) is not None
                if valid_current_boot and current_boot_id != boot_id:
                    rebooted = True
                    break
                if not valid_current_boot:
                    if mutation_possible and not planned_reboot:
                        unsafe_state = True
                        unsafe_reason = "boot-id-invalid-after-mutation"
                        raise ControllerError(
                            "unsafe state: the boot ID is invalid after "
                            "kernel mutation"
                        )
                    next_boot_check += 5
                    time.sleep(2)
                    continue
                if not planned_reboot:
                    current_security_pids = adb(
                        serial,
                        "shell",
                        "pidof",
                        security_process,
                        check=False,
                    ).split()
                    current_security_start_time = process_start_time(
                        serial, security_pid
                    )
                    if (
                        current_security_pids != [security_pid]
                        or current_security_start_time != security_start_time
                    ):
                        target_restarted = True
                        break
                next_boot_check += 5
            if elapsed >= next_notice:
                print(f"WAIT primitive-probe elapsed={elapsed}s", flush=True)
                next_notice += 30
            time.sleep(2)
        if not rebooted and not planned_reboot:
            current_boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
                check=False,
            )
            valid_current_boot = re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                r"[0-9a-f]{4}-[0-9a-f]{12}",
                current_boot_id,
            ) is not None
            if valid_current_boot and current_boot_id != boot_id:
                rebooted = True
            elif valid_current_boot:
                end_boot_id = current_boot_id
                current_security_pids = adb(
                    serial,
                    "shell",
                    "pidof",
                    security_process,
                    check=False,
                ).split()
                current_security_start_time = process_start_time(
                    serial, security_pid
                )
                target_restarted = target_restarted or (
                    current_security_pids != [security_pid]
                    or current_security_start_time != security_start_time
                )
            elif mutation_possible and not planned_reboot:
                unsafe_state = True
                unsafe_reason = "final-boot-id-invalid-after-mutation"
                raise ControllerError(
                    "unsafe state: the final boot ID is invalid after "
                    "kernel mutation"
                )
    except BaseException as exception:
        if (mutation_possible and not cleanup_claimed_clean and
                not planned_reboot and
                not unsafe_state):
            unsafe_state = True
            unsafe_reason = (
                "controller-failure-after-mutation-"
                + exception.__class__.__name__
            )
        probe_exception = exception
    finally:
        if not rebooted:
            try:
                final_boot_id = adb(
                    serial,
                    "shell",
                    "cat",
                    "/proc/sys/kernel/random/boot_id",
                    check=False,
                )
                if (
                    re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12}",
                        final_boot_id,
                    ) is not None
                    and final_boot_id != boot_id
                ):
                    rebooted = True
                    target_restarted = False
                    end_boot_id = final_boot_id
                elif final_boot_id == boot_id:
                    end_boot_id = final_boot_id
                elif (mutation_possible and not cleanup_claimed_clean and
                        not planned_reboot):
                    unsafe_state = True
                    unsafe_reason = (
                        unsafe_reason
                        or "final-boot-id-unavailable-after-mutation"
                    )
                    planned_reboot = True
            except BaseException:
                if (mutation_possible and not cleanup_claimed_clean and
                        not planned_reboot):
                    unsafe_state = True
                    unsafe_reason = (
                        unsafe_reason
                        or "final-boot-check-failed-after-mutation"
                    )
                    planned_reboot = True
        if not rebooted:
            try:
                live_progress = adb(
                    serial,
                    "exec-out",
                    "run-as",
                    PACKAGE,
                    "cat",
                    "files/chain.progress",
                    check=False,
                )
                if (not live_progress and mutation_possible and
                        not cleanup_claimed_clean and not planned_reboot):
                    unsafe_state = True
                    unsafe_reason = (
                        unsafe_reason
                        or "progress-unavailable-after-mutation"
                    )
                    planned_reboot = True
                if not live_progress:
                    live_progress = last_progress
            except BaseException:
                live_progress = last_progress
                if (mutation_possible and not cleanup_claimed_clean and
                        not planned_reboot):
                    unsafe_state = True
                    unsafe_reason = (
                        unsafe_reason
                        or "progress-read-failed-after-mutation"
                    )
                if root_mode:
                    planned_reboot = True
            if (
                not planned_reboot
                and not rebooted
                and f" {PROC_TEARDOWN_MARKER}" in live_progress
            ):
                last_progress = live_progress
                try:
                    proc_teardown_token = adb(
                        serial,
                        "exec-out",
                        "run-as",
                        PACKAGE,
                        "cat",
                        "files/proc-teardown.token",
                        check=False,
                    ).strip()
                    proc_teardown_proof = same_boot_process_teardown_reset(
                        serial,
                        profile,
                        result=result,
                        progress=live_progress,
                        token_text=proc_teardown_token,
                        boot_id=boot_id,
                        bridge_nonce=bridge_nonce,
                        helper_pid=helper_pid,
                        helper_start_time=helper_start_time,
                        helper_command_line=helper_command_line,
                        holder_pid=su_arm_holder_pid,
                        holder_seconds=su_arm_holder_seconds,
                        security_process=security_process,
                        security_pid=security_pid,
                        security_start_time=security_start_time,
                        profile_start=profile_start,
                    )
                    proc_teardown_recovered = True
                    su_arm_holder_pid = 0
                    end_boot_id = str(proc_teardown_proof["end_boot_id"])
                except BaseException as exception:
                    unsafe_state = True
                    unsafe_reason = "same-boot-process-teardown-failed"
                    planned_reboot = True
                    if probe_exception is None:
                        probe_exception = exception
            planned_reboot = planned_reboot or (
                " primitive-reboot-required" in live_progress
                or " root-window-reboot-required" in live_progress
                or " cred-quarantine-armed" in live_progress
            )
            if planned_reboot:
                try:
                    adb(serial, "reboot", check=False)
                except BaseException:
                    pass
        if (
            not rebooted
            and not planned_reboot
            and not proc_teardown_recovered
        ):
            kernel_mutation_started = (
                " arbitrary-read-reclaim-armed" in live_progress
                or " arbitrary-read-free-start" in live_progress
            )
            safe_to_kill = not kernel_mutation_started
            if root_mode:
                mutation_started = " root-mutation-start" in live_progress
                safe_to_kill = (
                    cleanup_claimed_clean
                    or
                    not kernel_mutation_started
                    and not mutation_started
                    or " root-window-restored" in live_progress
            )
            if safe_to_kill:
                try:
                    current_boot_id = adb(
                        serial,
                        "shell",
                        "cat",
                        "/proc/sys/kernel/random/boot_id",
                        check=False,
                    )
                    current_helper_start = process_start_time(
                        serial, str(helper_pid)
                    )
                    current_helper_command = adb(
                        serial,
                        "exec-out",
                        "cat",
                        f"/proc/{helper_pid}/cmdline",
                        check=False,
                    ).replace("\x00", " ").strip()
                    if cleanup_claimed_clean:
                        if (
                            current_boot_id != boot_id
                            or current_helper_start
                            or HELPER_CLASS in current_helper_command
                        ):
                            raise ControllerError(
                                "terminal cleanup did not retire the helper"
                            )
                    elif (
                        current_boot_id == boot_id
                        and current_helper_start == helper_start_time
                        and current_helper_command == helper_command_line
                    ):
                        adb(
                            serial,
                            "shell",
                            "kill",
                            str(helper_pid),
                            check=False,
                        )
                except BaseException:
                    if root_mode:
                        if cleanup_claimed_clean:
                            unsafe_state = True
                            unsafe_reason = (
                                "post-clean-helper-retirement-invalid"
                            )
                        planned_reboot = True
                        try:
                            adb(serial, "reboot", check=False)
                        except BaseException:
                            pass
            else:
                planned_reboot = True
                try:
                    adb(serial, "reboot", check=False)
                except BaseException:
                    pass
        if su_command_socket is not None:
            try:
                su_command_socket.close()
            except OSError:
                pass
            su_command_socket = None
        if partition_signal_socket is not None:
            try:
                partition_signal_socket.close()
            except OSError:
                pass
            partition_signal_socket = None
        if action_forward_port:
            try:
                adb(
                    serial,
                    "forward",
                    "--remove",
                    f"tcp:{action_forward_port}",
                    check=False,
                )
            except BaseException:
                pass
        if su_token and not rebooted and not planned_reboot:
            cleanup_su_setup(
                serial,
                su_arm_holder_pid,
                su_arm_holder_seconds,
                0,
                kill_bridge=False,
            )

    if cleanup_claimed_clean and not rebooted and not planned_reboot:
        try:
            time.sleep(POST_CLEAN_DWELL_SECONDS)
            dwell_boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
            )
            dwell_security_pids = adb(
                serial,
                "shell",
                "pidof",
                security_process,
                check=False,
            ).split()
            dwell_helper_start = process_start_time(serial, str(helper_pid))
            dwell_helper_original = (
                dwell_helper_start == helper_start_time
            )
            dwell_watchdog_status = (
                adb(
                    serial,
                    "exec-out",
                    "cat",
                    f"/proc/{helper_pid}/task/"
                    f"{command_watchdog_tid}/status",
                    check=False,
                )
                if dwell_helper_original and command_watchdog_tid > 0
                else ""
            )
            dwell_module_present = "lp3_ctlbuf_rescue" in adb(
                serial, "shell", "ls", "/sys/module"
            ).split()
            profile_end = device_profile_snapshot(serial, profile)
            health_after = read_health_evidence(serial)
            dwell_failures = []
            if dwell_boot_id != boot_id:
                dwell_failures.append("boot-id")
            if dwell_security_pids != [security_pid]:
                dwell_failures.append("donor-pids")
            if (process_start_time(serial, security_pid) !=
                    security_start_time):
                dwell_failures.append("donor-start")
            if (process_start_time(serial, ueventd_pid) !=
                    ueventd_start_time):
                dwell_failures.append("ueventd-start")
            if dwell_module_present:
                dwell_failures.append("module-present")
            if dwell_helper_original:
                dwell_failures.append("helper-original-live")
            if dwell_watchdog_status:
                dwell_failures.append("watchdog-live")
            if profile_end != profile_start:
                dwell_failures.append("profile")
            if not health_is_normal(health_after):
                dwell_failures.append("health")
            if dwell_failures:
                raise ControllerError(
                    "post-clean dwell failed: " + ",".join(dwell_failures)
                )
            post_clean_dwell_complete = True
            end_boot_id = dwell_boot_id
        except BaseException as exception:
            unsafe_state = True
            unsafe_reason = "post-clean-dwell-failed"
            cleanup_claimed_clean = False
            planned_reboot = True
            if probe_exception is None:
                probe_exception = exception
            try:
                adb(serial, "reboot", check=False)
            except BaseException:
                pass

    recovery_error = ""
    recovery_checked = False
    recovery_state = (
        "same-boot-proc-teardown-confirmed"
        if proc_teardown_recovered
        else "not-required"
    )
    if rebooted or planned_reboot:
        try:
            wait_for_android(serial, previous_boot_id=boot_id)
            recovery_checked = True
            rebooted = True
            end_boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
            )
            if (
                re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                    r"[0-9a-f]{4}-[0-9a-f]{12}",
                    end_boot_id,
                )
                is None
                or end_boot_id == boot_id
            ):
                raise ControllerError(
                    "clean reboot recovery did not change the boot ID"
                )
            recovery_state = (
                "unsafe-clean-reboot-confirmed"
                if unsafe_state
                else "clean-reboot-confirmed"
            )
            helper_command_line = adb(
                serial,
                "exec-out",
                "cat",
                f"/proc/{helper_pid}/cmdline",
                check=False,
            ).replace("\x00", " ")
            if HELPER_CLASS in helper_command_line:
                raise ControllerError(
                    "the old shell bridge still exists after reboot"
                )
        except ControllerError as exception:
            recovery_error = str(exception)
            recovery_state = (
                "unsafe-recovery-unconfirmed"
                if unsafe_state
                else "recovery-unconfirmed"
            )
    if su_token and rebooted and not recovery_error:
        cleanup_su_setup(
            serial,
            0,
            su_arm_holder_seconds,
            0,
            kill_bridge=False,
        )
    try:
        progress = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/chain.progress",
            check=False,
        )
    except Exception:
        progress = last_progress
    if not progress:
        progress = last_progress
    cred_quarantine_pass = " cred-quarantine-pass" in progress
    cleanup_result = root_cleanup_result
    if not cleanup_result:
        try:
            cleanup_result = adb(
                serial,
                "exec-out",
                "run-as",
                PACKAGE,
                "cat",
                "files/terminal-cleanup.result",
                check=False,
            ).strip()
        except Exception:
            cleanup_result = ""
    if proc_teardown_recovered and not cleanup_result:
        cleanup_result = (
            "status=not-requested stage=terminal-cleanup "
            "reason=pre-root-process-teardown"
        )
    elif direct_su and not cleanup_result:
        cleanup_result = (
            "status=reboot-required stage=terminal-cleanup "
            "outcome=incomplete reboot_required=1 reason=result-missing"
        )
    elif not cleanup_result:
        cleanup_result = "status=not-requested stage=terminal-cleanup"
    if not cleanup_stage:
        try:
            recovered_cleanup_stage = adb(
                serial,
                "exec-out",
                "run-as",
                PACKAGE,
                "cat",
                "files/terminal-cleanup.stage",
                check=False,
            ).strip()
            if re.fullmatch(r"[a-z0-9-]+", recovered_cleanup_stage):
                cleanup_stage = recovered_cleanup_stage
        except Exception:
            cleanup_stage = ""
    try:
        donor_retirement_result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/terminal-donor-retirement.result",
            check=False,
        ).strip()
    except Exception:
        donor_retirement_result = ""
    try:
        ctlbuf_rescue_plan_result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/ctlbuf-rescue-plan.result",
            check=False,
        ).strip()
    except Exception:
        ctlbuf_rescue_plan_result = ""
    try:
        ctlbuf_finalise_result = adb(
            serial,
            "exec-out",
            "run-as",
            PACKAGE,
            "cat",
            "files/ctlbuf-finalise.result",
            check=False,
        ).strip()
    except Exception:
        ctlbuf_finalise_result = ""
    miss_match = re.search(
        r"\binternal_write_misses=(\d+)\b",
        cleanup_result + " " + result,
    )
    internal_write_misses = (
        int(miss_match.group(1))
        if miss_match is not None
        else len(re.findall(r" root-write-\d+-retry-ready", progress))
    )
    same_boot = end_boot_id == boot_id
    ctlbuf_finalise_proof = parse_ctlbuf_finalise_status(
        ctlbuf_finalise_result
    )
    cleanup_proof = parse_terminal_cleanup_result(cleanup_result)
    cleanup_verified = (
        cleanup_proof is not None
        and ctlbuf_finalise_proof is not None
        and cleanup_proof["helper_pid"] == helper_pid
        and terminal_native_binding
        and cleanup_claimed_clean
        and post_clean_dwell_complete
    )
    strict_success = (
        root_window_validated
        and root_action_validated
        and root_command_exit == 0
        and cleanup_verified
        and same_boot
        and not target_restarted
        and not unsafe_state
        and not planned_reboot
        and not rebooted
    )
    if profile_end is None and not recovery_error:
        try:
            profile_end = device_profile_snapshot(serial, profile)
        except Exception:
            profile_end = None
    if health_after is None and not recovery_error:
        try:
            health_after = read_health_evidence(serial)
        except Exception:
            health_after = None
    artifact_dir = ROOT / "artifacts/runs"
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    artifact_name = "root-probe" if root_mode else "primitive-probe"
    artifact = artifact_dir / f"{artifact_name}-{stamp}.txt"
    artifact.write_text(
        "--- host ---\n"
        + f"boot_id={boot_id}\n"
        + f"start_boot_id={boot_id}\n"
        + f"end_boot_id={end_boot_id or 'unknown'}\n"
        + f"same_boot={1 if same_boot else 0}\n"
        + f"helper_pid={helper_pid}\n"
        + f"security_process={security_process}\n"
        + f"security_pid={security_pids[0]}\n"
        + f"security_start_time={security_start_time}\n"
        + f"security_target_stable={0 if target_restarted else 1}\n"
        + f"root_window_seen={1 if root_window_seen else 0}\n"
        + f"root_window_validated={1 if root_window_validated else 0}\n"
        + f"helper_uid={observed_helper_uid or 'unknown'}\n"
        + f"helper_gid={observed_helper_gid or 'unknown'}\n"
        + f"helper_context={observed_helper_context or 'unknown'}\n"
        + f"helper_cap_eff={observed_helper_capability or 'unknown'}\n"
        + f"root_action={root_action or 'none'}\n"
        + f"root_action_validated={1 if root_action_validated else 0}\n"
        + f"root_action_result={root_action_result or 'none'}\n"
        + f"root_command_exit={root_command_exit}\n"
        + f"su_command_remote_port={SU_COMMAND_PORT if direct_su else 0}\n"
        + f"su_forward_local_port={action_forward_port}\n"
        + f"su_forward_mapping={su_forward_mapping}\n"
        + f"su_protocol_phase={su_protocol_phase}\n"
        + f"root_watchdog_nonce={bridge_nonce}\n"
        + f"root_watchdog_helper_start={helper_start_time}\n"
        + f"command_watchdog_signalled={1 if command_watchdog_signalled else 0}\n"
        + f"command_watchdog_tid={command_watchdog_tid}\n"
        + f"internal_write_misses={internal_write_misses}\n"
        + f"cleanup_verified={1 if cleanup_verified else 0}\n"
        + f"strict_success={1 if strict_success else 0}\n"
        + f"mutation_possible={1 if mutation_possible else 0}\n"
        + f"kernel_mutation_observed={1 if kernel_mutation_observed else 0}\n"
        + f"post_clean_dwell_seconds={POST_CLEAN_DWELL_SECONDS}\n"
        + f"post_clean_dwell_complete={1 if post_clean_dwell_complete else 0}\n"
        + f"unsafe_state={1 if unsafe_state else 0}\n"
        + f"unsafe_reason={unsafe_reason or 'none'}\n"
        + f"recovery_state={recovery_state}\n"
        + "proc_teardown_proof="
        + (
            json.dumps(
                proc_teardown_proof,
                sort_keys=True,
                separators=(",", ":"),
            )
            if proc_teardown_proof is not None else "none"
        )
        + "\n"
        + f"cred_quarantine_pass={1 if cred_quarantine_pass else 0}\n"
        + f"planned_reboot={1 if planned_reboot else 0}\n"
        + f"reboot_confirmed={1 if rebooted else 0}\n"
        + f"controller_error={str(probe_exception) if probe_exception else 'none'}\n"
        + f"run_id={run_id}\n"
        + "run_metadata="
        + json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        + "\n"
        + "profile_start="
        + json.dumps(profile_start, sort_keys=True, separators=(",", ":"))
        + "\n"
        + "profile_end="
        + (
            json.dumps(profile_end, sort_keys=True, separators=(",", ":"))
            if profile_end is not None else "unavailable"
        )
        + "\n"
        + f"health_before={health_summary(health_before)}\n"
        + "health_after="
        + (
            health_summary(health_after)
            if health_after is not None else "unavailable"
        )
        + "\n"
        + "--- result ---\n"
        + result
        + "\n--- recovery ---\n"
        + f"state={recovery_state}\n"
        + f"error={recovery_error or 'none'}"
        + "\n--- cleanup ---\n"
        + cleanup_result
        + "\n--- cleanup stage ---\n"
        + (cleanup_stage or "unavailable")
        + "\n--- donor retirement proof ---\n"
        + (donor_retirement_result or "unavailable")
        + "\n--- ctlbuf rescue plan ---\n"
        + (ctlbuf_rescue_plan_result or "unavailable")
        + "\n--- ctlbuf finalise proof ---\n"
        + (ctlbuf_finalise_result or "unavailable")
        + "\n--- progress ---\n"
        + progress
        + "\n--- command output ---\n"
        + (root_command_output or "none")
        + "\n--- helper log ---\n"
        + (helper_output or "unavailable")
        + "\n--- JobStore before ---\n"
        + health_before["jobscheduler"]
        + "\n--- JobStore after ---\n"
        + (
            health_after["jobscheduler"]
            if health_after is not None else "unavailable"
        )
        + "\n--- thermal before ---\n"
        + health_before["thermalservice"]
        + "\n--- thermal after ---\n"
        + (
            health_after["thermalservice"]
            if health_after is not None else "unavailable"
        )
        + "\n",
        encoding="utf-8",
    )
    if artifact_sink is not None:
        artifact_sink.append(artifact)
    if probe_exception is not None:
        if isinstance(probe_exception, (KeyboardInterrupt, SystemExit)):
            raise probe_exception
        raise ControllerError(
            f"primitive probe controller error; full result: {artifact}"
        ) from probe_exception
    if proc_teardown_recovered:
        raise SameBootRetryRequired(
            "initial acquisition missed and was reset on the same boot; "
            f"full result: {artifact}"
        )
    expected_result = (
        "status=pass stage=root-chain"
        if root_mode
        else "status=pass stage=primitive-probe"
    )
    immediate_action_pass = (
        root_action == "jobstore-repair"
        and root_action_validated
        and planned_reboot
        and not recovery_error
    )
    if (
        target_restarted
        or (root_mode and not root_window_validated)
        or (root_mode and not root_action_validated)
        or (direct_su and not strict_success)
        or (partition_backup_action and not cred_quarantine_pass)
        or (root_action is not None and not direct_su and not planned_reboot)
        or (stage == "primitive-probe" and not planned_reboot)
        or (
            not immediate_action_pass
            and not result.startswith(expected_result)
        )
    ):
        state = (
            "device-rebooted"
            if rebooted
            else f"{security_process}-restarted" if target_restarted
            else "timeout" if not result else result.split(None, 1)[0]
        )
        label = "root probe" if root_mode else "primitive probe"
        raise ControllerError(
            f"{label} did not pass ({state}); full result: {artifact}"
        )
    start = result.find("profile=[")
    end = result.find("]", start)
    summary = result[start + len("profile=["):end] if start >= 0 else ""
    label = "root-probe" if root_mode else "primitive-probe"
    print(f"PASS {label} elapsed={int(time.monotonic() - started)}s")
    if job_store_backup_path is not None:
        print(f"backup={job_store_backup_path}")
    if summary:
        print(summary)
    if root_command_output:
        print(root_command_output)
    print(f"result={artifact}")
    return root_command_exit


def partition_backup(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
) -> None:
    download_dir = Path.home() / "Downloads"
    destinations = {
        name: download_dir / f"{name}.img"
        for name in PARTITION_BACKUPS
    }
    existing = [str(path) for path in destinations.values() if path.exists()]
    if existing:
        raise ControllerError(
            "refusing to replace local file: " + ", ".join(existing)
        )

    primitive_probe(
        serial,
        profile,
        timeout,
        stage="root-chain",
        root_action="partition-backup",
    )
    backup_result = adb(
        serial,
        "exec-out",
        "cat",
        PARTITION_BACKUP_RESULT,
    ).strip()
    backup_metadata = parse_partition_backup_result(backup_result)
    if backup_metadata is None:
        raise ControllerError("the partition backup result is invalid")

    for name, remote in PARTITION_BACKUPS.items():
        destination = destinations[name]
        if destination.exists():
            raise ControllerError(f"refusing to replace {destination}")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{name}.",
            suffix=".img.partial",
            dir=download_dir,
        )
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            adb(serial, "pull", remote, str(temporary))
            size = temporary.stat().st_size
            if size == 0:
                raise ControllerError(f"the pulled {name} image is empty")
            digest = hashlib.sha256()
            with temporary.open("rb") as source:
                while block := source.read(1024 * 1024):
                    digest.update(block)
            expected_size, expected_digest = backup_metadata[name]
            if size != expected_size or digest.hexdigest() != expected_digest:
                raise ControllerError(
                    f"the pulled {name} image does not match the device copy"
                )
            os.link(temporary, destination)
            print(
                f"PASS {destination} bytes={size} sha256={digest.hexdigest()}"
            )
        except FileExistsError as exception:
            raise ControllerError(
                f"refusing to replace {destination}"
            ) from exception
        finally:
            temporary.unlink(missing_ok=True)


def registered_job_count(serial: str) -> int:
    output = adb(
        serial,
        "shell",
        "dumpsys jobscheduler | grep -m 1 "
        "'^Registered [0-9][0-9]* jobs:'",
        check=False,
    )
    match = re.search(r"Registered (\d+) jobs:", output)
    if match is None:
        raise ControllerError("could not read the registered JobScheduler count")
    return int(match.group(1))


def require_safe_repair_temperature(serial: str) -> None:
    thermal = adb(serial, "shell", "dumpsys", "thermalservice")
    status = re.search(r"^Thermal Status: (\d+)$", thermal, re.MULTILINE)
    battery = re.search(
        r"mValue=([0-9.]+), mType=2, mName=battery", thermal
    )
    cpu_values = [
        float(value)
        for value in re.findall(
            r"mValue=([0-9.]+), mType=0, mName=CPU\d+", thermal
        )
    ]
    if status is None or battery is None or not cpu_values:
        raise ControllerError("could not read the thermal repair gate")
    battery_value = float(battery.group(1))
    cpu_value = max(cpu_values)
    if int(status.group(1)) != 0 or battery_value >= 42 or cpu_value >= 65:
        raise ControllerError(
            "device too hot for repair: "
            f"status={status.group(1)} battery={battery_value:.1f} "
            f"cpu={cpu_value:.1f}"
        )


def jobstore_repair(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    known_job_count: int | None,
) -> None:
    before = (
        known_job_count
        if known_job_count is not None
        else registered_job_count(serial)
    )
    if before < 1000:
        raise ControllerError(
            f"JobStore repair refused for a normal job count: {before}"
        )
    require_safe_repair_temperature(serial)
    primitive_probe(
        serial,
        profile,
        timeout,
        stage="root-chain",
        root_action="jobstore-repair",
    )
    after = registered_job_count(serial)
    if after >= 1000:
        raise ControllerError(
            "the JobScheduler count did not return to a safe range: "
            + str(after)
        )
    fallback_count = adb(
        serial,
        "shell",
        "dumpsys jobscheduler com.android.providers.settings | "
        "grep -c '^  JOB #.* "
        "com.android.providers.settings/.WriteFallbackSettingsFilesJobService$'",
        check=False,
    )
    if not fallback_count.isdigit() or int(fallback_count) > 1:
        raise ControllerError(
            "duplicate fallback jobs remain: "
            + (fallback_count or "unknown")
        )
    print(
        "PASS jobstore-repair "
        f"before={before} registered={after} fallback={fallback_count}"
    )


def reliable_primitive_probe(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    safe_retries: int,
) -> None:
    subattempt = 1
    while True:
        try:
            primitive_probe(serial, profile, timeout)
            print(f"PASS reliable-primitive subattempts={subattempt}")
            return
        except ControllerError as probe_error:
            if subattempt > safe_retries:
                raise
            try:
                fast_reset(serial, profile)
                clean_reboot(serial, profile)
            except ControllerError as reset_error:
                raise probe_error from reset_error
            subattempt += 1
            print(
                "RETRY reliable-primitive "
                f"subattempt={subattempt} reason=safe-no-free-clean-boot"
            )


def reliable_direct_root_probe(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    safe_retries: int,
) -> None:
    subattempt = 1
    while True:
        jobs = registered_job_count(serial)
        if jobs >= 1000:
            raise ControllerError(
                f"root probe refused for an unsafe job count: {jobs}"
            )
        print(f"JOBS registered={jobs} subattempt={subattempt}")
        try:
            primitive_probe(
                serial,
                profile,
                timeout,
                stage="root-chain",
                root_action="direct-root-probe",
            )
            after = registered_job_count(serial)
            if after >= 1000:
                raise ControllerError(
                    f"job count became unsafe after root: {after}"
                )
            print(
                "PASS reliable-direct-root "
                f"subattempts={subattempt} jobs={after}"
            )
            return
        except ControllerError as probe_error:
            if subattempt > safe_retries:
                raise
            try:
                marker = safe_retry_marker(serial)
            except ControllerError:
                clean_reboot(serial, profile)
                raise probe_error
            clean_reboot(serial, profile)
            subattempt += 1
            print(
                "RETRY reliable-direct-root "
                f"subattempt={subattempt} marker={marker}"
            )


def reliable_su(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    safe_retries: int,
    root_command: str,
) -> int:
    subattempt = 1
    while True:
        jobs = registered_job_count(serial)
        if jobs >= 1000:
            raise ControllerError(
                f"lp3 su refused for an unsafe job count: {jobs}"
            )
        print(f"JOBS registered={jobs} subattempt={subattempt}")
        try:
            exit_code = primitive_probe(
                serial,
                profile,
                timeout,
                stage="root-chain",
                root_action="direct-su",
                root_command=root_command,
                run_metadata={
                    "mode": "su",
                    "host_retries_allowed": safe_retries,
                    "host_retries_used": subattempt - 1,
                    "run_index": subattempt,
                },
            )
            after = registered_job_count(serial)
            if after >= 1000:
                raise ControllerError(
                    f"job count became unsafe after lp3 su: {after}"
                )
            print(
                ("PASS" if exit_code == 0 else "ROOT")
                + " lp3-su-root "
                f"subattempts={subattempt} jobs={after} "
                f"command_exit={exit_code}"
            )
            return exit_code
        except SameBootRetryRequired:
            if subattempt > safe_retries:
                raise
            subattempt += 1
            print(
                "RETRY lp3-su "
                f"subattempt={subattempt} "
                "reason=same-boot-process-teardown"
            )
        except ControllerError as probe_error:
            if subattempt > safe_retries:
                raise
            try:
                marker = safe_retry_marker(serial)
            except ControllerError:
                clean_reboot(serial, profile)
                raise probe_error
            clean_reboot(serial, profile)
            subattempt += 1
            print(
                "RETRY lp3-su "
                f"subattempt={subattempt} marker={marker}"
            )


def qualification_host(path: Path) -> dict[str, str] | None:
    sections = _issue_2_sections(path)
    return (
        _issue_2_pairs(sections["host"])
        if sections is not None else None
    )


def is_safe_pre_mutation_artifact(path: Path, boot_id: str) -> bool:
    sections = _issue_2_sections(path)
    host = qualification_host(path)
    names = (
        _issue_2_progress(sections["progress"])
        if sections is not None else None
    )
    return bool(
        host is not None
        and names is not None
        and host.get("start_boot_id") == boot_id
        and host.get("end_boot_id") == boot_id
        and host.get("same_boot") == "1"
        and host.get("kernel_mutation_observed") == "0"
        and host.get("unsafe_state") == "0"
        and host.get("planned_reboot") == "0"
        and host.get("reboot_confirmed") == "0"
        and host.get("controller_error") == "none"
        and "arbitrary-read-reclaim-armed" not in names
        and "arbitrary-read-free-start" not in names
        and not any(marker.startswith("root-mutation") for marker in names)
    )


def qualification_pre_mutation_reset(
    serial: str,
    profile: dict[str, Any],
    boot_id: str,
) -> None:
    adb(serial, "shell", "am", "force-stop", "--user", "0", PACKAGE)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and package_pids(serial):
        time.sleep(0.2)
    if package_pids(serial):
        raise ControllerError("pre-mutation qualification reset failed")
    time.sleep(1)
    if adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    ) != boot_id:
        raise ControllerError("boot changed during pre-mutation reset")
    verify(serial, profile)
    app_preflight(serial, profile)


def is_teardown_recovery_artifact(path: Path, boot_id: str) -> bool:
    host = qualification_host(path)
    if host is None or host.get("proc_teardown_proof") in {None, "none"}:
        return False
    try:
        proof = json.loads(host["proc_teardown_proof"])
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return bool(
        host.get("start_boot_id") == boot_id
        and host.get("end_boot_id") == boot_id
        and host.get("same_boot") == "1"
        and host.get("recovery_state")
            == "same-boot-proc-teardown-confirmed"
        and host.get("planned_reboot") == "0"
        and host.get("reboot_confirmed") == "0"
        and isinstance(proof, dict)
        and proof.get("start_boot_id") == boot_id
        and proof.get("end_boot_id") == boot_id
        and proof.get("helper_absent") == 1
        and proof.get("profile_equal") == 1
        and proof.get("token_consumed") == 1
    )


def is_strict_success_artifact(path: Path, boot_id: str) -> bool:
    host = qualification_host(path)
    return bool(
        host is not None
        and host.get("start_boot_id") == boot_id
        and host.get("end_boot_id") == boot_id
        and host.get("same_boot") == "1"
        and host.get("strict_success") == "1"
        and host.get("cleanup_verified") == "1"
        and host.get("planned_reboot") == "0"
        and host.get("reboot_confirmed") == "0"
        and host.get("controller_error") == "none"
    )


def qualify_proc_teardown(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
    max_attempts: int,
) -> None:
    if max_attempts < 1 or max_attempts > 100:
        raise ControllerError("max attempts must be between 1 and 100")
    qualification_id = (
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        + "-"
        + secrets.token_hex(4)
    )
    qualification_dir = ROOT / "artifacts/qualifications"
    qualification_dir.mkdir(parents=True, exist_ok=True)
    manifest = qualification_dir / f"proc-teardown-{qualification_id}.txt"
    clean_reboot(serial, profile)
    boot_id = adb(
        serial, "shell", "cat", "/proc/sys/kernel/random/boot_id"
    )
    successes: list[str] = []
    safe_failures: list[str] = []
    teardown_misses: list[str] = []
    retry_ordinal = 0
    retry_boot_id: str | None = None
    retry_miss_artifact: str | None = None
    phase = "seek-miss"
    acquisition_attempt = 0
    controller_attempt = 0
    successes_on_boot = 0
    consecutive_safe_failures = 0
    qualification_reboots = 1
    while acquisition_attempt < max_attempts:
        controller_attempt += 1
        if controller_attempt > max_attempts * 4:
            raise ControllerError(
                "teardown qualification exceeded the controller-attempt limit"
            )
        artifacts: list[Path] = []
        try:
            exit_code = primitive_probe(
                serial,
                profile,
                timeout,
                expected_boot_id=boot_id,
                stage="root-chain",
                root_action="direct-su",
                root_command=SU_IDENTITY_COMMAND,
                run_metadata={
                    "mode": "proc-teardown-qualification",
                    "qualification_id": qualification_id,
                    "attempt_index": controller_attempt,
                    "acquisition_attempt": acquisition_attempt + 1,
                    "phase": phase,
                    "host_retries_allowed": 5,
                    "host_retries_used": retry_ordinal,
                },
                artifact_sink=artifacts,
            )
        except SameBootRetryRequired:
            if (
                len(artifacts) != 1
                or not is_teardown_recovery_artifact(artifacts[0], boot_id)
            ):
                raise ControllerError(
                    "teardown qualification miss proof is invalid"
                )
            teardown_misses.append(str(artifacts[0]))
            retry_boot_id = boot_id
            retry_miss_artifact = str(artifacts[0])
            acquisition_attempt += 1
            retry_ordinal += 1
            if retry_ordinal > 5:
                raise ControllerError(
                    "teardown qualification exhausted same-boot retries"
                )
            phase = "same-boot-retry"
            continue
        except ControllerError:
            if (
                len(artifacts) != 1
                or not is_safe_pre_mutation_artifact(artifacts[0], boot_id)
            ):
                raise
            safe_failures.append(str(artifacts[0]))
            consecutive_safe_failures += 1
            if consecutive_safe_failures >= 2:
                clean_reboot(serial, profile)
                boot_id = adb(
                    serial,
                    "shell",
                    "cat",
                    "/proc/sys/kernel/random/boot_id",
                )
                successes_on_boot = 0
                consecutive_safe_failures = 0
                qualification_reboots += 1
                if phase == "same-boot-retry":
                    phase = "seek-miss"
                    retry_ordinal = 0
                    retry_boot_id = None
                    retry_miss_artifact = None
                    teardown_misses.clear()
            else:
                qualification_pre_mutation_reset(serial, profile, boot_id)
            continue
        if exit_code != 0 or len(artifacts) != 1:
            raise ControllerError(
                "teardown qualification successful attempt is invalid"
            )
        acquisition_attempt += 1
        if phase == "same-boot-retry":
            if (
                retry_boot_id != boot_id
                or retry_miss_artifact is None
                or not teardown_misses
                or teardown_misses[-1] != retry_miss_artifact
                or not all(
                    is_teardown_recovery_artifact(Path(path), boot_id)
                    for path in teardown_misses
                )
                or not is_strict_success_artifact(artifacts[0], boot_id)
            ):
                raise ControllerError(
                    "teardown qualification retry proof is invalid"
                )
            manifest.write_text(
                "\n".join([
                    "status=pass",
                    "qualification=proc-teardown",
                    f"qualification_id={qualification_id}",
                    f"boot_id={boot_id}",
                    f"acquisition_attempts={acquisition_attempt}",
                    f"controller_attempts={controller_attempt}",
                    f"successes_before_miss={len(successes)}",
                    f"safe_pre_mutation_failures={len(safe_failures)}",
                    f"same_boot_teardowns={len(teardown_misses)}",
                    f"qualification_reboots={qualification_reboots}",
                    "miss_artifacts=" + json.dumps(teardown_misses),
                    "retry_artifact=" + str(artifacts[0]),
                    "apk_sha256=" + hashlib.sha256(
                        APK_PATH.read_bytes()
                    ).hexdigest(),
                ]) + "\n",
                encoding="utf-8",
            )
            print(
                "PASS proc-teardown-qualification "
                f"attempts={acquisition_attempt} manifest={manifest}"
            )
            return
        successes.append(str(artifacts[0]))
        successes_on_boot += 1
        consecutive_safe_failures = 0
        if successes_on_boot >= 4:
            clean_reboot(serial, profile)
            boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
            )
            successes_on_boot = 0
            qualification_reboots += 1
        else:
            qualification_pre_mutation_reset(serial, profile, boot_id)
    raise ControllerError(
        "teardown qualification did not complete a miss/retry pair in "
        f"{max_attempts} attempts"
    )


def qualify_issue_2(
    serial: str,
    profile: dict[str, Any],
    timeout: int,
) -> None:
    qualification_id = (
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
        + "-"
        + secrets.token_hex(4)
    )
    qualification_dir = ROOT / "artifacts/qualifications"
    qualification_dir.mkdir(parents=True, exist_ok=True)
    manifest = qualification_dir / f"issue-2-{qualification_id}.txt"
    attempt_boot_ids: list[str] = []
    accepted_boot_ids: list[str] = []
    excluded_boot_ids: list[str] = []
    accepted_artifacts: list[dict[str, str]] = []
    excluded_artifacts: list[dict[str, str]] = []
    exclusions: list[dict[str, Any]] = []
    initial_exclusions = 0
    replacement_exclusions = 0
    attempts = 0
    failure: BaseException | None = None
    try:
        while len(accepted_boot_ids) < ISSUE_2_QUALIFICATION_RUNS:
            if attempts >= ISSUE_2_MAX_ATTEMPTS:
                raise ControllerError(
                    "issue #2 qualification reached the attempt limit"
                )
            attempts += 1
            run_index = attempts
            accepted_target_index = len(accepted_boot_ids) + 1
            clean_reboot(serial, profile)
            boot_id = adb(
                serial,
                "shell",
                "cat",
                "/proc/sys/kernel/random/boot_id",
            )
            if (
                BOOT_ID_PATTERN.fullmatch(boot_id) is None
                or boot_id in attempt_boot_ids
            ):
                raise ControllerError(
                    "issue #2 qualification did not start on a unique clean boot"
                )
            health = read_health_evidence(serial)
            if not health_is_normal(health):
                raise ControllerError(
                    "issue #2 qualification device health gate failed: "
                    + health_summary(health)
                )
            attempt_boot_ids.append(boot_id)
            print(
                "QUALIFY issue=2 "
                f"attempt={run_index}/{ISSUE_2_MAX_ATTEMPTS} "
                f"accepted={len(accepted_boot_ids)}/"
                f"{ISSUE_2_QUALIFICATION_RUNS} "
                f"boot_id={boot_id}",
                flush=True,
            )
            artifact_sink: list[Path] = []
            try:
                exit_code = primitive_probe(
                    serial,
                    profile,
                    timeout,
                    expected_boot_id=boot_id,
                    stage="root-chain",
                    root_action="direct-su",
                    root_command=SU_IDENTITY_COMMAND,
                    run_metadata={
                        "mode": "issue-2-qualification",
                        "qualification_id": qualification_id,
                        "run_index": accepted_target_index,
                        "attempt_index": run_index,
                        "run_total": ISSUE_2_QUALIFICATION_RUNS,
                        "clean_boot_id": boot_id,
                        "host_retries_allowed": 0,
                        "host_retries_used": 0,
                    },
                    artifact_sink=artifact_sink,
                )
            except ControllerError as probe_error:
                if (
                    len(artifact_sink) != 1
                    or not artifact_sink[0].is_file()
                ):
                    raise probe_error
                classified = classify_issue_2_artifact_v1(
                    artifact_sink[0],
                    expected_boot_id=boot_id,
                    qualification_id=qualification_id,
                    run_index=accepted_target_index,
                    attempt_index=run_index,
                )
                if classified is None:
                    raise probe_error
                if len(exclusions) >= ISSUE_2_MAX_EXCLUSIONS:
                    raise ControllerError(
                        "issue #2 qualification reached the exclusion limit"
                    ) from probe_error
                digest = hashlib.sha256(
                    artifact_sink[0].read_bytes()
                ).hexdigest()
                kind = str(classified["kind"])
                excluded_boot_ids.append(boot_id)
                excluded_artifacts.append({
                    "target_index": str(accepted_target_index),
                    "path": str(artifact_sink[0]),
                    "sha256": digest,
                })
                exclusions.append({
                    "attempt": run_index,
                    "accepted_before": len(accepted_boot_ids),
                    "target_index": accepted_target_index,
                    "kind": kind,
                    "start_boot_id": boot_id,
                    "recovery_boot_id": classified["metadata"][
                        "recovery_boot_id"
                    ],
                    "path": str(artifact_sink[0]),
                    "sha256": digest,
                })
                if kind == "initial-unlink-observe":
                    initial_exclusions += 1
                elif kind == "replacement-arb-read-complete":
                    replacement_exclusions += 1
                else:
                    raise ControllerError(
                        "issue #2 classifier returned an unknown exclusion"
                    ) from probe_error
                print(
                    "EXCLUDE issue=2 "
                    f"attempt={run_index} kind={kind} boot_id={boot_id} "
                    f"artifact={artifact_sink[0]}",
                    flush=True,
                )
                continue
            if exit_code != 0:
                raise ControllerError(
                    "issue #2 qualification identity command failed"
                )
            if (
                len(artifact_sink) != 1
                or not artifact_sink[0].is_file()
            ):
                raise ControllerError(
                    "issue #2 accepted attempt did not create one artefact"
                )
            accepted_evidence = validate_issue_2_accepted_artifact_v2(
                artifact_sink[0],
                expected_boot_id=boot_id,
                qualification_id=qualification_id,
                run_index=accepted_target_index,
                attempt_index=run_index,
            )
            if accepted_evidence is None:
                raise ControllerError(
                    "issue #2 accepted attempt failed strict evidence "
                    "validation"
                )
            accepted_boot_ids.append(boot_id)
            accepted_artifacts.append({
                "target_index": str(accepted_target_index),
                "path": str(artifact_sink[0]),
                "sha256": hashlib.sha256(
                    artifact_sink[0].read_bytes()
                ).hexdigest(),
            })
        if len(accepted_boot_ids) != ISSUE_2_QUALIFICATION_RUNS:
            raise ControllerError("issue #2 qualification evidence is incomplete")
    except BaseException as exception:
        failure = exception
    finally:
        manifest_values = [
            "status=" + ("pass" if failure is None else "fail"),
            "issue=2",
            f"qualification_id={qualification_id}",
            f"classifier_version={ISSUE_2_CLASSIFIER_VERSION}",
            f"runs_required={ISSUE_2_QUALIFICATION_RUNS}",
            f"runs_completed={len(accepted_boot_ids)}",
            f"attempts_total={attempts}",
            f"attempts_limit={ISSUE_2_MAX_ATTEMPTS}",
            f"attempt_limit={ISSUE_2_MAX_ATTEMPTS}",
            f"allocator_exclusion_count={len(exclusions)}",
            f"allocator_exclusion_limit={ISSUE_2_MAX_EXCLUSIONS}",
            f"allocator_exclusions={len(exclusions)}",
            f"allocator_exclusions_limit={ISSUE_2_MAX_EXCLUSIONS}",
            f"accepted_required={ISSUE_2_QUALIFICATION_RUNS}",
            f"max_exclusions={ISSUE_2_MAX_EXCLUSIONS}",
            f"max_attempts={ISSUE_2_MAX_ATTEMPTS}",
            f"attempt_count={attempts}",
            f"accepted_count={len(accepted_boot_ids)}",
            f"excluded_count={len(exclusions)}",
            f"initial_exclusion_count={initial_exclusions}",
            f"replacement_exclusion_count={replacement_exclusions}",
            f"attempt_unique_boot_count={len(set(attempt_boot_ids))}",
            f"accepted_unique_boot_count={len(set(accepted_boot_ids))}",
            "host_retries_allowed=0",
            "host_retries_used=0",
            "attempt_boot_ids=" + json.dumps(
                attempt_boot_ids, separators=(",", ":")
            ),
            "accepted_boot_ids=" + json.dumps(
                accepted_boot_ids, separators=(",", ":")
            ),
            "excluded_boot_ids=" + json.dumps(
                excluded_boot_ids, separators=(",", ":")
            ),
            "accepted_artifacts=" + json.dumps(
                accepted_artifacts, sort_keys=True, separators=(",", ":")
            ),
            "accepted_run_artifacts=" + json.dumps(
                accepted_artifacts, sort_keys=True, separators=(",", ":")
            ),
            "excluded_artifacts=" + json.dumps(
                excluded_artifacts, sort_keys=True, separators=(",", ":")
            ),
            "exclusions=" + json.dumps(
                exclusions, sort_keys=True, separators=(",", ":")
            ),
            "excluded_attempts=" + json.dumps(
                exclusions, sort_keys=True, separators=(",", ":")
            ),
            "failure=" + json.dumps(
                str(failure) if failure else "none",
                separators=(",", ":"),
            ),
        ]
        manifest.write_text(
            "\n".join(manifest_values) + "\n",
            encoding="utf-8",
        )
    if failure is not None:
        if isinstance(failure, (KeyboardInterrupt, SystemExit)):
            raise failure
        raise ControllerError(
            f"issue #2 qualification failed; manifest: {manifest}"
        ) from failure
    print(f"PASS issue-2-qualification manifest={manifest}")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="lp3/lp3")
    value.add_argument("--serial")
    subcommands = value.add_subparsers(dest="action", required=True)
    for name in (
        "probe",
        "build",
        "install",
        "clean-reboot",
        "fast-reset",
        "app-preflight",
        "status",
    ):
        subcommands.add_parser(name)
    probe_command = subcommands.add_parser("primitive-probe")
    probe_command.add_argument("--timeout", type=int, default=1200)
    probe_command.add_argument("--safe-retries", type=int, default=5)
    root_command = subcommands.add_parser("root-probe")
    root_command.add_argument("--timeout", type=int, default=1200)
    direct_root_command = subcommands.add_parser("direct-root-probe")
    direct_root_command.add_argument("--timeout", type=int, default=1200)
    direct_root_command.add_argument("--safe-retries", type=int, default=5)
    su_command = subcommands.add_parser("su")
    su_action = su_command.add_mutually_exclusive_group(required=True)
    su_action.add_argument("-c", "--command")
    su_action.add_argument(
        "--identity",
        action="store_true",
        help="prove the privileged identity without starting a shell",
    )
    su_command.add_argument("--timeout", type=int, default=1200)
    su_command.add_argument("--safe-retries", type=int, default=5)
    qualification_command = subcommands.add_parser("qualify-issue-2")
    qualification_command.add_argument("--timeout", type=int, default=1200)
    teardown_qualification = subcommands.add_parser(
        "qualify-proc-teardown"
    )
    teardown_qualification.add_argument("--timeout", type=int, default=1200)
    teardown_qualification.add_argument(
        "--max-attempts", type=int, default=20
    )
    backup_command = subcommands.add_parser("partition-backup")
    backup_command.add_argument("--timeout", type=int, default=1200)
    repair_command = subcommands.add_parser("jobstore-repair")
    repair_command.add_argument("--timeout", type=int, default=1200)
    repair_command.add_argument("--known-job-count", type=int)
    return value


def main() -> int:
    arguments = parser().parse_args()
    profile = load_profile()
    if arguments.action == "build":
        build()
        return 0
    serial = select_serial(arguments.serial)
    if arguments.action == "probe":
        probe(serial, profile)
    elif arguments.action == "install":
        install(serial, profile)
    elif arguments.action == "clean-reboot":
        clean_reboot(serial, profile)
    elif arguments.action == "fast-reset":
        fast_reset(serial, profile)
    elif arguments.action == "app-preflight":
        app_preflight(serial, profile)
    elif arguments.action == "primitive-probe":
        reliable_primitive_probe(
            serial,
            profile,
            arguments.timeout,
            arguments.safe_retries,
        )
    elif arguments.action == "root-probe":
        primitive_probe(
            serial,
            profile,
            arguments.timeout,
            stage="root-chain",
        )
    elif arguments.action == "direct-root-probe":
        reliable_direct_root_probe(
            serial,
            profile,
            arguments.timeout,
            arguments.safe_retries,
        )
    elif arguments.action == "su":
        return reliable_su(
            serial,
            profile,
            arguments.timeout,
            arguments.safe_retries,
            (
                SU_IDENTITY_COMMAND
                if arguments.identity
                else arguments.command
            ),
        )
    elif arguments.action == "qualify-issue-2":
        qualify_issue_2(serial, profile, arguments.timeout)
    elif arguments.action == "qualify-proc-teardown":
        qualify_proc_teardown(
            serial,
            profile,
            arguments.timeout,
            arguments.max_attempts,
        )
    elif arguments.action == "partition-backup":
        partition_backup(serial, profile, arguments.timeout)
    elif arguments.action == "jobstore-repair":
        jobstore_repair(
            serial,
            profile,
            arguments.timeout,
            arguments.known_job_count,
        )
    elif arguments.action == "status":
        status(serial, profile)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ControllerError as exception:
        print(f"FAIL {exception}", file=sys.stderr)
        raise SystemExit(1)
