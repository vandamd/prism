package com.vandam.prism;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Exact, durable binding for a proven no-mutation cleanup. */
final class SafeResetRecord {
    static final String STATE = "SAFE_RESET_PENDING";
    static final String CHECKPOINT_PROOF_DURABLE = "PROOF_DURABLE";
    static final String CHECKPOINT_APP_RECEIPT = "APP_RECEIPT";
    static final String CHECKPOINT_RETIRING = "RETIRING";
    static final String CHECKPOINT_PROCESSES_RETIRED = "PROCESSES_RETIRED";
    static final String CHECKPOINT_BASELINE_VERIFIED = "BASELINE_VERIFIED";
    static final String CHECKPOINT_PREARMED = "PREARMED";

    private static final String SESSION = "[0-9a-f]{64}";
    private static final String BOOT =
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    private static final String PID = "[1-9][0-9]*";
    private static final String START = "[1-9][0-9]*";
    private static final String DIGEST = "[0-9a-f]{64}";
    private static final String CHECKPOINT =
            "(?:PROOF_DURABLE|APP_RECEIPT|RETIRING|PROCESSES_RETIRED|" +
                    "BASELINE_VERIFIED|PREARMED)";
    private static final Pattern BINDING_PATTERN = Pattern.compile(
            "^version=1 kind=safe-reset session=(" + SESSION + ")" +
                    " boot_id=(" + BOOT + ") proof_sha256=(" + DIGEST + ")" +
                    " helper_pid=(" + PID + ") helper_start=(" + START + ")" +
                    " holder_pid=(" + PID + ") holder_start=(" + START + ")" +
                    " donor_pid=(" + PID + ") donor_start=(" + START + ")" +
                    " ueventd_pid=(" + PID + ") ueventd_start=(" + START + ")" +
                    " cohort=((?:" + PID + ":" + START +
                    ")(?:," + PID + ":" + START + ")*)$");
    private static final Pattern JOURNAL_PATTERN = Pattern.compile(
            "^version=1 state=" + STATE + " checkpoint=(" + CHECKPOINT + ") " +
                    "binding=(version=1 kind=safe-reset .+)$");

    final String session;
    final String bootId;
    final String proofDigest;
    final int helperPid;
    final String helperStart;
    final int holderPid;
    final String holderStart;
    final int donorPid;
    final String donorStart;
    final int ueventdPid;
    final String ueventdStart;
    final Map<Integer, String> cohort;

    private SafeResetRecord(
            String session,
            String bootId,
            String proofDigest,
            int helperPid,
            String helperStart,
            int holderPid,
            String holderStart,
            int donorPid,
            String donorStart,
            int ueventdPid,
            String ueventdStart,
            Map<Integer, String> cohort) {
        this.session = session;
        this.bootId = bootId;
        this.proofDigest = proofDigest;
        this.helperPid = helperPid;
        this.helperStart = helperStart;
        this.holderPid = holderPid;
        this.holderStart = holderStart;
        this.donorPid = donorPid;
        this.donorStart = donorStart;
        this.ueventdPid = ueventdPid;
        this.ueventdStart = ueventdStart;
        this.cohort = Collections.unmodifiableMap(new LinkedHashMap<>(cohort));
    }

    static SafeResetRecord create(
            String session,
            String bootId,
            String result,
            String progress,
            int helperPid,
            String helperStart,
            int holderPid,
            String holderStart,
            int donorPid,
            String donorStart,
            int ueventdPid,
            String ueventdStart,
            Map<Integer, String> cohort) {
        return parse(new SafeResetRecord(
                session,
                bootId,
                digest(result + "\n" + progress),
                helperPid,
                helperStart,
                holderPid,
                holderStart,
                donorPid,
                donorStart,
                ueventdPid,
                ueventdStart,
                cohort).binding());
    }

    static SafeResetRecord parse(String value) {
        if (value == null || value.length() > 8192 ||
                value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return null;
        }
        Matcher match = BINDING_PATTERN.matcher(value);
        if (!match.matches()) {
            return null;
        }
        try {
            Map<Integer, String> cohort = parseCohort(match.group(12));
            SafeResetRecord record = new SafeResetRecord(
                    match.group(1), match.group(2), match.group(3),
                    Integer.parseInt(match.group(4)), match.group(5),
                    Integer.parseInt(match.group(6)), match.group(7),
                    Integer.parseInt(match.group(8)), match.group(9),
                    Integer.parseInt(match.group(10)), match.group(11), cohort);
            return value.equals(record.binding()) ? record : null;
        } catch (RuntimeException exception) {
            return null;
        }
    }

    static Journal parseJournal(String value) {
        if (value == null || value.length() > 9216 ||
                value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) {
            return null;
        }
        Matcher match = JOURNAL_PATTERN.matcher(value);
        if (!match.matches()) {
            return null;
        }
        SafeResetRecord record = parse(match.group(2));
        if (record == null) {
            return null;
        }
        Journal journal = new Journal(match.group(1), record);
        return value.equals(journal.value()) ? journal : null;
    }

    String binding() {
        return "version=1 kind=safe-reset session=" + session +
                " boot_id=" + bootId +
                " proof_sha256=" + proofDigest +
                " helper_pid=" + helperPid +
                " helper_start=" + helperStart +
                " holder_pid=" + holderPid +
                " holder_start=" + holderStart +
                " donor_pid=" + donorPid +
                " donor_start=" + donorStart +
                " ueventd_pid=" + ueventdPid +
                " ueventd_start=" + ueventdStart +
                " cohort=" + encodeCohort(cohort);
    }

    String journal(String checkpoint) {
        if (!checkpoint.matches("^" + CHECKPOINT + "$")) {
            throw new IllegalArgumentException("safe-reset-checkpoint");
        }
        return "version=1 state=" + STATE + " checkpoint=" + checkpoint +
                " binding=" + binding();
    }

    static int checkpointRank(String checkpoint) {
        switch (checkpoint) {
            case CHECKPOINT_PROOF_DURABLE:
                return 1;
            case CHECKPOINT_APP_RECEIPT:
                return 2;
            case CHECKPOINT_RETIRING:
                return 3;
            case CHECKPOINT_PROCESSES_RETIRED:
                return 4;
            case CHECKPOINT_BASELINE_VERIFIED:
                return 5;
            case CHECKPOINT_PREARMED:
                return 6;
            default:
                throw new IllegalArgumentException("safe-reset-checkpoint");
        }
    }

    boolean bindsProof(
            String requestedSession,
            String requestedBootId,
            String result,
            String progress,
            int storedHelperPid,
            String storedHelperStart) {
        return session.equals(requestedSession) && bootId.equals(requestedBootId) &&
                proofDigest.equals(digest(result + "\n" + progress)) &&
                helperPid == storedHelperPid && helperStart.equals(storedHelperStart);
    }

    private static Map<Integer, String> parseCohort(String value) {
        Map<Integer, String> cohort = new LinkedHashMap<>();
        int previous = 0;
        for (String item : value.split(",")) {
            String[] fields = item.split(":", -1);
            if (fields.length != 2) {
                throw new IllegalArgumentException("cohort-field");
            }
            int pid = Integer.parseInt(fields[0]);
            if (pid <= previous || !fields[1].matches(START) ||
                    cohort.put(pid, fields[1]) != null) {
                throw new IllegalArgumentException("cohort-order");
            }
            previous = pid;
        }
        if (cohort.isEmpty()) {
            throw new IllegalArgumentException("cohort-empty");
        }
        return cohort;
    }

    private static String encodeCohort(Map<Integer, String> cohort) {
        if (cohort == null || cohort.isEmpty()) {
            throw new IllegalArgumentException("cohort-empty");
        }
        List<Integer> pids = new ArrayList<>(cohort.keySet());
        Collections.sort(pids);
        StringBuilder value = new StringBuilder();
        int previous = 0;
        for (int pid : pids) {
            String start = cohort.get(pid);
            if (pid <= previous || start == null || !start.matches(START)) {
                throw new IllegalArgumentException("cohort-binding");
            }
            if (value.length() > 0) {
                value.append(',');
            }
            value.append(pid).append(':').append(start);
            previous = pid;
        }
        return value.toString();
    }

    private static String digest(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(
                    value.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(bytes.length * 2);
            for (byte item : bytes) {
                result.append(String.format(Locale.ROOT, "%02x", item & 0xff));
            }
            return result.toString();
        } catch (Exception exception) {
            throw new IllegalStateException("safe-reset-digest", exception);
        }
    }

    static final class Journal {
        final String checkpoint;
        final SafeResetRecord record;

        Journal(String checkpoint, SafeResetRecord record) {
            this.checkpoint = checkpoint;
            this.record = record;
        }

        String value() {
            return record.journal(checkpoint);
        }
    }
}
