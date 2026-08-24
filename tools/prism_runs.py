#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path


PRISM_PACKAGE = "com.vandam.prism"
PRISM_COMPONENT = f"{PRISM_PACKAGE}/.PrismActivity"
RESUKISU_PACKAGE = "com.resukisu.resukisu"
SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
SHIZUKU_PERMISSION = "moe.shizuku.manager.permission.API_V23"
REMOTE_SHIZUKU_STARTER = "/data/local/tmp/prism-shizuku-starter"
REMOTE_CONTROLLER_TRACE = "/data/local/tmp/prism-controller.trace"
REMOTE_PERFETTO_TRACE = (
    "/data/misc/perfetto-traces/prism-activation.perfetto-trace"
)

SHELL_LOGS = (
    "/data/local/tmp/prism-controller.trace",
    "/data/local/tmp/light-side-of-the-moon-helper.log",
    "/data/local/tmp/prism-controller-journal",
    "/data/local/tmp/prism-controller-watchdog.pid",
    "/data/local/tmp/prism-arm-holder.pid",
    "/data/local/tmp/light-side-of-the-moon-safe-reset.journal",
    "/data/local/tmp/lp3-native-watchdog.trace",
    "/data/local/tmp/lp3-action-phase",
    "/data/local/tmp/lp3-action-result",
    "/data/local/tmp/lp3-ksud-stage",
)


class RunFailure(Exception):
    pass


class Adb:
    def run(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 30,
        text: bool = True,
    ) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(
                ["adb", *arguments],
                capture_output=True,
                check=False,
                timeout=timeout,
                text=text,
                errors="replace" if text else None,
            )
        except subprocess.TimeoutExpired as error:
            if check:
                raise RunFailure(f"adb {' '.join(arguments)} timed out") from error
            empty = "" if text else b""
            return subprocess.CompletedProcess(
                ["adb", *arguments], 124, empty, empty
            )
        if check and result.returncode != 0:
            standard_error = result.stderr.strip() if text else ""
            raise RunFailure(
                f"adb {' '.join(arguments)} failed"
                + (f": {standard_error}" if standard_error else "")
            )
        return result

    def shell(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 30,
    ) -> str:
        return self.run(
            "shell", *arguments, check=check, timeout=timeout
        ).stdout.strip()

    def exec_bytes(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 30,
    ) -> bytes:
        return self.run(
            "exec-out",
            *arguments,
            check=check,
            timeout=timeout,
            text=False,
        ).stdout


class ForegroundObserver:
    EVENT_PATTERN = re.compile(
        r"^\s*([0-9]+(?:\.[0-9]+)?)\s+\d+\s+\d+\s+I\s+"
        r"wm_set_resumed_activity:\s+\[\d+,([^/\],]+)/"
    )
    ACTIVE_FRAME_PATTERN = re.compile(
        r"^\s*([0-9]+(?:\.[0-9]+)?)\s+\d+\s+\d+\s+I\s+"
        r"PrismVisibleState:\s+active_frame\s+uptime_ns=([0-9]+)$"
    )

    def __init__(self) -> None:
        self.process = subprocess.Popen(
            [
                "adb",
                "logcat",
                "-b",
                "events",
                "-b",
                "main",
                "-v",
                "monotonic",
                "-T",
                "1",
                "wm_set_resumed_activity:I",
                "PrismVisibleState:I",
                "*:S",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            bufsize=1,
        )
        self.lock = threading.Lock()
        self.started_uptime: float | None = None
        self.events: list[dict[str, object]] = []
        self.last_package = ""
        self.reader = threading.Thread(
            target=self.read_events,
            name="prism-foreground-observer",
            daemon=True,
        )
        self.reader.start()

    def begin(self, started_uptime: float) -> None:
        with self.lock:
            self.started_uptime = started_uptime
            self.events.clear()
            self.last_package = ""

    def read_events(self) -> None:
        if self.process.stdout is None:
            return
        for line in self.process.stdout:
            active_match = self.ACTIVE_FRAME_PATTERN.match(line)
            if active_match is not None:
                observed_uptime = float(active_match.group(1))
                with self.lock:
                    if (
                        self.started_uptime is None
                        or observed_uptime < self.started_uptime
                    ):
                        continue
                    event = {
                        "elapsed_seconds": round(
                            observed_uptime - self.started_uptime, 3
                        ),
                        "event": "prism-active-frame",
                        "source": "frame-metrics-live",
                        "foreground_sampled": False,
                        "foreground_observed": False,
                    }
                    self.events.append(event)
                print(
                    f"  {event['elapsed_seconds']:6.1f}s "
                    "Prism Active frame completed",
                    flush=True,
                )
                continue
            match = self.EVENT_PATTERN.match(line)
            if match is None:
                continue
            observed_uptime = float(match.group(1))
            package = match.group(2)
            if package not in {PRISM_PACKAGE, RESUKISU_PACKAGE}:
                continue
            with self.lock:
                if (
                    self.started_uptime is None
                    or observed_uptime < self.started_uptime
                    or package == self.last_package
                ):
                    continue
                self.last_package = package
                event = {
                    "elapsed_seconds": round(
                        observed_uptime - self.started_uptime, 3
                    ),
                    "package": package,
                    "source": "wm_set_resumed_activity-stream",
                    "foreground_sampled": False,
                    "foreground_observed": True,
                }
                self.events.append(event)
            print(
                f"  {event['elapsed_seconds']:6.1f}s "
                f"foreground={package} source=android-lifecycle-live",
                flush=True,
            )

    def snapshot(self) -> list[dict[str, object]]:
        with self.lock:
            return [dict(event) for event in self.events]

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.reader.join(timeout=2)


class PrismRuns:
    def __init__(
        self,
        runs: int,
        output: Path,
        boot_timeout: int,
        run_timeout: int,
        trace: bool,
    ) -> None:
        self.requested_runs = runs
        self.output = output
        self.boot_timeout = boot_timeout
        self.run_timeout = run_timeout
        self.trace = trace
        self.trace_active = False
        self.trace_pid = ""
        self.adb = Adb()
        self.results: list[dict[str, object]] = []
        self.current_run_directory: Path | None = None
        self.current_boot_id = ""

    def execute(self) -> None:
        self.require_tools()
        self.output.mkdir(parents=True, exist_ok=False)
        self.write_json(
            self.output / "session.json",
            {
                "requested_runs": self.requested_runs,
                "started_at": timestamp(),
                "android_serial": os.environ.get("ANDROID_SERIAL", ""),
                "perfetto": self.trace,
                "status": "running",
            },
        )
        print(f"Evidence directory: {self.output}", flush=True)
        self.require_device()
        self.prepare_shizuku_starter()

        for run_number in range(1, self.requested_runs + 1):
            run_directory = self.output / f"run-{run_number:03d}"
            run_directory.mkdir()
            self.current_run_directory = run_directory
            result = self.run_once(run_number, run_directory)
            self.results.append(result)
            self.write_summary("running")
            if result["outcome"] != "success":
                self.write_summary("failed")
                raise RunFailure(str(result["reason"]))

        self.write_summary("passed")
        self.current_run_directory = None
        print(
            f"Completed {self.requested_runs} consecutive successful runs.",
            flush=True,
        )

    def run_once(self, run_number: int, run_directory: Path) -> dict[str, object]:
        started_at = timestamp()
        started_monotonic = time.monotonic()
        activation_started: float | None = None
        boot_id = ""
        saw_resukisu = False
        focus_events: list[dict[str, object]] = []
        foreground_observer: ForegroundObserver | None = None
        print(f"\nRun {run_number}/{self.requested_runs}", flush=True)

        try:
            boot_id = self.fresh_reboot(run_directory)
            self.current_boot_id = boot_id
            print(f"Fresh boot: {boot_id}", flush=True)
            self.start_shizuku(run_directory)
            self.open_prism()
            preflight = self.wait_for_prism_preflight(boot_id)
            self.wait_for_safe_thermal_state(boot_id)
            preflight = self.wait_for_prism_preflight(boot_id)
            (run_directory / "preflight-ui.xml").write_text(
                preflight, encoding="utf-8"
            )
            if self.trace:
                self.start_trace()
            foreground_observer = ForegroundObserver()
            activation_started, activation_uptime = self.tap_text(
                preflight, "ROOT", foreground_observer
            )
            print("Root pressed", flush=True)

            saw_resukisu, focus_events, activation_finished = (
                self.wait_for_activation(
                    boot_id,
                    run_directory,
                    activation_started,
                    activation_uptime,
                    foreground_observer,
                )
            )
            foreground_observer.stop()
            foreground_observer = None
            activation_duration = round(
                activation_finished - activation_started, 3
            )
            self.stop_trace(run_directory)
            self.confirm_active(boot_id)
            self.confirm_manager_working(boot_id, run_directory)
            self.open_prism()
            self.confirm_active(boot_id)
            run_duration = round(time.monotonic() - started_monotonic, 3)
            print(
                f"Run {run_number} passed: "
                f"activation={activation_duration:.1f}s "
                f"run_total={run_duration:.1f}s",
                flush=True,
            )
            self.collect_evidence(run_directory, full=False)
            return {
                "run": run_number,
                "outcome": "success",
                "reason": "",
                "started_at": started_at,
                "finished_at": timestamp(),
                "activation_duration_seconds": activation_duration,
                "duration_seconds": run_duration,
                "boot_id": boot_id,
                "saw_resukisu": saw_resukisu,
                "focus_events": focus_events,
            }
        except (RunFailure, OSError, ET.ParseError) as error:
            if foreground_observer is not None:
                streamed_events = foreground_observer.snapshot()
                focus_events.extend(streamed_events)
                saw_resukisu = saw_resukisu or any(
                    event.get("package") == RESUKISU_PACKAGE
                    for event in streamed_events
                )
                foreground_observer.stop()
                self.write_foreground_events(run_directory, focus_events)
            run_duration = round(time.monotonic() - started_monotonic, 3)
            activation_duration = (
                round(time.monotonic() - activation_started, 3)
                if activation_started is not None else None
            )
            reason = str(error) or error.__class__.__name__
            print(f"Run {run_number} failed: {reason}", flush=True)
            self.collect_evidence(run_directory, full=True)
            return {
                "run": run_number,
                "outcome": "failure",
                "reason": reason,
                "started_at": started_at,
                "finished_at": timestamp(),
                "activation_duration_seconds": activation_duration,
                "duration_seconds": run_duration,
                "boot_id": boot_id,
                "observed_boot_id": self.try_boot_id(),
                "saw_resukisu": saw_resukisu,
                "focus_events": focus_events,
            }

    def require_tools(self) -> None:
        for command in ("adb",):
            if shutil.which(command) is None:
                raise RunFailure(f"{command} is not installed or not on PATH")

    def require_device(self) -> None:
        state = self.adb.run("get-state", check=False).stdout.strip()
        if state != "device":
            raise RunFailure("exactly one authorised ADB device must be available")
        for package in (PRISM_PACKAGE, SHIZUKU_PACKAGE, RESUKISU_PACKAGE):
            if not self.package_path(package):
                raise RunFailure(f"{package} is not installed")

    def package_path(self, package: str) -> str:
        output = self.adb.shell("pm", "path", package, check=False)
        for line in output.splitlines():
            if line.startswith("package:") and line.endswith("/base.apk"):
                return line.removeprefix("package:")
        return ""

    def prepare_shizuku_starter(self) -> None:
        apk_path = self.package_path(SHIZUKU_PACKAGE)
        abi = self.adb.shell("getprop", "ro.product.cpu.abi")
        member = f"lib/{abi}/libshizuku.so"
        print(f"Preparing Shizuku starter for {abi}", flush=True)
        with tempfile.TemporaryDirectory(prefix="prism-runs-") as temporary:
            archive_path = Path(temporary) / "shizuku.apk"
            starter_path = Path(temporary) / "shizuku-starter"
            archive_path.write_bytes(
                self.adb.exec_bytes("cat", apk_path, timeout=60)
            )
            with zipfile.ZipFile(archive_path) as archive:
                if member not in archive.namelist():
                    raise RunFailure(f"Shizuku APK does not contain {member}")
                with archive.open(member) as source, starter_path.open("wb") as target:
                    shutil.copyfileobj(source, target)
            self.adb.run("push", str(starter_path), REMOTE_SHIZUKU_STARTER)
        self.adb.shell("chmod", "0755", REMOTE_SHIZUKU_STARTER)

    def fresh_reboot(self, run_directory: Path) -> str:
        previous_boot = self.boot_id()
        (run_directory / "previous-boot-id.txt").write_text(
            previous_boot + "\n", encoding="utf-8"
        )
        print(f"Rebooting from {previous_boot}", flush=True)
        self.adb.run("reboot", check=False, timeout=15)
        deadline = time.monotonic() + self.boot_timeout
        while time.monotonic() < deadline:
            boot_id = self.try_boot_id()
            boot_complete = (
                self.adb.shell(
                    "getprop", "sys.boot_completed", check=False, timeout=5
                )
                if boot_id
                else ""
            )
            if boot_id != previous_boot and boot_complete == "1":
                self.adb.shell("input", "keyevent", "KEYCODE_WAKEUP", check=False)
                self.adb.shell("wm", "dismiss-keyguard", check=False)
                self.adb.shell("input", "keyevent", "KEYCODE_HOME", check=False)
                return boot_id
            time.sleep(1)
        raise RunFailure("device did not complete a fresh reboot in time")

    def start_shizuku(self, run_directory: Path) -> None:
        self.adb.shell(
            "rm", "-f", "/data/local/tmp/lp3-action-phase", check=False
        )
        apk_path = self.package_path(SHIZUKU_PACKAGE)
        outputs: list[str] = []

        def start_server() -> None:
            outputs.append(self.adb.shell(
                REMOTE_SHIZUKU_STARTER,
                f"--apk={apk_path}",
                check=False,
                timeout=30,
            ))
            (run_directory / "shizuku-start.txt").write_text(
                "\n\n".join(outputs) + "\n", encoding="utf-8"
            )

        start_server()
        deadline = time.monotonic() + 30
        next_retry = time.monotonic() + 3
        attempts = 1
        stable_samples = 0
        while time.monotonic() < deadline:
            pid = self.adb.shell("pidof", "shizuku_server", check=False)
            running_as_shell = False
            if pid:
                status = self.adb.shell("cat", f"/proc/{pid.split()[0]}/status")
                match = re.search(r"^Uid:\s+(\d+)", status, re.MULTILINE)
                running_as_shell = bool(match and match.group(1) == "2000")
            stable_samples = stable_samples + 1 if running_as_shell else 0
            # The Shizuku boot receiver can race the manual starter several
            # seconds after Android reports boot completion. Require a longer
            # uninterrupted shell-server window so that race is observed and
            # recovered before Prism opens.
            if stable_samples == 10:
                break
            if (not running_as_shell and attempts < 3 and
                    time.monotonic() >= next_retry):
                start_server()
                attempts += 1
                next_retry = time.monotonic() + 3
            time.sleep(0.5)
        else:
            raise RunFailure("Shizuku did not start as the shell user")

        self.adb.shell(
            "pm",
            "grant",
            PRISM_PACKAGE,
            SHIZUKU_PERMISSION,
            check=False,
        )
        permissions = self.adb.shell("dumpsys", "package", PRISM_PACKAGE)
        expected = f"{SHIZUKU_PERMISSION}: granted=true"
        if expected not in permissions:
            raise RunFailure("Prism does not have Shizuku permission")
        print("Shizuku running as shell", flush=True)

    def open_prism(self) -> None:
        self.adb.shell("input", "keyevent", "KEYCODE_WAKEUP", check=False)
        self.adb.shell("wm", "dismiss-keyguard", check=False)
        self.adb.shell("cmd", "statusbar", "collapse", check=False)
        self.adb.shell("am", "force-stop", PRISM_PACKAGE)
        self.adb.shell("am", "start", "-W", "-n", PRISM_COMPONENT)
        deadline = time.monotonic() + 15
        used_home = False
        while time.monotonic() < deadline:
            if self.focused_package() == PRISM_PACKAGE:
                return
            if not used_home and time.monotonic() + 5 < deadline:
                time.sleep(2)
                self.adb.shell("input", "keyevent", "KEYCODE_HOME", check=False)
                self.adb.shell("am", "start", "-W", "-n", PRISM_COMPONENT)
                used_home = True
            time.sleep(0.5)
        raise RunFailure("Prism did not become the foreground app")

    def wait_for_prism_preflight(self, boot_id: str) -> str:
        deadline = time.monotonic() + 30
        last_text = ""
        lost_focus_at: float | None = None
        reopen_attempts = 0
        while time.monotonic() < deadline:
            self.require_same_boot(boot_id)
            if self.focused_package() != PRISM_PACKAGE:
                now = time.monotonic()
                if lost_focus_at is None:
                    lost_focus_at = now
                elif now - lost_focus_at >= 2 and reopen_attempts < 3:
                    self.adb.shell(
                        "input", "keyevent", "KEYCODE_WAKEUP", check=False
                    )
                    self.adb.shell("wm", "dismiss-keyguard", check=False)
                    self.adb.shell("cmd", "statusbar", "collapse", check=False)
                    self.adb.shell(
                        "am", "start", "-W", "-n", PRISM_COMPONENT,
                        check=False,
                    )
                    reopen_attempts += 1
                    lost_focus_at = now
                time.sleep(0.5)
                continue
            lost_focus_at = None
            xml = self.ui_xml()
            texts = self.ui_texts(xml)
            last_text = ", ".join(texts)
            required = {"root status", "inactive", "shizuku status", "running",
                        "resukisu status", "installed", "root"}
            controller_trace = self.current_controller_trace(boot_id)
            prepared = re.search(
                r"^[0-9]+ prepare-pass$", controller_trace, re.MULTILINE
            ) is not None
            if required.issubset(set(texts)) and prepared:
                return xml
            if "active" in texts:
                raise RunFailure("root was already active before Root was pressed")
            if "retry" in texts:
                raise RunFailure("Prism opened on a terminal failure")
            time.sleep(0.5)
        raise RunFailure(f"Prism preflight did not settle: {last_text}")

    def wait_for_safe_thermal_state(self, boot_id: str) -> None:
        deadline = time.monotonic() + 90
        safe_samples = 0
        last_state = "unavailable"
        while time.monotonic() < deadline:
            self.require_same_boot(boot_id)
            output = self.adb.shell(
                "dumpsys", "thermalservice", check=False, timeout=10
            )
            statuses = re.findall(r"(?m)^Thermal Status: ([0-9]+)$", output)
            current = output.partition("Current temperatures from HAL:\n")[2]
            current = current.partition("Current cooling devices from HAL:\n")[0]
            batteries = [
                float(value)
                for value in re.findall(
                    r"mValue=([0-9]+(?:\.[0-9]+)?), mType=2, "
                    r"mName=battery",
                    current,
                )
            ]
            cpus = [
                float(value)
                for value in re.findall(
                    r"mValue=([0-9]+(?:\.[0-9]+)?), mType=0, "
                    r"mName=CPU[0-9]+",
                    current,
                )
            ]
            safe = (
                statuses == ["0"]
                and batteries
                and batteries[0] < 40.0
                and cpus
                and max(cpus) < 45.0
            )
            last_state = (
                f"status={','.join(statuses) or 'missing'} "
                f"battery={batteries[0] if batteries else 'missing'} "
                f"cpu_max={max(cpus) if cpus else 'missing'}"
            )
            safe_samples = safe_samples + 1 if safe else 0
            if safe_samples == 5:
                return
            time.sleep(1)
        raise RunFailure(
            "device did not reach a stable safe thermal state: " + last_state
        )

    def wait_for_activation(
        self,
        boot_id: str,
        run_directory: Path,
        started: float,
        started_uptime: float,
        foreground_observer: ForegroundObserver,
    ) -> tuple[bool, list[dict[str, object]], float]:
        deadline = time.monotonic() + self.run_timeout
        saw_resukisu = False
        last_focus = ""
        ui_failures = 0
        events: list[dict[str, object]] = []
        streamed_event_count = 0
        dispatch_retries = 0
        next_dispatch_check = started + 2
        live_action_captured = False

        while time.monotonic() < deadline:
            current_boot = self.try_boot_id()
            if not current_boot:
                current_boot = self.wait_for_device_return(deadline)
            if current_boot != boot_id:
                raise RunFailure(
                    f"device rebooted during activation ({boot_id} -> {current_boot})"
                )

            streamed_events = foreground_observer.snapshot()
            if len(streamed_events) > streamed_event_count:
                new_events = streamed_events[streamed_event_count:]
                events.extend(new_events)
                saw_resukisu = saw_resukisu or any(
                    event.get("package") == RESUKISU_PACKAGE
                    for event in new_events
                )
                streamed_event_count = len(streamed_events)

            focus = self.focused_package()
            if focus != last_focus:
                elapsed = round(time.monotonic() - started, 3)
                event = {
                    "elapsed_seconds": elapsed,
                    "package": focus,
                    "source": "dumpsys-window-sample",
                    "foreground_sampled": True,
                }
                events.append(event)
                with (run_directory / "foreground.jsonl").open(
                    "a", encoding="utf-8"
                ) as output:
                    output.write(json.dumps(event) + "\n")
                print(f"  {elapsed:6.1f}s foreground={focus or 'unknown'}", flush=True)
                last_focus = focus
            if focus == RESUKISU_PACKAGE:
                saw_resukisu = True
            elif focus == PRISM_PACKAGE:
                controller_trace = self.current_controller_trace(boot_id)
                if (
                    not live_action_captured
                    and "resukisu-action-dispatch-pass" in controller_trace
                ):
                    self.capture_live_action_state(run_directory)
                    live_action_captured = True
                if (
                    not controller_trace
                    and time.monotonic() >= next_dispatch_check
                ):
                    try:
                        xml = self.ui_xml()
                    except RunFailure:
                        current_boot = self.try_boot_id()
                        if current_boot and current_boot != boot_id:
                            raise RunFailure(
                                "device rebooted during activation "
                                f"({boot_id} -> {current_boot})"
                            )
                        time.sleep(0.5)
                        continue
                    texts = self.ui_texts(xml)
                    if (
                        "inactive" in texts
                        and "root" in texts
                        and dispatch_retries < 2
                    ):
                        self.tap_text_without_clock(xml, "ROOT")
                        dispatch_retries += 1
                        next_dispatch_check = time.monotonic() + 2
                        elapsed = time.monotonic() - started
                        print(
                            f"  {elapsed:6.1f}s Root dispatch retry "
                            f"{dispatch_retries}",
                            flush=True,
                        )
                        time.sleep(0.1)
                        continue
                    if dispatch_retries >= 2:
                        raise RunFailure(
                            "Root input did not dispatch the activation "
                            "controller"
                        )
                terminal = re.search(
                    r"^[0-9]+ activation-result status=(pass|fail) ",
                    controller_trace,
                    re.MULTILINE,
                )
                if terminal is not None and terminal.group(1) == "fail":
                    raise RunFailure(
                        "the activation controller reported failure"
                    )
                manager_returned = re.search(
                    r"^[0-9]+ return-to-prism-manager-pass$",
                    controller_trace,
                    re.MULTILINE,
                ) is not None
                if terminal is None or not manager_returned:
                    time.sleep(0.1)
                    continue
                try:
                    xml = self.ui_xml()
                except RunFailure:
                    current_boot = self.try_boot_id()
                    if not current_boot:
                        current_boot = self.wait_for_device_return(deadline)
                    if current_boot != boot_id:
                        raise RunFailure(
                            "device rebooted during activation "
                            f"({boot_id} -> {current_boot})"
                        )
                    ui_failures += 1
                    if ui_failures >= 3:
                        raise
                    time.sleep(0.5)
                    continue
                ui_failures = 0
                texts = self.ui_texts(xml)
                if "retry" in texts:
                    (run_directory / "failure-ui.xml").write_text(
                        xml, encoding="utf-8"
                    )
                    raise RunFailure("Prism reported an activation failure")
                if "active" in texts:
                    streamed_events = foreground_observer.snapshot()
                    if len(streamed_events) > streamed_event_count:
                        events.extend(streamed_events[streamed_event_count:])
                        streamed_event_count = len(streamed_events)
                    if not self.has_foreground_round_trip(events):
                        events.extend(self.lifecycle_foreground_events(
                            started_uptime
                        ))
                    active_frames = [
                        event for event in events
                        if event.get("event") == "prism-active-frame"
                    ]
                    prism_returns = [
                        float(event.get("elapsed_seconds", -1.0))
                        for event in events
                        if event.get("package") == PRISM_PACKAGE
                        and event.get("source")
                            == "wm_set_resumed_activity-stream"
                        and any(
                            earlier.get("package") == RESUKISU_PACKAGE
                            and float(earlier.get("elapsed_seconds", -1.0))
                                < float(event.get("elapsed_seconds", -1.0))
                            for earlier in events
                        )
                    ]
                    visible_active_frames = [
                        event for event in active_frames
                        if prism_returns
                        and float(event["elapsed_seconds"])
                            >= prism_returns[-1]
                    ]
                    if not visible_active_frames:
                        time.sleep(0.1)
                        continue
                    active_elapsed = float(
                        visible_active_frames[-1]["elapsed_seconds"]
                    )
                    active_observed = started + active_elapsed
                    saw_resukisu = any(
                        event.get("package") == RESUKISU_PACKAGE
                        for event in events
                    )
                    if self.controller_opened_manager(boot_id):
                        receipt = {
                            "elapsed_seconds": round(
                                active_observed - started, 3
                            ),
                            "event": "manager-return-receipt",
                            "source": "controller-trace",
                            "foreground_sampled": False,
                        }
                        events.append(receipt)
                        print(
                            f"  {receipt['elapsed_seconds']:6.1f}s "
                            "manager-return-receipt source=controller-trace",
                            flush=True,
                        )
                    self.write_foreground_events(run_directory, events)
                    if not self.has_foreground_round_trip(events):
                        raise RunFailure(
                            "the foreground sequence did not show ReSukiSU "
                            "followed by the return to Prism"
                        )
                    return saw_resukisu, events, active_observed
            time.sleep(0.5)
        missing = "ReSukiSU transition" if not saw_resukisu else "return to active Prism"
        raise RunFailure(f"activation timed out waiting for {missing}")

    def capture_live_action_state(self, run_directory: Path) -> None:
        helper_log = self.adb.shell(
            "cat",
            "/data/local/tmp/light-side-of-the-moon-helper.log",
            check=False,
            timeout=2,
        )
        matches = re.findall(r"BRIDGE_READY .* pid=([1-9][0-9]*)", helper_log)
        if not matches:
            return
        pid = matches[-1]
        script = (
            f"echo HELPER_PID={pid}; "
            f"ps -T -p {pid} -o PID,TID,STAT,WCHAN:32,NAME,ARGS"
        )
        snapshot = self.adb.shell(
            "sh", "-c", script, check=False, timeout=8
        )
        (run_directory / "live-action-state.txt").write_text(
            snapshot or f"HELPER_PID={pid}\nCAPTURE_FAILED\n",
            encoding="utf-8",
        )

    def controller_opened_manager(self, boot_id: str) -> bool:
        trace = self.current_controller_trace(boot_id)
        return (
            re.search(
                r"^[0-9]+ return-to-prism-manager-pass$",
                trace,
                re.MULTILINE,
            )
            is not None
        )

    def current_controller_trace(self, boot_id: str) -> str:
        trace = self.adb.shell(
            "cat", REMOTE_CONTROLLER_TRACE, check=False, timeout=5
        )
        return trace if f"controller-start boot_id={boot_id} " in trace else ""

    def confirm_active(self, boot_id: str) -> None:
        for _ in range(3):
            self.require_same_boot(boot_id)
            if self.focused_package() != PRISM_PACKAGE:
                raise RunFailure("Prism did not remain in the foreground")
            texts = self.ui_texts(self.ui_xml())
            if "active" not in texts or "running" not in texts:
                raise RunFailure("active root status did not remain stable")
            time.sleep(1)

    def confirm_manager_working(
        self, boot_id: str, run_directory: Path
    ) -> None:
        self.require_same_boot(boot_id)
        self.adb.shell(
            "am", "force-stop", "--user", "0", RESUKISU_PACKAGE,
            timeout=10,
        )
        self.adb.shell(
            "am", "start", "--user", "0", "-W", "-n",
            RESUKISU_PACKAGE + "/.ui.MainActivity",
            timeout=15,
        )
        deadline = time.monotonic() + 15
        last_xml = ""
        last_texts: set[str] = set()
        while time.monotonic() < deadline:
            self.require_same_boot(boot_id)
            if self.focused_package() != RESUKISU_PACKAGE:
                time.sleep(0.2)
                continue
            last_xml = self.ui_xml()
            last_texts = self.ui_texts(last_xml)
            if {
                "working", "lkm", "jailbreak mode"
            }.issubset(last_texts):
                if "not installed" in last_texts or (
                    "failed to grant root!" in last_texts
                ):
                    break
                (run_directory / "manager-ui.xml").write_text(
                    last_xml, encoding="utf-8"
                )
                return
            time.sleep(0.2)
        if last_xml:
            (run_directory / "manager-ui-failure.xml").write_text(
                last_xml, encoding="utf-8"
            )
        raise RunFailure(
            "ReSukiSU Manager did not report Working, LKM, and "
            "Jailbreak mode without a root warning: "
            + ", ".join(sorted(last_texts))
        )

    def wait_for_device_return(self, overall_deadline: float) -> str:
        deadline = min(overall_deadline, time.monotonic() + self.boot_timeout)
        while time.monotonic() < deadline:
            boot_id = self.try_boot_id()
            if boot_id:
                return boot_id
            time.sleep(1)
        raise RunFailure("ADB did not return after disconnecting during activation")

    def boot_id(self) -> str:
        boot_id = self.try_boot_id()
        if not boot_id:
            raise RunFailure("could not read the device boot ID")
        return boot_id

    def try_boot_id(self) -> str:
        result = self.adb.run(
            "shell",
            "cat",
            "/proc/sys/kernel/random/boot_id",
            check=False,
            timeout=5,
        )
        if result.returncode != 0:
            return ""
        value = result.stdout.strip()
        return value if re.fullmatch(r"[0-9a-f-]{36}", value) else ""

    def require_same_boot(self, expected: str) -> None:
        observed = self.boot_id()
        if observed != expected:
            raise RunFailure(f"boot ID changed ({expected} -> {observed})")

    def focused_package(self) -> str:
        output = self.adb.shell("dumpsys", "window", check=False, timeout=10)
        match = re.search(
            r"mCurrentFocus=.*?\s([A-Za-z0-9._]+)/[A-Za-z0-9.$_/]+", output
        )
        return match.group(1) if match else ""

    def lifecycle_foreground_events(
        self, started_uptime: float
    ) -> list[dict[str, object]]:
        output = self.adb.shell(
            "logcat",
            "-b",
            "events",
            "-d",
            "-v",
            "monotonic",
            check=False,
            timeout=30,
        )
        pattern = re.compile(
            r"^\s*([0-9]+(?:\.[0-9]+)?)\s+\d+\s+\d+\s+I\s+"
            r"wm_set_resumed_activity:\s+\[\d+,([^/\],]+)/",
            re.MULTILINE,
        )
        events: list[dict[str, object]] = []
        last_package = ""
        for match in pattern.finditer(output):
            observed_uptime = float(match.group(1))
            package = match.group(2)
            if observed_uptime < started_uptime or package not in {
                PRISM_PACKAGE,
                RESUKISU_PACKAGE,
            }:
                continue
            if package == last_package:
                continue
            last_package = package
            event = {
                "elapsed_seconds": round(
                    observed_uptime - started_uptime, 3
                ),
                "package": package,
                "source": "wm_set_resumed_activity",
                "foreground_sampled": False,
                "foreground_observed": True,
            }
            events.append(event)
            print(
                f"  {event['elapsed_seconds']:6.1f}s "
                f"foreground={package} source=android-lifecycle",
                flush=True,
            )
        return events

    @staticmethod
    def has_foreground_round_trip(
        events: list[dict[str, object]],
    ) -> bool:
        saw_resukisu = False
        for event in sorted(
            events,
            key=lambda candidate: float(
                candidate.get("elapsed_seconds", 0.0)
            ),
        ):
            package = event.get("package")
            if package == RESUKISU_PACKAGE:
                saw_resukisu = True
            elif package == PRISM_PACKAGE and saw_resukisu:
                return True
        return False

    @staticmethod
    def write_foreground_events(
        run_directory: Path, events: list[dict[str, object]]
    ) -> None:
        ordered = sorted(
            events,
            key=lambda event: (
                float(event.get("elapsed_seconds", 0.0)),
                str(event.get("source", "")),
            ),
        )
        with (run_directory / "foreground.jsonl").open(
            "w", encoding="utf-8"
        ) as output:
            for event in ordered:
                output.write(json.dumps(event) + "\n")

    def ui_xml(self) -> str:
        output = self.adb.exec_bytes(
            "uiautomator", "dump", "/dev/tty", check=False, timeout=15
        ).decode("utf-8", errors="replace")
        start = output.find("<?xml")
        end = output.rfind("</hierarchy>")
        if start < 0 or end < 0:
            raise RunFailure("could not read the foreground UI hierarchy")
        return output[start : end + len("</hierarchy>")]

    def ui_texts(self, xml: str) -> list[str]:
        root = ET.fromstring(xml)
        return [
            text.casefold()
            for node in root.iter()
            if (text := node.attrib.get("text", "").strip())
        ]

    def tap_text(
        self,
        xml: str,
        expected: str,
        foreground_observer: ForegroundObserver,
    ) -> tuple[float, float]:
        root = ET.fromstring(xml)
        for node in root.iter():
            if node.attrib.get("text", "").casefold() != expected.casefold():
                continue
            if node.attrib.get("enabled") != "true":
                continue
            match = re.fullmatch(
                r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                node.attrib.get("bounds", ""),
            )
            if not match:
                continue
            left, top, right, bottom = map(int, match.groups())
            self.adb.shell(
                "input", "keyevent", "KEYCODE_WAKEUP", check=False
            )
            self.adb.shell("wm", "dismiss-keyguard", check=False)
            self.adb.shell("cmd", "statusbar", "collapse", check=False)
            device_uptime = float(
                self.adb.shell("cat", "/proc/uptime").split()[0]
            )
            activation_started = time.monotonic()
            foreground_observer.begin(device_uptime)
            self.tap_bounds(left, top, right, bottom)
            return activation_started, device_uptime
        raise RunFailure(f"could not find the enabled {expected} button")

    def tap_text_without_clock(self, xml: str, expected: str) -> None:
        root = ET.fromstring(xml)
        for node in root.iter():
            if node.attrib.get("text", "").casefold() != expected.casefold():
                continue
            if node.attrib.get("enabled") != "true":
                continue
            match = re.fullmatch(
                r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]",
                node.attrib.get("bounds", ""),
            )
            if match:
                self.tap_bounds(*map(int, match.groups()))
                return
        raise RunFailure(f"could not retry the enabled {expected} button")

    def tap_bounds(self, left: int, top: int, right: int, bottom: int) -> None:
        self.adb.shell(
            "input", "tap", str((left + right) // 2), str((top + bottom) // 2)
        )

    def collect_evidence(self, directory: Path, full: bool) -> None:
        self.stop_trace(directory)
        print(
            f"Collecting {'failure' if full else 'run'} evidence in {directory}",
            flush=True,
        )
        device_state = [
            f"collected_at={timestamp()}",
            f"boot_id={self.try_boot_id()}",
            f"focused_package={self.focused_package()}",
            f"boot_reason={self.adb.shell('getprop', 'ro.boot.bootreason', check=False)}",
            f"uptime={self.adb.shell('uptime', check=False)}",
        ]
        (directory / "device-state.txt").write_text(
            "\n".join(device_state) + "\n", encoding="utf-8"
        )

        for remote in SHELL_LOGS:
            data = self.adb.exec_bytes("cat", remote, check=False, timeout=10)
            if data:
                (directory / Path(remote).name).write_bytes(data)

        archive_path = directory / "app-files.tar"
        result = self.adb.run(
            "exec-out",
            "run-as",
            PRISM_PACKAGE,
            "tar",
            "-cf",
            "-",
            "-C",
            "files",
            ".",
            check=False,
            timeout=30,
            text=False,
        )
        if result.returncode == 0 and result.stdout:
            archive_path.write_bytes(result.stdout)
            app_files = directory / "app-files"
            app_files.mkdir()
            try:
                with tarfile.open(archive_path) as archive:
                    members = archive.getmembers()
                    if any(
                        member.name.startswith("/")
                        or ".." in Path(member.name).parts
                        for member in members
                    ):
                        raise tarfile.TarError("unsafe app evidence path")
                    archive.extractall(app_files, filter="data")
                archive_path.unlink()
            except tarfile.TarError:
                pass

        if not full:
            return
        captures = {
            "logcat.txt": ("logcat", "-b", "all", "-d", "-v", "threadtime"),
            "window.txt": ("dumpsys", "window"),
            "activities.txt": ("dumpsys", "activity", "activities"),
            "processes.txt": ("ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"),
            "properties.txt": ("getprop",),
            "pstore-list.txt": ("ls", "-la", "/sys/fs/pstore"),
        }
        for name, command in captures.items():
            content = self.adb.shell(*command, check=False, timeout=30)
            (directory / name).write_text(content + "\n", encoding="utf-8")
        pstore_names = self.adb.shell(
            "ls", "-1", "/sys/fs/pstore", check=False, timeout=10
        ).splitlines()
        pstore = directory / "pstore"
        for name in pstore_names:
            if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
                continue
            content = self.adb.exec_bytes(
                "cat", f"/sys/fs/pstore/{name}", check=False, timeout=10
            )
            if content:
                pstore.mkdir(exist_ok=True)
                (pstore / name).write_bytes(content)
        try:
            (directory / "failure-ui.xml").write_text(
                self.ui_xml(), encoding="utf-8"
            )
        except (RunFailure, OSError):
            pass
        screenshot = self.adb.exec_bytes(
            "screencap", "-p", check=False, timeout=15
        )
        if screenshot.startswith(b"\x89PNG"):
            (directory / "screen.png").write_bytes(screenshot)

    def start_trace(self) -> None:
        self.adb.shell("rm", "-f", REMOTE_PERFETTO_TRACE, check=False)
        result = self.adb.run(
            "shell", "perfetto", "-o", REMOTE_PERFETTO_TRACE,
            "-b", "16mb", "-t", "5m", "--background-wait",
            "binder/binder_transaction",
            "binder/binder_transaction_received",
            "binder/binder_transaction_buffer_release",
            "binder/binder_transaction_failed_buffer_release",
            "binder/binder_ioctl",
            "sched/sched_process_exec",
            "sched/sched_process_exit",
            "sched/sched_process_fork",
            "sched/sched_process_free",
            "workqueue/workqueue_queue_work",
            "workqueue/workqueue_execute_start",
            "workqueue/workqueue_execute_end",
            check=False, timeout=30,
        )
        trace_pid = result.stdout.strip()
        if result.returncode != 0 or not trace_pid.isdigit():
            raise RunFailure(
                "could not start Perfetto: " + result.stderr.strip()
            )
        self.trace_pid = trace_pid
        self.trace_active = True

    def stop_trace(self, directory: Path) -> None:
        if not self.trace_active:
            return
        self.adb.shell(
            "kill", "-TERM", self.trace_pid, check=False, timeout=10
        )
        for _ in range(10):
            alive = self.adb.run(
                "shell", "kill", "-0", self.trace_pid,
                check=False, timeout=5,
            )
            if alive.returncode != 0:
                break
            time.sleep(0.5)
        self.trace_active = False
        self.trace_pid = ""
        trace = self.adb.exec_bytes(
            "cat", REMOTE_PERFETTO_TRACE, check=False, timeout=60
        )
        if trace:
            (directory / "activation.perfetto-trace").write_bytes(trace)
        else:
            (directory / "perfetto-error.txt").write_text(
                "Perfetto produced no trace data.\n", encoding="utf-8"
            )
        self.adb.shell("rm", "-f", REMOTE_PERFETTO_TRACE, check=False)

    def write_summary(self, status: str) -> None:
        self.write_json(
            self.output / "summary.json",
            {
                "requested_runs": self.requested_runs,
                "completed_runs": len(self.results),
                "successful_runs": sum(
                    result["outcome"] == "success" for result in self.results
                ),
                "status": status,
                "updated_at": timestamp(),
                "results": self.results,
            },
        )

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run consecutive fresh-boot Prism activation attempts."
    )
    parser.add_argument("runs", type=int, help="number of consecutive runs")
    parser.add_argument(
        "--output",
        type=Path,
        help="evidence directory (default: artifacts/prism-runs/<timestamp>)",
    )
    parser.add_argument("--boot-timeout", type=int, default=180)
    parser.add_argument("--run-timeout", type=int, default=360)
    parser.add_argument(
        "--perfetto",
        action="store_true",
        help="capture targeted Binder and lifecycle Perfetto data",
    )
    values = parser.parse_args()
    if values.runs < 1:
        parser.error("runs must be greater than zero")
    return values


def main() -> int:
    values = arguments()
    repository = Path(__file__).resolve().parent.parent
    run_timestamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    output = values.output or repository / "artifacts" / "prism-runs" / run_timestamp
    runner = PrismRuns(
        values.runs, output.resolve(), values.boot_timeout, values.run_timeout,
        values.perfetto,
    )
    try:
        runner.execute()
        return 0
    except KeyboardInterrupt:
        print("Interrupted; no further run will start.", file=sys.stderr)
        if runner.current_run_directory is not None:
            runner.collect_evidence(runner.current_run_directory, full=True)
        return 130
    except RunFailure as error:
        print(f"Stopped: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
