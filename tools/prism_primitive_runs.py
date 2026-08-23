#!/usr/bin/env python3

import argparse
import datetime as dt
import json
import re
import shutil
import subprocess
import time
from pathlib import Path


PACKAGE = "com.vandam.prism"
HARNESS = f"{PACKAGE}/.HarnessService"


class RunFailure(Exception):
    pass


class Adb:
    def run(
        self,
        *arguments: str,
        check: bool = True,
        timeout: float = 30,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                ["adb", *arguments],
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise RunFailure(f"adb {' '.join(arguments)} timed out") from error
        if check and result.returncode != 0:
            detail = result.stderr.strip()
            raise RunFailure(
                f"adb {' '.join(arguments)} failed" +
                (f": {detail}" if detail else "")
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


class PrimitiveRuns:
    def __init__(self, runs: int, output: Path, timeout: int) -> None:
        self.runs = runs
        self.output = output
        self.timeout = timeout
        self.adb = Adb()
        self.results: list[dict[str, object]] = []

    def execute(self) -> None:
        if shutil.which("adb") is None:
            raise RunFailure("adb is not installed or not on PATH")
        if self.adb.run("get-state", check=False).stdout.strip() != "device":
            raise RunFailure("exactly one authorised ADB device is required")
        if not self.adb.shell("pm", "path", PACKAGE, check=False):
            raise RunFailure("Prism is not installed")
        self.output.mkdir(parents=True, exist_ok=False)
        self.write_summary("running")
        print(f"Evidence directory: {self.output}", flush=True)
        for number in range(1, self.runs + 1):
            result = self.run_once(number)
            self.results.append(result)
            self.write_summary("running")
            if result["outcome"] != "success":
                self.write_summary("failed")
                raise RunFailure(str(result["reason"]))
        self.write_summary("passed")
        print(f"Completed {self.runs} consecutive disclosure runs.", flush=True)

    def run_once(self, number: int) -> dict[str, object]:
        directory = self.output / f"run-{number:03d}"
        directory.mkdir()
        started = time.monotonic()
        boot_id = ""
        print(f"\nRun {number}/{self.runs}", flush=True)
        try:
            boot_id = self.fresh_reboot()
            self.wait_for_safe_thermal_state(boot_id)
            self.require_idle(boot_id)
            self.adb.shell("am", "force-stop", PACKAGE)
            self.adb.shell(
                "run-as", PACKAGE, "rm", "-f",
                "files/chain.progress", "files/direct.result",
            )
            self.adb.run("logcat", "-c", check=False)
            stage_started = time.monotonic()
            self.adb.shell(
                "am", "start-foreground-service", "-n", HARNESS,
                "--es", "stage", "chain-addresses",
            )
            result = self.wait_for_result(boot_id)
            duration = time.monotonic() - stage_started
            progress = self.app_file("chain.progress")
            (directory / "chain.progress").write_text(
                progress, encoding="utf-8"
            )
            (directory / "direct.result").write_text(
                result + "\n", encoding="utf-8"
            )
            (directory / "logcat.txt").write_text(
                self.adb.run("logcat", "-d", check=False).stdout,
                encoding="utf-8",
            )
            self.require_disclosure_only(progress)
            if not result.startswith("status=pass stage=chain-addresses "):
                raise RunFailure("disclosure acquisition missed")
            self.adb.shell("am", "force-stop", PACKAGE)
            self.require_package_retired()
            checkpoint_duration = self.checkpoint_duration(progress)
            print(
                f"Passed: host={duration:.3f}s "
                f"checkpoints={checkpoint_duration:.3f}s",
                flush=True,
            )
            return {
                "run": number,
                "outcome": "success",
                "reason": "",
                "boot_id": boot_id,
                "duration_seconds": round(duration, 6),
                "checkpoint_duration_seconds": round(
                    checkpoint_duration, 6
                ),
            }
        except RunFailure as error:
            duration = time.monotonic() - started
            print(f"Failed: {error}", flush=True)
            return {
                "run": number,
                "outcome": "failure",
                "reason": str(error),
                "boot_id": boot_id,
                "observed_boot_id": self.try_boot_id(),
                "duration_seconds": round(duration, 6),
            }

    def fresh_reboot(self) -> str:
        previous = self.boot_id()
        print(f"Rebooting from {previous}", flush=True)
        self.adb.run("reboot", check=False, timeout=15)
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            boot_id = self.try_boot_id()
            complete = self.adb.shell(
                "getprop", "sys.boot_completed", check=False, timeout=5
            ) if boot_id else ""
            if boot_id and boot_id != previous and complete == "1":
                print(f"Fresh boot: {boot_id}", flush=True)
                return boot_id
            time.sleep(1)
        raise RunFailure("device did not complete a fresh reboot")

    def wait_for_safe_thermal_state(self, boot_id: str) -> None:
        deadline = time.monotonic() + 90
        samples = 0
        last = "unavailable"
        while time.monotonic() < deadline:
            self.require_same_boot(boot_id)
            output = self.adb.shell(
                "dumpsys", "thermalservice", check=False, timeout=10
            )
            statuses = re.findall(r"(?m)^Thermal Status: ([0-9]+)$", output)
            current = output.partition("Current temperatures from HAL:\n")[2]
            current = current.partition(
                "Current cooling devices from HAL:\n"
            )[0]
            batteries = self.temperatures(current, 2, "battery")
            cpus = self.temperatures(current, 0, r"CPU[0-9]+")
            safe = (
                statuses == ["0"] and batteries and batteries[0] < 40.0
                and cpus and max(cpus) < 45.0
            )
            last = (
                f"status={','.join(statuses) or 'missing'} "
                f"battery={batteries[0] if batteries else 'missing'} "
                f"cpu_max={max(cpus) if cpus else 'missing'}"
            )
            samples = samples + 1 if safe else 0
            if samples == 5:
                return
            time.sleep(1)
        raise RunFailure("unsafe thermal state: " + last)

    @staticmethod
    def temperatures(output: str, kind: int, name: str) -> list[float]:
        return [
            float(value)
            for value in re.findall(
                rf"mValue=([0-9]+(?:\.[0-9]+)?), mType={kind}, "
                rf"mName={name}",
                output,
            )
        ]

    def require_idle(self, boot_id: str) -> None:
        self.require_same_boot(boot_id)
        marker = self.adb.shell(
            "cat", "/data/local/tmp/prism-controller-watchdog.pid",
            check=False,
        )
        if f"boot_id={boot_id}" in marker:
            raise RunFailure("a controller watchdog owns the current boot")
        processes = self.adb.shell("pidof", PACKAGE, check=False)
        if processes:
            self.adb.shell("am", "force-stop", PACKAGE)
            self.require_package_retired()

    def require_package_retired(self) -> None:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            output = self.adb.shell(
                "ps", "-A", "-o", "NAME", check=False
            )
            if not any(
                line == PACKAGE or line.startswith(PACKAGE + ":")
                for line in output.splitlines()
            ):
                return
            time.sleep(0.05)
        raise RunFailure("Prism disclosure processes did not retire")

    def wait_for_result(self, boot_id: str) -> str:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            self.require_same_boot(boot_id)
            result = self.app_file("direct.result").strip()
            if result.startswith("status="):
                return result
            time.sleep(0.05)
        raise RunFailure("disclosure run timed out")

    def app_file(self, name: str) -> str:
        return self.adb.shell(
            "run-as", PACKAGE, "cat", f"files/{name}",
            check=False,
        )

    @staticmethod
    def require_disclosure_only(progress: str) -> None:
        forbidden = (
            "arbitrary-read-start", "root-mutation-start",
            "root-write-", "root-window-",
        )
        if any(value in progress for value in forbidden):
            raise RunFailure("benchmark crossed the disclosure-only boundary")

    @staticmethod
    def checkpoint_duration(progress: str) -> float:
        values = [
            int(match.group(1))
            for line in progress.splitlines()
            if (match := re.match(r"^([0-9]+) ", line))
        ]
        if len(values) < 2:
            raise RunFailure("checkpoint timeline is incomplete")
        return (values[-1] - values[0]) / 1000.0

    def boot_id(self) -> str:
        value = self.try_boot_id()
        if not value:
            raise RunFailure("could not read the boot ID")
        return value

    def try_boot_id(self) -> str:
        value = self.adb.shell(
            "cat", "/proc/sys/kernel/random/boot_id",
            check=False, timeout=5,
        )
        return value if re.fullmatch(r"[0-9a-f-]{36}", value) else ""

    def require_same_boot(self, expected: str) -> None:
        observed = self.boot_id()
        if observed != expected:
            raise RunFailure(f"boot ID changed ({expected} -> {observed})")

    def write_summary(self, status: str) -> None:
        (self.output / "summary.json").write_text(
            json.dumps(
                {
                    "requested_runs": self.runs,
                    "completed_runs": len(self.results),
                    "status": status,
                    "results": self.results,
                },
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).astimezone().strftime(
        "%Y%m%d-%H%M%S"
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run fresh-boot, disclosure-only Prism acquisitions."
    )
    parser.add_argument("runs", nargs="?", type=int, default=5)
    parser.add_argument("--timeout", type=int, default=90)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.runs < 1:
        parser.error("runs must be positive")
    return arguments


def main() -> int:
    arguments = parse_arguments()
    output = arguments.output or Path("artifacts/prism-primitive-runs") / timestamp()
    try:
        PrimitiveRuns(arguments.runs, output, arguments.timeout).execute()
    except RunFailure as error:
        print(f"prism-primitive-runs: {error}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
