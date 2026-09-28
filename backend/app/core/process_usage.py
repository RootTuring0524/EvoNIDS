"""Portable child-process CPU and peak-memory measurement.

The rule-validation requirement asks for the execution cost of a sandbox replay
(CPU and memory) next to precision/recall. Neither ``psutil`` nor POSIX
``resource.RUSAGE_CHILDREN`` is available on every platform this project runs on
(Windows has no ``RUSAGE_CHILDREN``), so this module measures through the OS API
that does exist and returns ``None`` - reported as "unmeasured" - when neither
path is available. It never guesses a number.
"""

from __future__ import annotations

import ctypes
import sys
import time
from dataclasses import dataclass
from typing import Any, Sequence


@dataclass(frozen=True, slots=True)
class ProcessUsage:
    cpu_seconds: float | None
    peak_rss_kb: int | None
    exit_code: int
    wall_seconds: float
    source: str
    error: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "cpuSeconds": self.cpu_seconds,
            "peakRssKb": self.peak_rss_kb,
            "exitCode": self.exit_code,
            "wallSeconds": round(self.wall_seconds, 3),
            "source": self.source,
            "measured": {
                "cpuSeconds": self.cpu_seconds is not None,
                "peakRssKb": self.peak_rss_kb is not None,
            },
            "error": self.error,
        }


def _posix_child_usage() -> tuple[float | None, int | None, str, str | None]:
    try:
        import resource
    except ImportError as error:  # pragma: no cover - Windows without resource
        return None, None, "unavailable", str(error)
    if not hasattr(resource, "RUSAGE_CHILDREN"):
        return None, None, "unavailable", "resource.RUSAGE_CHILDREN is not available on this platform"
    # mypy sees the Windows stub where RUSAGE_CHILDREN/getrusage are absent.
    getrusage = getattr(resource, "getrusage")
    usage = getrusage(getattr(resource, "RUSAGE_CHILDREN"))
    cpu = float(usage.ru_utime) + float(usage.ru_stime)
    # ru_maxrss is kilobytes on Linux and bytes on macOS.
    peak_kb = int(usage.ru_maxrss)
    if sys.platform == "darwin":
        peak_kb = peak_kb // 1024
    return cpu, peak_kb, "resource.RUSAGE_CHILDREN", None


def _windows_child_usage(handle: int) -> tuple[float | None, int | None, str, str | None]:
    """Read CPU time and peak working set from a running process handle."""
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        psapi = ctypes.WinDLL("psapi", use_last_error=True)
    except OSError as error:  # pragma: no cover - non-Windows
        return None, None, "unavailable", str(error)

    class FILETIME(ctypes.Structure):
        _fields_ = [("dwLowDateTime", ctypes.c_ulong), ("dwHighDateTime", ctypes.c_ulong)]

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    creation, exit_time, kernel, user = FILETIME(), FILETIME(), FILETIME(), FILETIME()
    ok = kernel32.GetProcessTimes(
        ctypes.c_void_p(handle),
        ctypes.byref(creation),
        ctypes.byref(exit_time),
        ctypes.byref(kernel),
        ctypes.byref(user),
    )
    if not ok:
        return None, None, "unavailable", f"GetProcessTimes failed ({ctypes.get_last_error()})"

    def to_seconds(value: FILETIME) -> float:
        return ((value.dwHighDateTime << 32) | value.dwLowDateTime) / 10_000_000

    counters = PROCESS_MEMORY_COUNTERS()
    counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
    peak_kb: int | None = None
    if psapi.GetProcessMemoryInfo(ctypes.c_void_p(handle), ctypes.byref(counters), counters.cb):
        peak_kb = int(counters.PeakWorkingSetSize // 1024)
    return to_seconds(kernel) + to_seconds(user), peak_kb, "win32:GetProcessTimes", None


def run_measured(
    command: Sequence[str],
    *,
    cwd: str | None = None,
    timeout: float = 300.0,
    poll_seconds: float = 0.05,
) -> tuple[int, str, str, ProcessUsage]:
    """Run a command, capturing stdout/stderr plus measured resource usage.

    Returns ``(exit_code, stdout, stderr, usage)``. ``usage`` values are ``None``
    when the platform does not expose them.
    """
    import subprocess

    started = time.perf_counter()
    process = subprocess.Popen(  # noqa: S603 - command is built from validated parts
        list(command),
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peak_kb: int | None = None
    usage_error: str | None = None
    handle: int | None = None
    if sys.platform == "win32" and process.pid:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            handle = int(kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, process.pid) or 0)
            if not handle:
                handle = None
                usage_error = "OpenProcess failed; resource usage is unmeasured"
        except OSError as error:  # pragma: no cover - defensive
            usage_error = str(error)
    try:
        while True:
            if process.poll() is not None:
                break
            if handle and sys.platform == "win32":
                _, sampled_kb, _, _ = _windows_child_usage(handle)
                if sampled_kb is not None:
                    peak_kb = max(peak_kb or 0, sampled_kb)
            if time.perf_counter() - started > timeout:
                process.kill()
                raise TimeoutError(f"command exceeded {timeout} seconds")
            time.sleep(poll_seconds)
        stdout, stderr = process.communicate()
        exit_code = process.returncode if process.returncode is not None else -1
    finally:
        if handle:
            try:
                ctypes.WinDLL("kernel32").CloseHandle(ctypes.c_void_p(handle))
            except OSError:  # pragma: no cover - defensive
                pass
    wall = time.perf_counter() - started
    if sys.platform == "win32":
        cpu = None
        source = "win32:GetProcessTimes"
        if handle is None:
            source = "unavailable"
        else:
            # The process has exited, so read the final numbers from a fresh
            # handle to its pid is not possible; use the sampled peak only.
            cpu = None
            usage_error = usage_error or "CPU time is not readable after the process exits on Windows"
        return exit_code, stdout, stderr, ProcessUsage(
            cpu_seconds=cpu,
            peak_rss_kb=peak_kb,
            exit_code=exit_code,
            wall_seconds=wall,
            source=source,
            error=usage_error,
        )
    cpu, rss_kb, source, error = _posix_child_usage()
    return exit_code, stdout, stderr, ProcessUsage(
        cpu_seconds=cpu,
        peak_rss_kb=rss_kb if rss_kb is not None else peak_kb,
        exit_code=exit_code,
        wall_seconds=wall,
        source=source,
        error=error or usage_error,
    )


def platform_support() -> dict[str, Any]:
    """What this host can actually measure (used in capability reporting)."""
    if sys.platform == "win32":
        return {
            "cpuSeconds": False,
            "peakRssKb": True,
            "wallSeconds": True,
            "note": (
                "Windows 下可测量峰值内存与墙钟时间；子进程 CPU 时间需 psutil 或作业对象，"
                "当前环境未安装，故 CPU 时间保持未测量。"
            ),
        }
    try:
        import resource  # noqa: F401

        return {
            "cpuSeconds": hasattr(resource, "RUSAGE_CHILDREN"),
            "peakRssKb": hasattr(resource, "RUSAGE_CHILDREN"),
            "wallSeconds": True,
            "note": "POSIX：通过 resource.RUSAGE_CHILDREN 测量子进程 CPU 与峰值内存。",
        }
    except ImportError:  # pragma: no cover
        return {
            "cpuSeconds": False,
            "peakRssKb": False,
            "wallSeconds": True,
            "note": "当前平台不可测量子进程资源。",
        }


__all__ = ["ProcessUsage", "platform_support", "run_measured"]
