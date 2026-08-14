import asyncio
import re
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from nmapaas.models import ScanProfile

PROFILE_ARGUMENTS = {
    ScanProfile.QUICK: ["-sT", "-Pn", "-T4", "--top-ports", "100"],
    ScanProfile.STANDARD: ["-sT", "-Pn", "-T3", "--top-ports", "1000", "-sV"],
    ScanProfile.FULL: ["-sT", "-Pn", "-T3", "-p-", "-sV"],
}
PROGRESS_PATTERN = re.compile(r"About\s+(\d+(?:\.\d+)?)% done", re.IGNORECASE)


class ScanCancelledError(Exception):
    pass


class ScanExecutionError(Exception):
    pass


async def run_scan(
    target: str,
    profile: ScanProfile,
    *,
    timeout_seconds: int,
    on_progress: Callable[[float], Awaitable[None]],
    should_cancel: Callable[[], Awaitable[bool]],
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="nmapaas-") as temporary_directory:
        output_path = Path(temporary_directory) / "result.xml"
        command = [
            "nmap",
            *PROFILE_ARGUMENTS[profile],
            "--stats-every",
            "1s",
            "-oX",
            str(output_path),
            "--",
            target,
        ]
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        stderr_lines: list[str] = []

        async def consume_stderr() -> None:
            assert process.stderr is not None
            async for raw_line in process.stderr:
                line = raw_line.decode(errors="replace").strip()
                stderr_lines.append(line)
                if match := PROGRESS_PATTERN.search(line):
                    await on_progress(float(match.group(1)))

        stderr_task = asyncio.create_task(consume_stderr())
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout_seconds
        cancelled = False
        timed_out = False
        try:
            while process.returncode is None:
                if await should_cancel():
                    cancelled = True
                    process.terminate()
                    break
                if loop.time() >= deadline:
                    timed_out = True
                    process.terminate()
                    break
                try:
                    await asyncio.wait_for(process.wait(), timeout=0.5)
                except TimeoutError:
                    pass
            if process.returncode is None:
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    process.kill()
                    await process.wait()
            await stderr_task
        finally:
            if not stderr_task.done():
                stderr_task.cancel()

        if cancelled:
            raise ScanCancelledError
        if timed_out:
            raise ScanExecutionError(f"scan exceeded {timeout_seconds} second timeout")
        if process.returncode != 0:
            detail = next((line for line in reversed(stderr_lines) if line), "unknown error")
            raise ScanExecutionError(f"nmap exited with code {process.returncode}: {detail}")
        return parse_nmap_xml(output_path)


def parse_nmap_xml(path: Path) -> dict[str, Any]:
    root = ET.parse(path).getroot()
    hosts: list[dict[str, Any]] = []
    for host_node in root.findall("host"):
        status_node = host_node.find("status")
        addresses = [
            {"address": node.get("addr"), "type": node.get("addrtype")}
            for node in host_node.findall("address")
        ]
        ports = []
        for port_node in host_node.findall("ports/port"):
            state_node = port_node.find("state")
            service_node = port_node.find("service")
            ports.append(
                {
                    "port": int(port_node.get("portid", "0")),
                    "protocol": port_node.get("protocol"),
                    "state": state_node.get("state") if state_node is not None else None,
                    "service": service_node.get("name") if service_node is not None else None,
                    "product": service_node.get("product") if service_node is not None else None,
                    "version": service_node.get("version") if service_node is not None else None,
                }
            )
        hosts.append(
            {
                "status": status_node.get("state") if status_node is not None else "unknown",
                "addresses": addresses,
                "ports": ports,
            }
        )
    finished = root.find("runstats/finished")
    return {
        "scanner": root.get("scanner"),
        "nmap_version": root.get("version"),
        "elapsed_seconds": float(finished.get("elapsed", "0")) if finished is not None else None,
        "hosts": hosts,
    }
