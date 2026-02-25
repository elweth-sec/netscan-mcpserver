from typing import Optional

from .settings import NETSCAN_PATH


def base_cmd(module: str) -> list[str]:
    """Return the base command for a netscan module."""
    return [NETSCAN_PATH, module]


def add_targets(
    cmd: list[str],
    targets: Optional[str],
    target_file: Optional[str],
) -> None:
    """Append target arguments to cmd in-place."""
    if targets:
        cmd.append(targets)
    if target_file:
        cmd.extend(["-H", target_file])


def add_common(
    cmd: list[str],
    workers: int,
    timeout: int,
    delay: float,
    resume: int,
    nodb: bool,
) -> None:
    """Append common arguments shared by all scanners to cmd in-place."""
    cmd.extend(["-w", str(workers), "--timeout", str(timeout)])
    if delay > 0:
        cmd.extend(["--delay", str(delay)])
    if resume > 0:
        cmd.extend(["--resume", str(resume)])
    if nodb:
        cmd.append("--nodb")
