import asyncio

from .history import log
from .settings import NETSCAN_PATH, SCAN_TIMEOUT


async def run(cmd: list[str]) -> str:
    """Execute a netscan command, log it to history, and return combined stdout/stderr."""
    exit_code: int | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=SCAN_TIMEOUT
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.communicate()
            output = (
                f"[TIMEOUT] Scan timed out after {SCAN_TIMEOUT}s. "
                "Reduce scope or increase NETSCAN_SCAN_TIMEOUT."
            )
            await log(cmd, output, exit_code=None)
            return output

        exit_code = proc.returncode
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()

        parts: list[str] = []
        if out:
            parts.append(out)
        if err:
            parts.append(f"[stderr]\n{err}")

        output = "\n".join(parts) if parts else f"[done] No output (exit {exit_code})"

    except FileNotFoundError:
        output = (
            f"[error] netscan binary not found at '{NETSCAN_PATH}'. "
            "Set the NETSCAN_PATH environment variable."
        )
    except Exception as exc:
        output = f"[error] {exc}"

    await log(cmd, output, exit_code)
    return output
