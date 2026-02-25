import asyncio
from datetime import datetime

from .settings import HISTORY_FILE

_lock = asyncio.Lock()

_SEPARATOR = "─" * 72


async def log(cmd: list[str], output: str, exit_code: int | None) -> None:
    """Append a command + result entry to the history file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cmd_str = " ".join(cmd)

    status = f"exit {exit_code}" if exit_code is not None else "timeout/error"

    entry = (
        f"\n{_SEPARATOR}\n"
        f"[{timestamp}]  {status}\n"
        f"CMD: {cmd_str}\n"
        f"{_SEPARATOR}\n"
        f"{output}\n"
    )

    async with _lock:
        await asyncio.to_thread(_write, entry)


def _write(entry: str) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    with HISTORY_FILE.open("a", encoding="utf-8") as f:
        f.write(entry)
