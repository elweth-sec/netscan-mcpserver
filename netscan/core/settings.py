import os
from pathlib import Path

NETSCAN_PATH: str = os.environ.get("NETSCAN_PATH", "netscan")
SCAN_TIMEOUT: int = int(os.environ.get("NETSCAN_SCAN_TIMEOUT", "600"))
HISTORY_FILE: Path = Path(
    os.environ.get(
        "NETSCAN_HISTORY_FILE",
        Path.home() / ".netscan_history.log",
    )
)
