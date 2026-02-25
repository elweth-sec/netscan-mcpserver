from netscan import mcp
from netscan.core import HISTORY_FILE


@mcp.tool()
async def show_history(last_n: int = 0) -> str:
    """
    Display the netscan command history log.

    Args:
        last_n: Return only the last N entries (0 = all entries)

    Examples:
        show_history()          # full history
        show_history(last_n=5)  # last 5 commands only
    """
    if not HISTORY_FILE.exists():
        return f"No history yet. Log file: {HISTORY_FILE}"

    content = HISTORY_FILE.read_text(encoding="utf-8")

    if last_n > 0:
        # Each entry starts with the separator line
        separator = "─" * 72
        entries = [e for e in content.split(f"\n{separator}") if e.strip()]
        trimmed = entries[-last_n:]
        content = f"\n{separator}".join(trimmed)

    return f"History file: {HISTORY_FILE}\n\n{content}"


@mcp.tool()
async def clear_history() -> str:
    """
    Clear the netscan command history log.
    """
    if not HISTORY_FILE.exists():
        return "History is already empty."

    HISTORY_FILE.write_text("", encoding="utf-8")
    return f"History cleared: {HISTORY_FILE}"
