"""
Auto-discovery engine for netscan MCP tools.

Every .py module placed in this directory that uses @mcp.tool() will have
its tools registered automatically. No file outside this directory needs
to be modified when adding a new scanner module.
"""
import importlib
import pkgutil
from pathlib import Path


def _load_all_scanners() -> None:
    package_dir = Path(__file__).parent
    package_name = __name__  # "netscan.scanners"

    for module_info in pkgutil.iter_modules([str(package_dir)]):
        if module_info.name.startswith("_"):
            continue  # skip __init__ and private helpers
        importlib.import_module(f"{package_name}.{module_info.name}")


_load_all_scanners()
