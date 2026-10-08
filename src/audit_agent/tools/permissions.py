"""Tool allowlist and filesystem sandbox.

``PermissionGuard`` answers two questions before anything runs:

* **May this tool run at all?** Only names on the allowlist are approved.
* **May it touch this path?** Reads must resolve inside the data dir; writes inside
  the output dir. Paths are fully resolved (``..``, absolute paths, symlinks) before
  the containment check, so a tool cannot escape its sandbox.

Path checks raise ``PermissionDenied`` *before* any I/O happens.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

DEFAULT_ALLOWLIST: tuple[str, ...] = ("read_sales_data", "calculate_stats", "write_summary")


class PermissionDenied(Exception):
    """A tool or path was refused by the ``PermissionGuard``."""


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str


class PermissionGuard:
    def __init__(
        self,
        data_dir: str | Path,
        output_dir: str | Path,
        allowlist: Iterable[str] = DEFAULT_ALLOWLIST,
    ) -> None:
        self.data_dir = Path(data_dir).resolve()
        self.output_dir = Path(output_dir).resolve()
        self.allowlist = frozenset(allowlist)

    def check_tool(self, name: str) -> Verdict:
        if name in self.allowlist:
            return Verdict(True, f"Tool {name!r} is in the allowlist")
        return Verdict(False, f"Tool {name!r} is not in the allowlist")

    def resolve_read(self, path: str | Path) -> Path:
        """Resolve ``path`` (relative to the data dir) and ensure it stays inside it."""
        return _contain(self.data_dir, path, "read")

    def resolve_write(self, path: str | Path) -> Path:
        """Resolve ``path`` (relative to the output dir) and ensure it stays inside it."""
        return _contain(self.output_dir, path, "write")

    def display_path(self, path: Path) -> str:
        """Short, stable label for a sandboxed path, e.g. ``data/sample/sales_q1.csv``."""
        for root in (self.data_dir, self.output_dir):
            if path.is_relative_to(root):
                return (Path(root.name) / path.relative_to(root)).as_posix()
        raise PermissionDenied(f"{path} is outside the sandbox")


def _contain(root: Path, path: str | Path, operation: str) -> Path:
    if not str(path).strip():
        raise PermissionDenied(f"Empty path is not allowed for {operation}")
    resolved = (root / path).resolve()  # an absolute ``path`` replaces ``root`` here
    if resolved == root or not resolved.is_relative_to(root):
        raise PermissionDenied(f"Path {str(path)!r} is outside the allowed {operation} directory")
    return resolved
