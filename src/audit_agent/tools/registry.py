"""Registry of available tools."""

from collections.abc import Iterable
from typing import Any

from audit_agent.tools.base import Tool
from audit_agent.tools.restricted import export_customer_list_tool
from audit_agent.tools.sales import read_sales_data_tool
from audit_agent.tools.summary import calculate_stats_tool, write_summary_tool


class ToolRegistry:
    """A collection of tools accessible by name."""

    def __init__(self, tools: Iterable[Tool] = ()) -> None:
        self._tools: dict[str, Tool] = {}
        for tool in tools:
            self.register(tool)

    def register(self, tool: Tool) -> None:
        self._tools[tool.name] = tool

    def get(self, name: str) -> Tool | None:
        return self._tools.get(name)

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def list_tools(self) -> list[Tool]:
        return list(self._tools.values())

    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def anthropic_schemas(self, names: Iterable[str] | None = None) -> list[dict[str, Any]]:
        """Return the Anthropic tool schemas (with rationale auto-injected)."""
        target = (
            self.list_tools()
            if names is None
            else [self._tools[n] for n in names if n in self._tools]
        )
        return [tool.anthropic_schema() for tool in target]


def create_default_registry() -> ToolRegistry:
    """Create a registry containing all standard and restricted demonstration tools."""
    return ToolRegistry(
        [
            read_sales_data_tool,
            calculate_stats_tool,
            write_summary_tool,
            export_customer_list_tool,
        ]
    )
