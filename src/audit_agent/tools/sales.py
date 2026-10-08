"""Sales data reading tool."""

import csv
import json
from typing import Any

from audit_agent.audit.events import DataOperation
from audit_agent.tools.base import Tool, ToolContext

READ_SALES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "dataset": {
            "type": "string",
            "description": (
                "Dataset filename or relative path inside data directory "
                "(e.g. 'sample/sales_q1.csv' or 'sales_q1')"
            ),
            "default": "sample/sales_q1.csv",
        },
        "limit": {
            "type": "integer",
            "description": "Maximum number of rows to return",
            "minimum": 1,
        },
        "region": {
            "type": "string",
            "description": "Filter by region (e.g. 'North', 'South', 'East', 'West')",
            "enum": ["North", "South", "East", "West"],
        },
    },
    "additionalProperties": False,
}


def _resolve_dataset_path(raw: str) -> str:
    cleaned = raw.strip().replace("\\", "/")
    if cleaned in ("sales_q1", "sales_q1.csv"):
        return "sample/sales_q1.csv"
    if not cleaned.endswith(".csv"):
        return f"{cleaned}.csv"
    return cleaned


def read_sales_data_func(ctx: ToolContext, args: dict[str, Any]) -> str:
    """Read sales records from a CSV file inside the data directory."""
    raw_dataset = args.get("dataset", "sample/sales_q1.csv")
    rel_path = _resolve_dataset_path(raw_dataset)
    file_path = ctx.resolve_read(rel_path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {ctx.guard.display_path(file_path)}")

    with file_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        all_rows = list(reader)

    # Record data access event for the read
    ctx.record_access(
        file_path,
        DataOperation.READ,
        records=len(all_rows),
        fields=fields,
    )

    # Apply optional filtering
    filtered = all_rows
    region_filter = args.get("region")
    if region_filter:
        filtered = [r for r in filtered if r.get("region") == region_filter]

    limit = args.get("limit")
    if limit is not None:
        filtered = filtered[:limit]

    output_data = {
        "dataset": ctx.guard.display_path(file_path),
        "total_records": len(all_rows),
        "returned_records": len(filtered),
        "columns": fields,
        "rows": filtered,
    }
    return json.dumps(output_data, ensure_ascii=False)


read_sales_data_tool = Tool(
    name="read_sales_data",
    description="Read sales records and customer orders from a CSV dataset.",
    input_schema=READ_SALES_SCHEMA,
    func=read_sales_data_func,
)
