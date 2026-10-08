"""Statistical calculation and summary writing tools."""

import csv
import json
import statistics
from collections import defaultdict
from typing import Any

from audit_agent.audit.events import DataOperation
from audit_agent.tools.base import Tool, ToolContext
from audit_agent.tools.sales import _resolve_dataset_path

CALCULATE_STATS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "dataset": {
            "type": "string",
            "description": "Dataset CSV filename to analyze (default: 'sample/sales_q1.csv')",
            "default": "sample/sales_q1.csv",
        },
        "group_by": {
            "type": "string",
            "description": "Optional dimension to group by ('region', 'product')",
            "enum": ["region", "product"],
        },
    },
    "additionalProperties": False,
}

WRITE_SUMMARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "filename": {
            "type": "string",
            "description": "Output filename inside output directory (e.g. 'q1_summary.txt')",
            "minLength": 1,
        },
        "content": {
            "type": "string",
            "description": "The text summary or report content to write",
            "minLength": 1,
        },
    },
    "required": ["filename", "content"],
    "additionalProperties": False,
}


def calculate_stats_func(ctx: ToolContext, args: dict[str, Any]) -> str:
    """Compute summary statistics and aggregations over a sales dataset."""
    raw_dataset = args.get("dataset", "sample/sales_q1.csv")
    rel_path = _resolve_dataset_path(raw_dataset)
    file_path = ctx.resolve_read(rel_path)

    if not file_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {ctx.guard.display_path(file_path)}")

    with file_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        rows = list(reader)

    accessed_fields = [f for f in ["revenue", "units", "product", "region"] if f in fields]
    ctx.record_access(
        file_path,
        DataOperation.READ,
        records=len(rows),
        fields=accessed_fields,
    )

    if not rows:
        return json.dumps({"dataset": ctx.guard.display_path(file_path), "total_orders": 0})

    revenues = [float(r["revenue"]) for r in rows if "revenue" in r and r["revenue"]]
    units = [int(r["units"]) for r in rows if "units" in r and r["units"]]

    total_revenue = sum(revenues)
    total_units = sum(units)

    stats: dict[str, Any] = {
        "dataset": ctx.guard.display_path(file_path),
        "total_orders": len(rows),
        "total_revenue": round(total_revenue, 2),
        "total_units_sold": total_units,
        "average_order_value": round(statistics.mean(revenues), 2) if revenues else 0.0,
        "median_order_value": round(statistics.median(revenues), 2) if revenues else 0.0,
        "min_order_revenue": round(min(revenues), 2) if revenues else 0.0,
        "max_order_revenue": round(max(revenues), 2) if revenues else 0.0,
    }

    group_by = args.get("group_by")
    if group_by in ("region", "product"):
        group_data: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"units": 0, "revenue": 0.0, "orders": 0}
        )
        for r in rows:
            key = r.get(group_by, "Unknown")
            rev = float(r.get("revenue", 0.0))
            u = int(r.get("units", 0))
            group_data[key]["orders"] += 1
            group_data[key]["units"] += u
            group_data[key]["revenue"] = round(group_data[key]["revenue"] + rev, 2)

        breakdown = {}
        for key, g in sorted(group_data.items(), key=lambda x: x[1]["revenue"], reverse=True):
            share_pct = round((g["revenue"] / total_revenue * 100), 1) if total_revenue > 0 else 0.0
            breakdown[key] = {
                "orders": g["orders"],
                "units": g["units"],
                "revenue": g["revenue"],
                "revenue_share_pct": share_pct,
            }
        stats[f"by_{group_by}"] = breakdown
    else:
        # Include breakdown by both region and product by default
        by_region: dict[str, float] = defaultdict(float)
        by_product: dict[str, float] = defaultdict(float)
        for r in rows:
            by_region[r.get("region", "Unknown")] += float(r.get("revenue", 0.0))
            by_product[r.get("product", "Unknown")] += float(r.get("revenue", 0.0))
        stats["revenue_by_region"] = {
            k: round(v, 2) for k, v in sorted(by_region.items(), key=lambda x: x[1], reverse=True)
        }
        stats["revenue_by_product"] = {
            k: round(v, 2) for k, v in sorted(by_product.items(), key=lambda x: x[1], reverse=True)
        }

    return json.dumps(stats, indent=2, ensure_ascii=False)


def write_summary_func(ctx: ToolContext, args: dict[str, Any]) -> str:
    """Write a text report or summary file into the sandboxed output directory."""
    filename = args["filename"].strip()
    content = args["content"]
    file_path = ctx.resolve_write(filename)

    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as f:
        f.write(content)

    ctx.record_access(
        file_path,
        DataOperation.WRITE,
        records=1,
        fields=["summary_content"],
    )

    display_name = ctx.guard.display_path(file_path)
    return f"Successfully wrote summary to {display_name} ({len(content)} characters)."


calculate_stats_tool = Tool(
    name="calculate_stats",
    description="Calculate aggregated statistics, metrics, and breakdowns from a sales dataset.",
    input_schema=CALCULATE_STATS_SCHEMA,
    func=calculate_stats_func,
)

write_summary_tool = Tool(
    name="write_summary",
    description="Write an analysis summary or report file to the output directory.",
    input_schema=WRITE_SUMMARY_SCHEMA,
    func=write_summary_func,
)
