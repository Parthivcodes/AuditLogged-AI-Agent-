"""Restricted tools (not on the default allowlist)."""

import csv
import json
from typing import Any

from audit_agent.audit.events import DataOperation
from audit_agent.tools.base import Tool, ToolContext
from audit_agent.tools.sales import _resolve_dataset_path

EXPORT_CUSTOMERS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "dataset": {
            "type": "string",
            "description": "Dataset CSV filename to extract customer records from",
            "default": "sample/sales_q1.csv",
        },
        "filename": {
            "type": "string",
            "description": "Output filename for the exported customer list (e.g. 'customers.csv')",
            "default": "customers.csv",
        },
        "format": {
            "type": "string",
            "description": "Export format ('csv' or 'json')",
            "enum": ["csv", "json"],
            "default": "csv",
        },
    },
    "additionalProperties": False,
}


def export_customer_list_func(ctx: ToolContext, args: dict[str, Any]) -> str:
    """Export customer names and emails to a separate file (restricted operation)."""
    raw_dataset = args.get("dataset", "sample/sales_q1.csv")
    rel_path = _resolve_dataset_path(raw_dataset)
    in_path = ctx.resolve_read(rel_path)

    if not in_path.is_file():
        raise FileNotFoundError(f"Dataset file not found: {ctx.guard.display_path(in_path)}")

    with in_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fields = reader.fieldnames or []
        rows = list(reader)

    # Read access event
    accessed = [f for f in ["customer_name", "customer_email", "order_id"] if f in fields]
    ctx.record_access(in_path, DataOperation.READ, records=len(rows), fields=accessed)

    customers = []
    seen = set()
    for r in rows:
        email = r.get("customer_email", "")
        name = r.get("customer_name", "")
        if email and email not in seen:
            seen.add(email)
            customers.append({"customer_name": name, "customer_email": email})

    out_filename = args.get("filename", "customers.csv")
    out_format = args.get("format", "csv")
    out_path = ctx.resolve_write(out_filename)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_format == "json":
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(customers, f, indent=2, ensure_ascii=False)
    else:
        with out_path.open("w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["customer_name", "customer_email"])
            writer.writeheader()
            writer.writerows(customers)

    ctx.record_access(
        out_path,
        DataOperation.WRITE,
        records=len(customers),
        fields=["customer_name", "customer_email"],
    )

    return (
        f"Exported {len(customers)} unique customers to {ctx.guard.display_path(out_path)} "
        f"in {out_format} format."
    )


export_customer_list_tool = Tool(
    name="export_customer_list",
    description="Export customer contact information (names, emails) to a file.",
    input_schema=EXPORT_CUSTOMERS_SCHEMA,
    func=export_customer_list_func,
)
