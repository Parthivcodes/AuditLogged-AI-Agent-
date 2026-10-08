"""Pytest fixtures and test doubles for the test suite."""

from collections.abc import Sequence
from typing import Any

from audit_agent.agent.model_client import ModelResponse, ToolCallBlock
from audit_agent.audit.events import TokenUsage


class FakeModelClient:
    """A scripted ModelClient that returns pre-configured responses in order."""

    def __init__(self, responses: Sequence[ModelResponse] | None = None) -> None:
        self.responses = list(responses or [])
        self.calls: list[dict[str, Any]] = []

    def queue_response(self, response: ModelResponse) -> None:
        self.responses.append(response)

    def generate(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str | None = None,
    ) -> ModelResponse:
        self.calls.append(
            {
                "system": system,
                "messages": messages,
                "tools": tools,
                "model": model,
            }
        )
        if not self.responses:
            raise RuntimeError("FakeModelClient called with no scripted responses remaining")
        return self.responses.pop(0)


def make_tool_response(
    tool_name: str,
    tool_input: dict[str, Any],
    tool_id: str = "tool_1",
    text: str | None = "I will call a tool.",
    tokens: TokenUsage | None = None,
    latency_ms: float = 120.0,
) -> ModelResponse:
    """Helper to build a scripted ModelResponse with a single tool call."""
    usage = tokens if tokens is not None else TokenUsage(input=100, output=25)
    return ModelResponse(
        text=text,
        tool_calls=[ToolCallBlock(id=tool_id, name=tool_name, input=tool_input)],
        stop_reason="tool_use",
        tokens=usage,
        latency_ms=latency_ms,
    )


def make_text_response(
    text: str,
    tokens: TokenUsage | None = None,
    latency_ms: float = 200.0,
) -> ModelResponse:
    """Helper to build a scripted final text ModelResponse."""
    usage = tokens if tokens is not None else TokenUsage(input=150, output=50)
    return ModelResponse(
        text=text,
        tool_calls=[],
        stop_reason="end_turn",
        tokens=usage,
        latency_ms=latency_ms,
    )
