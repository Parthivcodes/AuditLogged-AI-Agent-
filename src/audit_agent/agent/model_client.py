"""Model client protocol and Anthropic SDK implementation."""

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

from audit_agent.audit.events import TokenUsage


@dataclass(frozen=True)
class ToolCallBlock:
    """A tool use block emitted by the model."""

    id: str
    name: str
    input: dict[str, Any]


@dataclass(frozen=True)
class ModelResponse:
    """Standardized response from a ModelClient."""

    text: str | None
    tool_calls: list[ToolCallBlock]
    stop_reason: str
    tokens: TokenUsage
    latency_ms: float
    raw_content: Any = field(default=None, repr=False)


class ModelClient(Protocol):
    """Protocol for model communication (Anthropic SDK in prod, fakes in tests)."""

    def generate(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str | None = None,
    ) -> ModelResponse: ...


class AnthropicModelClient:
    """Anthropic SDK implementation of ModelClient."""

    def __init__(
        self, api_key: str | None = None, default_model: str = "claude-sonnet-4-5"
    ) -> None:
        import anthropic

        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()
        self.default_model = default_model

    def generate(
        self,
        *,
        system: str,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        model: str | None = None,
    ) -> ModelResponse:
        chosen_model = model or self.default_model

        start_time = time.perf_counter()
        response = self.client.messages.create(
            model=chosen_model,
            system=system,
            messages=messages,
            tools=tools,
            max_tokens=4096,
        )
        latency_ms = (time.perf_counter() - start_time) * 1000.0

        texts: list[str] = []
        tool_calls: list[ToolCallBlock] = []

        for block in response.content:
            if block.type == "text":
                texts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(
                    ToolCallBlock(
                        id=block.id,
                        name=block.name,
                        input=dict(block.input),
                    )
                )

        combined_text = "\n\n".join(texts).strip() if texts else None
        usage = TokenUsage(
            input=response.usage.input_tokens,
            output=response.usage.output_tokens,
        )

        return ModelResponse(
            text=combined_text,
            tool_calls=tool_calls,
            stop_reason=response.stop_reason or "end_turn",
            tokens=usage,
            latency_ms=round(latency_ms, 2),
            raw_content=response.content,
        )
