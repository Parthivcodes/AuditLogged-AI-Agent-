"""Agent loop driving ModelClient ↔ Tool execution with complete audit logging."""

import time
from dataclasses import dataclass
from typing import Any

from audit_agent.agent.model_client import ModelClient, ToolCallBlock
from audit_agent.agent.prompts import SYSTEM_PROMPT
from audit_agent.audit.events import Actor, ErrorInfo, Status
from audit_agent.audit.logger import AuditLogger
from audit_agent.tools.base import ToolContext
from audit_agent.tools.permissions import PermissionGuard
from audit_agent.tools.registry import ToolRegistry


@dataclass(frozen=True)
class AgentRunResult:
    """Outcome of an agent execution."""

    run_id: str
    success: bool
    final_response: str | None
    error: str | None
    step_count: int


class AgentRunner:
    """Orchestrates the model and tool execution loop."""

    def __init__(
        self,
        *,
        model_client: ModelClient,
        logger: AuditLogger,
        registry: ToolRegistry,
        guard: PermissionGuard,
        model: str = "claude-sonnet-4-5",
        max_steps: int = 10,
    ) -> None:
        self.model_client = model_client
        self.logger = logger
        self.registry = registry
        self.guard = guard
        self.model = model
        self.max_steps = max_steps

    def run(self, user_prompt: str, run_id: str | None = None) -> AgentRunResult:
        """Run the agent on a user prompt, recording every step in the audit log."""
        active_run_id = run_id or self.logger.new_run_id()

        # Step 1: Log initial user request
        self.logger.user_request(active_run_id, user_prompt)

        messages: list[dict[str, Any]] = [{"role": "user", "content": user_prompt}]
        tool_schemas = self.registry.anthropic_schemas()

        step_counter = 0

        try:
            while step_counter < self.max_steps:
                step_counter += 1

                # Step 2: Query the model
                try:
                    response = self.model_client.generate(
                        system=SYSTEM_PROMPT,
                        messages=messages,
                        tools=tool_schemas,
                        model=self.model,
                    )
                except Exception as exc:
                    self.logger.error(
                        active_run_id,
                        ErrorInfo(type=type(exc).__name__, message=str(exc)),
                        actor=Actor.SYSTEM,
                        model=self.model,
                    )
                    return AgentRunResult(
                        run_id=active_run_id,
                        success=False,
                        final_response=None,
                        error=str(exc),
                        step_count=step_counter,
                    )

                # Step 3: Handle model responses with tool calls
                if response.tool_calls:
                    assistant_content = response.raw_content
                    if assistant_content is None:
                        # Build synthetic message content if raw_content was not
                        # supplied (e.g. in tests)
                        content_blocks: list[dict[str, Any]] = []
                        if response.text:
                            content_blocks.append({"type": "text", "text": response.text})
                        for tc in response.tool_calls:
                            content_blocks.append(
                                {
                                    "type": "tool_use",
                                    "id": tc.id,
                                    "name": tc.name,
                                    "input": tc.input,
                                }
                            )
                        assistant_content = content_blocks

                    messages.append({"role": "assistant", "content": assistant_content})

                    tool_results: list[dict[str, Any]] = []

                    for idx, tool_call in enumerate(response.tool_calls):
                        # Attribute token usage and explanation to the first decision
                        tokens = response.tokens if idx == 0 else None
                        explanation = response.text if idx == 0 else None

                        result_block = self._handle_tool_call(
                            run_id=active_run_id,
                            tool_call=tool_call,
                            model_explanation=explanation,
                            model_latency_ms=response.latency_ms if idx == 0 else None,
                            tokens=tokens,
                        )
                        tool_results.append(result_block)

                    messages.append({"role": "user", "content": tool_results})
                    continue

                # Step 4: Model returned text answer without tool calls
                final_text = response.text or "Done."
                self.logger.final_response(
                    active_run_id,
                    final_text,
                    model=self.model,
                    model_explanation=response.text,
                    latency_ms=response.latency_ms,
                    tokens=response.tokens,
                )
                return AgentRunResult(
                    run_id=active_run_id,
                    success=True,
                    final_response=final_text,
                    error=None,
                    step_count=step_counter,
                )

            # If loop terminated due to max_steps limit
            err_msg = f"Agent exceeded maximum step limit of {self.max_steps}"
            self.logger.error(
                active_run_id,
                ErrorInfo(type="MaxStepsExceeded", message=err_msg),
                actor=Actor.AGENT,
                model=self.model,
            )
            return AgentRunResult(
                run_id=active_run_id,
                success=False,
                final_response=None,
                error=err_msg,
                step_count=step_counter,
            )

        except Exception as exc:
            self.logger.error(
                active_run_id,
                ErrorInfo(type=type(exc).__name__, message=str(exc)),
                actor=Actor.SYSTEM,
                model=self.model,
            )
            return AgentRunResult(
                run_id=active_run_id,
                success=False,
                final_response=None,
                error=str(exc),
                step_count=step_counter,
            )

    def _handle_tool_call(
        self,
        *,
        run_id: str,
        tool_call: ToolCallBlock,
        model_explanation: str | None,
        model_latency_ms: float | None,
        tokens: Any | None,
    ) -> dict[str, Any]:
        """Process a single tool call with permission checks, audit logging, and execution."""
        tool_name = tool_call.name
        raw_args = dict(tool_call.input)
        raw_rationale = raw_args.get("rationale")
        rationale = str(raw_rationale).strip() if raw_rationale is not None else ""

        # Check 1: Mandatory rationale validation
        if not rationale:
            err_msg = f"Tool '{tool_name}' call rejected: missing or empty rationale"
            self.logger.decision(
                run_id,
                f"call_tool:{tool_name}",
                rationale="[missing]",
                model_explanation=model_explanation,
                model=self.model,
                tool_name=tool_name,
                latency_ms=model_latency_ms,
                tokens=tokens,
            )
            self.logger.error(
                run_id,
                ErrorInfo(type="MissingRationale", message=err_msg),
                actor=Actor.AGENT,
                tool_name=tool_name,
                model=self.model,
            )
            return {
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": err_msg,
                "is_error": True,
            }

        # Log valid decision
        self.logger.decision(
            run_id,
            f"call_tool:{tool_name}",
            rationale=rationale,
            model_explanation=model_explanation,
            model=self.model,
            tool_name=tool_name,
            latency_ms=model_latency_ms,
            tokens=tokens,
        )

        # Check 2: PermissionGuard allowlist check
        verdict = self.guard.check_tool(tool_name)
        if not verdict.allowed:
            denied_msg = f"Permission denied: {verdict.reason}"
            self.logger.tool_call(
                run_id,
                tool_name,
                raw_args,
                rationale=rationale,
                status=Status.DENIED,
                decision=f"deny:{tool_name}",
                error=ErrorInfo(type="PermissionDenied", message=verdict.reason),
            )
            return {
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": denied_msg,
                "is_error": True,
            }

        # Check 3: Tool existence
        tool = self.registry.get(tool_name)
        if tool is None:
            err_msg = f"Tool '{tool_name}' not found in registry"
            self.logger.tool_call(
                run_id,
                tool_name,
                raw_args,
                rationale=rationale,
                status=Status.ERROR,
                error=ErrorInfo(type="ToolNotFound", message=err_msg),
            )
            return {
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": err_msg,
                "is_error": True,
            }

        # Check 4: Execute tool in sandbox
        ctx = ToolContext(
            run_id=run_id,
            tool_name=tool_name,
            logger=self.logger,
            guard=self.guard,
        )

        start_t = time.perf_counter()
        try:
            prepared_args = tool.prepare_args(raw_args)
            result_str = tool.func(ctx, prepared_args)
            duration_ms = (time.perf_counter() - start_t) * 1000.0

            self.logger.tool_call(
                run_id,
                tool_name,
                raw_args,
                rationale=rationale,
                status=Status.OK,
                result_preview=result_str,
                latency_ms=round(duration_ms, 2),
            )
            return {
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": result_str,
                "is_error": False,
            }

        except Exception as exc:
            duration_ms = (time.perf_counter() - start_t) * 1000.0
            self.logger.tool_call(
                run_id,
                tool_name,
                raw_args,
                rationale=rationale,
                status=Status.ERROR,
                error=ErrorInfo(type=type(exc).__name__, message=str(exc)),
                latency_ms=round(duration_ms, 2),
            )
            return {
                "type": "tool_result",
                "tool_use_id": tool_call.id,
                "content": f"Tool error: {str(exc)}",
                "is_error": True,
            }
