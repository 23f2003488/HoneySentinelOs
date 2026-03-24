"""
HoneySentinel-OS — BaseAgent
Every agent inherits this. The loop is defined here once.
Subclasses only implement: _observe(), _plan(), _act(), _evaluate(), _should_stop()
The orchestration of those 5 steps — the agentic loop — lives here and nowhere else.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Optional

from openai import AsyncAzureOpenAI

from backend.memory import (
    get_memory_store, MemoryStore,
    AgentState, AgentStatus, HITLQuestion, ToolResult, _now,
)
from backend.policy import get_policy_engine, PolicyEngine

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """
    The agentic reasoning loop.

    Loop per iteration:
        1. observe()   — read memory + tool results, build current picture
        2. plan()      — call Azure OpenAI to reason about next action
        3. act()       — call ONE tool based on plan output
        4. evaluate()  — call Azure OpenAI to score result vs goal
        5. decide()    — continue | ask_human | stop

    All state is written to MemoryStore after every step.
    The UI subscribes to MemoryStore change events for live updates.
    """

    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        goal: str,
        session_id: str,
    ):
        self.agent_id   = agent_id
        self.agent_type = agent_type
        self.goal       = goal
        self.session_id = session_id

        # Shared services — injected via singletons
        self.memory: MemoryStore   = get_memory_store()
        self.policy: PolicyEngine  = get_policy_engine()

        # Azure OpenAI client — one per agent instance
        self._llm = AsyncAzureOpenAI(
            azure_endpoint = os.environ["AZURE_OPENAI_ENDPOINT"],
            api_key        = os.environ["AZURE_OPENAI_API_KEY"],
            api_version    = "2024-08-01-preview",
        )
        self._deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

        # Agent config from policy
        self._cfg = self.policy.get_agent_config()

        # Internal loop state (not shared — only for loop control)
        self._running       = True
        self._context_block = self.policy.get_context_prompt()

    # ── Public entry point ────────────────────────────────────────────────────

    async def run(self) -> None:
        """
        Start the agent loop. Call this from the orchestrator.
        Writes initial state to memory then enters the loop.
        """
        state = AgentState(
            agent_id       = self.agent_id,
            agent_type     = self.agent_type,
            goal           = self.goal,
            status         = AgentStatus.RUNNING,
            started_at     = _now(),
            max_iterations = self._cfg.max_iterations,   # FIX: sync UI denominator with policy
        )
        await self.memory.upsert_agent_state(self.session_id, state)
        logger.info(f"[{self.agent_id}] Starting — goal: {self.goal}")

        try:
            await self._loop(state)
        except Exception as e:
            logger.exception(f"[{self.agent_id}] Fatal error")
            state.update(
                status        = AgentStatus.FAILED,
                thought       = f"Fatal error: {e}",
                decision      = "stop",
                finished_at   = _now(),
            )
            await self.memory.upsert_agent_state(self.session_id, state)

    # ── Main loop ─────────────────────────────────────────────────────────────

    async def _loop(self, state: AgentState) -> None:
        while self._running:

            # Guard: max iterations
            if state.iterations >= self._cfg.max_iterations:
                logger.warning(f"[{self.agent_id}] Max iterations reached")
                await self._finish(state, "Max iterations reached — stopping.")
                break

            # Count one full loop iteration
            state.increment()

            # ── STEP 1: OBSERVE ───────────────────────────────────────────────
            observation = await self._observe(state)
            state.update(
                status           = AgentStatus.RUNNING,
                last_observation = _truncate(observation, 400),
                thought          = "Observed environment. Planning next action.",
            )
            await self.memory.upsert_agent_state(self.session_id, state)

            # ── STEP 2: PLAN ──────────────────────────────────────────────────
            plan = await self._plan(state, observation)
            state.update(thought = _truncate(plan.get("thought", ""), 400))
            await self.memory.upsert_agent_state(self.session_id, state)

            # ── STEP 3: ACT ───────────────────────────────────────────────────
            action_result = await self._act(state, plan)
            state.update(
                last_action      = plan.get("action", ""),
                last_observation = _truncate(str(action_result), 400),
            )
            await self.memory.upsert_agent_state(self.session_id, state)

            # ── STEP 4: EVALUATE ──────────────────────────────────────────────
            evaluation = await self._evaluate(state, plan, action_result)
            confidence = float(evaluation.get("confidence", 0.5))
            state.update(confidence = confidence)

            # ── STEP 5: DECIDE ────────────────────────────────────────────────
            if await self._should_stop(state, evaluation):
                await self._finish(state, evaluation.get("reason", "Goal satisfied."))
                break

            if self.policy.should_ask_human(confidence):
                await self._trigger_hitl(state, evaluation)
                # Pause loop — wait for answer
                answered = await self._wait_for_human(state)
                if not answered:
                    await self._finish(state, "HITL timed out — stopping.")
                    break
                # Resume with updated context
                state.update(
                    status   = AgentStatus.RUNNING,
                    decision = "continue_after_human_input",
                )
                await self.memory.upsert_agent_state(self.session_id, state)
                continue

            state.update(decision = "continue")
            await self.memory.upsert_agent_state(self.session_id, state)

            # Small yield so other agents can run concurrently
            await asyncio.sleep(0)

    # ── Abstract steps — subclasses implement these ───────────────────────────

    @abstractmethod
    async def _observe(self, state: AgentState) -> str:
        """
        Read from memory and return a plain-text summary of current state.
        No LLM call here — pure data reading.
        """
        ...

    @abstractmethod
    async def _plan(self, state: AgentState, observation: str) -> dict:
        """
        Call Azure OpenAI to decide the next action.
        Must return: {"thought": str, "action": str, "action_input": dict}
        """
        ...

    @abstractmethod
    async def _act(self, state: AgentState, plan: dict) -> Any:
        """
        Execute the action decided in _plan() by calling a tool.
        No LLM here — pure tool execution.
        Returns raw tool output.
        """
        ...

    @abstractmethod
    async def _evaluate(self, state: AgentState, plan: dict, result: Any) -> dict:
        """
        Call Azure OpenAI to score whether the action moved us toward the goal.
        Must return: {"confidence": float, "goal_met": bool, "reason": str}
        """
        ...

    @abstractmethod
    async def _should_stop(self, state: AgentState, evaluation: dict) -> bool:
        """
        Agent-specific stopping condition.
        Called after evaluate — return True to end the loop.
        """
        ...

    # ── Azure OpenAI helper ───────────────────────────────────────────────────

    async def _llm_call(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.2,
        max_tokens: int = 1000,
    ) -> str:
        """
        Single Azure OpenAI call. All agent LLM calls go through here.
        Low temperature by default — we want deterministic reasoning, not creativity.
        """
        try:
            response = await self._llm.chat.completions.create(
                model       = self._deployment,
                temperature = temperature,
                max_tokens  = max_tokens,
                messages    = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            logger.error(f"[{self.agent_id}] LLM call failed: {e}")
            raise

    def _base_system_prompt(self) -> str:
        """
        Shared system prompt prefix — injected into every agent's prompts.
        This is where policy context grounds every single LLM call.
        """
        return f"""You are a security intelligence agent in the HoneySentinel-OS system.
Your agent ID is {self.agent_id} and your type is {self.agent_type}.
Your current goal: {self.goal}

{self._context_block}

Rules:
- Be precise and evidence-based. Never invent findings without tool evidence.
- If uncertain, say so and lower your confidence score.
- Respond only in the JSON format specified in each prompt.
- Do not repeat findings already written to memory.
"""

    # ── Tool result logging ───────────────────────────────────────────────────

    async def _log_tool(
        self,
        tool_name: str,
        input_summary: str,
        output: Any,
        duration_ms: int,
        success: bool = True,
        error: Optional[str] = None,
    ) -> None:
        result = ToolResult(
            tool_name     = tool_name,
            agent_id      = self.agent_id,
            input_summary = input_summary,
            output        = output,
            success       = success,
            error         = error,
            duration_ms   = duration_ms,
        )
        await self.memory.log_tool_result(self.session_id, result)

    # ── HITL helpers ──────────────────────────────────────────────────────────

    async def _trigger_hitl(self, state: AgentState, evaluation: dict) -> None:
        """
        Agent confidence is below threshold.
        Build a question, write it to memory, set status to WAITING_FOR_HUMAN.
        """
        question_text = evaluation.get(
            "human_question",
            f"Agent {self.agent_id} is uncertain (confidence={state.confidence:.0%}). "
            f"Context: {state.last_observation[:300]}. How should I proceed?"
        )
        q = HITLQuestion(
            agent_id = self.agent_id,
            question = question_text,
            context  = state.last_observation[:500],
            options  = evaluation.get("human_options", []),
        )
        await self.memory.push_question(self.session_id, q)
        state.update(
            status   = AgentStatus.WAITING_FOR_HUMAN,
            decision = f"waiting_for_human:{q.question_id}",
            thought  = f"Confidence {state.confidence:.0%} below threshold. Asking human.",
        )
        await self.memory.upsert_agent_state(self.session_id, state)
        logger.info(f"[{self.agent_id}] HITL triggered — question {q.question_id}")

    async def _wait_for_human(
        self, state: AgentState, timeout_seconds: int = 300
    ) -> bool:
        """
        Poll memory for an answer every 2 seconds.
        Returns True if answered, False if timed out.
        """
        # Extract question_id from decision field
        qid = state.decision.split(":")[-1] if ":" in state.decision else None
        if not qid:
            return False

        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            q = await self.memory.get_question(self.session_id, qid)
            if q and q.answer:
                logger.info(f"[{self.agent_id}] Human answered: {q.answer[:100]}")
                return True
            await asyncio.sleep(2)

        logger.warning(f"[{self.agent_id}] HITL timed out after {timeout_seconds}s")
        return False

    # ── Finish ────────────────────────────────────────────────────────────────

    async def _finish(self, state: AgentState, reason: str) -> None:
        state.update(
            status      = AgentStatus.DONE,
            decision    = "stop",
            thought     = reason,
            finished_at = _now(),
        )
        await self.memory.upsert_agent_state(self.session_id, state)
        logger.info(f"[{self.agent_id}] Done — {reason}")


# ── Utility ────────────────────────────────────────────────────────────────────

def _truncate(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "…"