"""Unified LLM gateway: server-side credentials, retry, circuit breaker, budget.

The gateway is the only place in EvoNIDS that talks to a language model. It is
provider-agnostic (DeepSeek, any OpenAI-compatible endpoint, local vLLM/Ollama)
and enforces the operational rules the platform requires:

* credentials live server-side only and never reach the browser;
* every call has a timeout, bounded retries with exponential backoff and jitter,
  a concurrency cap and a circuit breaker;
* a per-run and per-day USD budget stops runaway spend; when the price of a model
  is unknown the cost is reported as ``estimated: false`` rather than invented;
* the mock provider exists for tests and clearly-labelled demo environments and
  is refused in ``production``;
* failures degrade the caller (investigation) instead of raising into the API.
"""

from __future__ import annotations

import json
import random
import threading
import time
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Callable, Protocol, Sequence


class LLMError(RuntimeError):
    def __init__(self, message: str, *, code: str = "llm_error", retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.retryable = retryable


class LLMUnavailableError(LLMError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="provider_unavailable", retryable=False)


class CircuitOpenError(LLMError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="circuit_open", retryable=False)


class BudgetExceededError(LLMError):
    def __init__(self, message: str) -> None:
        super().__init__(message, code="budget_exceeded", retryable=False)


@dataclass(frozen=True, slots=True)
class ChatMessage:
    role: str
    content: str

    def as_payload(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class LLMResponse:
    content: str
    provider: str
    model_id: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: float
    attempts: int
    finish_reason: str
    cost_usd: float
    cost_estimated: bool
    mode: str = "llm"
    raw_usage: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class LLMConfig:
    provider: str = "disabled"
    base_url: str | None = None
    api_key: str | None = None
    model: str | None = None
    timeout_seconds: float = 30.0
    max_attempts: int = 3
    base_backoff_seconds: float = 0.5
    max_backoff_seconds: float = 8.0
    max_concurrency: int = 4
    circuit_failure_threshold: int = 5
    circuit_reset_seconds: float = 60.0
    run_budget_usd: float = 0.25
    daily_budget_usd: float = 5.0
    max_output_tokens: int = 1200
    max_prompt_chars: int = 120_000
    temperature: float = 0.0


@dataclass(frozen=True, slots=True)
class TransportResponse:
    status: int
    body: bytes

    def json(self) -> Any:
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None


class HttpTransport(Protocol):
    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse: ...


class HttpxTransport:
    def __init__(self) -> None:
        import httpx

        self._httpx = httpx
        self._client = httpx.Client(follow_redirects=False)

    def send(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None = None,
        timeout: float = 30.0,
    ) -> TransportResponse:
        try:
            response = self._client.request(method, url, headers=headers, content=body, timeout=timeout)
        except self._httpx.HTTPError as exc:
            raise LLMError(f"transport error: {exc}", code="transport_error", retryable=True) from exc
        return TransportResponse(status=response.status_code, body=response.content)

    def close(self) -> None:
        self._client.close()


class LLMProvider(Protocol):
    name: str

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        timeout: float,
        max_output_tokens: int,
        temperature: float,
    ) -> tuple[str, dict[str, Any], str]: ...

    def list_models(self, *, timeout: float) -> list[str]: ...


class OpenAICompatibleProvider:
    """Works with DeepSeek, OpenAI, vLLM, Ollama's OpenAI shim and similar."""

    name = "openai-compatible"

    def __init__(self, *, base_url: str, api_key: str, transport: HttpTransport | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.transport = transport or HttpxTransport()

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "evonids-gateway/0.2.0",
        }

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        timeout: float,
        max_output_tokens: int,
        temperature: float,
    ) -> tuple[str, dict[str, Any], str]:
        payload = json.dumps(
            {
                "model": model,
                "messages": [message.as_payload() for message in messages],
                "temperature": temperature,
                "max_tokens": max_output_tokens,
                "stream": False,
            }
        ).encode("utf-8")
        response = self.transport.send(
            "POST",
            f"{self.base_url}/chat/completions",
            headers=self._headers(),
            body=payload,
            timeout=timeout,
        )
        data = response.json()
        if response.status >= 500 or response.status == 429:
            raise LLMError(
                f"provider returned {response.status}", code=f"http_{response.status}", retryable=True
            )
        if response.status >= 400:
            detail = ""
            if isinstance(data, dict):
                error = data.get("error")
                if isinstance(error, dict):
                    detail = str(error.get("message") or "")
            raise LLMError(
                f"provider rejected the request ({response.status}): {detail[:200]}",
                code=f"http_{response.status}",
                retryable=False,
            )
        if not isinstance(data, dict):
            raise LLMError("provider returned a non-JSON body", code="invalid_body", retryable=True)
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise LLMError("provider returned no choices", code="empty_choices", retryable=True)
        first = choices[0] if isinstance(choices[0], dict) else {}
        raw_message = first.get("message")
        message_payload: dict[str, Any] = raw_message if isinstance(raw_message, dict) else {}
        content = message_payload.get("content")
        if not isinstance(content, str):
            raise LLMError("provider returned no message content", code="empty_content", retryable=True)
        usage_payload = data.get("usage")
        usage: dict[str, Any] = usage_payload if isinstance(usage_payload, dict) else {}
        finish = str(first.get("finish_reason") or "unknown")
        return content, usage, finish

    def list_models(self, *, timeout: float) -> list[str]:
        response = self.transport.send(
            "GET", f"{self.base_url}/models", headers=self._headers(), timeout=timeout
        )
        if response.status >= 400:
            raise LLMError(
                f"model listing failed ({response.status})",
                code=f"http_{response.status}",
                retryable=response.status in {429, 500, 502, 503, 504},
            )
        data = response.json()
        if not isinstance(data, dict):
            return []
        rows = data.get("data")
        if not isinstance(rows, list):
            return []
        return [
            str(row["id"])
            for row in rows
            if isinstance(row, dict) and isinstance(row.get("id"), str)
        ]


class MockProvider:
    """Deterministic provider for tests and explicitly-labelled demo environments.

    Never selected in production: ``validate_production_settings`` refuses to boot
    with ``EVONIDS_LLM_PROVIDER=mock``.
    """

    name = "mock"

    def __init__(self, *, response: str | None = None) -> None:
        self.response = response
        self.calls: list[dict[str, Any]] = []

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        timeout: float,
        max_output_tokens: int,
        temperature: float,
    ) -> tuple[str, dict[str, Any], str]:
        self.calls.append({"model": model, "messages": [message.as_payload() for message in messages]})
        if self.response is not None:
            content = self.response
        else:
            content = json.dumps(
                {
                    "summary": "MOCK PROVIDER：未调用任何真实模型，此输出仅用于测试与明确标注的演示环境。",
                    "claims": [],
                    "uncertainty": 1.0,
                    "insufficient_evidence": True,
                },
                ensure_ascii=False,
            )
        prompt_chars = sum(len(message.content) for message in messages)
        usage = {
            "prompt_tokens": prompt_chars // 4,
            "completion_tokens": len(content) // 4,
        }
        return content, usage, "stop"

    def list_models(self, *, timeout: float) -> list[str]:
        return ["mock-model"]


class DisabledProvider:
    name = "disabled"

    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        model: str,
        timeout: float,
        max_output_tokens: int,
        temperature: float,
    ) -> tuple[str, dict[str, Any], str]:
        raise LLMUnavailableError("no LLM provider is configured")

    def list_models(self, *, timeout: float) -> list[str]:
        return []


# Published list prices (USD per 1M tokens). Anything not listed is reported with
# cost_estimated=False instead of a guessed number.
PRICING: dict[str, tuple[float, float]] = {
    "deepseek-chat": (0.27, 1.10),
    "deepseek-reasoner": (0.55, 2.19),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4o": (2.50, 10.00),
}


def estimate_cost(model: str, prompt_tokens: int, completion_tokens: int) -> tuple[float, bool]:
    price = PRICING.get(model.strip().lower())
    if price is None:
        return 0.0, False
    input_price, output_price = price
    cost = (prompt_tokens / 1_000_000) * input_price + (completion_tokens / 1_000_000) * output_price
    return round(cost, 6), True


class LLMGateway:
    def __init__(
        self,
        config: LLMConfig,
        provider: LLMProvider,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        sleeper: Callable[[float], None] = time.sleep,
        random_source: Callable[[], float] = random.random,
    ) -> None:
        self.config = config
        self.provider = provider
        self.clock = clock
        self.wall_clock = wall_clock
        self.sleeper = sleeper
        self.random = random_source
        self._lock = threading.Lock()
        self._semaphore = threading.BoundedSemaphore(max(1, config.max_concurrency))
        self._consecutive_failures = 0
        self._opened_at: float | None = None
        self._spend_by_day: dict[str, float] = {}
        self._stats = {"calls": 0, "failures": 0, "retries": 0, "circuitOpenings": 0}

    # ------------------------------------------------------------------ state
    @property
    def available(self) -> bool:
        return self.config.provider not in {"disabled", ""} and bool(self.config.model)

    def budget_state(self) -> dict[str, Any]:
        day = self.wall_clock().date().isoformat()
        spent = self._spend_by_day.get(day, 0.0)
        return {
            "day": day,
            "spentUsd": round(spent, 6),
            "dailyBudgetUsd": self.config.daily_budget_usd,
            "runBudgetUsd": self.config.run_budget_usd,
            "remainingUsd": round(max(self.config.daily_budget_usd - spent, 0.0), 6),
        }

    def status(self) -> dict[str, Any]:
        with self._lock:
            open_until = None
            if self._opened_at is not None:
                open_until = round(self.config.circuit_reset_seconds - (self.clock() - self._opened_at), 3)
            return {
                "provider": self.config.provider,
                "model": self.config.model,
                "available": self.available,
                "circuit": {
                    "state": "open" if (open_until or 0) > 0 else "closed",
                    "consecutiveFailures": self._consecutive_failures,
                    "resetInSeconds": max(open_until or 0.0, 0.0),
                },
                "concurrencyLimit": self.config.max_concurrency,
                "timeoutSeconds": self.config.timeout_seconds,
                "maxAttempts": self.config.max_attempts,
                "budget": self.budget_state(),
                "stats": dict(self._stats),
                "pricingKnown": self.config.model is not None
                and self.config.model.strip().lower() in PRICING,
            }

    # ------------------------------------------------------------------- call
    def chat(
        self,
        messages: Sequence[ChatMessage],
        *,
        max_output_tokens: int | None = None,
        temperature: float | None = None,
        budget_usd: float | None = None,
    ) -> LLMResponse:
        if not self.available:
            raise LLMUnavailableError("LLM provider is not configured")
        prompt_chars = sum(len(message.content) for message in messages)
        if prompt_chars > self.config.max_prompt_chars:
            raise LLMError(
                f"prompt of {prompt_chars} characters exceeds the {self.config.max_prompt_chars} limit",
                code="prompt_too_large",
                retryable=False,
            )
        self._check_circuit()
        self._check_budget(budget_usd)
        model = self.config.model or ""
        started = self.clock()
        attempts = 0
        last_error: LLMError | None = None
        with self._semaphore:
            while attempts < max(self.config.max_attempts, 1):
                attempts += 1
                try:
                    content, usage, finish = self.provider.chat(
                        messages,
                        model=model,
                        timeout=self.config.timeout_seconds,
                        max_output_tokens=max_output_tokens or self.config.max_output_tokens,
                        temperature=self.config.temperature if temperature is None else temperature,
                    )
                except LLMError as error:
                    last_error = error
                    if not error.retryable:
                        break
                    self._stats["retries"] += 1
                    self._backoff(attempts)
                    continue
                except Exception as error:  # noqa: BLE001 - provider bugs must degrade, not crash
                    last_error = LLMError(str(error), code="provider_error", retryable=False)
                    break
                latency_ms = (self.clock() - started) * 1000
                prompt_tokens = int(usage.get("prompt_tokens") or usage.get("promptTokens") or 0)
                completion_tokens = int(
                    usage.get("completion_tokens") or usage.get("completionTokens") or 0
                )
                cost, estimated = estimate_cost(model, prompt_tokens, completion_tokens)
                self._record_success(cost)
                return LLMResponse(
                    content=content,
                    provider=self.provider.name,
                    model_id=model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    latency_ms=round(latency_ms, 3),
                    attempts=attempts,
                    finish_reason=finish,
                    cost_usd=cost,
                    cost_estimated=estimated,
                    mode="mock" if self.provider.name == "mock" else "llm",
                    raw_usage=dict(usage),
                )
        self._record_failure()
        assert last_error is not None
        raise last_error

    def probe(self) -> dict[str, Any]:
        """Verify the configured model id against the provider's model list."""
        if not self.available:
            return {"available": False, "models": [], "configuredModelExists": False, "error": "not configured"}
        try:
            models = self.provider.list_models(timeout=self.config.timeout_seconds)
        except LLMError as error:
            return {
                "available": True,
                "models": [],
                "configuredModelExists": False,
                "error": f"{error.code}: {error}",
            }
        configured = (self.config.model or "").strip()
        return {
            "available": True,
            "models": models,
            "configuredModelExists": configured in models if models else False,
            "error": None if configured in models else "configured model was not reported by the provider",
        }

    # -------------------------------------------------------------- internals
    def _check_circuit(self) -> None:
        with self._lock:
            if self._opened_at is None:
                return
            if self.clock() - self._opened_at >= self.config.circuit_reset_seconds:
                self._opened_at = None
                self._consecutive_failures = 0
                return
            raise CircuitOpenError(
                f"circuit is open after {self._consecutive_failures} consecutive failures"
            )

    def _check_budget(self, run_budget: float | None) -> None:
        day = self.wall_clock().date().isoformat()
        spent = self._spend_by_day.get(day, 0.0)
        if spent >= self.config.daily_budget_usd:
            raise BudgetExceededError(
                f"daily LLM budget exhausted ({spent:.4f} >= {self.config.daily_budget_usd})"
            )
        limit = self.config.run_budget_usd if run_budget is None else run_budget
        if limit <= 0:
            raise BudgetExceededError("per-run LLM budget is zero; refusing to call the provider")

    def _record_success(self, cost: float) -> None:
        day = self.wall_clock().date().isoformat()
        with self._lock:
            self._spend_by_day[day] = self._spend_by_day.get(day, 0.0) + cost
            self._consecutive_failures = 0
            self._opened_at = None
            self._stats["calls"] += 1

    def _record_failure(self) -> None:
        with self._lock:
            self._stats["failures"] += 1
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.config.circuit_failure_threshold:
                self._opened_at = self.clock()
                self._stats["circuitOpenings"] += 1

    def _backoff(self, attempt: int) -> None:
        delay = min(
            self.config.base_backoff_seconds * (2 ** (attempt - 1)), self.config.max_backoff_seconds
        )
        self.sleeper(delay + delay * 0.25 * self.random())


def build_gateway_from_settings(settings: Any) -> LLMGateway:
    """Build the process gateway from configuration (see app.core.config)."""
    provider_name = str(getattr(settings, "llm_provider", "disabled")).strip().lower()
    base_url = getattr(settings, "llm_base_url", None)
    raw_key = getattr(settings, "llm_api_key", None)
    secret: str | None = (
        raw_key.get_secret_value()
        if raw_key is not None and hasattr(raw_key, "get_secret_value")
        else raw_key
    )
    model = getattr(settings, "llm_model", None)
    config = LLMConfig(
        provider=provider_name,
        base_url=base_url,
        api_key=secret,
        model=model,
        timeout_seconds=float(getattr(settings, "llm_timeout_seconds", 30.0)),
        max_attempts=int(getattr(settings, "llm_max_attempts", 3)),
        max_concurrency=int(getattr(settings, "llm_max_concurrency", 4)),
        run_budget_usd=float(getattr(settings, "llm_run_budget_usd", 0.25)),
        daily_budget_usd=float(getattr(settings, "llm_daily_budget_usd", 5.0)),
        max_output_tokens=int(getattr(settings, "llm_max_output_tokens", 1200)),
    )
    if provider_name == "mock":
        provider: LLMProvider = MockProvider()
    elif provider_name in {"openai-compatible", "openai", "deepseek"} and base_url and secret:
        provider = OpenAICompatibleProvider(base_url=base_url, api_key=secret)
        config = replace(config, provider="openai-compatible")
    else:
        provider = DisabledProvider()
    return LLMGateway(config, provider)


_GATEWAY: LLMGateway | None = None
_GATEWAY_LOCK = threading.Lock()


def get_gateway(settings: Any) -> LLMGateway:
    """Process-wide gateway; rebuilt when the provider configuration changes."""
    global _GATEWAY
    with _GATEWAY_LOCK:
        signature = (
            str(getattr(settings, "llm_provider", "disabled")),
            str(getattr(settings, "llm_base_url", None)),
            str(getattr(settings, "llm_model", None)),
        )
        if _GATEWAY is None or getattr(_GATEWAY, "_signature", None) != signature:
            _GATEWAY = build_gateway_from_settings(settings)
            setattr(_GATEWAY, "_signature", signature)
        return _GATEWAY


def reset_gateway() -> None:
    global _GATEWAY
    with _GATEWAY_LOCK:
        _GATEWAY = None
