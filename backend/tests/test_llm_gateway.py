"""LLM gateway: retry, circuit breaker, budget, cost honesty, provider parsing."""
import json

import pytest

from app.services.llm_gateway import (
    BudgetExceededError,
    ChatMessage,
    CircuitOpenError,
    LLMConfig,
    LLMError,
    LLMGateway,
    LLMUnavailableError,
    MockProvider,
    OpenAICompatibleProvider,
    TransportResponse,
    estimate_cost,
)

MESSAGES = [ChatMessage(role="user", content="hello")]


class ScriptedProvider:
    name = "scripted"

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def chat(self, messages, *, model, timeout, max_output_tokens, temperature):
        self.calls += 1
        item = self.outcomes.pop(0) if self.outcomes else ("ok", {}, "stop")
        if isinstance(item, Exception):
            raise item
        return item

    def list_models(self, *, timeout):
        return ["model-a", "model-b"]


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def send(self, method, url, *, headers, body=None, timeout=30.0):
        self.calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
        return self.responses.pop(0)


def _gateway(outcomes, *, model="deepseek-chat", **overrides):
    sleeps = []
    config = LLMConfig(
        provider="openai-compatible",
        base_url="https://llm.test/v1",
        api_key="secret",
        model=model,
        **overrides,
    )
    return (
        LLMGateway(
            config,
            ScriptedProvider(outcomes),
            clock=lambda: 100.0,
            sleeper=sleeps.append,
            random_source=lambda: 0.0,
        ),
        sleeps,
    )


def test_retryable_failure_is_retried_and_succeeds():
    gateway, sleeps = _gateway(
        [LLMError("boom", code="http_503", retryable=True), ("answer", {"prompt_tokens": 10, "completion_tokens": 5}, "stop")]
    )
    response = gateway.chat(MESSAGES)
    assert response.content == "answer"
    assert response.attempts == 2
    assert response.prompt_tokens == 10
    assert sleeps == [0.5]


def test_non_retryable_failure_is_not_retried():
    gateway, sleeps = _gateway([LLMError("bad key", code="http_401", retryable=False)])
    with pytest.raises(LLMError) as error:
        gateway.chat(MESSAGES)
    assert error.value.code == "http_401"
    assert sleeps == []
    assert gateway.status()["stats"]["failures"] == 1


def test_circuit_opens_after_threshold_and_recovers_after_reset():
    gateway, _ = _gateway(
        [LLMError("down", code="http_503", retryable=False)] * 5, circuit_failure_threshold=2
    )
    with pytest.raises(LLMError):
        gateway.chat(MESSAGES)
    with pytest.raises(LLMError):
        gateway.chat(MESSAGES)
    with pytest.raises(CircuitOpenError):
        gateway.chat(MESSAGES)
    assert gateway.status()["circuit"]["state"] == "open"

    # The clock is frozen, so simulate the reset window by moving it forward.
    gateway.clock = lambda: 1000.0
    with pytest.raises(LLMError):
        gateway.chat(MESSAGES)
    assert gateway.status()["circuit"]["state"] == "closed"


def test_zero_run_budget_refuses_to_call_the_provider():
    gateway, _ = _gateway([("answer", {}, "stop")], run_budget_usd=0.0)
    with pytest.raises(BudgetExceededError):
        gateway.chat(MESSAGES)


def test_daily_budget_stops_further_spend():
    gateway, _ = _gateway([("answer", {"prompt_tokens": 0, "completion_tokens": 0}, "stop")], daily_budget_usd=0.000001)
    gateway.chat(MESSAGES)
    gateway._spend_by_day[gateway.wall_clock().date().isoformat()] = 1.0
    with pytest.raises(BudgetExceededError):
        gateway.chat(MESSAGES)


def test_oversized_prompt_is_refused_before_the_call():
    gateway, _ = _gateway([("answer", {}, "stop")], max_prompt_chars=3)
    with pytest.raises(LLMError) as error:
        gateway.chat(MESSAGES)
    assert error.value.code == "prompt_too_large"


def test_cost_is_only_reported_when_the_model_price_is_known():
    cost, estimated = estimate_cost("deepseek-chat", 1_000_000, 1_000_000)
    assert estimated is True
    assert cost == pytest.approx(0.27 + 1.10)
    unknown_cost, unknown_estimated = estimate_cost("some-private-model", 1_000_000, 1_000_000)
    assert unknown_estimated is False
    assert unknown_cost == 0.0


def test_disabled_gateway_is_unavailable_and_probe_is_honest():
    gateway = LLMGateway(LLMConfig(provider="disabled", model=None), ScriptedProvider([]))
    assert gateway.available is False
    with pytest.raises(LLMUnavailableError):
        gateway.chat(MESSAGES)
    probe = gateway.probe()
    assert probe["available"] is False
    assert probe["configuredModelExists"] is False


def test_probe_reports_missing_configured_model():
    gateway, _ = _gateway([], model="model-that-does-not-exist")
    probe = gateway.probe()
    assert probe["available"] is True
    assert probe["configuredModelExists"] is False
    assert probe["error"]

    gateway.config = LLMConfig(provider="openai-compatible", model="model-a", base_url="x", api_key="y")
    assert gateway.probe()["configuredModelExists"] is True


def test_mock_provider_is_labelled_and_never_claims_a_real_call():
    gateway = LLMGateway(
        LLMConfig(provider="mock", model="mock-model"), MockProvider(), clock=lambda: 5.0
    )
    response = gateway.chat(MESSAGES)
    assert response.mode == "mock"
    payload = json.loads(response.content)
    assert payload["insufficient_evidence"] is True
    assert payload["claims"] == []
    assert "MOCK PROVIDER" in payload["summary"]


def test_openai_compatible_provider_parses_usage_and_classifies_http_errors():
    body = json.dumps(
        {
            "choices": [{"message": {"content": '{"ok":true}'}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 3},
        }
    ).encode()
    transport = FakeTransport([TransportResponse(200, body)])
    provider = OpenAICompatibleProvider(base_url="https://llm.test/v1", api_key="k", transport=transport)
    content, usage, finish = provider.chat(
        MESSAGES, model="deepseek-chat", timeout=5.0, max_output_tokens=100, temperature=0.0
    )
    assert content == '{"ok":true}'
    assert usage["prompt_tokens"] == 12
    assert finish == "stop"
    assert transport.calls[0]["url"] == "https://llm.test/v1/chat/completions"
    assert transport.calls[0]["headers"]["Authorization"] == "Bearer k"

    retryable = OpenAICompatibleProvider(
        base_url="https://llm.test/v1", api_key="k", transport=FakeTransport([TransportResponse(503, b"")])
    )
    with pytest.raises(LLMError) as error:
        retryable.chat(MESSAGES, model="m", timeout=5.0, max_output_tokens=10, temperature=0.0)
    assert error.value.retryable is True

    rejected = OpenAICompatibleProvider(
        base_url="https://llm.test/v1",
        api_key="k",
        transport=FakeTransport([TransportResponse(401, b'{"error":{"message":"bad key"}}')]),
    )
    with pytest.raises(LLMError) as error:
        rejected.chat(MESSAGES, model="m", timeout=5.0, max_output_tokens=10, temperature=0.0)
    assert error.value.retryable is False
    assert "bad key" in str(error.value)
