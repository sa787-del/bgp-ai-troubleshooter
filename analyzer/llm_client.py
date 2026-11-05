"""LLM client: chat_json() sends a prompt and returns a dict matching a JSON schema.

Settings (environment variables):
  BGP_LLM_PROVIDER  ollama | anthropic                (default ollama)
  BGP_LLM_MODEL     model to use                      (default qwen2.5:7b for ollama,
                                                       claude-opus-5-5 for anthropic)
  BGP_LLM_URL       Ollama address                    (default http://host.orb.internal:11434)
  BGP_LLM_NUM_CTX   Ollama context window tokens      (default 16384)
  BGP_LLM_TIMEOUT   seconds to wait for Ollama        (default 300)

Ollama runs on the Mac and is reached from the VM at host.orb.internal.
anthropic needs ANTHROPIC_API_KEY.
"""
import json
import logging
import os
from contextvars import ContextVar

import requests

PROVIDER = os.environ.get("BGP_LLM_PROVIDER", "ollama").lower()
DEFAULT_MODELS = {"ollama": "qwen2.5:7b", "anthropic": "claude-opus-5-5"}
MODEL = os.environ.get("BGP_LLM_MODEL", DEFAULT_MODELS.get(PROVIDER, ""))
OLLAMA_URL = os.environ.get("BGP_LLM_URL", "http://host.orb.internal:11434").rstrip("/")
NUM_CTX = int(os.environ.get("BGP_LLM_NUM_CTX", "16384"))
TIMEOUT = int(os.environ.get("BGP_LLM_TIMEOUT", "120"))

log = logging.getLogger(__name__)
_usage_context: ContextVar[dict | None] = ContextVar("llm_usage_context", default=None)


def start_usage_tracking():
    """Start isolated token accounting for one diagnosis run."""
    return _usage_context.set({"calls": []})


def finish_usage_tracking(token) -> dict:
    """Return this run's provider-reported token totals and restore prior context."""
    usage = _usage_context.get() or {"calls": []}
    calls = usage["calls"]
    known = [call for call in calls if call["input_tokens"] is not None and call["output_tokens"] is not None]
    return_value = {
        "provider": PROVIDER,
        "model": MODEL,
        "call_count": len(calls),
        "input_tokens": sum(call["input_tokens"] for call in known),
        "output_tokens": sum(call["output_tokens"] for call in known),
        "total_tokens": sum(call["input_tokens"] + call["output_tokens"] for call in known),
        "reported_call_count": len(known),
        "calls": calls,
    }
    _usage_context.reset(token)
    return return_value


def _record_usage(model: str, input_tokens, output_tokens) -> None:
    context = _usage_context.get()
    if context is None:
        return
    context["calls"].append({
        "provider": PROVIDER,
        "model": model,
        "input_tokens": input_tokens if isinstance(input_tokens, int) else None,
        "output_tokens": output_tokens if isinstance(output_tokens, int) else None,
        "total_tokens": input_tokens + output_tokens
        if isinstance(input_tokens, int) and isinstance(output_tokens, int) else None,
    })


class LLMUnavailable(Exception):
    """The LLM couldn't be reached or gave an unusable answer."""


def describe() -> str:
    if PROVIDER == "ollama":
        return f"ollama model {MODEL} at {OLLAMA_URL}"
    return f"{PROVIDER} model {MODEL}"


def chat_json(system: str, user: str, schema: dict, max_tokens: int = 512,
              timeout: int | None = None) -> tuple[dict, str]:
    """Returns (answer, model name). Raises LLMUnavailable on any failure."""
    if PROVIDER == "ollama":
        text, model, usage = _ollama(system, user, schema, max_tokens, timeout=timeout)
    elif PROVIDER == "anthropic":
        text, model, usage = _anthropic(system, user, schema, max_tokens)
    else:
        raise LLMUnavailable(f"unknown BGP_LLM_PROVIDER {PROVIDER!r} (use ollama or anthropic)")

    log.debug("LLM answer: %s", text)
    try:
        answer = json.loads(text)
    except json.JSONDecodeError as e:
        raise LLMUnavailable("the model did not return valid JSON") from e
    if not isinstance(answer, dict):
        raise LLMUnavailable("the model did not return a JSON object")
    missing = [k for k in schema.get("required", []) if k not in answer]
    if missing:
        raise LLMUnavailable(f"the model's answer is missing {', '.join(missing)}")
    return answer, model


def _ollama(system: str, user: str, schema: dict, max_tokens: int,
            timeout: int | None = None) -> tuple[str, str, dict]:
    request_timeout = timeout or TIMEOUT
    try:
        r = requests.post(f"{OLLAMA_URL}/api/chat", timeout=request_timeout, json={
            "model": MODEL,
            "stream": False,
            "keep_alive": "10m",
            # Ollama constrains the output to this JSON schema.
            "format": schema,
            # temperature 0 keeps structured output stable; num_predict stops runaway output.
            "options": {"temperature": 0, "num_ctx": NUM_CTX, "num_predict": max_tokens},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": (
                    user + "\n\nReply with only a JSON object matching this schema:\n"
                    + json.dumps(schema))},
            ],
        })
    except requests.ConnectionError as e:
        raise LLMUnavailable(f"could not reach Ollama at {OLLAMA_URL} (is the Ollama app running?)") from e
    except requests.Timeout as e:
        raise LLMUnavailable(f"Ollama did not answer within {request_timeout}s") from e
    if r.status_code == 404:
        raise LLMUnavailable(f"model {MODEL} not found in Ollama; run `ollama pull {MODEL}` on the Mac")
    if not r.ok:
        raise LLMUnavailable(f"Ollama error {r.status_code}: {r.text[:200]}")

    data = r.json()
    input_tokens = data.get("prompt_eval_count")
    output_tokens = data.get("eval_count")
    model = data.get("model", MODEL)
    _record_usage(model, input_tokens, output_tokens)
    log.info("LLM response: model=%s done_reason=%s input_tokens=%s output_tokens=%s",
             data.get("model"), data.get("done_reason"), input_tokens, data.get("eval_count"))
    if input_tokens and input_tokens >= NUM_CTX:
        log.warning("Prompt filled the %s-token context window and was likely truncated; "
                    "raise BGP_LLM_NUM_CTX", NUM_CTX)
    if data.get("done_reason") == "length":
        raise LLMUnavailable("the model's answer was cut off")
    return data["message"]["content"], model, {
        "input_tokens": input_tokens, "output_tokens": output_tokens,
    }


def _anthropic(system: str, user: str, schema: dict, max_tokens: int) -> tuple[str, str, dict]:
    import anthropic   # only needed for this provider

    try:
        client = anthropic.Anthropic()
        response = client.beta.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            # If Claude's safety classifiers decline, retry on Anthropic's recommended fallback model.
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
            system=system,
            output_config={"format": {"type": "json_schema", "schema": schema}},
            messages=[{"role": "user", "content": user}],
        )
    except anthropic.AuthenticationError as e:
        raise LLMUnavailable("Anthropic API key was rejected") from e
    except anthropic.RateLimitError as e:
        raise LLMUnavailable("Anthropic API rate limit hit; try again shortly") from e
    except anthropic.APIStatusError as e:
        raise LLMUnavailable(f"Anthropic API error {e.status_code}: {e.message}") from e
    except anthropic.APIConnectionError as e:
        raise LLMUnavailable("could not reach the Anthropic API") from e
    except TypeError as e:
        if "authentication" not in str(e):
            raise
        raise LLMUnavailable("no Anthropic credentials (set ANTHROPIC_API_KEY)") from e

    _record_usage(response.model, response.usage.input_tokens, response.usage.output_tokens)
    log.info("LLM response: model=%s stop_reason=%s input_tokens=%s output_tokens=%s",
             response.model, response.stop_reason,
             response.usage.input_tokens, response.usage.output_tokens)
    if response.stop_reason == "refusal":
        raise LLMUnavailable("the model declined to answer")
    if response.stop_reason == "max_tokens":
        raise LLMUnavailable("the model's answer was cut off")
    return next(b.text for b in response.content if b.type == "text"), response.model, {
        "input_tokens": response.usage.input_tokens,
        "output_tokens": response.usage.output_tokens,
    }
