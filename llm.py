"""Multi-provider LLM router with RUNTIME MODEL DISCOVERY.

Providers: Groq, Gemini, Claude (Anthropic or any Anthropic-compatible base URL), OpenRouter (free ':free' models).

Model names go stale (retired, or restricted to certain accounts), so nothing is hard-wired:
  1. ask each provider which models THIS key can use (cached 1 h),
  2. rank them by preference, try the best, and on 404/403/429/5xx move to the next model,
  3. remember the model that worked, skip a provider whose key is rejected (401) for a few minutes,
  4. fall through to the next provider.
Override any choice with GROQ_MODEL / GEMINI_MODEL / CLAUDE_MODEL / OPENROUTER_MODEL in .env.
"""
import os
import re
import json
import time
import threading
import requests

PROVIDERS = ("groq", "gemini", "claude", "openrouter")
STATS = {p: {"ok": 0, "fail": 0, "last_ms": None, "last_error": None, "model": None} for p in PROVIDERS}
_lock = threading.Lock()
_CACHE = {}      # provider -> (timestamp, [model ids])
_WORKING = {}    # (provider, mode) -> model id that last worked
_DEAD = {}       # provider -> (until, reason)  (rejected key)
ORDER = {
    "fast": ["groq", "gemini", "openrouter", "claude"],   # voice latency matters
    "deep": ["claude", "gemini", "groq", "openrouter"],   # reports, analysis
}
# last-resort lists, used only if the provider's model-list call itself fails
STATIC = {
    "groq": ["llama-3.3-70b-versatile", "openai/gpt-oss-120b", "llama-3.1-8b-instant", "openai/gpt-oss-20b"],
    "gemini": ["gemini-3.8-flash", "gemini-3.6-flash", "gemini-3.5-flash-lite", "gemini-3.1-flash-lite", "gemini-3-flash-preview", "gemini-2.5-flash"],
    "claude": ["claude-sonnet-5-5", "claude-haiku-5-5", "claude-opus-5-5"],
    "openrouter": ["openrouter/free"],
}


class LLMError(Exception):
    def __init__(self, msg, status=None):
        super().__init__(msg)
        self.status = status


def configured():
    return {p: bool(os.getenv(k)) for p, k in (("groq", "GROQ_API_KEY"), ("gemini", "GEMINI_API_KEY"),
                                               ("claude", "ANTHROPIC_API_KEY"), ("openrouter", "OPENROUTER_API_KEY"))}


def _record(name, ok, ms=None, err=None, model=None):
    with _lock:
        s = STATS[name]
        s["ok" if ok else "fail"] += 1
        s["last_ms"] = ms
        s["last_error"] = None if ok else str(err)[:200]
        if model and ok:
            s["model"] = model


# ------------------------------------------------------------------ model discovery
def _get(url, headers, timeout=15):
    r = requests.get(url, headers=headers, timeout=timeout)
    if r.status_code != 200:
        raise LLMError(f"{r.status_code}: {r.text[:160]}", r.status_code)
    return r.json()


def _list_models(name):
    if name == "groq":
        d = _get("https://api.groq.com/openai/v1/models", {"Authorization": f"Bearer {os.getenv('GROQ_API_KEY')}"})
        bad = re.compile(r"whisper|orpheus|guard|tts|embed|playai|speech|safeguard", re.I)
        return [m["id"] for m in d.get("data", []) if m.get("active", True) and not bad.search(m["id"])]
    if name == "gemini":
        d = _get("https://generativelanguage.googleapis.com/v1beta/models?pageSize=200", {"x-goog-api-key": os.getenv("GEMINI_API_KEY")})
        bad = re.compile(r"embed|image|imagen|tts|audio|live|veo|robotics|computer|aqa|learnlm|gemma|native|vision", re.I)
        return [m["name"].split("/")[-1] for m in d.get("models", [])
                if "generateContent" in m.get("supportedGenerationMethods", []) and not bad.search(m["name"])]
    if name == "claude":
        base = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
        d = _get(f"{base}/v1/models?limit=100", {"x-api-key": os.getenv("ANTHROPIC_API_KEY"), "anthropic-version": "2023-06-01"})
        return [m["id"] for m in d.get("data", [])]
    if name == "openrouter":
        d = _get("https://openrouter.ai/api/v1/models", {})
        out = []
        for m in d.get("data", []):
            p = m.get("pricing") or {}
            try:
                free = float(p.get("prompt", 1)) == 0 and float(p.get("completion", 1)) == 0
            except (TypeError, ValueError):
                free = False
            outs = (m.get("architecture") or {}).get("output_modalities") or ["text"]
            if free and outs == ["text"] and not re.search(r"embed|guard|moderation", m["id"], re.I):
                out.append((m.get("context_length") or 0, m["id"]))
        return ["openrouter/free"] + [i for _, i in sorted(out, reverse=True)]
    return []


def _rank(name, models, mode):
    """Most preferred first. Newer / larger / non-preview ranks higher; reasoning-heavy models rank lower for voice."""
    def ver(s):
        return [int(x) for x in re.findall(r"\d+", s)][:3] or [0]

    def score(m):
        ml = m.lower()
        if name == "groq":
            pref = ["llama-3.3-70b", "gpt-oss-120b", "llama-3.1-8b" if mode == "fast" else "gpt-oss-20b", "gpt-oss-20b", "llama-3.1-8b", "llama", "qwen"]
            for i, p in enumerate(pref):
                if p in ml:
                    return (0, i, 0)
            return (1, 0, 0)
        if name == "gemini":
            tier = 0 if re.search(r"flash(?!-lite)", ml) else 1 if "flash-lite" in ml else 2 if "pro" in ml else 3
            if "argon" in ml and mode == "deep":
                tier = -1
            return (tier, 1 if "preview" in ml or "exp" in ml else 0, [-x for x in ver(ml)])
        if name == "claude":
            fam = ("haiku", "sonnet", "opus") if mode == "fast" else ("sonnet", "opus", "haiku")
            i = next((k for k, f in enumerate(fam) if f in ml), 9)
            return (i, 0, [-x for x in ver(ml)])
        return (0 if m == "openrouter/free" else 1, 0, 0)

    return sorted(dict.fromkeys(models), key=score)


def models_for(name, mode="fast", force=False):
    """Ordered candidate model list for a provider (env override first, last-known-good next)."""
    now = time.time()
    hit = _CACHE.get(name)
    if force or not hit or now - hit[0] > 3600:
        try:
            _CACHE[name] = (now, _list_models(name))
        except LLMError as e:
            if e.status in (401, 403) and name != "openrouter":
                _mark_dead(name, f"key rejected while listing models ({e})")
            _CACHE[name] = (now - 3300, [])      # retry listing in ~5 min
        except Exception:  # noqa: BLE001
            _CACHE[name] = (now - 3300, [])
    found = _CACHE[name][1]
    ordered = _rank(name, found, mode) if found else list(STATIC[name])
    first = [x for x in (os.getenv(f"{name.upper() if name != 'claude' else 'CLAUDE'}_MODEL"), _WORKING.get((name, mode))) if x]
    return list(dict.fromkeys(first + ordered))


def _mark_dead(name, reason, secs=300):
    _DEAD[name] = (time.time() + secs, reason)


def is_dead(name):
    d = _DEAD.get(name)
    if d and time.time() < d[0]:
        return d[1]
    _DEAD.pop(name, None)
    return None


# ------------------------------------------------------------------ one request to one model
def _post(url, headers, body, timeout):
    r = requests.post(url, headers=headers, json=body, timeout=timeout)
    if r.status_code != 200:
        raise LLMError(f"{r.status_code}: {r.text[:240]}", r.status_code)
    return r.json()


def _openai_style(url, key, extra_headers, model, system, messages, max_tokens, json_mode, timeout):
    body = {"model": model, "messages": [{"role": "system", "content": system}] + messages, "max_tokens": max_tokens, "temperature": 0.3}
    if "gpt-oss" in model:
        body["reasoning_effort"] = "low"
        body["max_tokens"] = max_tokens + 800
    if json_mode:
        body["response_format"] = {"type": "json_object"}
    h = {"Authorization": f"Bearer {key}", **extra_headers}
    try:
        j = _post(url, h, body, timeout)
    except LLMError as e:
        if json_mode and e.status == 400:      # model has no JSON mode -> our parser copes with plain text
            body.pop("response_format")
            j = _post(url, h, body, timeout)
        else:
            raise
    txt = ((j.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    if not txt.strip():
        raise LLMError("empty response", 404)
    return txt


def _one(name, model, system, messages, max_tokens, json_mode, timeout):
    if name == "groq":
        return _openai_style("https://api.groq.com/openai/v1/chat/completions", os.getenv("GROQ_API_KEY"), {}, model, system, messages, max_tokens, json_mode, timeout)
    if name == "openrouter":
        return _openai_style("https://openrouter.ai/api/v1/chat/completions", os.getenv("OPENROUTER_API_KEY"),
                             {"HTTP-Referer": "http://localhost:5000", "X-Title": "VIRUS Voice SOC"}, model, system, messages, max_tokens, json_mode, timeout)
    if name == "gemini":
        gen = {"maxOutputTokens": max_tokens + 1500, "temperature": 0.3}   # newer Gemini models spend tokens on thinking
        if json_mode:
            gen["responseMimeType"] = "application/json"
        body = {"systemInstruction": {"parts": [{"text": system}]}, "generationConfig": gen,
                "contents": [{"role": "model" if m["role"] == "assistant" else "user", "parts": [{"text": m["content"]}]} for m in messages]}
        j = _post(f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
                  {"x-goog-api-key": os.getenv("GEMINI_API_KEY")}, body, timeout)
        try:
            txt = "".join(p.get("text", "") for p in j["candidates"][0]["content"]["parts"])
        except Exception:  # noqa: BLE001
            txt = ""
        if not txt.strip():
            raise LLMError(f"empty response ({str((j.get('candidates') or [{}])[0].get('finishReason'))})", 404)
        return txt
    if name == "claude":
        base = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com").rstrip("/")
        j = _post(f"{base}/v1/messages", {"x-api-key": os.getenv("ANTHROPIC_API_KEY"), "anthropic-version": "2023-06-01", "content-type": "application/json"},
                  {"model": model, "max_tokens": max_tokens, "system": system, "messages": messages}, timeout)
        return "".join(b.get("text", "") for b in j.get("content", []) if b.get("type") == "text")
    raise LLMError(f"unknown provider {name}")


# ------------------------------------------------------------------ public API
def call(name, system, messages, max_tokens=600, json_mode=False, timeout=25, mode="fast"):
    """Call one provider, trying its accessible models in order. Returns text."""
    if not configured()[name]:
        raise LLMError(f"{name}: no API key")
    why = is_dead(name)
    if why:
        raise LLMError(f"{name}: skipped - {why}", 401)
    errors, t0 = [], time.time()
    for model in models_for(name, mode)[:5]:
        try:
            out = _one(name, model, system, messages, max_tokens, json_mode, timeout)
            _WORKING[(name, mode)] = model
            _record(name, True, int((time.time() - t0) * 1000), model=model)
            return out
        except LLMError as e:
            errors.append(f"{model}: {e}")
            if e.status == 401:                      # bad key: no model will work
                _mark_dead(name, str(e)[:120])
                break
            if e.status == 400 and "api key" in str(e).lower():
                _mark_dead(name, str(e)[:120])
                break
            _WORKING.pop((name, mode), None)         # try the next model
        except requests.RequestException as e:
            errors.append(f"{model}: network {type(e).__name__}")
            break                                    # network problem: other models won't help
    msg = f"{name} failed -> " + " | ".join(errors[-3:])
    _record(name, False, err=msg)
    raise LLMError(msg)


def chat(mode, system, messages, max_tokens=600, json_mode=False, timeout=25):
    """Try providers in order for the mode. Returns (text, 'provider/model')."""
    errors = []
    for name in ORDER[mode]:
        if not configured()[name] or is_dead(name):
            continue
        try:
            out = call(name, system, messages, max_tokens, json_mode, timeout, mode)
            return out, f"{name}/{STATS[name]['model']}"
        except Exception as e:  # noqa: BLE001
            errors.append(str(e)[:200])
    raise LLMError("; ".join(errors) or "no LLM provider available (check keys with: python check_llm.py)")


def status():
    """For /api/health and the UI: per provider key state, model in use, last error."""
    out = {}
    for p, on in configured().items():
        c = _CACHE.get(p)
        out[p] = {"configured": on, "model": STATS[p]["model"], "available_models": len(c[1]) if c else None,
                  "rejected": is_dead(p), "last_error": STATS[p]["last_error"], "ok": STATS[p]["ok"], "fail": STATS[p]["fail"]}
    return out


def warmup():
    """Discover models in the background at start-up so the first voice command is not slow."""
    def run():
        for p, on in configured().items():
            if on:
                try:
                    models_for(p, "fast", force=True)
                except Exception:  # noqa: BLE001
                    pass
    threading.Thread(target=run, daemon=True).start()


def parse_json(text):
    """Lenient JSON extraction (handles ```json fences, <think> blocks and chatter around the object)."""
    if not text:
        raise ValueError("empty")
    t = re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()
    t = re.sub(r"^```(?:json)?|```$", "", t, flags=re.M).strip()
    try:
        return json.loads(t)
    except Exception:  # noqa: BLE001
        pass
    m = re.search(r"\{.*\}", t, re.S)
    if not m:
        raise ValueError("no json object")
    return json.loads(m.group(0))
