"""LLM router tests with simulated provider responses (reproducing the real errors seen: Groq 404 on a model the key cannot use,
Gemini 2.5 restricted to old users, Claude 401 invalid key). Run: python tests/test_llm.py"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import llm  # noqa: E402


class R:
    def __init__(self, code, data):
        self.status_code, self._d, self.text = code, data, str(data)

    def json(self):
        return self._d


CALLS = []


def fake_get(url, headers=None, timeout=0):
    if "groq.com" in url:
        return R(200, {"data": [{"id": "whisper-large-v3", "active": True}, {"id": "llama-3.3-70b-versatile", "active": True},
                                {"id": "llama-3.1-8b-instant", "active": True}, {"id": "openai/gpt-oss-20b", "active": True}]})
    if "generativelanguage" in url:
        return R(200, {"models": [{"name": "models/gemini-2.5-flash", "supportedGenerationMethods": ["generateContent"]},
                                  {"name": "models/gemini-3.6-flash", "supportedGenerationMethods": ["generateContent"]},
                                  {"name": "models/gemini-3.8-flash", "supportedGenerationMethods": ["generateContent"]},
                                  {"name": "models/text-embedding-9", "supportedGenerationMethods": ["embedContent"]}]})
    if "anthropic" in url:
        return R(401, {"error": {"message": "invalid x-api-key"}})
    if "openrouter" in url:
        return R(200, {"data": [{"id": "vendor/paid-model", "pricing": {"prompt": "0.001", "completion": "0.002"}, "context_length": 9e5},
                                {"id": "meta/llama-free:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 131072},
                                {"id": "x/small:free", "pricing": {"prompt": "0", "completion": "0"}, "context_length": 8000}]})
    raise AssertionError(url)


def fake_post(url, headers=None, json=None, timeout=0):
    CALLS.append((url.split("/")[2], (json or {}).get("model") or url.split("models/")[-1].split(":")[0]))
    if "groq.com" in url:
        if json["model"] == "llama-3.3-70b-versatile":
            return R(404, {"error": {"message": "The model `llama-3.3-70b-versatile` does not exist or you do not have access to it."}})
        return R(200, {"choices": [{"message": {"content": '{"reply":"ok from groq"}'}}]})
    if "generativelanguage" in url:
        if "gemini-3.8-flash" in url:
            return R(404, {"error": {"message": "no longer available to new users"}})
        return R(200, {"candidates": [{"content": {"parts": [{"text": "hello from gemini"}]}}]})
    if "anthropic" in url:
        return R(401, {"error": {"message": "invalid x-api-key"}})
    if "openrouter" in url:
        return R(200, {"choices": [{"message": {"content": "hello from free model"}}]})
    raise AssertionError(url)


llm.requests.get, llm.requests.post = fake_get, fake_post
for k in ("GROQ_API_KEY", "GEMINI_API_KEY", "ANTHROPIC_API_KEY", "OPENROUTER_API_KEY"):
    os.environ[k] = "test"
for k in ("GROQ_MODEL", "GEMINI_MODEL", "CLAUDE_MODEL", "OPENROUTER_MODEL"):
    os.environ.pop(k, None)


def test_groq_skips_inaccessible_model():
    txt = llm.call("groq", "s", [{"role": "user", "content": "hi"}], 50, True)
    assert "ok from groq" in txt and llm.STATS["groq"]["model"] == "llama-3.1-8b-instant", llm.STATS["groq"]
    assert "whisper" not in " ".join(llm.models_for("groq"))


def test_gemini_falls_back_to_next_model():
    txt = llm.call("gemini", "s", [{"role": "user", "content": "hi"}], 50)
    assert txt == "hello from gemini" and llm.STATS["gemini"]["model"] == "gemini-3.6-flash", llm.STATS["gemini"]
    assert llm.models_for("gemini")[0] == "gemini-3.6-flash" and "text-embedding-9" not in llm.models_for("gemini")


def test_claude_401_marks_provider_dead_and_chat_skips_it():
    try:
        llm.call("claude", "s", [{"role": "user", "content": "hi"}], 50)
        raise SystemExit("claude should have failed")
    except llm.LLMError:
        pass
    assert llm.is_dead("claude")
    CALLS.clear()
    out, prov = llm.chat("deep", "s", [{"role": "user", "content": "hi"}], 50)   # deep prefers claude, must skip to gemini
    assert prov.startswith("gemini/"), prov
    assert not any(c[0].startswith("api.anthropic") for c in CALLS)


def test_openrouter_only_free_models():
    m = llm.models_for("openrouter")
    assert m[0] == "openrouter/free" and "meta/llama-free:free" in m and "vendor/paid-model" not in m
    assert llm.call("openrouter", "s", [{"role": "user", "content": "hi"}], 50) == "hello from free model"


def test_fallthrough_when_first_provider_has_no_models_working():
    llm._DEAD["groq"] = (9e12, "rejected")
    _, prov = llm.chat("fast", "s", [{"role": "user", "content": "hi"}], 50)
    assert prov.startswith("gemini/"), prov
    llm._DEAD.pop("groq")


def test_parse_json_variants():
    assert llm.parse_json('<think>x</think>```json\n{"a":1}\n```') == {"a": 1}
    assert llm.parse_json('Sure! {"a": 2} done') == {"a": 2}


if __name__ == "__main__":
    for n, f in list(globals().items()):
        if n.startswith("test_"):
            f(); print("ok", n)
