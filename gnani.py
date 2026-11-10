"""Gnani Vachana client: Prisma (speech-to-text) and Timbre (text-to-speech).

Endpoints and fields follow docs.gnani.ai:
  STT  POST https://api.vachana.ai/stt/v3                 (multipart, header X-API-Key-ID)
  TTS  POST https://api.vachana.ai/api/v1/tts/inference   (JSON, header X-API-Key-ID, returns raw audio)
"""
import os
import requests

BASE = os.getenv("GNANI_BASE_URL", "https://api.vachana.ai")

# UI language -> (STT language_code, STT model, STT format, TTS language)
LANGS = {
    "auto":  ("indic-auto", "prisma-v3.0", "transcribe", "auto"),
    "en-IN": ("en-IN", None, "transcribe", "en-IN"),
    "hi-IN": ("hi-IN", None, "transcribe", "hi-IN"),
    "hi-en": ("hi-IN,en-IN", "prisma-v3.0", "codemix", "hi-en"),  # Hinglish
    "ta-IN": ("ta-IN", None, "transcribe", "ta-IN"),
    "te-IN": ("te-IN", None, "transcribe", "te-IN"),
    "kn-IN": ("kn-IN", None, "transcribe", "kn-IN"),
    "ml-IN": ("ml-IN", None, "transcribe", "ml-IN"),
    "mr-IN": ("mr-IN", None, "transcribe", "mr-IN"),
    "bn-IN": ("bn-IN", None, "transcribe", "bn-IN"),
    "gu-IN": ("gu-IN", None, "transcribe", "gu-IN"),
    "pa-IN": ("pa-IN", None, "transcribe", "pa-IN"),
}
TTS_LANGS = {v[3] for v in LANGS.values()}


class GnaniError(Exception):
    pass


def configured():
    return bool(os.getenv("GNANI_API_KEY"))


def _headers(extra=None):
    key = os.getenv("GNANI_API_KEY", "")
    if not key:
        raise GnaniError("GNANI_API_KEY is not set")
    h = {"X-API-Key-ID": key}
    h.update(extra or {})
    return h


def _err(resp):
    try:
        j = resp.json()
        msg = j.get("message") or j.get("detail") or j
    except Exception:
        msg = resp.text[:200]
    return f"Gnani {resp.status_code}: {msg}"


def _stt_once(audio, filename, mime, code, model, fmt):
    data = {"language_code": code, "format": fmt}
    if model:
        data["model"] = model
    r = requests.post(
        f"{BASE}/stt/v3",
        headers=_headers(),
        files={"audio_file": (filename, audio, mime)},
        data=data,
        timeout=40,
    )
    if r.status_code != 200:
        raise GnaniError(_err(r))
    j = r.json()
    if not j.get("success", True):
        raise GnaniError(str(j))
    return {
        "text": (j.get("transcript") or "").strip(),
        "lang": j.get("detected_language_code") or None,
        "model": j.get("model"),
        "latency": j.get("end_to_end_latency"),
    }


def stt(audio, ui_lang="auto", filename="speech.wav", mime="audio/wav"):
    """Transcribe <=30 s of audio. Falls back to Prisma v2.5 if v3 is not enabled for the key."""
    code, model, fmt, _ = LANGS.get(ui_lang, LANGS["auto"])
    try:
        return _stt_once(audio, filename, mime, code, model, fmt)
    except GnaniError as first:
        if model is None:
            raise
        fb = "hi-IN" if ui_lang in ("auto", "hi-en") else "en-IN"
        try:
            out = _stt_once(audio, filename, mime, fb, None, "transcribe")
            out["note"] = f"v3 unavailable ({first}); used v2.5/{fb}"
            return out
        except GnaniError:
            raise first


def _tts_once(text, model, voice, language, speed):
    body = {
        "text": text,
        "model": model,
        "voice": voice,
        "language": language,
        "speed": speed,
        "audio_config": {
            "sample_rate": 24000,
            "num_channels": 1,
            "sample_width": 2,
            "encoding": "linear_pcm",
            "container": "wav",
        },
    }
    r = requests.post(
        f"{BASE}/api/v1/tts/inference",
        headers=_headers({"Content-Type": "application/json"}),
        json=body,
        timeout=40,
    )
    if r.status_code != 200 or "json" in r.headers.get("Content-Type", ""):
        raise GnaniError(_err(r))
    return r.content


def tts(text, language="auto", speed=1.05):
    """Return WAV bytes. Tries Timbre v3.0, then v2.5."""
    text = (text or "").strip()[:900]
    if not text:
        raise GnaniError("empty text")
    if language not in TTS_LANGS:
        language = "auto"
    m3 = os.getenv("GNANI_TTS_MODEL", "timbre-v3.0")
    v3 = os.getenv("GNANI_TTS_VOICE", "Shivani")
    v25 = os.getenv("GNANI_TTS_VOICE_FALLBACK", "Nalini")
    try:
        return _tts_once(text, m3, v3, language, speed)
    except GnaniError as first:
        try:
            return _tts_once(text, "timbre-v2.5", v25, language, speed)
        except GnaniError:
            raise first
