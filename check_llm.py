"""Diagnose the AI providers on YOUR machine:   python check_llm.py
For each key in .env: lists the models that key can use, tests the best ones with a tiny prompt, and tells you what to fix."""
import os
from dotenv import load_dotenv
load_dotenv()
import llm

conf = llm.configured()
for name in llm.PROVIDERS:
    print(f"\n== {name.upper()} " + ("" if conf[name] else "(no key in .env - skipped)"))
    if not conf[name]:
        continue
    try:
        models = llm.models_for(name, "fast", force=True)
        why = llm.is_dead(name)
        if why:
            print("   KEY REJECTED:", why[:160]); continue
        print(f"   {len(llm._CACHE.get(name, (0, []))[1])} models available to this key; best candidates: {models[:4]}")
        out = llm.call(name, "Answer with one word.", [{"role": "user", "content": "Say OK"}], 20, False, 25)
        print(f"   WORKS  model={llm.STATS[name]['model']}  {llm.STATS[name]['last_ms']} ms  reply={out.strip()[:30]!r}")
    except Exception as e:  # noqa: BLE001
        print("   FAILED:", str(e)[:300])
print("\nDone. Anything that FAILED is skipped automatically; the app keeps working on the others.")
