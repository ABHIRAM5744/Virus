import os

# ONE worker on purpose: the SOC engine (events, nodes, SSE subscribers) lives in memory.
# Several workers would each run their own engine and the dashboard would flicker between them.
workers = 1
worker_class = "gthread"
threads = int(os.getenv("GUNICORN_THREADS", "32"))   # each open dashboard holds one thread for /api/stream
bind = f"0.0.0.0:{os.getenv('PORT', '10000')}"
timeout = 120          # incident report LLM call can take up to 60 s
graceful_timeout = 20
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = "info"
