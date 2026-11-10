"""Production entry point (Render / any gunicorn host).

    gunicorn wsgi:app -c gunicorn.conf.py

app.py only calls boot() under `python app.py`, so gunicorn would serve a page with no live
data. This module starts every background source exactly once, then exposes the Flask app.
"""
import app as _app_module

_app_module.boot()
app = _app_module.app
