"""Development server: reloads on every code change, watch-only (no blocking, no AI, no self-checks).

  docker compose -p harrier-dev -f compose.dev.yml up -d     # then open http://localhost:8096
"""
import logging
import os

import web

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":  # only in the reloaded child, so loops don't run twice
        db = web.harrier.open_db()
        web.auth.ensure_admin(db, os.environ.get("ADMIN_USERNAME", ""), os.environ.get("ADMIN_PASSWORD", ""))
        db.close()
        web.harrier.start_background()
    web.app.run(host="0.0.0.0", port=8095, debug=False, use_reloader=True, extra_files=["app.html", "login.html"])
