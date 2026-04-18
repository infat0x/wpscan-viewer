"""
WPScan Viewer — Single entry point
  Frontend: frontend/index.html
  Backend:  backend/parser.py
  Run:      python run.py
  URL:      http://localhost:9090
"""
import os
from pathlib import Path
from flask import Flask, request, jsonify, send_file
from backend.parser import parse_wpscan

BASE_DIR     = Path(__file__).parent
FRONTEND_DIR = BASE_DIR / "frontend"
EXAMPLE_FILE = BASE_DIR / "example-input.txt"

app = Flask(__name__, static_folder=str(FRONTEND_DIR), static_url_path="")


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the premium Apple-dark dashboard."""
    return send_file(FRONTEND_DIR / "index.html")


@app.route("/parse", methods=["POST"])
def parse():
    """Parse raw WPScan output and return structured JSON."""
    data = request.get_json(force=True, silent=True) or {}
    raw  = data.get("raw", "")
    if not raw.strip():
        return jsonify({"error": "Empty input"}), 400
    return jsonify(parse_wpscan(raw))


@app.route("/example")
def example():
    """Return the bundled example WPScan output (for the Load Example button)."""
    if EXAMPLE_FILE.exists():
        return send_file(str(EXAMPLE_FILE), mimetype="text/plain")
    return "# No example file found.", 404


# ── Entry ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9090))
    print(f"\n  🛡  WPScan Viewer  →  http://localhost:{port}\n")
    app.run(host="0.0.0.0", port=port, debug=False)
