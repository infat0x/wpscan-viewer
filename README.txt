================================================================================
  WPScan Viewer
  A self-hosted web dashboard for parsing and visualizing WPScan output
  https://github.com/infat0x/wpscan-viewer
================================================================================

DESCRIPTION
-----------
WPScan Viewer is a lightweight, self-hosted web application that parses raw
WPScan terminal output and displays it as a clean, structured dashboard.
No more scrolling through walls of terminal text — paste your scan results
and get an organized, readable view instantly.


FEATURES
--------
  - Paste raw WPScan output and get a structured JSON-powered dashboard
  - Apple-dark themed web UI served directly from the app
  - Built-in example input (Load Example button) for quick demo
  - REST API (/parse) returns structured JSON for tool integration
  - Docker support — run anywhere with a single build command
  - Lightweight stack: Python + Flask backend, plain HTML frontend


PROJECT STRUCTURE
-----------------
  wpscan-viewer/
  |-- backend/
  |   `-- parser.py          Core WPScan output parser
  |-- frontend/
  |   `-- index.html         Web dashboard UI
  |-- Dockerfile             Container build config
  |-- .dockerignore
  |-- example-input.txt      Sample WPScan output for demo
  |-- requirements.txt       Python dependencies
  `-- run.py                 Application entry point


REQUIREMENTS
------------
  - Python 3.8 or higher
  - Flask (listed in requirements.txt)
  - Docker (optional, for containerized usage)


INSTALLATION
------------
  Clone the repository:

    git clone https://github.com/infat0x/wpscan-viewer.git
    cd wpscan-viewer

  Install Python dependencies:

    pip install -r requirements.txt

  Start the server:

    python run.py

  Open in browser:

    http://localhost:9090


DOCKER USAGE
------------
  Build the image:

    docker build -t wpscan-viewer .

  Run the container:

    docker run -p 9090:9090 wpscan-viewer

  Open in browser:

    http://localhost:9090


HOW TO USE
----------
  1. Run WPScan against your target (authorized systems only):

       wpscan --url https://example.com -o scan_output.txt

  2. Open WPScan Viewer in your browser (http://localhost:9090).

  3. Paste the raw WPScan output into the input area.

  4. Click "Parse" to view the structured results.

  5. Or click "Load Example" to try it with the built-in sample.


API REFERENCE
-------------
  POST /parse
    Parses raw WPScan output and returns structured JSON.

    Request body (JSON):
      { "raw": "<paste raw wpscan output here>" }

    Response (JSON):
      {
        "target": "...",
        "wordpress_version": "...",
        "vulnerabilities": [...],
        "plugins": [...],
        "themes": [...]
      }

    Error (400):
      { "error": "Empty input" }

  GET /example
    Returns the bundled example WPScan output.
    Used internally by the Load Example button.


ENVIRONMENT VARIABLES
---------------------
  PORT    Port the server listens on. Default: 9090

  Example:
    PORT=8080 python run.py


LEGAL DISCLAIMER
----------------
  This tool is intended for use on systems you own or have explicit written
  permission to test. Unauthorized scanning is illegal. The author is not
  responsible for any misuse of this tool.


AUTHOR
------
  infat0x
  https://github.com/infat0x


================================================================================
