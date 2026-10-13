"""Start the app locally: python run.py

With certs/ in place (`flask make-cert`), it serves https://localhost:5000 (R01).
Without them it falls back to plain HTTP on this computer only, and says so.
"""
import os
from pathlib import Path

from app import create_app

app = create_app()

if __name__ == "__main__":
    # S13: the Werkzeug debugger can run any code, so it is OFF unless FLASK_DEBUG=1,
    # and the server only listens on this computer (127.0.0.1), not the whole network.
    debug = os.environ.get("FLASK_DEBUG") == "1"
    cert, key = Path("certs/dev-cert.pem"), Path("certs/dev-key.pem")
    if cert.exists() and key.exists():
        # R01: authenticated encryption (TLS) for everything the browser sends
        app.run(host="127.0.0.1", port=5000, debug=debug, ssl_context=(str(cert), str(key)))
    else:
        print("No certificate in certs/: serving plain HTTP on localhost only. "
              "Run `flask make-cert` to serve HTTPS (R01).")
        app.run(host="127.0.0.1", port=5000, debug=debug)