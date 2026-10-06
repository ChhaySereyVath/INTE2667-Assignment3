"""Start the app locally: python run.py, then open http://localhost:5000"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    # S13: the Werkzeug debugger can run any code, so it is OFF unless FLASK_DEBUG=1,
    # and the server only listens on this computer (127.0.0.1), not the whole network.
    debug = os.environ.get("FLASK_DEBUG") == "1"
    app.run(host="127.0.0.1", port=5000, debug=debug)