"""Flask application factory for the browser UI and REST API."""

import logging

from flask import Flask, jsonify, render_template, request

from .engine import ScamDetector

LOGGER = logging.getLogger(__name__)
MAX_MESSAGE_LENGTH = 10_000
MAX_URLENCODED_MESSAGE_BYTES = MAX_MESSAGE_LENGTH * 12 + 1_024


def create_app(detector: ScamDetector | None = None) -> Flask:
    """Create a configured Flask app; dependency injection aids testing."""
    app = Flask(__name__)
    # A four-byte Unicode character can occupy 12 bytes when URL-encoded.
    app.config["MAX_CONTENT_LENGTH"] = MAX_URLENCODED_MESSAGE_BYTES
    app.extensions["scamguard_detector"] = detector or ScamDetector()

    @app.get("/")
    def index():
        return render_template("index.html", result=None, message="", error=None)

    @app.post("/")
    def scan_page():
        message = request.form.get("message", "")
        if not message.strip():
            return render_template(
                "index.html", result=None, message=message, error="Paste a message to scan."
            ), 400
        if len(message) > MAX_MESSAGE_LENGTH:
            return render_template(
                "index.html",
                result=None,
                message=message[:MAX_MESSAGE_LENGTH],
                error=f"Messages must be {MAX_MESSAGE_LENGTH:,} characters or fewer.",
            ), 413
        result = app.extensions["scamguard_detector"].scan(message)
        LOGGER.info("Web scan completed: risk=%s score=%d", result.risk_level.value, result.score)
        return render_template("index.html", result=result, message=message, error=None)

    @app.post("/api/scan")
    def scan_api():
        payload = request.get_json(silent=True)
        if not isinstance(payload, dict) or not isinstance(payload.get("text"), str):
            return jsonify({"error": "Send a JSON object with a string 'text' field."}), 400
        message = payload["text"]
        if not message.strip():
            return jsonify({"error": "The 'text' field cannot be empty."}), 400
        if len(message) > MAX_MESSAGE_LENGTH:
            error = f"Text must be {MAX_MESSAGE_LENGTH:,} characters or fewer."
            return jsonify({"error": error}), 413
        result = app.extensions["scamguard_detector"].scan(message)
        LOGGER.info("API scan completed: risk=%s score=%d", result.risk_level.value, result.score)
        return jsonify(result.to_dict())

    @app.get("/health")
    def health():
        return jsonify({"status": "ok", "service": "ScamGuard"})

    @app.errorhandler(413)
    def request_too_large(_error):
        if request.path.startswith("/api/"):
            return jsonify({"error": "Request body is too large."}), 413
        return render_template(
            "index.html", result=None, message="", error="Request body is too large."
        ), 413

    return app
