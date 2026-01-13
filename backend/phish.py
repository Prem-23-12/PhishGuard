from flask import Flask, request, jsonify
from flask_cors import CORS
import re
from services import detect_phishing

app = Flask(__name__)
CORS(app)

@app.route("/")
def home():
    return "✅ Backend is running correctly"


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    if not data or "url" not in data:
        return jsonify({"error": "URL not provided"}), 400

    return jsonify(detect_phishing(data["url"]))


if __name__ == "__main__":
    app.run(debug=True)
