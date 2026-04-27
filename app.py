from flask import Flask, render_template, request, jsonify
from flask_cors import CORS          # NEW
from analyzer import analyze_url

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})   # NEW – allow any origin on /api/*


# ------- HTML form route -------
@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    url = None
    if request.method == "POST":
        url = request.form["url"]
        report = analyze_url(url, APIFLASH_KEY)
    return render_template("index.html", report=report, url=url)


# ------- JSON API route for React ---------
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()            # Expect JSON body
    if not data or "url" not in data:
        return jsonify({"error": "Missing 'url'"}), 400

    url  = data["url"]
    report = analyze_url(url, APIFLASH_KEY)
    return jsonify({"url": url, "report": report})   # JSON back to React
import os

# Fetch the key from environment variables instead of hardcoding
APIFLASH_KEY = os.environ.get("APIFLASH_KEY")

# ------- HTML form route -------
# ... (Keep your routes the same) ...

if __name__ == "__main__":
    # Cloud Run assigns a port dynamically, defaulting to 8080
    port = int(os.environ.get("PORT", 8080))
    # Host must be 0.0.0.0 to accept external connections
    app.run(host="0.0.0.0", port=port, debug=False)