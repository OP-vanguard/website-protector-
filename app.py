"""
Vulnerable Target Web App — Web Security Monitoring Project

Purpose: intentionally weak Flask app used as a lab target for practicing
brute force, web shell upload, and DDoS attacks — and for building/testing
a detection + blocking tool ("the protector") against real attack traffic.

INTENTIONAL WEAKNESSES (do not "fix" these — they're the point):
  - /login has no rate limiting and no account lockout (brute force surface)
  - /upload accepts any file extension and saves it directly (web shell surface)
  - /api/ping is unauthenticated and does no throttling (DDoS surface)

Everything is logged to logs/access.log and logs/auth.log so the protector
tool has real data to detect against.

defense.py (app-layer detection + prevention, no admin required) is wired
in below: every request is checked against the blocklist, DDoS/webshell
detection runs on every request, and brute-force detection runs on login.

LOCAL LAB USE ONLY. Do not expose this to the internet.
"""

from flask import Flask, request, render_template, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import logging
import os
import time

from defense import record_login_attempt, record_request, is_blocked, start_maintenance_loop

app = Flask(__name__)
app.secret_key = "lab-only-not-for-production"  # fine for a local lab, never reuse this

# Start the background loop that auto-unblocks IPs once their block duration expires
start_maintenance_loop()

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# --- Fake user store (one user, lab purposes only) ---------------------
USERS = {
    "admin": generate_password_hash("Summer2027!")
}

# --- Logging setup -------------------------------------------------------
# Two separate logs on purpose: access.log is "what happened on the wire",
# auth.log is "who tried to log in and did it work". Splitting them makes
# the protector's brute-force detector simpler — it only has to read one
# focused log instead of filtering a noisy combined one.

os.makedirs("logs", exist_ok=True)

access_logger = logging.getLogger("access")
access_logger.setLevel(logging.INFO)
access_handler = logging.FileHandler("logs/access.log")
access_handler.setFormatter(logging.Formatter("%(message)s"))
access_logger.addHandler(access_handler)

auth_logger = logging.getLogger("auth")
auth_logger.setLevel(logging.INFO)
auth_handler = logging.FileHandler("logs/auth.log")
auth_handler.setFormatter(logging.Formatter("%(message)s"))
auth_logger.addHandler(auth_handler)


def log_access(status_code):
    """Log every request: timestamp | src_ip | method | path | status"""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    ip = request.remote_addr
    access_logger.info(f"{ts}|{ip}|{request.method}|{request.path}|{status_code}")


def log_auth(username, ip, success):
    """Log every login attempt: timestamp | src_ip | username | SUCCESS/FAIL"""
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    result = "SUCCESS" if success else "FAIL"
    auth_logger.info(f"{ts}|{ip}|{username}|{result}")


# --- Defense hooks ---------------------------------------------------------

@app.before_request
def _enforce_block():
    """Runs before every request. Rejects anything from a blocked IP."""
    if is_blocked(request.remote_addr):
        return "Forbidden — IP blocked by defense system", 403


@app.after_request
def after_request(response):
    """Runs after every request. Logs it, then feeds it to the DDoS/webshell detector."""
    log_access(response.status_code)
    record_request(request.remote_addr, request.path)
    return response


# --- Routes ---------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    VULNERABLE ON PURPOSE: no rate limit, no lockout, no CAPTCHA at the
    app level — brute force protection is handled by defense.py instead,
    which blocks the IP after too many failed attempts.
    """
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        ip = request.remote_addr

        valid = username in USERS and check_password_hash(USERS[username], password)
        log_auth(username, ip, valid)
        record_login_attempt(ip, success=valid)

        if valid:
            session["user"] = username
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid credentials")
            return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", user=session["user"])


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("home"))


@app.route("/upload", methods=["GET", "POST"])
def upload():
    """
    VULNERABLE ON PURPOSE: no file extension allowlist, no content
    inspection, saves with the original filename. This is the web shell
    surface — a .php or .py file dropped here and then requested directly
    is the attack you're meant to detect, not prevent at the app layer
    (that's the protector's job, triggered when /uploads/<file> is hit).
    """
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        file = request.files.get("file")
        if file and file.filename:
            filename = secure_filename(file.filename)  # stops path traversal, NOT extension
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)
            flash(f"Uploaded: {filename}")
        return redirect(url_for("upload"))

    files = os.listdir(app.config["UPLOAD_FOLDER"])
    return render_template("upload.html", files=files)


@app.route("/uploads/<path:filename>")
def serve_upload(filename):
    """
    Serves uploaded files directly — including anything malicious that
    was uploaded. This is intentional: it's what lets an uploaded web
    shell actually get 'executed'/accessed in your attack simulation.
    Hitting this path triggers webshell detection in defense.py.
    """
    from flask import send_from_directory
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/api/ping")
def ping():
    """
    VULNERABLE ON PURPOSE: cheap, unauthenticated, unthrottled endpoint.
    This is the DDoS target — flood this with the attacker script and
    watch request-rate-per-IP spike in access.log, then get auto-blocked
    once DDOS_THRESHOLD is hit in defense.py.
    """
    return {"status": "ok", "time": time.time()}


if __name__ == "__main__":
  app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
