"""
defense.py
Unified detection + prevention engine for the SOC lab (app-layer version).

No admin/sudo required — blocking happens inside Flask itself via a
before_request check, not at the OS firewall level. This is the same
pattern real WAFs and reverse proxies use (L7 enforcement).

Usage:
    Import into app.py and call the record_*() functions from the
    relevant hooks/routes, plus check is_blocked() in a before_request.
    Run this file directly to test the block/unblock cycle standalone.
"""

import json
import os
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque

# ---------------- Config ----------------
BLOCKED_IPS_FILE = "blocked_ips.json"
LOG_FILE = "defense.log"

BRUTE_FORCE_THRESHOLD = 5       # failed logins
BRUTE_FORCE_WINDOW = 60         # seconds
DDOS_THRESHOLD = 50             # requests
DDOS_WINDOW = 10                # seconds
BLOCK_DURATION_MINUTES = 30     # auto-unblock after this long

WHITELIST = {"127.0.0.1", "::1"}   # never block these

WEBSHELL_SUSPICIOUS_PATHS = {"/uploads"}  # adjust to match where dropped files get served

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# ---------------- Persistent block state ----------------
def _load_blocked_ips() -> dict:
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_blocked_ips(data: dict):
    with open(BLOCKED_IPS_FILE, "w") as f:
        json.dump(data, f, indent=2)


# ---------------- Enforcement (app-layer prevention) ----------------
def block_ip(ip: str, reason: str = "unspecified", duration_minutes: int = BLOCK_DURATION_MINUTES) -> bool:
    """Add an IP to the blocklist. Enforcement happens via is_blocked() in Flask's before_request."""
    if ip in WHITELIST:
        logging.warning(f"Refused to block whitelisted IP {ip}")
        return False

    blocked = _load_blocked_ips()
    if ip in blocked:
        return True  # already blocked, nothing to do

    blocked[ip] = {
        "blocked_at": datetime.now().isoformat(),
        "reason": reason,
        "expires_at": (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
    }
    _save_blocked_ips(blocked)
    logging.info(f"BLOCKED {ip} | reason={reason} | duration={duration_minutes}m")
    print(f"[BLOCKED] {ip} — {reason}")
    return True


def unblock_ip(ip: str) -> bool:
    blocked = _load_blocked_ips()
    if ip in blocked:
        blocked.pop(ip)
        _save_blocked_ips(blocked)
        logging.info(f"UNBLOCKED {ip}")
        print(f"[UNBLOCKED] {ip}")
    return True


def check_expired_blocks():
    blocked = _load_blocked_ips()
    now = datetime.now()
    expired = [ip for ip, meta in blocked.items()
               if meta.get("expires_at") and now >= datetime.fromisoformat(meta["expires_at"])]
    for ip in expired:
        unblock_ip(ip)
    return expired


def list_blocked_ips() -> dict:
    return _load_blocked_ips()


def is_blocked(ip: str) -> bool:
    return ip in _load_blocked_ips()


# ---------------- Detection ----------------
# In-memory sliding-window trackers. Not persisted — resets on restart by design,
# since these are short detection windows (seconds), not long-term state.
_failed_logins = defaultdict(lambda: deque())   # ip -> timestamps of failed logins
_request_times = defaultdict(lambda: deque())   # ip -> timestamps of all requests
_lock = threading.Lock()


def _prune(dq: deque, window_seconds: int):
    cutoff = time.time() - window_seconds
    while dq and dq[0] < cutoff:
        dq.popleft()


def record_login_attempt(ip: str, success: bool):
    """Call this from your Flask login route on every attempt."""
    if success:
        return  # only track failures
    with _lock:
        dq = _failed_logins[ip]
        dq.append(time.time())
        _prune(dq, BRUTE_FORCE_WINDOW)
        if len(dq) >= BRUTE_FORCE_THRESHOLD:
            logging.info(f"DETECTED brute force from {ip} ({len(dq)} failed logins in {BRUTE_FORCE_WINDOW}s)")
            block_ip(ip, reason="bruteforce_threshold_exceeded")
            dq.clear()


def record_request(ip: str, path: str = ""):
    """Call this from an after_request/before_request hook in Flask on every incoming request."""
    with _lock:
        dq = _request_times[ip]
        dq.append(time.time())
        _prune(dq, DDOS_WINDOW)
        if len(dq) >= DDOS_THRESHOLD:
            logging.info(f"DETECTED possible DDoS from {ip} ({len(dq)} requests in {DDOS_WINDOW}s)")
            block_ip(ip, reason="ddos_rate_exceeded")
            dq.clear()

    if path and any(path.lower().startswith(p) for p in WEBSHELL_SUSPICIOUS_PATHS):
        logging.info(f"DETECTED webshell access attempt from {ip} on path {path}")
        block_ip(ip, reason=f"webshell_path_access:{path}")


# ---------------- Background maintenance ----------------
def start_maintenance_loop(interval_seconds: int = 60):
    """Runs check_expired_blocks() on a timer in a daemon thread."""
    def _loop():
        while True:
            expired = check_expired_blocks()
            if expired:
                logging.info(f"Auto-unblocked expired IPs: {expired}")
            time.sleep(interval_seconds)

    t = threading.Thread(target=_loop, daemon=True)
    t.start()
    return t


# ---------------- Standalone test mode ----------------
if __name__ == "__main__":
    print("=== defense.py standalone test (app-layer, no admin needed) ===")

    test_ip = "192.0.2.123"  # TEST-NET-1, safe non-routable address

    print("\n[1] Simulating brute force detection...")
    for _ in range(BRUTE_FORCE_THRESHOLD):
        record_login_attempt(test_ip, success=False)

    print("Blocked IPs now:", list_blocked_ips())
    print("is_blocked check:", is_blocked(test_ip))

    print("\n[2] Testing unblock...")
    unblock_ip(test_ip)
    print("Blocked IPs now:", list_blocked_ips())

    print("\n[3] Starting maintenance loop (Ctrl+C to stop)...")
    start_maintenance_loop(interval_seconds=10)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped.")
