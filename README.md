# Flask Attack/Defense Lab

Multi-component lab simulating common attack patterns (brute force, DDoS, webshell upload) against a Flask app, with an application-layer defense module mapped to MITRE ATT&CK.

## Architecture

- `app.py` — target Flask application, imports `defense.py` directly (no separate process)
- `defense.py` — application-layer detection/blocking module (IP blocking done at app layer, not OS/firewall level — avoids requiring admin privileges)
- `brute.py` — brute force attack simulator
- `ddos.py` — request-flood attack simulator
- `webshell.py` — webshell upload/access simulator

**Design note:** originally split into `firewall.py` + `defense.py`; consolidated into a single `defense.py` imported into `app.py` for simplicity and to eliminate cross-process coordination overhead.

## MITRE ATT&CK Mapping

| Attack Script | Technique ID | Technique Name |
|---|---|---|
| `brute.py` | T1110 | Brute Force |
| `ddos.py` | T1498 | Network Denial of Service |
| `webshell.py` | T1505.003 | Web Shell |

## Verified Metrics

| Attack | Detection/Block Point | Notes |
|---|---|---|
| Brute force | Blocked at attempt 5 (401 → 403) | |
| DDoS | Threshold: 50 req/10s | 30-min cooldown after trigger |
| Webshell | Detected on first access | One-request window before block engages |

## Setup

```bash
pip install -r requirements.txt
python app.py --port <port>
```

## Running the Attacks

```bash
python brute.py --target <LAN_IP>:<port>
python ddos.py --target <LAN_IP>:<port>
python webshell.py --target <LAN_IP>:<port>
```

> **Note:** point attack scripts at the LAN IP, not `127.0.0.1`. See known limitations below.

## Debugging Lessons Learned

- **Whitelist false-negative:** `127.0.0.1` silently bypassed IP blocks when attack scripts targeted localhost instead of the LAN IP — the whitelist logic treated loopback as trusted by default.
- **Double-port argparse bug:** duplicate `--port` argument definitions caused silent overrides; only the last-defined default was ever used.
- **Ground truth is `defense.log`, not attacker-side terminal output.** Attacker scripts can report false negatives/positives due to timing or connection handling on their end — always verify against the defender's own log.
- **Isolate with a single manual request before changing code.** When behavior looked wrong, sending one manual `curl`/request first confirmed whether the bug was in the attack script or the defense logic, before touching either.

## Known Limitations

- IP blocking is application-layer only (not enforced at OS/firewall level) — trades robustness for zero-admin-privilege setup
- [add: single-host lab, not tested against distributed/multi-source attacks]
- [add: no persistence of block state across app restarts, if applicable]
- [add: any other limitation specific to your testing]

proof of firewall 
before firewall 

<img width="1600" height="820" alt="brute before firewall" src="https://github.com/user-attachments/assets/00597b31-e13f-4f9e-91c9-720a3a4087f5" />

<img width="801" height="422" alt="ddos before firewall" src="https://github.com/user-attachments/assets/ce0d0e80-23ca-4062-8d02-f2f35c64521d" />

<img width="1600" height="846" alt="webshell before firewall" src="https://github.com/user-attachments/assets/46dc5700-eba8-4349-8e08-846fb9e32788" />
after firewall
<img width="1600" height="849" alt="brute after firewall" src="https://github.com/user-attachments/assets/dee132dc-a714-467d-8835-0e15808003a5" />

<img width="1491" height="956" alt="ddos after firewall" src="https://github.com/user-attachments/assets/5edb3516-2dae-421c-8dcd-627eb7eddd2f" />

  <img width="1600" height="844" alt="webshell after firewall" src="https://github.com/user-attachments/assets/0b4401b4-d709-4b31-a182-4f0d23e412a4" />

  



