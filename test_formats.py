"""Test all 7 DNS log formats against the live API."""
import requests, os

BASE = "http://localhost:8000"

# Login
r = requests.post(f"{BASE}/auth/register",
    json={"name": "Test User", "email": "test@dtds.dev", "password": "password123"})

r = requests.post(f"{BASE}/auth/login",
    json={"email": "test@dtds.dev", "password": "password123"})
r.raise_for_status()
token = r.json()["access_token"]
headers = {"Authorization": f"Bearer {token}"}

FILES = [
    ("sample_dns_logs.csv",      "text/csv"),
    ("sample_zeek_dns.log",      "text/plain"),
    ("sample_suricata_eve.json", "application/json"),
    ("sample_route53.csv",       "text/csv"),
    ("sample_dnsmasq.log",       "text/plain"),
    ("sample_bind_named.log",    "text/plain"),
    ("sample_generic.tsv",       "text/tab-separated-values"),
]

print(f"{'File':<32} {'Detected Format':<32} {'Rows':>5}  Status")
print("-" * 80)

for fname, mime in FILES:
    path = os.path.join(os.path.dirname(__file__), fname)
    with open(path, "rb") as f:
        raw = f.read()
    resp = requests.post(
        f"{BASE}/uploads",
        headers=headers,
        files={"file": (fname, raw, mime)},
    )
    if resp.ok:
        d = resp.json()
        print(f"{fname:<32} {d['detected_format']:<32} {d['row_count']:>5}  OK")
    else:
        print(f"{fname:<32} {'ERROR ' + str(resp.status_code):<32}       {resp.text[:80]}")
