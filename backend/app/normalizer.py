"""
DNS log format normalizer for DTDS.

Auto-detects the source format and normalizes to a standard 6-column DataFrame.

Supported formats
-----------------
1. DTDS CSV          — native 6-column CSV
2. Zeek dns.log      — TSV with #separator / #fields header
3. Suricata eve.json — JSON Lines, event_type = "dns"
4. AWS Route53       — AWS DNS query log CSV (hosted-zone-id column)
5. Windows DNS Debug — text log from Windows DNS Server debug mode
6. dnsmasq log       — syslog-style  dnsmasq[pid]: query[TYPE] domain
7. BIND named log    — ISC BIND  named[pid]: query: domain IN TYPE
8. Generic CSV/TSV   — any CSV/TSV with recognizable column names
"""

from __future__ import annotations

import io
import json
import re
from datetime import datetime, timezone

import pandas as pd

# ---------------------------------------------------------------------------
# Standard output column names
# ---------------------------------------------------------------------------
_REQUIRED = ["timestamp", "domain", "query_type", "query_length", "subdomain_count", "response_size"]

# ---------------------------------------------------------------------------
# Generic CSV: synonym maps  (key = standard name, value = accepted names)
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# Generic CSV: synonym maps  (key = standard name, value = accepted names)
#
# Covers: DTDS native, Elastic ECS, Splunk, Windows Event Log, CrowdStrike,
# Cisco Umbrella, Palo Alto, Zeek exported CSV, pcap tools, various SIEMs.
# Dots / spaces / hyphens in column names are normalised → underscores before
# this table is consulted. CamelCase is split → snake_case automatically.
# ---------------------------------------------------------------------------
_SYNONYMS: dict[str, set[str]] = {
    "timestamp": {
        # Generic
        "ts", "time", "date", "datetime", "date_time",
        "event_time", "log_time", "query_time", "request_time",
        "start_time", "timestamp", "received_time", "created_at",
        "occurred_at", "log_timestamp", "event_datetime",
        "time_dt", "time_utc", "dns_time", "record_time",
        # Splunk
        "_time",
        # Elastic / ECS  (dot-notation normalized)
        "timestamp", "event_timestamp", "event_created",
        "event_start", "event_ingested", "zeek_ts",
        # Windows Event Log
        "eventtime", "eventcreatedtime", "systemtime",
        "timecreated", "event_time_utc",
        # Cisco Umbrella
        "querytime", "internalip", "externalip",   # keep for later cols
        # CrowdStrike
        "eventtimestamp", "detectiontime",
        # Palo Alto
        "receive_time", "generate_time", "session_start_time",
        # BIND/named
        "query_timestamp", "log_ts", "log_date",
    },
    "domain": {
        # Generic
        "query", "fqdn", "qname", "hostname", "host",
        "dns_query", "rrname", "name", "domain_name",
        "resource", "domain", "queried_domain", "question",
        "lookup", "searched_domain", "resolved_domain",
        "queried_name", "dns_record_name", "dns_fqdn",
        "answer", "record_name", "dns_name", "dns_hostname",
        # Elastic ECS (dots → underscores)
        "dns_question_name", "dns_query_name",
        "dns_question_registered_domain", "url_domain",
        "destination_domain", "source_domain",
        # Windows Event Log
        "queryname", "dnsqueryname", "dns_query_name",
        # Splunk
        "query_name", "src_domain", "dst_domain", "target_domain",
        # Cisco Umbrella
        "domain", "blocked_domain", "requestdomain",
        # CrowdStrike
        "domainname", "networkdnsquery",
        # Palo Alto
        "url", "dns_query_name", "xdns_query",
        # Zeek exported CSV
        "query", "dns_query",
        # pcap/tshark exports
        "dns_qry_name", "dns_a", "col_info",
        # Generic SIEM
        "network_dns_query", "networkdnsquery",
        "dns_request_name", "dns_lookup_domain",
    },
    "query_type": {
        # Generic
        "type", "qtype", "record_type", "dns_type",
        "rtype", "rrtype", "qtype_name", "dns_record_type",
        "query_type", "dns_type_name", "dnstype",
        "lookup_type", "resolution_type", "dns_class",
        "record_type_name",
        # Elastic ECS
        "dns_question_type", "dns_question_type_name",
        "dns_query_type",
        # Windows Event Log
        "querytype", "dnsquerytype",
        # CrowdStrike
        "networkdnsquerytype", "network_dns_query_type",
        # Cisco Umbrella
        "responsetype", "requesttype",
        # Palo Alto
        "dns_type", "xdns_type",
        # tshark
        "dns_qry_type",
        # Generic
        "rrclass",
    },
    "query_length": {
        # Generic
        "length", "len", "qlen", "query_len", "payload_len",
        "size", "query_length", "packet_length", "pkt_len",
        "query_size", "request_size", "dns_length",
        "bytes_sent", "query_bytes", "message_length",
        "dns_msg_size", "query_name_length",
        # tshark
        "frame_len", "ip_len",
        # Splunk
        "bytes", "sent_bytes",
    },
    "subdomain_count": {
        # Generic
        "labels", "depth", "label_count", "subdomain_count",
        "subdomain_levels", "num_labels", "num_subdomains",
        "label_num", "dns_labels", "label_depth",
        # Computed variants
        "subdomains", "n_labels", "dot_count", "levels",
    },
    "response_size": {
        # Generic
        "resp_size", "answer_size", "response_len",
        "response_bytes", "response_size", "reply_length",
        "ans_length", "resp_len", "response_length",
        "reply_size", "answer_bytes",
        # Splunk
        "bytes_received", "received_bytes",
        # tshark
        "dns_resp_len", "udp_length",
        # Generic SIEM
        "dns_response_size", "response_payload",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _subdomain_count(domain: str) -> int:
    try:
        parts = domain.strip(".").split(".")
        return max(0, len(parts) - 2)
    except Exception:
        return 0


def _fill_computed(df: pd.DataFrame) -> pd.DataFrame:
    """Add missing standard columns with computed/default values."""
    df = df.reset_index(drop=True)  # ensure clean 0-based index throughout

    if "query_length" not in df.columns or df["query_length"].isna().all():
        df["query_length"] = df.get("domain", pd.Series([""] * len(df))).str.len().fillna(0).values
    if "subdomain_count" not in df.columns or df["subdomain_count"].isna().all():
        df["subdomain_count"] = (
            df.get("domain", pd.Series([""] * len(df)))
            .apply(lambda d: _subdomain_count(str(d)))
            .values
        )
    if "response_size" not in df.columns or df["response_size"].isna().all():
        df["response_size"] = 0
    if "query_type" not in df.columns or df["query_type"].isna().all():
        df["query_type"] = "A"
    if "timestamp" not in df.columns or df["timestamp"].isna().all():
        df["timestamp"] = datetime.now(timezone.utc).isoformat()
    return df


def _standardize(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce every standard column to the correct type."""
    df["query_length"] = pd.to_numeric(df["query_length"], errors="coerce").fillna(0).astype(int)
    df["subdomain_count"] = pd.to_numeric(df["subdomain_count"], errors="coerce").fillna(0).astype(int)
    df["response_size"] = pd.to_numeric(df["response_size"], errors="coerce").fillna(0).astype(int)
    df["domain"] = df["domain"].fillna("").astype(str).str.strip().str.rstrip(".")
    df["query_type"] = df["query_type"].fillna("A").astype(str).str.upper().str.strip()
    df["timestamp"] = df["timestamp"].fillna("").astype(str)
    return df


def _finalize(df: pd.DataFrame) -> pd.DataFrame:
    """Fill missing columns, standardize types, reorder."""
    df = _fill_computed(df)
    df = _standardize(df)
    ordered = [c for c in _REQUIRED if c in df.columns]
    extra = [c for c in df.columns if c not in ordered]
    df = df[ordered + extra]
    df = df.dropna(subset=["domain"])
    df = df[df["domain"].str.strip() != ""]
    df = df.reset_index(drop=True)
    return df


# ---------------------------------------------------------------------------
# Format 1 — DTDS CSV (native)
# ---------------------------------------------------------------------------

def _is_dtds(cols: set[str]) -> bool:
    return {
        "timestamp", "domain", "query_type",
        "query_length", "subdomain_count", "response_size",
    }.issubset(cols)


def _parse_dtds(raw: bytes) -> pd.DataFrame:
    df = pd.read_csv(io.BytesIO(raw), comment="#")
    df.columns = df.columns.str.strip().str.lower()
    return df


# ---------------------------------------------------------------------------
# Format 2 — Zeek / Bro dns.log
# ---------------------------------------------------------------------------

def _is_zeek(raw: bytes) -> bool:
    try:
        head = raw[:600].decode("utf-8", errors="ignore")
        return ("#separator" in head or "#fields" in head) and (
            "uid" in head or "id.orig_h" in head
        )
    except Exception:
        return False


def _parse_zeek(raw: bytes) -> pd.DataFrame:
    text = raw.decode("utf-8", errors="ignore")
    lines = text.splitlines()
    fields: list[str] = []
    separator = "\t"
    data_lines: list[str] = []

    for line in lines:
        if line.startswith("#separator"):
            parts = line.split()
            sep_hex = parts[-1] if parts else "\\x09"
            if sep_hex.startswith("\\x"):
                separator = bytes.fromhex(sep_hex[2:]).decode()
        elif line.startswith("#fields"):
            fields = line.split(separator)[1:]
        elif line.startswith("#"):
            continue
        else:
            data_lines.append(line)

    if not fields or not data_lines:
        raise ValueError("Zeek dns.log: #fields header missing or no data rows")

    df = pd.DataFrame(
        [line.split(separator) for line in data_lines if line.strip()],
        columns=fields,
    )

    rename: dict[str, str] = {}
    for zeek_col, std_col in [
        ("ts", "timestamp"),
        ("query", "domain"),
        ("qtype_name", "query_type"),
        ("qtype", "query_type"),        # fallback if qtype_name absent
        ("orig_ip_bytes", "response_size"),
        ("resp_ip_bytes", "response_size"),
    ]:
        if zeek_col in df.columns and std_col not in rename.values():
            rename[zeek_col] = std_col
    df = df.rename(columns=rename)

    # Convert Zeek Unix epoch float → ISO string
    if "timestamp" in df.columns:
        def _ts(v: str) -> str:
            try:
                return datetime.fromtimestamp(float(v), tz=timezone.utc).isoformat()
            except Exception:
                return str(v)
        df["timestamp"] = df["timestamp"].apply(_ts)

    if "domain" in df.columns:
        df["query_length"] = df["domain"].str.len().fillna(0)

    return df


# ---------------------------------------------------------------------------
# Format 3 — Suricata eve.json
# ---------------------------------------------------------------------------

def _is_suricata(raw: bytes) -> bool:
    try:
        head = raw[:600].decode("utf-8", errors="ignore")
        return '"event_type"' in head and '"dns"' in head
    except Exception:
        return False


def _parse_suricata(raw: bytes) -> pd.DataFrame:
    rows: list[dict] = []
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("event_type") != "dns":
            continue
        dns = obj.get("dns", {})
        # Handle both query and answer events
        domain = (
            dns.get("rrname")
            or (dns.get("queries") or [{}])[0].get("rrname", "")
        )
        qtype = (
            dns.get("rrtype")
            or (dns.get("queries") or [{}])[0].get("rrtype", "A")
        )
        answers = dns.get("answers") or []
        rows.append({
            "timestamp": obj.get("timestamp", ""),
            "domain": str(domain).rstrip("."),
            "query_type": str(qtype).upper(),
            "query_length": len(str(domain)),
            "response_size": sum(len(str(a.get("rdata", ""))) for a in answers) if answers else 0,
        })
    if not rows:
        raise ValueError("No DNS events found in Suricata eve.json")
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Format 4 — AWS Route53 DNS query logs
# ---------------------------------------------------------------------------

def _is_route53(cols: set[str]) -> bool:
    return "hosted_zone_id" in cols or "hosted-zone-id" in cols or (
        "responsecode" in cols and "name" in cols
    )


def _parse_route53(raw: bytes) -> pd.DataFrame:
    df = pd.read_csv(io.BytesIO(raw), comment="#")
    df.columns = (
        df.columns.str.strip().str.lower().str.replace("-", "_").str.replace(" ", "_")
    )

    rename: dict[str, str] = {}

    # Timestamp: combine date + time or use single column
    if "date" in df.columns and "time" in df.columns:
        df["timestamp"] = df["date"].astype(str) + "T" + df["time"].astype(str)
    elif "date" in df.columns:
        rename["date"] = "timestamp"

    # Domain
    for c in ("name", "query_name", "qname"):
        if c in df.columns:
            rename[c] = "domain"
            break

    # Query type
    for c in ("type", "qtype", "querytype"):
        if c in df.columns:
            rename[c] = "query_type"
            break

    df = df.rename(columns=rename)
    if "domain" in df.columns:
        df["domain"] = df["domain"].str.rstrip(".")
    return df


# ---------------------------------------------------------------------------
# Format 5 — Windows DNS Server Debug log
# ---------------------------------------------------------------------------
_WIN_LINE = re.compile(
    r"(\d{1,2}/\d{1,2}/\d{2,4}\s+\d{1,2}:\d{2}:\d{2}(?:\s+[AP]M)?)"  # timestamp
    r".*?(?:QUERY|RESPONSE|PACKET|Q)\s+"
    r"(\w+)\s+"                             # query type
    r"([\w][\w\.\-]*[\w])",                # domain (at least 2 chars)
    re.IGNORECASE,
)


def _is_windows_dns(raw: bytes) -> bool:
    try:
        head = raw[:800].decode("utf-8", errors="ignore")
        return bool(
            re.search(r"\d{1,2}/\d{1,2}/\d{4}\s+\d{1,2}:\d{2}:\d{2}", head)
        ) and ("QUERY" in head.upper() or "PACKET" in head.upper())
    except Exception:
        return False


def _parse_windows_dns(raw: bytes) -> pd.DataFrame:
    rows: list[dict] = []
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        m = _WIN_LINE.search(line)
        if m:
            domain = m.group(3)
            rows.append({
                "timestamp": m.group(1).strip(),
                "domain": domain.rstrip("."),
                "query_type": m.group(2).upper(),
                "query_length": len(domain),
            })
    if not rows:
        raise ValueError("No DNS query lines matched in Windows DNS debug log")
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Format 6 — dnsmasq log (syslog style)
# ---------------------------------------------------------------------------
_DNSMASQ_LINE = re.compile(
    r"(\w{3}\s+\d+\s+[\d:]+)"  # syslog timestamp
    r".*?dnsmasq.*?"
    r"query\[(\w+)\]\s+([\w][\w\.\-]+)",
    re.IGNORECASE,
)


def _is_dnsmasq(raw: bytes) -> bool:
    try:
        head = raw[:600].decode("utf-8", errors="ignore")
        return "dnsmasq" in head.lower() and "query[" in head.lower()
    except Exception:
        return False


def _parse_dnsmasq(raw: bytes) -> pd.DataFrame:
    rows: list[dict] = []
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        m = _DNSMASQ_LINE.search(line)
        if m:
            domain = m.group(3)
            rows.append({
                "timestamp": m.group(1).strip(),
                "domain": domain.rstrip("."),
                "query_type": m.group(2).upper(),
                "query_length": len(domain),
            })
    if not rows:
        raise ValueError("No dnsmasq query lines found")
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Format 7 — ISC BIND / named query log
# ---------------------------------------------------------------------------
_BIND_LINE = re.compile(
    r"(\d{2}-\w{3}-\d{4}\s+[\d:\.]+|\w{3}\s+\d+\s+[\d:]+)"  # timestamp variants
    r".*?query:\s+([\w][\w\.\-]+)\s+IN\s+(\w+)",
    re.IGNORECASE,
)


def _is_bind(raw: bytes) -> bool:
    try:
        head = raw[:600].decode("utf-8", errors="ignore")
        return "named" in head.lower() and "query:" in head.lower() and " IN " in head.upper()
    except Exception:
        return False


def _parse_bind(raw: bytes) -> pd.DataFrame:
    rows: list[dict] = []
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        m = _BIND_LINE.search(line)
        if m:
            domain = m.group(2)
            rows.append({
                "timestamp": m.group(1).strip(),
                "domain": domain.rstrip("."),
                "query_type": m.group(3).upper(),
                "query_length": len(domain),
            })
    if not rows:
        raise ValueError("No BIND query lines found")
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# Format 8 — Generic CSV / TSV with synonym column mapping
# ---------------------------------------------------------------------------
# FQDN-like pattern (used for content-based inference)
_FQDN_RE = re.compile(
    r"^[a-zA-Z0-9][a-zA-Z0-9\-\.]{0,252}\.[a-zA-Z]{2,}[\.]?$"
)
# DNS record type values
_DNS_RECORD_TYPES: set[str] = {
    "A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT", "PTR",
    "SRV", "NAPTR", "CAA", "DNSKEY", "DS", "NULL", "ANY",
    "HINFO", "HTTPS", "SVCB", "LOC", "SPF", "CERT", "AFSDB",
}

_SYNONYMS = {
    "timestamp": {"timestamp", "date", "time", "datetime", "ts", "query_time", "date_time"},
    "domain": {"domain", "qname", "query_name", "name", "query", "hostname", "fqdn"},
    "query_type": {"query_type", "type", "qtype", "rrtype", "query_type_name"},
    "query_length": {"query_length", "len", "qlen"},
    "response_size": {"response_size", "size", "bytes", "respsize", "answer_size"},
    "subdomain_count": {"subdomain_count", "sub_count", "label_count"},
}


def _to_snake(col: str) -> str:
    """
    Normalise any column naming style to lowercase_snake_case.

    Handles:
    - Spaces / hyphens / dots     → underscores
    - Leading @ or #              → stripped
    - CamelCase / PascalCase      → snake_case
    - UPPER_CASE                  → lower_case
    - Elastic ECS  dns.question.name  → dns_question_name
    - Windows      DnsQueryName       → dns_query_name
    - Splunk       _time               → time
    """
    col = col.strip()
    # Strip leading special chars (@, #, _)
    col = re.sub(r'^[@#_]+', '', col)
    # Replace dots, hyphens, spaces with underscores
    col = re.sub(r'[.\-\s]+', '_', col)
    # Insert underscore before an uppercase letter that follows a lowercase letter or digit
    col = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', col)
    # Insert underscore before an uppercase letter followed by lowercase (e.g. DNSQuery → DNS_Query)
    col = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', '_', col)
    return col.lower().strip('_')


def _apply_synonyms(df: pd.DataFrame) -> pd.DataFrame:
    """
    1. Normalise every column name to snake_case.
    2. Map via _SYNONYMS to standard names.
    Returns the renamed DataFrame.
    """
    # Step 1: normalise
    df = df.rename(columns={c: _to_snake(c) for c in df.columns})
    # Step 2: synonym map (first match wins per standard column)
    rename: dict[str, str] = {}
    assigned: set[str] = set()
    for std_name, synonyms in _SYNONYMS.items():
        for col in df.columns:
            if col in synonyms and std_name not in assigned:
                rename[col] = std_name
                assigned.add(std_name)
                break
    return df.rename(columns=rename)


def _infer_from_content(df: pd.DataFrame) -> pd.DataFrame:
    """
    Last-resort: inspect cell values to find the domain / query_type /
    timestamp columns when synonym mapping didn't find them.
    Only touches columns that are not already mapped to a standard name.
    """
    std_already = set(df.columns) & {
        "timestamp", "domain", "query_type",
        "query_length", "subdomain_count", "response_size",
    }
    candidates = [c for c in df.columns if c not in std_already]

    rename: dict[str, str] = {}

    for col in candidates:
        sample = df[col].dropna().astype(str).head(30)
        if not len(sample):
            continue

        # --- Domain detection ---
        if "domain" not in std_already and "domain" not in rename.values():
            fqdn_hits = sample.str.strip().apply(
                lambda v: bool(_FQDN_RE.match(v)) and "." in v
            ).sum()
            if fqdn_hits >= max(1, len(sample) * 0.6):
                rename[col] = "domain"
                continue

        # --- Query type detection ---
        if "query_type" not in std_already and "query_type" not in rename.values():
            type_hits = sample.str.strip().str.upper().apply(
                lambda v: v in _DNS_RECORD_TYPES
            ).sum()
            if type_hits >= max(1, len(sample) * 0.7):
                rename[col] = "query_type"
                continue

        # --- Timestamp detection ---
        if "timestamp" not in std_already and "timestamp" not in rename.values():
            try:
                pd.to_datetime(sample.head(5), errors="raise")
                rename[col] = "timestamp"
                continue
            except Exception:
                pass
            # Unix epoch integers
            try:
                nums = pd.to_numeric(sample.head(5), errors="raise")
                if (nums > 1_000_000_000).all() and (nums < 10_000_000_000).all():
                    rename[col] = "timestamp"
                    df[col] = pd.to_datetime(nums, unit="s", utc=True).astype(str)
                    continue
            except Exception:
                pass

        # --- Numeric size / length fields (fill in order of priority) ---
        try:
            nums = pd.to_numeric(sample, errors="raise")
            if "query_length" not in std_already and "query_length" not in rename.values():
                if (nums >= 0).all() and (nums <= 500).all():
                    rename[col] = "query_length"
                    continue
            if "response_size" not in std_already and "response_size" not in rename.values():
                rename[col] = "response_size"
                continue
        except Exception:
            pass

    return df.rename(columns=rename)


def _parse_generic(raw: bytes) -> pd.DataFrame:
    """Try common delimiters; apply synonym mapping + content inference."""
    errors: list[str] = []
    for sep in (",", "\t", ";", "|"):
        try:
            df = pd.read_csv(
                io.BytesIO(raw), sep=sep, engine="python",
                on_bad_lines="skip", comment="#",
            )
            if df.shape[1] < 2:
                continue
            df = _apply_synonyms(df)
            if "domain" not in df.columns:
                df = _infer_from_content(df)
            if "domain" in df.columns:
                return df
            errors.append(f"sep={sep!r}: no domain column found after synonym+content inference")
        except Exception as exc:
            errors.append(f"sep={sep!r}: {exc}")
    raise ValueError(
        "Generic CSV/TSV: could not identify a domain column. "
        + " | ".join(errors)
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

ACCEPTED_EXTENSIONS = {".csv", ".tsv", ".log", ".txt", ".json"}


def detect_and_normalize(raw: bytes, filename: str) -> tuple[pd.DataFrame, str]:
    """
    Auto-detect format and return (normalized_dataframe, format_name).

    The returned DataFrame always has all 6 standard columns:
      timestamp, domain, query_type, query_length, subdomain_count, response_size

    Missing columns are filled with computed or sensible defaults.
    """
    # --- 1. JSON-based formats ---
    if _is_suricata(raw):
        return _finalize(_parse_suricata(raw)), "Suricata eve.json"

    # --- 2. Zeek TSV ---
    if _is_zeek(raw):
        return _finalize(_parse_zeek(raw)), "Zeek dns.log"

    # --- 3. Syslog-style text logs ---
    if _is_dnsmasq(raw):
        return _finalize(_parse_dnsmasq(raw)), "dnsmasq log"

    if _is_bind(raw):
        return _finalize(_parse_bind(raw)), "BIND named query log"

    if _is_windows_dns(raw):
        return _finalize(_parse_windows_dns(raw)), "Windows DNS Debug log"

    # --- 4. CSV-based formats ---
    try:
        probe = pd.read_csv(io.BytesIO(raw), nrows=5, comment="#")
        cols = set(probe.columns.str.strip().str.lower())

        if _is_dtds(cols):
            return _finalize(_parse_dtds(raw)), "DTDS CSV (native)"

        if _is_route53(cols):
            return _finalize(_parse_route53(raw)), "AWS Route53 query log"

        # Generic CSV — try synonym mapping
        df = _apply_synonyms(pd.read_csv(io.BytesIO(raw), on_bad_lines="skip", comment="#"))
        if "domain" in df.columns:
            return _finalize(df), "Generic CSV (auto-mapped)"

    except Exception:
        pass

    # --- 5. Generic TSV / other delimiters ---
    df, fmt = _finalize(_parse_generic(raw)), "Generic CSV (auto-mapped)"
    return df, fmt
