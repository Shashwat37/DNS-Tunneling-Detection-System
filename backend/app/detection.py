"""
Detection engine for DNS tunneling.

Feature extraction + rule-based scoring → Normal / Suspicious label.
Optional Isolation Forest as secondary signal.
"""

import math
import re
from collections import Counter

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(s: str) -> float:
    """Shannon entropy of a string (bits per character)."""
    if not s:
        return 0.0
    freq = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_subdomain(domain: str) -> str:
    """Return everything before the last two labels (the registered domain)."""
    parts = domain.strip(".").split(".")
    if len(parts) <= 2:
        return ""
    return ".".join(parts[:-2])


def _domain_label_length(domain: str) -> int:
    """Length of the longest label in the FQDN."""
    parts = domain.strip(".").split(".")
    return max((len(p) for p in parts), default=0)


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Compute per-row features from the raw DNS log DataFrame.
    Returns a new DataFrame with feature columns appended.
    """
    feats = df.copy()

    # 1. Subdomain string
    feats["_subdomain"] = feats["domain"].apply(_extract_subdomain)

    # 2. Subdomain entropy
    feats["feat_subdomain_entropy"] = feats["_subdomain"].apply(_shannon_entropy)

    # 3. Domain total length
    feats["feat_domain_length"] = feats["domain"].str.len()

    # 4. Longest label length
    feats["feat_max_label_length"] = feats["domain"].apply(_domain_label_length)

    # 5. Number of labels (dots + 1)
    feats["feat_label_count"] = feats["domain"].str.count(r"\.") + 1

    # 6. Numeric ratio in domain
    feats["feat_numeric_ratio"] = feats["domain"].apply(
        lambda d: sum(c.isdigit() for c in d) / max(len(d), 1)
    )

    # 7. Query frequency per unique domain within this upload
    freq = feats["domain"].value_counts()
    feats["feat_query_freq"] = feats["domain"].map(freq)

    # 8. Is high-risk query type (TXT / NULL / ANY convey data in DNS tunnels)
    HIGH_RISK_TYPES = {"TXT", "NULL", "ANY"}
    feats["feat_high_risk_qtype"] = feats["query_type"].str.upper().isin(HIGH_RISK_TYPES).astype(int)

    # 9. query_length and response_size already in CSV — just cast
    feats["query_length"] = pd.to_numeric(feats["query_length"], errors="coerce").fillna(0)
    feats["response_size"] = pd.to_numeric(feats["response_size"], errors="coerce").fillna(0)
    feats["subdomain_count"] = pd.to_numeric(feats["subdomain_count"], errors="coerce").fillna(0)

    feats.drop(columns=["_subdomain"], inplace=True)
    return feats


# ---------------------------------------------------------------------------
# Rule-based scoring
# ---------------------------------------------------------------------------

RULES = [
    # (feature_col, operator, threshold, points)
    ("feat_subdomain_entropy",  ">",  3.5,  30),
    ("feat_subdomain_entropy",  ">",  2.5,  15),
    ("feat_domain_length",      ">",  50,   20),
    ("feat_domain_length",      ">",  35,   10),
    ("feat_max_label_length",   ">",  30,   20),
    ("feat_label_count",        ">",   5,   10),
    ("feat_numeric_ratio",      ">",   0.3, 15),
    ("feat_query_freq",         ">",  20,   15),
    ("feat_high_risk_qtype",    "==",  1,   20),
    ("query_length",            ">",  60,   10),
    ("subdomain_count",         ">",   3,   10),
    ("response_size",           "<",  80,   10),  # tiny response = data not returned = channel
]

SUSPICIOUS_THRESHOLD = 40  # score >= this → Suspicious


def _apply_rules(row: pd.Series) -> int:
    score = 0
    for col, op, thresh, pts in RULES:
        val = row.get(col, 0)
        if op == ">" and val > thresh:
            score += pts
        elif op == "<" and val < thresh:
            score += pts
        elif op == "==" and val == thresh:
            score += pts
    return min(score, 100)


def rule_based_score(feats: pd.DataFrame) -> pd.Series:
    return feats.apply(_apply_rules, axis=1)


# ---------------------------------------------------------------------------
# Isolation Forest (secondary signal)
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "feat_subdomain_entropy",
    "feat_domain_length",
    "feat_max_label_length",
    "feat_label_count",
    "feat_numeric_ratio",
    "feat_query_freq",
    "feat_high_risk_qtype",
    "query_length",
    "response_size",
    "subdomain_count",
]


def isolation_forest_signal(feats: pd.DataFrame) -> pd.Series:
    """
    Returns a boolean Series: True = anomalous (potential tunnel).
    Falls back gracefully if too few rows.
    """
    X = feats[FEATURE_COLS].fillna(0).values
    if len(X) < 10:
        return pd.Series([False] * len(feats), index=feats.index)

    clf = IsolationForest(
        n_estimators=100,
        contamination=0.15,
        random_state=42,
        n_jobs=-1,
    )
    preds = clf.fit_predict(X)  # -1 = anomaly, 1 = normal
    return pd.Series(preds == -1, index=feats.index)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze(df: pd.DataFrame) -> pd.DataFrame:
    """
    Full pipeline: extract features → rule score → IF signal → label.

    Returns df with added columns:
      score          int   0-100
      label          str   'Normal' | 'Suspicious'
      if_anomaly     bool  secondary Isolation Forest signal
    """
    feats = extract_features(df)
    feats["score"] = rule_based_score(feats)
    feats["if_anomaly"] = isolation_forest_signal(feats)
    feats["label"] = feats["score"].apply(
        lambda s: "Suspicious" if s >= SUSPICIOUS_THRESHOLD else "Normal"
    )
    return feats
