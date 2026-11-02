import re
from collections import Counter

KEYWORD_PATTERNS = {
    "sql_injection": ["union select", "or 1=1", "sleep(", "select * from", "drop table", "information_schema"],
    "xss": ["<script>", "javascript:", "onerror=", "document.cookie", "alert("] ,
    "file_access": ["/etc/passwd", "cmd.exe", "powershell", "wget ", "curl ", "base64"],
    "bruteforce": ["failed password", "invalid password", "authentication failed", "too many attempts"],
    "web_probe": ["wp-admin", "phpmyadmin", "admin/login", ".env", "robots.txt", ".git/config"],
    "shell_exec": ["bash -i", "/bin/sh", "nc ", "ncat ", "curl http", "wget http"],
}

THRESHOLD_RULES = {
    "failed password": 3,
    "authentication failed": 2,
    "union select": 1,
    "<script>": 1,
    "/etc/passwd": 1,
    "/bin/sh": 1,
}


def _normalize_logs(logs):
    if logs is None:
        return []
    if isinstance(logs, str):
        lines = [line.strip() for line in logs.splitlines() if line.strip()]
        return lines
    if isinstance(logs, (list, tuple)):
        result = []
        for item in logs:
            if isinstance(item, str) and item.strip():
                result.append(item.strip())
        return result
    return []


def _score_for_hits(hits):
    score = 0
    for hit in hits:
        if hit in THRESHOLD_RULES:
            score += THRESHOLD_RULES[hit]
        else:
            score += 1
    return min(score * 12, 100)


def analyze_logs(logs):
    entries = _normalize_logs(logs)
    if not entries:
        return {
            "overall_score": 0,
            "risk_level": "none",
            "detections": [],
            "summary": "No log data provided for anomaly analysis.",
        }

    detections = []
    seen = set()
    keyword_counter = Counter()

    for idx, entry in enumerate(entries):
        lowered = entry.lower()
        hits = []
        for category, patterns in KEYWORD_PATTERNS.items():
            for pattern in patterns:
                if pattern.lower() in lowered:
                    hits.append(pattern.lower())
                    keyword_counter[pattern.lower()] += 1
        if hits:
            # Normalize duplicates per log entry
            unique_hits = sorted(set(hits))
            score = _score_for_hits(unique_hits)
            severity = "low"
            if score >= 50:
                severity = "high"
            elif score >= 20:
                severity = "medium"
            rule_bits = []
            for hit in unique_hits:
                for category, patterns in KEYWORD_PATTERNS.items():
                    if hit in [p.lower() for p in patterns]:
                        rule_bits.append(category)
                        break
            detection = {
                "id": f"anomaly-{idx+1}",
                "severity": severity,
                "score": score,
                "matches": unique_hits,
                "categories": sorted(set(rule_bits)),
                "preview": entry[:220],
            }
            detections.append(detection)

    repeated_pattern_hits = [
        {"pattern": pattern, "count": count}
        for pattern, count in keyword_counter.most_common(5)
        if count > 1
    ]

    if not detections:
        return {
            "overall_score": 10,
            "risk_level": "low",
            "detections": [],
            "summary": "No obvious malicious activity was detected in the supplied logs.",
            "repeated_patterns": repeated_pattern_hits,
        }

    max_score = max(d["score"] for d in detections)
    overall_score = min(100, max(25, max_score + len(detections) * 10))
    if overall_score >= 70:
        risk_level = "high"
    elif overall_score >= 35:
        risk_level = "medium"
    else:
        risk_level = "low"

    return {
        "overall_score": overall_score,
        "risk_level": risk_level,
        "detections": detections,
        "summary": f"Rule-based analysis identified {len(detections)} suspicious log entries that may indicate attack activity.",
        "repeated_patterns": repeated_pattern_hits,
    }
