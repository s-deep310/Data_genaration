#!/usr/bin/env python3
"""
End-to-end incident log pipeline (Stages 1-5)
- Generates 1000 raw synthetic incident logs (realistic style)
- Parses -> Quality categorizes -> Cleans -> Feature engineers
- Outputs JSON artifacts and an SQLite feature store

Files produced:
- raw_incident_logs.txt
- collected_incident_data.json
- data_quality_report.json
- cleaned_incident_data.json
- feature_engineered_incidents.json
- incidents.db (SQLite table 'incidents')
"""

import random
import string
import json
import re
import sqlite3
from datetime import datetime, timedelta
from statistics import median
from typing import List, Dict, Any

# ----------------------------
# Stage 1: Generate Raw Logs
# ----------------------------
def generate_instance_id():
    return "i-" + "".join(random.choices("0123456789abcdef", k=8))

def generate_alert_id(i):
    return f"AL{10000 + i}"

def pick_service():
    return random.choice([
        "auth-service", "payment-api", "frontend-app", "user-db", "order-service",
        "cache", "search-service", "analytics-worker", "lb-controller", "cdn-edge"
    ])

def pick_region():
    return random.choice(["us-central1", "us-east1", "us-west1", "eu-central1", "asia-south1"])

def pick_severity():
    return random.choice(["INFO", "WARN", "ERROR", "CRITICAL"])

def pick_cause(service):
    causes = {
        "auth-service": ["TLS cert expired", "DB connection timeout", "token parse error"],
        "payment-api": ["DB connection pool exhaustion", "payment gateway timeout", "slow downstream"],
        "frontend-app": ["asset CDN delay", "JS error", "session store latency"],
        "user-db": ["deadlock on write", "replica lag", "high read latency"],
        "order-service": ["queue backlog", "order ingestion burst", "serialization bug"],
        "cache": ["cache evictions", "TTL misconfiguration", "hot-key traffic"],
        "search-service": ["index rebuild", "shard imbalance", "slow query"],
        "analytics-worker": ["batch job spike", "OOM in spark worker", "dependency timeout"],
        "lb-controller": ["healthcheck flaps", "backend not registered", "dns resolution issue"],
        "cdn-edge": ["peering outage", "edge cache miss storm", "rate limiting"]
    }
    return random.choice(causes.get(service, ["unknown issue"]))

def generate_cpu_mem_for_severity(severity):
    # severity tends to correlate with higher cpu/mem, but still realistic variance
    if severity == "CRITICAL":
        return round(random.uniform(80, 99), 2), round(random.uniform(70, 95), 2)
    if severity == "ERROR":
        return round(random.uniform(60, 90), 2), round(random.uniform(50, 85), 2)
    if severity == "WARN":
        return round(random.uniform(30, 70), 2), round(random.uniform(20, 65), 2)
    return round(random.uniform(1, 40), 2), round(random.uniform(1, 50), 2)

def generate_raw_logs(n=1000, out_path="raw_incident_logs.txt"):
    """
    Create n raw log lines and write to out_path.
    Each line simulates what might be written to a log stream.
    """
    base_time = datetime(2025, 10, 31, 8, 0, 0)
    lines = []
    for i in range(n):
        ts = (base_time + timedelta(seconds=random.randint(0, 3600*8))).strftime("%Y-%m-%d %H:%M:%S")
        service = pick_service()
        instance = generate_instance_id()
        region = pick_region()
        severity = pick_severity()
        cause = pick_cause(service)
        cpu, mem = generate_cpu_mem_for_severity(severity)
        alert_id = generate_alert_id(i)
        # occasionally omit some fields to reflect real raw data variability
        include_cpu = random.random() > 0.02  # mostly present
        include_mem = random.random() > 0.03
        include_alert = random.random() > 0.1
        include_region = random.random() > 0.02

        # craft a realistic message with some variability
        templates = [
            f"{ts} {severity} [{service}] Instance {instance} CPU usage {cpu}% Memory usage {mem}% AlertID={alert_id} Region={region} Cause={cause}",
            f"{ts} {severity} {service}: CPU={cpu}% MEM={mem}% instance={instance} region={region} alert={alert_id} -- {cause}",
            f"{ts} {severity} {service} instance {instance} - {cause} | CPU:{cpu}% | MEM:{mem}% | Region:{region} | Alert={alert_id}",
            f"{ts} {severity} {service} - {cause} (inst:{instance})",
            f"{ts} {severity} {service} inst={instance} cpu={cpu} mem={mem} region={region}"
        ]
        line = random.choice(templates)

        # randomly insert small realistic corruptions (not nonsense)
        if random.random() < 0.05:
            # missing 'cpu' or 'mem' label or truncated token
            line = line.replace("CPU", "CPU") if "CPU" in line else line
        if random.random() < 0.03:
            # missing alert or region intentionally (simulate partial logs)
            line = re.sub(r"AlertID=\w+", "", line)
        if random.random() < 0.02:
            # change timestamp format sometimes
            alt_ts = (base_time + timedelta(seconds=random.randint(0, 3600*8))).strftime("%d-%m-%Y %H:%M")
            line = line.replace(ts, alt_ts)
        if random.random() < 0.01:
            # append extra noise characters
            line = line + " ###"
        lines.append(line.strip())

    with open(out_path, "w") as f:
        for l in lines:
            f.write(l + "\n")
    print(f"Stage 1: Generated {n} raw log lines -> {out_path}")
    return out_path

# ----------------------------
# Stage 2: Collect & Parse Raw Logs -> structured JSON records
# ----------------------------
def parse_log_line(line: str) -> Dict[str, Any]:
    """
    Try to extract a consistent set of fields from raw log line.
    If a field can't be found, put empty string or None to reflect raw ingestion.
    Fields: timestamp, service, instance_id, cpu_usage, memory_usage, severity, region, alert_id, probable_cause
    """
    rec = {
        "timestamp": "",
        "service": "",
        "instance_id": "",
        "cpu_usage": None,
        "memory_usage": None,
        "severity": "",
        "region": "",
        "alert_id": "",
        "probable_cause": ""
    }

    # Timestamp: common ISO-like "YYYY-MM-DD HH:MM:SS" or alt "DD-MM-YYYY HH:MM"
    ts_match = re.search(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", line)
    if not ts_match:
        ts_match = re.search(r"\d{2}-\d{2}-\d{4} \d{2}:\d{2}", line)
    if ts_match:
        rec["timestamp"] = ts_match.group(0)

    # severity (INFO/WARN/ERROR/CRITICAL)
    sev_match = re.search(r"\b(INFO|WARN|ERROR|CRITICAL)\b", line)
    if sev_match:
        rec["severity"] = sev_match.group(1)

    # service between brackets or the beginning tokens like 'service:' or token match
    svc_match = re.search(r"\[([a-zA-Z0-9_-]+)\]", line)
    if svc_match:
        rec["service"] = svc_match.group(1)
    else:
        # fallback: first token that looks like service (contains '-service' or '-api' etc)
        svc_match2 = re.search(r"\b([a-zA-Z0-9\-_]+(?:service|api|worker|db|controller|edge|cache))\b", line)
        if svc_match2:
            rec["service"] = svc_match2.group(1)

    # instance id
    inst_match = re.search(r"\b(i-[0-9a-fA-F]{8})\b", line)
    if inst_match:
        rec["instance_id"] = inst_match.group(1)
    else:
        # other instance-like patterns
        inst_match2 = re.search(r"\b(inst[:=][a-zA-Z0-9\-]+|instance[:=]?[a-zA-Z0-9\-]+)\b", line)
        if inst_match2:
            # extract the part after ':' or '='
            rec["instance_id"] = re.sub(r"^(inst[:=]|instance[:=])", "", inst_match2.group(0))

    # cpu / memory
    cpu_match = re.search(r"(?:CPU|CPU usage|CPU=|cpu=)\s*:?([0-9]+(?:\.[0-9]+)?)\s*%?", line, re.IGNORECASE)
    if cpu_match:
        try:
            rec["cpu_usage"] = float(cpu_match.group(1))
        except:
            rec["cpu_usage"] = None
    mem_match = re.search(r"(?:Memory usage|MEM|MEMORY|Memory|MEM=|mem=)\s*:?([0-9]+(?:\.[0-9]+)?)\s*%?", line, re.IGNORECASE)
    if mem_match:
        try:
            rec["memory_usage"] = float(mem_match.group(1))
        except:
            rec["memory_usage"] = None

    # alert id
    alert_match = re.search(r"(?:AlertID|alert|Alert)=\s*([A-Za-z0-9_]+)", line, re.IGNORECASE)
    if alert_match:
        rec["alert_id"] = alert_match.group(1)

    # region
    region_match = re.search(r"\b(us|eu|asia)[a-z0-9-]*[0-9]\b", line, re.IGNORECASE)
    if region_match:
        rec["region"] = region_match.group(0).lower()

    # probable cause: text after 'Cause=' or ' -- ' or after service mention
    cause_match = re.search(r"Cause=([^\n]+)$", line)
    if cause_match:
        rec["probable_cause"] = cause_match.group(1).strip()
    else:
        # try to extract trailing explanatory clause
        trailing = re.split(r"\s-\s|\s\|\s|--", line)
        if len(trailing) > 1:
            rec["probable_cause"] = trailing[-1].strip()

    return rec

def collect_and_parse(raw_file: str, out_json="collected_incident_data.json"):
    parsed = []
    with open(raw_file, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            rec = parse_log_line(ln)
            # attach raw_line for traceability
            rec["raw_line"] = ln
            parsed.append(rec)
    with open(out_json, "w") as f:
        json.dump(parsed, f, indent=2)
    print(f"Stage 2: Parsed {len(parsed)} lines -> {out_json}")
    return out_json

# ----------------------------
# Stage 3: Data Quality Categorization
# ----------------------------
def is_valid_timestamp(ts: str) -> bool:
    if not ts:
        return False
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M"):
        try:
            datetime.strptime(ts, fmt)
            return True
        except:
            pass
    return False

def score_record(rec: Dict[str, Any]) -> Dict[str, Any]:
    # start at 10 and subtract weights for problems
    score = 10
    issues = []
    # completeness checks
    for key in ("timestamp", "instance_id", "service"):
        if not rec.get(key):
            score -= 1
            issues.append(f"missing_{key}")
    # numeric fields
    cpu = rec.get("cpu_usage")
    mem = rec.get("memory_usage")
    if cpu is None:
        score -= 1
        issues.append("missing_cpu")
    else:
        try:
            if not (0 <= float(cpu) <= 100):
                score -= 2
                issues.append("cpu_out_of_range")
        except:
            score -= 2
            issues.append("cpu_bad_type")
    if mem is None:
        score -= 1
        issues.append("missing_mem")
    else:
        try:
            if not (0 <= float(mem) <= 100):
                score -= 2
                issues.append("mem_out_of_range")
        except:
            score -= 2
            issues.append("mem_bad_type")
    # timestamp validity
    if not is_valid_timestamp(rec.get("timestamp", "")):
        score -= 1
        issues.append("bad_timestamp")
    # region format
    if rec.get("region"):
        if not re.match(r"^[a-z]+-[a-z]+[0-9]$", rec["region"]):
            score -= 1
            issues.append("weird_region_format")
    # text noise heuristic
    if len(str(rec.get("probable_cause", ""))) > 200:
        score -= 2
        issues.append("probable_cause_too_long")
    # clamp score
    score = max(0, min(10, score))
    # map to category
    if score >= 8:
        cat = "Best"
    elif score >= 5:
        cat = "Average"
    else:
        cat = "Worst"
    rec["quality_score"] = score
    rec["quality_category"] = cat
    rec["quality_issues"] = issues
    return rec

def categorize_quality(input_json="collected_incident_data.json", out_json="data_quality_report.json"):
    with open(input_json, "r") as f:
        records = json.load(f)
    scored = [score_record(r) for r in records]
    with open(out_json, "w") as f:
        json.dump(scored, f, indent=2)
    counts = {"Best":0,"Average":0,"Worst":0}
    for r in scored:
        counts[r["quality_category"]] += 1
    print(f"Stage 3: Categorized quality -> {out_json} :: counts={counts}")
    return out_json

# ----------------------------
# Stage 4: Data Cleaning Pipeline
# ----------------------------
def normalize_timestamp(ts: str) -> str:
    if not ts:
        return "unknown"
    for fmt in ("%Y-%m-%d %H:%M:%S", "%d-%m-%Y %H:%M"):
        try:
            dt = datetime.strptime(ts, fmt)
            return dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        except:
            pass
    return "unknown"

def clean_text(s: str) -> str:
    if s is None:
        return ""
    # remove HTML-like tags and control characters, normalize whitespace
    s = re.sub(r"<.*?>", "", str(s))
    s = re.sub(r"[\x00-\x1f]+", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s

def clean_records(input_json="data_quality_report.json", out_json="cleaned_incident_data.json"):
    with open(input_json, "r") as f:
        records = json.load(f)
    cleaned = []
    for r in records:
        c = {
            "timestamp": normalize_timestamp(r.get("timestamp", "")),
            "service": clean_text(r.get("service", "")),
            "instance_id": clean_text(r.get("instance_id", "")),
            "cpu_usage": r.get("cpu_usage"),
            "memory_usage": r.get("memory_usage"),
            "severity": clean_text(r.get("severity", "")).upper() if r.get("severity") else "UNKNOWN",
            "region": clean_text(r.get("region", "")).lower() or "unknown",
            "alert_id": clean_text(r.get("alert_id", "")),
            "probable_cause": clean_text(r.get("probable_cause", "")),
            "raw_line": r.get("raw_line", ""),
            "quality_score": r.get("quality_score", 0),
            "quality_category": r.get("quality_category", "Worst"),
            "quality_issues": r.get("quality_issues", [])
        }
        # numeric imputation placeholder: we'll compute medians later
        cleaned.append(c)

    # compute medians for cpu and memory ignoring invalids
    cpu_vals = [v["cpu_usage"] for v in cleaned if isinstance(v.get("cpu_usage"), (int, float))]
    mem_vals = [v["memory_usage"] for v in cleaned if isinstance(v.get("memory_usage"), (int, float))]
    cpu_med = median(cpu_vals) if cpu_vals else 50.0
    mem_med = median(mem_vals) if mem_vals else 50.0

    # fix numeric outliers and impute missing
    for c in cleaned:
        cpu = c.get("cpu_usage")
        mem = c.get("memory_usage")
        try:
            if isinstance(cpu, (int, float)):
                if cpu < 0: c["cpu_usage"] = 0.0
                elif cpu > 100: c["cpu_usage"] = 100.0
            else:
                c["cpu_usage"] = cpu_med
        except:
            c["cpu_usage"] = cpu_med
        try:
            if isinstance(mem, (int, float)):
                if mem < 0: c["memory_usage"] = 0.0
                elif mem > 100: c["memory_usage"] = 100.0
            else:
                c["memory_usage"] = mem_med
        except:
            c["memory_usage"] = mem_med

    # remove obvious duplicates by (alert_id, timestamp, instance_id) key - keep first
    seen = set()
    unique = []
    for c in cleaned:
        key = (c.get("alert_id"), c.get("timestamp"), c.get("instance_id"))
        if key in seen:
            continue
        seen.add(key)
        unique.append(c)

    with open(out_json, "w") as f:
        json.dump(unique, f, indent=2)
    print(f"Stage 4: Cleaned data saved -> {out_json} (rows={len(unique)})")
    return out_json

# ----------------------------
# Stage 5: Feature Engineering & Storage
# ----------------------------
def categorize_load(value):
    if value >= 85: return "High"
    if value >= 60: return "Medium"
    return "Low"

def extract_incident_type(text):
    txt = (text or "").lower()
    if "cpu" in txt: return "cpu"
    if "memory" in txt or "ram" in txt: return "memory"
    if "disk" in txt or "storage" in txt: return "storage"
    if "db" in txt or "database" in txt: return "database"
    if "network" in txt or "packet" in txt or "latency" in txt: return "network"
    return "other"

def region_to_cluster(region):
    mapping = {
        "us-central1": 1,
        "us-east1": 2,
        "us-west1": 3,
        "eu-central1": 4,
        "asia-south1": 5,
        "unknown": 0
    }
    return mapping.get(region, 0)

def engineer_features(input_json="cleaned_incident_data.json", out_json="feature_engineered_incidents.json", sqlite_db="incidents.db"):
    with open(input_json, "r") as f:
        recs = json.load(f)

    for r in recs:
        cpu = float(r.get("cpu_usage", 0))
        mem = float(r.get("memory_usage", 0))
        r["cpu_load_level"] = categorize_load(cpu)
        r["mem_load_level"] = categorize_load(mem)
        r["system_stress_index"] = round(cpu * 0.6 + mem * 0.4, 2)
        r["region_cluster"] = region_to_cluster(r.get("region", "unknown"))
        r["incident_type"] = extract_incident_type(r.get("probable_cause", ""))
        r["is_critical"] = True if r.get("severity", "").upper() == "CRITICAL" else False
        # data quality flag from quality_category
        r["data_quality_flag"] = "Good" if r.get("quality_category") == "Best" else ("Medium" if r.get("quality_category")=="Average" else "Poor")

    # save JSON
    with open(out_json, "w") as f:
        json.dump(recs, f, indent=2)
    print(f"Stage 5: Feature engineered JSON -> {out_json} (rows={len(recs)})")

    # store into sqlite for quick demo queries
    conn = sqlite3.connect(sqlite_db)
    cur = conn.cursor()
    # create table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            service TEXT,
            instance_id TEXT,
            cpu_usage REAL,
            memory_usage REAL,
            severity TEXT,
            region TEXT,
            alert_id TEXT,
            probable_cause TEXT,
            quality_score INTEGER,
            quality_category TEXT,
            cpu_load_level TEXT,
            mem_load_level TEXT,
            system_stress_index REAL,
            region_cluster INTEGER,
            incident_type TEXT,
            is_critical INTEGER,
            data_quality_flag TEXT
        )
    """)
    conn.commit()

    # insert rows (clear existing)
    cur.execute("DELETE FROM incidents")
    insert_query = """
    INSERT INTO incidents (
      timestamp, service, instance_id, cpu_usage, memory_usage, severity, region, alert_id, probable_cause,
      quality_score, quality_category, cpu_load_level, mem_load_level, system_stress_index, region_cluster,
      incident_type, is_critical, data_quality_flag
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    rows = []
    for r in recs:
        rows.append((
            r.get("timestamp"), r.get("service"), r.get("instance_id"),
            float(r.get("cpu_usage", 0)), float(r.get("memory_usage", 0)),
            r.get("severity"), r.get("region"), r.get("alert_id"), r.get("probable_cause"),
            int(r.get("quality_score", 0)), r.get("quality_category"),
            r.get("cpu_load_level"), r.get("mem_load_level"), float(r.get("system_stress_index", 0)),
            int(r.get("region_cluster", 0)), r.get("incident_type"),
            1 if r.get("is_critical") else 0, r.get("data_quality_flag")
        ))
    cur.executemany(insert_query, rows)
    conn.commit()
    conn.close()
    print(f"Stage 5: Inserted {len(rows)} rows into SQLite DB -> {sqlite_db}")

# ----------------------------
# Main: run all stages end-to-end
# ----------------------------
def main():
    raw_path = generate_raw_logs(n=1000, out_path="raw_incident_logs.txt")
    collected = collect_and_parse(raw_path, out_json="collected_incident_data.json")
    categorized = categorize_quality(collected, out_json="data_quality_report.json")
    cleaned = clean_records(categorized, out_json="cleaned_incident_data.json")
    engineer_features(cleaned, out_json="feature_engineered_incidents.json", sqlite_db="incidents.db")
    print("✅ Pipeline complete. Files output in current directory.")

if __name__ == "__main__":
    main()
