#!/usr/bin/env python3
"""
Score Snort alerts against ground truth.

Unit of evaluation: one (rule, capture) pair.
  - ground_truth.csv lists every pair where the capture CONTAINS the behavior
    the rule is meant to detect (expected = 1). Every other pair is expected = 0.
  - A pair "fired" if Snort raised at least one alert with that SID on that capture.

  TP = expected and fired      FP = not expected but fired
  FN = expected, not fired     TN = not expected, not fired

Usage:  python3 scripts/score.py            -> writes results/ for v1 and v2
"""
import csv
import glob
import os
import re
from collections import Counter, defaultdict

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIDS = {
    1000001: "ICMP echo (oversized in v2)",
    1000002: "Inbound Telnet attempt",
    1000003: "TCP SYN port scan",
    1000004: "HTTP /etc/passwd traversal",
    1000005: "HTTP SQL injection",
    1000006: "HTTP high-rate GETs",
    1000007: "Repeated FTP login failures",
    1000008: "HTTP Basic auth cleartext",
    1000009: "Repeated SSH attempts",
}
ALERT_RE = re.compile(r"\[1:(\d+):\d+\]")


def load_truth():
    truth = defaultdict(set)  # capture -> {sids expected}
    notes = {}
    with open(os.path.join(ROOT, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row["expected"].strip() == "1":
                truth[row["capture"]].add(int(row["sid"]))
            notes[(row["capture"], int(row["sid"]))] = row.get("note", "")
    return truth


def load_alerts(ver):
    fired = {}  # capture -> Counter(sid -> n alerts)
    for path in sorted(glob.glob(os.path.join(ROOT, "alerts", ver, "*.txt"))):
        cap = os.path.basename(path)[:-4]
        c = Counter()
        with open(path) as f:
            for line in f:
                m = ALERT_RE.search(line)
                if m and int(m.group(1)) in SIDS:
                    c[int(m.group(1))] += 1
        fired[cap] = c
    return fired


def score(ver, truth):
    fired = load_alerts(ver)
    rows, tot = [], Counter()
    for cap in sorted(fired):
        for sid in SIDS:
            exp = sid in truth.get(cap, set())
            n = fired[cap][sid]
            out = ("TP" if n else "FN") if exp else ("FP" if n else "TN")
            tot[out] += 1
            rows.append([cap, sid, SIDS[sid], int(exp), n, out])
    tp, fp, fn, tn = tot["TP"], tot["FP"], tot["FN"], tot["TN"]
    prec = tp / (tp + fp) if tp + fp else float("nan")
    rec = tp / (tp + fn) if tp + fn else float("nan")
    os.makedirs(os.path.join(ROOT, "results"), exist_ok=True)
    with open(os.path.join(ROOT, "results", f"pairs_{ver}.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["capture", "sid", "rule", "expected", "alerts", "outcome"])
        w.writerows(rows)
    summary = dict(version=ver, TP=tp, FP=fp, FN=fn, TN=tn,
                   precision=round(prec, 3), recall=round(rec, 3),
                   total_alerts=sum(sum(c.values()) for c in fired.values()))
    return summary, rows


def main():
    truth = load_truth()
    summaries = []
    for ver in ("v1", "v2"):
        if not os.path.isdir(os.path.join(ROOT, "alerts", ver)):
            continue
        s, rows = score(ver, truth)
        summaries.append(s)
        print(f"\n== {ver} ==  TP={s['TP']} FP={s['FP']} FN={s['FN']} TN={s['TN']}  "
              f"precision={s['precision']} recall={s['recall']}  alerts={s['total_alerts']}")
        for r in rows:
            if r[5] in ("TP", "FP", "FN"):
                print(f"  {r[5]}  {r[0]:<32} sid {r[1]}  {r[2]:<30} alerts={r[4]}")
    with open(os.path.join(ROOT, "results", "summary.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(summaries[0].keys()))
        w.writeheader()
        w.writerows(summaries)


if __name__ == "__main__":
    main()
