# Results table (tuned v2 rules)

| Traffic scenario | Capture(s) | Expected detection | Detected? | Alert generated | False positive? |
|---|---|---|---|---|---|
| ICMP activity (oversized echo) | ipv4frags | Yes | Yes | 1 × SID 1000001 | No (v1: yes, 2 FPs on Nmap OS-scan pings) |
| TCP activity (Telnet) | telnet-cooked + 3 Nmap SYN/OS scans | Yes | Yes (4/4) | 1 to 2 × SID 1000002 each | No |
| Scanning (SYN-based) | nmap standard / OS / OS-successful | Yes | Yes (3/3) | 1 × SID 1000003 each (v1: ~1,980 each) | No |
| Scanning (ACK / idle) | 2 ACK scans, zombie scan | Yes | **No (0/3)**: FN | none | No |
| HTTP activity (benign) | http, jpg/pdf downloads, digest auth | No | No | none | No |
| HTTP attack: traversal (rule 4) | no positive sample | n/a | Not tested | none | No |
| Suspicious payload: SQLi (rule 5) | no positive sample | n/a | Not tested | none | No |
| Repeated requests (rule 6) | no positive sample | n/a | Not tested | none | No |
| Authentication: HTTP Basic (rule 8) | http_basic_auth | Yes | Yes | 31 × SID 1000008 | No (Digest correctly ignored) |
| Authentication: FTP failures (rule 7) | ftp_login, ftpv6 (successful logins only) | No | No | none | No |
| Authentication: SSH (rule 9) | no positive sample | n/a | Not tested | none | No |
| Benign baseline | normal_mac, dns | No | No | none | No |

## Metrics (153 rule × capture cases per version)

| Version | TP | FP | FN | TN | Precision | Recall | Total alerts |
|---|---|---|---|---|---|---|---|
| v1 (before tuning) | 9 | 2 | 3 | 139 | 0.818 | 0.750 | 6,010 |
| v2 (tuned) | 9 | 0 | 3 | 141 | 1.000 | 0.750 | 42 |
