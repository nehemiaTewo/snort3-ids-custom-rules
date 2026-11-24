# Snort 3 Network IDS: Custom Rules and Evaluation

Nehemia Tewodros · Temple University · October 2026

Snort 3.12.2.0 IDS with 9 custom detection rules, evaluated against 17 labeled
traffic captures. Final (tuned) result: **precision 1.00, recall 0.75, alerts 6,010 → 42**.
Full write-up: `report/IDS_Report.pdf`.

## Contents

| Path | What it is |
|---|---|
| `report/IDS_Report.pdf` | Technical report (architecture, rules, method, results, FP/FN, limitations, recommendations) |
| `report/report.html`, `report/architecture.png`, `report/architecture.dot` | Report source and architecture diagram |
| `rules/local.rules` | **Final custom rules (v2, tuned)**, SIDs 1000001 to 1000009 |
| `rules/local_v1.rules` | Rules before tuning (for the before/after comparison) |
| `config/snort.lua` | Deployment config (`HOME_NET 192.168.56.0/24`, includes `tuning_v2.lua`) |
| `config/snort_eval.lua` | Evaluation config for v1 (`HOME_NET`/`EXTERNAL_NET = any`, since public captures use arbitrary IPs) |
| `config/snort_eval_v2.lua` | Evaluation config for v2 (= eval config + `tuning_v2.lua`) |
| `config/tuning_v2.lua` | `event_filter` limits that stop alert flooding |
| `config/snort_defaults.lua`, `config/file_magic.rules` | Stock Snort 3 files included by `snort.lua` |
| `pcaps/` | 16 of the 17 test captures (the benign baseline is not included; see below) |
| `ground_truth.csv` | Which captures contain which detectable behavior (verified with tshark) |
| `alerts/v1/`, `alerts/v2/` | Raw Snort alert output (`alert_fast`) per capture |
| `results/summary.csv`, `results/pairs_v1.csv`, `results/pairs_v2.csv` | Confusion matrix and per-(rule, capture) outcomes |
| `logs/` | Text logs of version check, config validation, test run and scoring |
| `screenshots/` | Terminal screenshots of the working environment |
| `scripts/run_tests.sh` | Runs Snort over every capture with v1 and v2 |
| `scripts/score.py` | Computes TP/FP/FN/TN, precision, recall |
| `scripts/render_terminal.py` | Renders command output to the PNG screenshots |

## Reproduce

Requirements: Snort 3 (tested with 3.12.2.0, DAQ 3.0.27) and Python 3. No Python packages are needed.

```bash
# 1. Install Snort 3
#    Ubuntu/Debian: build from source (https://github.com/snort3/snort3, snort3/libdaq)
#    Apple Silicon macOS: brew install snort
#    (Homebrew no longer supports Intel Macs; that is why this project ran on Linux.)
snort -V

# 2. Validate config + rules (expect "Snort successfully validated the configuration")
snort -c config/snort.lua -R rules/local.rules -T

# 3. Run every capture through v1 and v2 rules  ->  alerts/v1, alerts/v2
./scripts/run_tests.sh                 # or: SNORT=/path/to/snort ./scripts/run_tests.sh

# 4. Score against ground truth  ->  results/
python3 scripts/score.py
```

Run a single capture by hand:

```bash
snort -c config/snort_eval_v2.lua -R rules/local.rules -r pcaps/nmap_standard_scan.pcap -A alert_fast -q -k none
```

`-k none` disables checksum validation, because captures taken on the sending host
often have unset (offloaded) checksums.

## Test data sources

- Wireshark Sample Captures: https://wiki.wireshark.org/SampleCaptures
  (`http.cap`, `telnet-cooked.pcap`, `ipv4frags.pcap`, `dns.cap`, `FTPv6-1.cap` converted
  from NetMon to pcap with `editcap -F pcap`, `NMap-Captures.zip` files saved with a `.pcap` extension)
- BruteShark Pcap_Examples: https://github.com/odedshimon/BruteShark (HTTP Basic/Digest auth,
  FTP login, HTTP JPG/PDF downloads; renamed to `http_basic_auth.pcap`, etc.)
- `normal_mac.pcap`: 60 s of ordinary browsing captured with
  `sudo tcpdump -i en0 -w normal_mac.pcap -G 60 -W 1` (benign baseline).
  Not included in this repository because it contains personal browsing traffic. To reproduce
  the baseline results, capture your own 60 seconds with the command above and save it as
  `pcaps/normal_mac.pcap`.