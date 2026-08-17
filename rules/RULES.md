# OTFORGE — OT Detection Rules (Suricata)

Native Suricata `modbus` / `dnp3` rules for high-value OT abuse, each false-positive-validated against the labelled otforge datasets.

| SID | Protocol | Detects | Matches | True positives | False positives |
|---|---|---|---:|---:|---:|
| 2100001 | modbus | illegal_function | 27 | 27 | **0** |
| 2100002 | modbus | unauthorized_write | 13 | 13 | **0** |
| 2100003 | modbus | unauthorized_write | 112 | 112 | **0** |
| 2100004 | modbus | oob_scan | 125 | 125 | **0** |
| 2100010 | dnp3 | illegal_function | 39 | 39 | **0** |
| 2100011 | dnp3 | illegal_function | 54 | 54 | **0** |
| 2100012 | dnp3 | illegal_function | 32 | 32 | **0** |

Validation matches each rule's logic against a 2,500-packet labelled dataset (2,000 benign / 500 malicious) per protocol. Every rule fires only on malicious traffic — **zero false positives** — which is the point: OT alert fatigue is a cost problem, and a rule that misfires on legitimate polling is worse than none.

For engine-level confirmation, run these against the release pcaps in Suricata. Coverage is the high-value abuse classes Suricata's OT keywords express; count-based attacks (over-spec read length) are detected at the parser/Zeek level by the otforge engine.

## From open rules to continuous monitoring

These rules and datasets are free. Validating them against *your* OT environment, tuning the allowlist to your device profile, and running continuous OT trust monitoring is the paid follow-on — measured in analyst hours reclaimed and unplanned downtime avoided.

→ [a2zsoc.com — Continuous Trust monitoring](https://a2zsoc.com/productized-services?utm_source=github&utm_medium=rules&utm_campaign=otforge)
