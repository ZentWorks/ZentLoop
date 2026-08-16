# Scoring model 0.1

ZentLoop keeps two separate scores because "malicious" and "automated" are different questions.

## Risk score

The risk score uses accumulated evidence such as:

- secret discovery paths such as `/.env` and `/.git`
- CMS/admin enumeration
- API/OpenAPI/Swagger discovery
- framework and CI probes
- path traversal and local-file probes
- SQL injection, XSS, JNDI and command-style payload patterns
- known scanner User-Agent fingerprints
- following a session-specific path that ZentLoop only disclosed inside a previous lure

Default classification bands:

```text
0..29    benign
30..59   suspicious
60..100  hostile
```

After a visitor has followed the deception journey deeply enough, hostile classification is sticky. This avoids suddenly exposing benign content in the middle of a fake environment just because later requests carry fewer individual signals.

## Automation score

Automation is estimated independently from:

- request interval
- interval variance
- short bursts
- scanner/tool User-Agent strings
- parallel sessions from the same source IP
- rapid User-Agent or claimed-crawler identity rotation
- systematic credential/config path families
- recurring low-and-slow SSH revisit intervals
- missing browser navigation headers
- browser-like `Sec-Fetch-*` and `Accept-Language` signals

The first few requests remain `unknown`. Current actor labels are:

```text
human
automated
unknown
```

Confidence is `low`, `medium` or `high`.

## Timing and concurrency

Arrival timestamps are captured before session locking and before any deception delay. This matters because ZentLoop itself may deliberately delay hostile responses. Without arrival timestamps, those server-side delays could incorrectly make a fast scanner look human.

## Important limitation

This is heuristic classification, not identity proof. A patient bot can imitate human timing and a browser can generate fast parallel asset requests. The dashboard therefore exposes the numeric score and confidence instead of presenting the actor label as certainty.


## Official crawler claims

A crawler-looking User-Agent is never sufficient to mark traffic as trusted or human. When the optional official-bot registry has cached ranges for the claimed provider, ZentLoop compares the observed source IP to those ranges. A match is labelled as verified automation. A mismatch becomes a spoofed-bot automation signal. If ZentLoop has no healthy range cache for that provider, the claim remains unverified and is not treated as proof either way.

Actor-wide automation evidence is stronger than a per-session human-looking hint. Once parallel probing or UA rotation makes a source clearly automated, retained active sessions from that IP are promoted as well so the dashboard does not keep contradictory `human` rows.
