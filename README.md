# straightedge-verify

Check a [Straightedge](#what-is-straightedge) audit log for tampering, without having to trust Straightedge or whoever hands you the log.

Straightedge records every step of an AI analysis job, such as a credit memo or a claims summary: who asked, what evidence was used, who approved the exact output. Each record is chained to the one before it with SHA-256. This tool recomputes that chain, so an auditor, a regulator or a customer can check the record themselves.

```
python straightedge_verify.py audit_log.json
OK: 16 events, chain intact, head a22306fb…

python straightedge_verify.py audit_log.json --head a22306fb…
```

Exit code 0 means intact, 1 means problems were found (each one is listed), 2 means the file couldn't be read.

## What it catches

- Any edited event, down to a single character
- Deleted, inserted, duplicated or reordered events
- Events with missing or extra fields
- With `--head`: events cut off the end, or the chain rewritten from some point on. Keep the last hash each time you receive a log, then pass it next time. A log that has grown since is fine.

## Use it from Python

```python
import json, straightedge_verify

events = json.load(open("audit_log.json", encoding="utf-8"))
problems = straightedge_verify.verify_log(events, expected_head=saved_head)
saved_head = straightedge_verify.head_hash(events)
```

The format is specified in [LOG_FORMAT.md](LOG_FORMAT.md), so you can write a checker in any language. Single file, Python 3.8+, standard library only.

## Tests

```
pip install pytest
pytest
```

The tests run against a real Straightedge log in `tests/fixtures/`, made with synthetic data.

## What is Straightedge

Straightedge is the sign-off and evidence layer for AI work: it makes sure a named person approves the exact AI output, and keeps a record anyone can verify. This repository holds only the open log format and checker; the Straightedge runtime itself is not open source.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

---

Copyright 2026 Fronson Dinkelaar, trading as Order of Operation. Licensed under the Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
