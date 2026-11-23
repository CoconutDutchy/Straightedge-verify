# straightedge-verify

Check a [Straightedge](#what-is-straightedge) audit log for tampering, without having to trust Straightedge or whoever hands you the log.

Straightedge records what happens in an AI analysis job, such as a credit memo or a claims summary: who asked, what evidence was used, who approved the exact output. Each record is chained to the one before it with SHA-256. This tool recomputes that chain, so an auditor, a regulator or a customer can check the record themselves.

```
python straightedge_verify.py audit_log.json
OK: 16 events, chain intact, head a22306fb…

python straightedge_verify.py audit_log.json --head a22306fb…
python straightedge_verify.py audit_log.json --head receipt.json
```

Exit code 0 means intact, 1 means problems were found (each one is listed), 2 means a file couldn't be read or `--head` isn't a hash or a receipt.

Files saved on Windows are fine: UTF-8 with or without a byte order mark, and the UTF-16 that `>` writes in Windows PowerShell 5.1, are all read.

## What it catches

- Any edited event, down to a single character
- Deleted, inserted, duplicated or reordered events
- Events with missing or extra fields
- Fields of the wrong type, badly written hashes, and `NaN` or `Infinity`
- A field written twice in one object, which different JSON readers would read differently
- With `--head`: events cut off the end, or the chain rewritten from some point on. Keep the last hash each time you receive a log, then pass it next time. A log that has grown since is fine.
- With `--head receipt.json`: the same, using the receipt the runtime gives out at each checkpoint, and also that the head sits at the position the receipt names.

## What it doesn't check

- That the job followed its rules (for example that review happened before completion). It shows the log wasn't changed, not that what it records was allowed.
- The timestamp tokens behind `log.anchored` events.

## Use it from Python

```python
import json, straightedge_verify

events = json.load(open("audit_log.json", encoding="utf-8"))
problems = straightedge_verify.verify_log(events, expected_head=saved_head)
saved_head = straightedge_verify.head_hash(events)

# Or read the file the way the command line does (encodings, repeated fields, NaN),
# and check it against a receipt:
events = straightedge_verify.load_log("audit_log.json")
problems = straightedge_verify.verify_receipt(events, straightedge_verify.load_receipt("receipt.json"))
```

The format is specified in [LOG_FORMAT.md](LOG_FORMAT.md), so you can write a checker in any language. Single file, Python 3.8+, standard library only.

## Tests

```
pip install pytest
pytest
```

54 tests. They run against two real Straightedge logs in `tests/fixtures/`, made with invented data: a credit memo job, and a newer job with checkpoints, a hold and an erasure (with its receipt).

## What is Straightedge

Straightedge is the sign-off and evidence layer for AI work: it makes sure a named person approves the exact AI output, and keeps a record anyone can verify. This repository holds only the open log format and checker; the Straightedge runtime itself is not open source.

## Licence

Apache License 2.0. See [LICENSE](LICENSE).

---

Copyright 2026 Fronson Dinkelaar, trading as Order of Operation. Licensed under the Apache License 2.0; see [LICENSE](LICENSE) and [NOTICE](NOTICE).
