# Straightedge audit log format, version 1

A Straightedge audit log is a JSON array of event objects, oldest first. Each event records one thing that happened to an AI analysis job: it was created or refused, it moved to a new stage, evidence or a result was added, a reviewer approved it, and so on.

## Event fields

Every event has exactly these fields:

| Field | Type | Meaning |
|---|---|---|
| `event_id` | string | Unique id of this event |
| `operation_id` | string | The job this event belongs to; empty for events about no single job, such as a refused request |
| `event_type` | string | What happened, for example `operation.created`, `operation.transition`, `operation.approval_recorded` |
| `timestamp` | string | ISO 8601 time in UTC |
| `actor` | object | Who or what caused the event, for example `{"type": "user", "subject_id": "reviewer-3"}` |
| `details` | object | Event-specific data. Raw inputs and outputs are never included, only references and hashes |
| `previous_state` | string or null | The job's stage before the event |
| `new_state` | string or null | The job's stage after the event |
| `previous_hash` | string | `immutable_hash` of the event before this one; 64 zeros for the first event |
| `immutable_hash` | string | SHA-256 of this event, computed as below |

Readers should ignore event types they don't recognise; the chain still verifies.

## How the hash is computed

1. Take the event object without its `immutable_hash` field.
2. Write it as the canonical text below. This is exactly what Python's `json.dumps(obj, sort_keys=True, ensure_ascii=False)` produces; the rules are written out so a checker in any language can match it.
3. Hash the UTF-8 bytes of that text with SHA-256 and write it as 64 lowercase hex characters.

### Canonical text

- **Objects:** `{`, the members sorted by key in Unicode code point order, each written `"key": value`, joined by `, ` (comma and space), then `}`. An empty object is `{}`.
- **Arrays:** `[`, the items joined by `, `, then `]`. An empty array is `[]`.
- **`true`, `false`, `null`** as written.
- **Strings** in double quotes. Escape `"` as `\"` and `\` as `\\`, and write these as two characters: backspace `\b`, form feed `\f`, newline `\n`, carriage return `\r`, tab `\t`. Every other character below U+0020 is written `\u00XX` with lowercase hex. Everything else, including `/`, `<`, `>`, `&`, U+007F, U+2028, U+2029 and all non-ASCII characters, is written as itself.
- **Integers** (a JSON number with no `.`, `e` or `E`) in plain decimal, of any size, with a leading `-` if negative.
- **Every other number** is a 64-bit float, written as the shortest decimal that reads back to the same float. Take that shortest form as digits `d1d2...dn` with decimal exponent `x` (value = `d1.d2...dn × 10^x`). If `-4 <= x < 16`, write it in plain decimal and always keep at least one digit after the point (`1.0`, `0.0001`, `100.5`). Otherwise write `d1`, then `.d2...dn` if there is more than one digit, then `e`, a sign (`+` or `-`), and the exponent with at least two digits (`1e-05`, `1e+16`, `1.5e+300`). Negative zero is `-0.0`.

### Example

This event (shown without its `immutable_hash`):

```json
{"event_id": "e1", "operation_id": "", "event_type": "example", "timestamp": "2026-01-01T00:00:00+00:00", "actor": {"type": "system"}, "details": {"score": 0.5, "note": "Kōwhai"}, "previous_state": null, "new_state": null, "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000"}
```

has this canonical text:

```
{"actor": {"type": "system"}, "details": {"note": "Kōwhai", "score": 0.5}, "event_id": "e1", "event_type": "example", "new_state": null, "operation_id": "", "previous_hash": "0000000000000000000000000000000000000000000000000000000000000000", "previous_state": null, "timestamp": "2026-01-01T00:00:00+00:00"}
```

and its `immutable_hash` is `53af3f432ecd60b34c621103ee9df73d5efad06f7859291365424369d62ce9f0`.

## Reading the file

- The file is JSON text in UTF-8. Checkers should also accept a UTF-8 byte order mark, and UTF-16 or UTF-32, because Windows tools (for example `>` in Windows PowerShell 5.1) write those.
- A field must not appear twice in the same object. JSON libraries disagree on which copy wins, so two readers could see different events that both verify. Refuse such a file.
- `NaN`, `Infinity` and `-Infinity` are not JSON and are not allowed anywhere.
- Field types must be as in the table above, and both hash fields must be 64 lowercase hex characters.

## What makes a log intact

- Each event's `immutable_hash` equals the hash computed from its other fields.
- Each event's `previous_hash` equals the `immutable_hash` of the event before it; the first event's is `"0" * 64`.
- No two events share an `event_id`.

Editing, deleting, inserting or reordering any event breaks one of these rules. Two changes the chain alone cannot show are cutting events off the end and rewriting the whole chain from some point onwards. To catch both, keep the hash of the last event (the head) whenever you receive or publish a log, and later check that the head is still in the log.

## Checkpoints and receipts

The runtime writes a `log.checkpoint` event when a job completes and every so many events. Each one comes with a receipt to hand to someone outside the operator's control:

```json
{"format": "straightedge-receipt/1", "event_id": "…", "log_length": 18, "head": "<immutable_hash of the checkpoint event>", "timestamp": "…"}
```

A log matches a receipt when the chain is intact and the event at position `log_length` (counting from 1) has `immutable_hash` equal to `head`. A log that has grown since still matches.

`log.anchored` events record that a checkpoint hash was timestamped by an outside authority. Like any other event type, they are covered by the chain; this checker does not check the timestamp tokens themselves.

---

Copyright 2026 Fronson Dinkelaar, trading as Order of Operation. Licensed under the Apache License 2.0.
