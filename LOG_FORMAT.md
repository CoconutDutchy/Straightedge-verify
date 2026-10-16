# Straightedge audit log format, version 1

A Straightedge audit log is a JSON array of event objects, oldest first. Each event records one thing that happened to an AI analysis job: it was created or refused, it moved to a new step, evidence or a result was added, a reviewer approved it, and so on.

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
| `previous_state` | string or null | The job's step before the event |
| `new_state` | string or null | The job's step after the event |
| `previous_hash` | string | `immutable_hash` of the event before this one; 64 zeros for the first event |
| `immutable_hash` | string | SHA-256 of this event, computed as below |

Readers should ignore event types they don't recognise; the chain still verifies.

## How the hash is computed

1. Take the event object without its `immutable_hash` field.
2. Serialise it as JSON with keys sorted at every level, UTF-8 text (non-ASCII characters are written as themselves, not escaped), and the separators `", "` between items and `": "` between a key and its value. This is Python's `json.dumps(obj, sort_keys=True, ensure_ascii=False)`.
3. Hash the UTF-8 bytes with SHA-256 and write it as 64 lowercase hex characters.

## What makes a log intact

- Each event's `immutable_hash` equals the hash computed from its other fields.
- Each event's `previous_hash` equals the `immutable_hash` of the event before it; the first event's is `"0" * 64`.
- No two events share an `event_id`.

Editing, deleting, inserting or reordering any event breaks one of these rules. Two changes the chain alone cannot show are cutting events off the end and rewriting the whole chain from some point onwards. To catch both, keep the hash of the last event (the head) whenever you receive or publish a log, and later check that the head is still in the log.

---

Copyright 2026 Fronson Dinkelaar, trading as Order of Operation. Licensed under the Apache License 2.0.
