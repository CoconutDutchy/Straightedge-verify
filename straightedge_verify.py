# Copyright 2026 Order of Operation
# SPDX-License-Identifier: Apache-2.0
"""
straightedge-verify: check a Straightedge audit log for tampering, without trusting Straightedge.

A Straightedge audit log is a JSON array of events. Each event carries a SHA-256
hash over its own fields and the hash of the event before it, so editing,
deleting, inserting or reordering any event breaks the chain. See
LOG_FORMAT.md for the exact format.

Usage:
    python straightedge_verify.py audit_log.json
    python straightedge_verify.py audit_log.json --head <last event hash you were given>

Exit code 0 means the log is intact, 1 means problems were found, 2 means the
file could not be read.
"""

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional

__version__ = "1.0.0"

GENESIS_HASH = "0" * 64

FIELDS = (
    "event_id",
    "operation_id",
    "event_type",
    "timestamp",
    "actor",
    "details",
    "previous_state",
    "new_state",
    "previous_hash",
    "immutable_hash",
)


def canonical_json(value: Any) -> str:
    """The exact text that is hashed: sorted keys, UTF-8, default separators."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def event_hash(event: Dict[str, Any]) -> str:
    """SHA-256 over every field except immutable_hash."""
    body = {k: v for k, v in event.items() if k != "immutable_hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def verify_log(events: List[Dict[str, Any]], expected_head: Optional[str] = None) -> List[str]:
    """
    Return every problem found in the log; an empty list means it is intact.

    The chain alone cannot show that events were cut off the end. Pass the
    last hash you were given earlier (or that was published) as
    expected_head to catch that too.
    """
    if not isinstance(events, list):
        return ["log must be a JSON array of events"]
    problems: List[str] = []
    prev = GENESIS_HASH
    seen_ids = set()
    for i, ev in enumerate(events):
        label = f"event {i}"
        if not isinstance(ev, dict):
            problems.append(f"{label}: not a JSON object")
            prev = None
            continue
        label = f"event {i} ({ev.get('event_id', '?')})"
        missing = [f for f in FIELDS if f not in ev]
        extra = sorted(set(ev) - set(FIELDS))
        if missing:
            problems.append(f"{label}: missing fields {missing}")
        if extra:
            problems.append(f"{label}: unexpected fields {extra}")
        if ev.get("event_id") in seen_ids:
            problems.append(f"{label}: duplicate event_id")
        seen_ids.add(ev.get("event_id"))
        if ev.get("previous_hash") != prev:
            problems.append(f"{label}: chain broken (previous_hash does not match the event before)")
        if event_hash(ev) != ev.get("immutable_hash"):
            problems.append(f"{label}: hash mismatch (event was changed)")
        prev = ev.get("immutable_hash")
    if expected_head is not None:
        # The log may have grown since; the old head must still be in it.
        hashes = {e.get("immutable_hash") for e in events if isinstance(e, dict)} | {GENESIS_HASH}
        if expected_head not in hashes:
            problems.append(
                "expected head hash is not in the log: events were removed, "
                "or this is not the log you were given"
            )
    return problems


def head_hash(events: List[Dict[str, Any]]) -> str:
    """The hash of the last event, to keep and check against later."""
    return events[-1]["immutable_hash"] if events else GENESIS_HASH


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Straightedge audit log for tampering.")
    parser.add_argument("log", help="path to the audit log JSON file ('-' for stdin)")
    parser.add_argument("--head", help="the last event hash you were given, to detect removed events at the end")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)
    try:
        if args.log == "-":
            events = json.load(sys.stdin)
        else:
            with open(args.log, encoding="utf-8") as f:
                events = json.load(f)
    except (OSError, ValueError) as exc:
        print(f"could not read log: {exc}", file=sys.stderr)
        return 2
    problems = verify_log(events, args.head)
    if problems:
        for p in problems:
            print(p)
        print(f"FAILED: {len(problems)} problem(s) in {len(events) if isinstance(events, list) else 0} events")
        return 1
    print(f"OK: {len(events)} events, chain intact, head {head_hash(events)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
