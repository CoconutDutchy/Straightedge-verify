# Copyright 2026 Fronson Dinkelaar, trading as Order of Operation
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
    python straightedge_verify.py audit_log.json --head receipt.json

Exit code 0 means the log is intact, 1 means problems were found, 2 means the
file could not be read.
"""

import argparse
import codecs
import hashlib
import json
import math
import os
import re
import sys
from typing import Any, Dict, List, Optional, Tuple

__version__ = "1.1.0"

RECEIPT_FORMAT = "straightedge-receipt/1"
HASH_RE = re.compile(r"[0-9a-f]{64}")

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


class LogReadError(ValueError):
    """The file can't be read as JSON text at all (exit code 2)."""


class LogFormatError(ValueError):
    """The file is JSON, but written in a way the format forbids (exit code 1)."""


def _no_repeated_fields(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    seen: Dict[str, Any] = {}
    for key, value in pairs:
        if key in seen:
            raise LogFormatError(
                f"field {key!r} appears more than once in one object; different readers would see "
                "different values, so the log can't be trusted"
            )
        seen[key] = value
    return seen


def _no_non_finite(text: str) -> Any:
    raise LogFormatError(f"{text} is not allowed: the format only has finite numbers")


def decode_log_bytes(data: bytes) -> str:
    """Decode a log file: UTF-8 (with or without a byte order mark), UTF-16 or UTF-32, as Windows tools write them."""
    for bom, enc in ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
                     (codecs.BOM_UTF8, "utf-8-sig"),
                     (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16")):
        if data.startswith(bom):
            break
    else:
        # No byte order mark. JSON starts with an ASCII character, so zero bytes give UTF-16 away.
        if len(data) >= 2 and data[0] == 0 and data[1] != 0:
            enc = "utf-16-be"
        elif len(data) >= 2 and data[0] != 0 and data[1] == 0:
            enc = "utf-16-le"
        else:
            enc = "utf-8"
    try:
        return data.decode(enc)
    except UnicodeDecodeError as exc:
        raise LogReadError(
            f"the file is not valid {enc.upper()} text ({exc.reason} at byte {exc.start}). "
            "Save it as UTF-8 and try again, for example in PowerShell: "
            "Get-Content log.json | Set-Content -Encoding utf8 log-utf8.json"
        ) from exc


def parse_log_text(text: str) -> Any:
    """Parse log text, refusing repeated fields and NaN or Infinity."""
    try:
        return json.loads(text, object_pairs_hook=_no_repeated_fields, parse_constant=_no_non_finite)
    except LogFormatError:
        raise
    except ValueError as exc:
        raise LogReadError(f"the file is not valid JSON ({exc})") from exc
    except RecursionError as exc:
        raise LogReadError("the file nests objects or arrays too deeply to read") from exc


def load_log(path: str) -> Any:
    """Read a log file ('-' for standard input). Raises LogReadError or LogFormatError."""
    try:
        if path == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(path, "rb") as f:
                data = f.read()
    except OSError as exc:
        raise LogReadError(str(exc)) from exc
    return parse_log_text(decode_log_bytes(data))


def event_hash(event: Dict[str, Any]) -> str:
    """SHA-256 over every field except immutable_hash."""
    body = {k: v for k, v in event.items() if k != "immutable_hash"}
    return hashlib.sha256(canonical_json(body).encode("utf-8")).hexdigest()


def _non_finite_paths(value: Any, path: str) -> List[str]:
    if isinstance(value, float) and not math.isfinite(value):
        return [path]
    if isinstance(value, dict):
        return [p for k, v in value.items() for p in _non_finite_paths(v, f"{path}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _non_finite_paths(v, f"{path}[{i}]")]
    return []


def _type_problems(ev: Dict[str, Any]) -> List[str]:
    problems = []
    for f in ("event_id", "operation_id", "event_type", "timestamp"):
        if f in ev and not isinstance(ev[f], str):
            problems.append(f"{f} must be text")
    for f in ("actor", "details"):
        if f in ev and not isinstance(ev[f], dict):
            problems.append(f"{f} must be an object")
    for f in ("previous_state", "new_state"):
        if f in ev and ev[f] is not None and not isinstance(ev[f], str):
            problems.append(f"{f} must be text or null")
    for f in ("previous_hash", "immutable_hash"):
        if f in ev and not (isinstance(ev[f], str) and HASH_RE.fullmatch(ev[f])):
            problems.append(f"{f} must be 64 lowercase hex characters")
    for p in _non_finite_paths(ev, "event"):
        problems.append(f"{p} is not a finite number (NaN and Infinity are not allowed)")
    return problems


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
        event_id = ev.get("event_id")
        label = f"event {i} ({event_id if isinstance(event_id, str) else '?'})"
        missing = [f for f in FIELDS if f not in ev]
        extra = sorted(set(ev) - set(FIELDS))
        if missing:
            problems.append(f"{label}: missing fields {missing}")
        if extra:
            problems.append(f"{label}: unexpected fields {extra}")
        for p in _type_problems(ev):
            problems.append(f"{label}: {p}")
        event_id = ev.get("event_id")
        if isinstance(event_id, str):
            if event_id in seen_ids:
                problems.append(f"{label}: duplicate event_id")
            seen_ids.add(event_id)
        if ev.get("previous_hash") != prev:
            problems.append(f"{label}: chain broken (previous_hash does not match the event before)")
        try:
            changed = event_hash(ev) != ev.get("immutable_hash")
        except ValueError:  # e.g. text that isn't valid Unicode
            changed = True
        if changed:
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


def verify_receipt(events: List[Dict[str, Any]], receipt: Dict[str, Any]) -> List[str]:
    """
    Check a log against a receipt the runtime handed out at a checkpoint:
    the chain is intact, the receipt's head is in the log, and at the position the receipt names.
    """
    problems = verify_log(events, expected_head=receipt["head"])
    length = receipt.get("log_length")
    if isinstance(events, list) and isinstance(length, int) and not isinstance(length, bool):
        hashes = [e.get("immutable_hash") if isinstance(e, dict) else None for e in events]
        if receipt["head"] in hashes and (length < 1 or length > len(hashes) or hashes[length - 1] != receipt["head"]):
            where = hashes.index(receipt["head"]) + 1
            problems.append(
                f"receipt says the head is record {length}, but the log has it at record {where}: "
                "records before it were added or removed"
            )
    return problems


def load_receipt(path: str) -> Dict[str, Any]:
    """Read a receipt file. Raises LogReadError if it isn't one."""
    receipt = load_log(path)
    if not (isinstance(receipt, dict) and receipt.get("format") == RECEIPT_FORMAT
            and isinstance(receipt.get("head"), str) and HASH_RE.fullmatch(receipt["head"])):
        raise LogReadError(
            f"{path} is not a Straightedge receipt (expected format {RECEIPT_FORMAT!r} with a 'head' hash)"
        )
    return receipt


def head_hash(events: List[Dict[str, Any]]) -> str:
    """The hash of the last event, to keep and check against later."""
    return events[-1]["immutable_hash"] if events else GENESIS_HASH


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Check a Straightedge audit log for tampering.")
    parser.add_argument("log", help="path to the audit log JSON file ('-' for stdin)")
    parser.add_argument("--head", help="the last event hash you were given, or a receipt file, "
                                       "to detect removed events at the end")
    parser.add_argument("--version", action="version", version=__version__)
    args = parser.parse_args(argv)

    receipt = None
    if args.head is not None and HASH_RE.fullmatch(args.head.lower()):
        args.head = args.head.lower()  # a hash copied in capitals is the same hash
    elif args.head is not None:
        if os.path.isfile(args.head):
            try:
                receipt = load_receipt(args.head)
            except (LogReadError, LogFormatError) as exc:
                print(f"could not read receipt: {exc}", file=sys.stderr)
                return 2
        else:
            print("--head must be a hash of 64 lowercase hex characters, or the path of a receipt file. "
                  f"Got {args.head!r}.", file=sys.stderr)
            return 2

    try:
        events = load_log(args.log)
    except LogReadError as exc:
        print(f"could not read log: {exc}", file=sys.stderr)
        return 2
    except LogFormatError as exc:
        print(exc)
        print("FAILED: the log file breaks the format")
        return 1

    if receipt is not None:
        problems = verify_receipt(events, receipt)
    else:
        problems = verify_log(events, args.head)
    if problems:
        for p in problems:
            print(p)
        print(f"FAILED: {len(problems)} problem(s) in {len(events) if isinstance(events, list) else 0} events")
        return 1
    print(f"OK: {len(events)} events, chain intact, head {head_hash(events)}")
    if receipt is not None:
        print(f"OK: matches receipt for record {receipt.get('log_length', '?')} ({receipt['head']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
