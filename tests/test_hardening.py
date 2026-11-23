# Copyright 2026 Fronson Dinkelaar, trading as Order of Operation
# SPDX-License-Identifier: Apache-2.0
"""Malformed input, Windows text encodings, receipts and the written number rules."""
import codecs
import json
import pathlib

import pytest

import straightedge_verify as pv

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CHECKPOINT_LOG = FIXTURES / "checkpoint_log.json"
RECEIPT = FIXTURES / "checkpoint_receipt.json"


@pytest.fixture
def log():
    return json.loads(CHECKPOINT_LOG.read_text(encoding="utf-8"))


def rehash_from(events, start):
    prev = events[start - 1]["immutable_hash"] if start else pv.GENESIS_HASH
    for ev in events[start:]:
        ev["previous_hash"] = prev
        ev["immutable_hash"] = pv.event_hash(ev)
        prev = ev["immutable_hash"]


# A log from the current runtime: checkpoints, a hold and an erasure.

def test_current_runtime_log_is_intact(log):
    assert len(log) == 18
    assert {"log.checkpoint", "operation.hold_set", "operation.content_erased"} <= {e["event_type"] for e in log}
    assert pv.verify_log(log) == []


# 1. Wrong types are reported, not a crash.

@pytest.mark.parametrize("value", [["x"], {"a": 1}, None, 7])
def test_event_id_of_the_wrong_type_is_reported(log, value):
    log[2]["event_id"] = value
    rehash_from(log, 2)
    problems = pv.verify_log(log)
    assert any("event_id must be text" in p for p in problems)


def test_wrong_field_types_are_reported_even_when_rehashed(log):
    log[2]["actor"] = "anyone"
    log[3]["details"] = []
    log[4]["new_state"] = 5
    rehash_from(log, 2)
    problems = pv.verify_log(log)
    assert any("event 2" in p and "actor must be an object" in p for p in problems)
    assert any("event 3" in p and "details must be an object" in p for p in problems)
    assert any("event 4" in p and "new_state must be text or null" in p for p in problems)


def test_badly_written_hashes_are_reported(log):
    log[-1]["immutable_hash"] = log[-1]["immutable_hash"].upper()
    problems = pv.verify_log(log)
    assert any("immutable_hash must be 64 lowercase hex" in p for p in problems)


@pytest.mark.parametrize("bad", [float("nan"), float("inf"), float("-inf")])
def test_non_finite_numbers_are_reported(log, bad):
    log[2]["details"]["x"] = [bad]
    rehash_from(log, 2)
    assert any("not a finite number" in p for p in pv.verify_log(log))


# 2. A field written twice in one object is refused.

def test_repeated_field_is_refused(log, tmp_path, capsys):
    text = json.dumps(log, ensure_ascii=False)
    first = json.dumps(log[0], ensure_ascii=False)
    # A reader that keeps the first copy sees "ceo"; Python keeps the last, which verifies.
    forged = first.replace('{"event_id"', '{"actor": {"type": "user", "subject_id": "ceo"}, "event_id"', 1)
    path = tmp_path / "repeated.json"
    path.write_text(text.replace(first, forged, 1), encoding="utf-8")
    assert pv.main([str(path)]) == 1
    out = capsys.readouterr().out
    assert "'actor' appears more than once" in out


def test_nan_in_the_file_is_refused(log, tmp_path, capsys):
    path = tmp_path / "nan.json"
    path.write_text(json.dumps(log).replace('"details": {}', '"details": {"x": NaN}', 1), encoding="utf-8")
    assert pv.main([str(path)]) == 1
    assert "NaN" in capsys.readouterr().out


# 3. Files saved on Windows.

@pytest.mark.parametrize("encode", [
    lambda t: codecs.BOM_UTF8 + t.encode("utf-8"),
    lambda t: t.encode("utf-16"),          # Windows PowerShell 5.1 ">" writes this
    lambda t: t.encode("utf-16-be"),
    lambda t: codecs.BOM_UTF16_BE + t.encode("utf-16-be"),
    lambda t: t.encode("utf-32"),
], ids=["utf8-bom", "utf16-le-bom", "utf16-be-no-bom", "utf16-be-bom", "utf32"])
def test_windows_encodings_are_read(tmp_path, capsys, encode):
    path = tmp_path / "log.json"
    path.write_bytes(encode(CHECKPOINT_LOG.read_text(encoding="utf-8")))
    assert pv.main([str(path)]) == 0
    assert "OK: 18 events" in capsys.readouterr().out


def test_unreadable_bytes_explain_the_fix(tmp_path, capsys):
    path = tmp_path / "log.json"
    path.write_bytes(b"\xff\xfe\xff\x00garbage")
    assert pv.main([str(path)]) == 2
    err = capsys.readouterr().err
    assert "could not read log" in err and "UTF-8" in err


# 4. --head: a hash or a receipt file.

def test_head_must_look_like_a_hash(capsys):
    assert pv.main([str(CHECKPOINT_LOG), "--head", "abc"]) == 2
    assert "64 lowercase hex" in capsys.readouterr().err


def test_head_can_be_a_receipt_file(capsys):
    assert pv.main([str(CHECKPOINT_LOG), "--head", str(RECEIPT)]) == 0
    assert "matches receipt" in capsys.readouterr().out


def test_receipt_catches_truncation(log, tmp_path, capsys):
    path = tmp_path / "short.json"
    path.write_text(json.dumps(log[:-1]), encoding="utf-8")
    assert pv.main([str(path), "--head", str(RECEIPT)]) == 1
    assert "expected head" in capsys.readouterr().out


def test_receipt_position_must_match(log):
    receipt = json.loads(RECEIPT.read_text(encoding="utf-8"))
    receipt["log_length"] = 3
    problems = pv.verify_receipt(log, receipt)
    assert any("receipt says the head is record 3" in p for p in problems)


def test_bad_receipt_file_is_explained(tmp_path, capsys):
    path = tmp_path / "receipt.json"
    path.write_text('{"format": "something-else"}', encoding="utf-8")
    assert pv.main([str(CHECKPOINT_LOG), "--head", str(path)]) == 2
    assert "not a Straightedge receipt" in capsys.readouterr().err


# 6. The number rules written in LOG_FORMAT.md.

@pytest.mark.parametrize("value,text", [
    (1, "1"), (-12345678901234567890, "-12345678901234567890"),
    (1.0, "1.0"), (0.0001, "0.0001"), (100.5, "100.5"), (0.85, "0.85"),
    (1e-05, "1e-05"), (1e16, "1e+16"), (1.5e300, "1.5e+300"), (-0.0, "-0.0"),
    (123456789012345.6, "123456789012345.6"),
])
def test_number_text_matches_the_written_rules(value, text):
    assert pv.canonical_json(value) == text


def test_string_escapes_match_the_written_rules():
    assert pv.canonical_json("a\"\\\b\f\n\r\t\x01\x7f/<>& é") == '"a\\"\\\\\\b\\f\\n\\r\\t\\u0001\x7f/<>& é"'


def test_object_layout_matches_the_written_rules():
    assert pv.canonical_json({"b": [1, {}], "a": [], "é": None, "B": True}) == \
        '{"B": true, "a": [], "b": [1, {}], "é": null}'


def test_log_format_example_vector():
    # The worked example in LOG_FORMAT.md.
    ev = {"event_id": "e1", "operation_id": "", "event_type": "example", "timestamp": "2026-01-01T00:00:00+00:00",
          "actor": {"type": "system"}, "details": {"score": 0.5, "note": "Kōwhai"}, "previous_state": None,
          "new_state": None, "previous_hash": pv.GENESIS_HASH}
    assert pv.event_hash(ev) == EXAMPLE_HASH


EXAMPLE_HASH = "53af3f432ecd60b34c621103ee9df73d5efad06f7859291365424369d62ce9f0"


def test_head_in_capitals_is_accepted():
    head = json.loads(RECEIPT.read_text(encoding="utf-8"))["head"]
    assert pv.main([str(CHECKPOINT_LOG), "--head", head.upper()]) == 0


def test_lone_surrogate_text_is_reported_not_a_crash(log, tmp_path):
    path = tmp_path / "surrogate.json"
    path.write_text(json.dumps(log).replace('"details": {}', '"details": {"x": "\\ud800"}', 1), encoding="utf-8")
    assert pv.main([str(path)]) == 1


def test_deep_nesting_is_reported_not_a_crash(tmp_path):
    path = tmp_path / "deep.json"
    path.write_text("[" * 100000 + "]" * 100000, encoding="utf-8")
    assert pv.main([str(path)]) == 2
