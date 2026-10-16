import copy
import json
import pathlib

import pytest

import plexi_verify as pv

FIXTURE = pathlib.Path(__file__).parent / "fixtures" / "credit_memo_log.json"


@pytest.fixture
def log():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def rehash_from(events, start):
    """What a tamperer would do: recompute hashes after an edit."""
    prev = events[start - 1]["immutable_hash"] if start else pv.GENESIS_HASH
    for ev in events[start:]:
        ev["previous_hash"] = prev
        ev["immutable_hash"] = pv.event_hash(ev)
        prev = ev["immutable_hash"]


def test_real_plexi_log_is_intact(log):
    assert len(log) == 16
    assert pv.verify_log(log) == []


def test_empty_log_is_intact():
    assert pv.verify_log([]) == []
    assert pv.head_hash([]) == pv.GENESIS_HASH


def test_edited_detail_is_caught(log):
    log[7]["details"]["output_hash"] = "0" * 64
    assert any("hash mismatch" in p for p in pv.verify_log(log))


def test_edited_actor_is_caught(log):
    log[-3]["actor"]["subject_id"] = "someone-else"
    assert any("event 13" in p and "hash mismatch" in p for p in pv.verify_log(log))


def test_deleted_event_is_caught(log):
    del log[5]
    assert any("chain broken" in p for p in pv.verify_log(log))


def test_reordered_events_are_caught(log):
    log[3], log[4] = log[4], log[3]
    assert pv.verify_log(log)


def test_inserted_event_is_caught(log):
    log.insert(2, copy.deepcopy(log[2]))
    problems = pv.verify_log(log)
    assert any("duplicate event_id" in p for p in problems)
    assert any("chain broken" in p for p in problems)


def test_rewriting_the_whole_chain_is_caught_by_the_head(log):
    head = pv.head_hash(log)
    log[7]["details"]["output_hash"] = "f" * 64
    rehash_from(log, 7)
    assert pv.verify_log(log) == []  # internally consistent again
    assert any("expected head" in p for p in pv.verify_log(log, expected_head=head))


def test_truncation_is_caught_by_the_head(log):
    head = pv.head_hash(log)
    assert any("expected head" in p for p in pv.verify_log(log[:-2], expected_head=head))


def test_a_grown_log_still_matches_an_older_head(log):
    older_head = log[9]["immutable_hash"]
    assert pv.verify_log(log, expected_head=older_head) == []


def test_missing_and_extra_fields_are_reported(log):
    del log[0]["timestamp"]
    log[1]["note"] = "x"
    problems = pv.verify_log(log)
    assert any("missing fields ['timestamp']" in p for p in problems)
    assert any("unexpected fields ['note']" in p for p in problems)


def test_non_list_and_non_object_inputs():
    assert pv.verify_log({"a": 1}) == ["log must be a JSON array of events"]
    assert any("not a JSON object" in p for p in pv.verify_log([1]))


def test_unicode_is_hashed_as_utf8(log):
    # The fixture's evidence text is not ASCII; its hash must still verify.
    assert "\\u" not in pv.canonical_json({"t": "Ünïcode"})
    assert pv.verify_log(log) == []


def test_cli_exit_codes(log, tmp_path, capsys):
    good = tmp_path / "good.json"
    good.write_text(json.dumps(log), encoding="utf-8")
    assert pv.main([str(good)]) == 0
    assert "OK: 16 events" in capsys.readouterr().out

    log[4]["new_state"] = "COMPLETED"
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(log), encoding="utf-8")
    assert pv.main([str(bad)]) == 1
    assert "FAILED" in capsys.readouterr().out

    assert pv.main([str(tmp_path / "missing.json")]) == 2
    assert pv.main([str(good), "--head", "a" * 64]) == 1
