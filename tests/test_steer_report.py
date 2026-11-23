"""Tests for the results matrix built from a honeypot log."""

import json

import pytest

import steer_report


def issued(profile, payload, port=None, service=None):
    event = {"event": "steer_issued", "profile": profile, "payload": payload}
    if port:
        event["listen_port"] = port
    if service:
        event["service"] = service
    return event


def hit(issued_event, carrier, source="10.0.0.5", attributed=True):
    return {
        "event": "steer_hit",
        "attributed": attributed,
        "carrier": carrier,
        "source_ip": source,
        "issued": issued_event,
    }


def test_matrix_groups_by_profile_payload_and_listener():
    first = issued("pentestagent", "steer_ack", port=8081)
    second = issued("neurosploit", "steer_ack", port=8084)
    events = [
        first,
        first,
        second,
        hit(first, "TI"),
        hit(first, "TI", source="10.0.0.6"),
        hit(first, "VI"),
    ]
    rows = steer_report.build_matrix(events)
    assert rows[0] == {
        "profile": "pentestagent",
        "payload": "steer_ack",
        "listener": "8081",
        "delivered": 2,
        "hits": 3,
        "sources": 2,
        "carriers": {"TI": 2, "VI": 1},
    }
    assert rows[1]["hits"] == 0 and rows[1]["delivered"] == 1


def test_service_banners_are_listed_by_service_name():
    event = issued("generic", "steer_ack", service="SSH")
    rows = steer_report.build_matrix([event, hit(event, "BN")])
    assert rows[0]["listener"] == "SSH"


def test_unattributed_hits_are_counted_separately():
    events = [hit({}, "TI", attributed=False), hit({}, "TI", attributed=False)]
    assert steer_report.build_matrix(events) == []
    assert steer_report.count_unattributed(events) == 2


def test_report_reads_log_with_decorative_and_broken_lines(tmp_path):
    event = issued("artex", "steer_ack_plain", port=8088)
    log = tmp_path / "honeypot.log"
    log.write_text(
        "\n".join(
            [
                "=" * 80,
                "CALLBACK HIT DETECTED",
                json.dumps(event),
                "{not json",
                json.dumps(hit(event, "HD")),
                json.dumps({"event": "connection"}),
            ]
        )
    )
    text = steer_report.report(str(log))
    lines = text.splitlines()
    assert lines[0].split() == list(steer_report.HEADERS)
    assert lines[1].split() == [
        "artex",
        "steer_ack_plain",
        "8088",
        "1",
        "1",
        "1",
        "HD:1",
    ]
    assert lines[-1] == "Unattributed steering-path requests: 0"


def test_empty_log_says_so(tmp_path):
    log = tmp_path / "empty.log"
    log.write_text("")
    assert "(no steering codes issued in this log)" in steer_report.report(str(log))


def test_missing_log_raises():
    with pytest.raises(OSError):
        steer_report.report("/nonexistent/honeypot.log")
