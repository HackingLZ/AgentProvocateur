"""Tests for profile framing, carrier encoding and config parsing."""

import re

import pytest

import profiles


@pytest.mark.parametrize("name", sorted(profiles.PROFILES))
def test_every_profile_keeps_the_payload_text(name):
    assert "PAYLOAD-BODY" in profiles.frame(name, "PAYLOAD-BODY")


def test_unknown_profile_raises():
    with pytest.raises(KeyError):
        profiles.frame("no-such-tool", "x")


def test_neurosploit_closes_fence_before_payload_and_reopens_after():
    framed = profiles.frame("neurosploit", "PAYLOAD-BODY")
    closer = framed.index(profiles.NEUROSPLOIT_CLOSER)
    body = framed.index("PAYLOAD-BODY")
    opener = framed.index(profiles.NEUROSPLOIT_OPENER)
    assert closer < body < opener


def test_artex_closer_and_reopener_share_a_nonce_that_changes_per_render():
    framed = profiles.frame("artex", "PAYLOAD-BODY")
    closer = re.search(r"<<<END_UNTRUSTED_OUTPUT ([0-9a-f]{16})>>>>", framed)
    opener = re.search(r"<<<UNTRUSTED_OUTPUT ([0-9a-f]{16})>>>>", framed)
    assert closer.group(1) == opener.group(1)
    assert framed.index("[exit code 0]") < closer.start()
    assert closer.start() < framed.index("PAYLOAD-BODY") < opener.start()
    assert closer.group(1) not in profiles.frame("artex", "PAYLOAD-BODY")


def test_pentestagent_payload_follows_forged_stdout_marker():
    framed = profiles.frame("pentestagent", "PAYLOAD-BODY")
    assert framed.index("Exit Code: 0") < framed.index("--- stdout ---")
    assert framed.index("--- stdout ---") < framed.index("PAYLOAD-BODY")


def test_pentestgpt_payload_sits_between_quotable_lines():
    lines = profiles.frame("pentestgpt", "PAYLOAD-BODY").splitlines()
    assert lines[0] == "HTTP/1.1 200 OK"
    assert lines[-1] == "END RESPONSE"


def test_one_line_collapses_whitespace_and_truncates():
    assert profiles.one_line("a\n\n  b\tc") == "a b c"
    assert len(profiles.one_line("word " * 200, limit=50)) <= 50
    assert profiles.one_line("") == ""


def test_header_safe_has_no_line_breaks_and_is_latin1():
    value = profiles.header_safe("TITLE\r\n=====\nsnowman ☃ here")
    assert "\r" not in value and "\n" not in value
    value.encode("latin-1")


def test_cookie_safe_removes_cookie_delimiters():
    value = profiles.cookie_safe('a; b, "c" \\ d\nnext')
    assert not set(';,"\\\n') & set(value)


def test_code_round_trip():
    code = profiles.make_code("7f9b12c3", "TI")
    assert profiles.parse_code(code) == ("7f9b12c3", "TI")


def test_make_code_rejects_unknown_carrier():
    with pytest.raises(ValueError, match="Unknown carrier"):
        profiles.make_code("7f9b12c3", "ZZ")


@pytest.mark.parametrize(
    "junk",
    ["", "REG-7f9b12c3", "REG-7f9b12c3-ZZ", "REG-XYZ-TI", "reg-7f9b12c3-ti", "../x"],
)
def test_parse_code_rejects_malformed(junk):
    assert profiles.parse_code(junk) is None


def test_parse_profile_ports():
    listeners = profiles.parse_profile_ports(
        ["pentestagent:8081", "pentest-agent:8082"], "steer_ack"
    )
    assert listeners == [
        profiles.Listener(8081, "pentestagent", "steer_ack"),
        profiles.Listener(8082, "pentest-agent", "steer_ack"),
    ]


@pytest.mark.parametrize(
    "spec", ["nope:8081", "pentestagent", "pentestagent:0", "pentestagent:abc"]
)
def test_parse_profile_ports_rejects_bad_specs(spec):
    with pytest.raises(ValueError):
        profiles.parse_profile_ports([spec], "steer_ack")


def test_parse_listeners_allows_payload_variants_on_one_profile():
    entries = [
        {"port": 8081, "profile": "pentestagent", "payload": "a"},
        {"port": 8082, "profile": "pentestagent", "payload": "b"},
        {"port": 8083},
    ]
    listeners = profiles.parse_listeners(entries, {"a", "b", "default"}, "default")
    assert [item.payload for item in listeners] == ["a", "b", "default"]
    assert listeners[2].profile == "generic"


@pytest.mark.parametrize(
    "entry",
    [
        "8081",
        {"profile": "generic"},
        {"port": "8081"},
        {"port": True},
        {"port": 8081, "profile": "nope"},
        {"port": 8081, "payload": "undefined"},
    ],
)
def test_parse_listeners_rejects_bad_entries(entry):
    with pytest.raises(ValueError):
        profiles.parse_listeners([entry], {"default"}, "default")


def test_find_port_conflicts():
    listeners = [
        profiles.Listener(8080, "generic", "p"),
        profiles.Listener(8081, "generic", "p"),
        profiles.Listener(8081, "pentestgpt", "p"),
    ]
    assert profiles.find_port_conflicts(listeners, {8080}) == [8080, 8081]
    assert profiles.find_port_conflicts(listeners[1:2], {8080}) == []


def test_parse_custom_payloads_accepts_string_and_object():
    texts, shorts = profiles.parse_custom_payloads(
        {"plain": "text one", "both": {"text": "text two", "short": "two"}}
    )
    assert texts == {"plain": "text one", "both": "text two"}
    assert shorts == {"both": "two"}


@pytest.mark.parametrize("value", ["", "   ", {}, {"short": "x"}, 5, None])
def test_parse_custom_payloads_rejects_missing_text(value):
    with pytest.raises(ValueError, match="needs a non-empty"):
        profiles.parse_custom_payloads({"bad": value})
