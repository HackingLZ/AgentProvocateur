"""Summarise a honeypot log into a results matrix.

One row per (profile, payload, listener): how many responses carried steering
codes, how many attributed hits came back, from how many sources, and through
which carriers.
"""

import json
from collections import Counter, defaultdict

HEADERS = ("PROFILE", "PAYLOAD", "LISTENER", "DELIVERED", "HITS", "SOURCES", "CARRIERS")


def read_events(path: str) -> list:
    """Read JSON events from a honeypot log, skipping decorative lines.

    Raises:
        OSError: If the log cannot be read.
    """
    events = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _row_key(issued: dict) -> tuple:
    listener = issued.get("service") or issued.get("listen_port") or "?"
    return (
        issued.get("profile", "?"),
        issued.get("payload", "?"),
        str(listener),
    )


def build_matrix(events: list) -> list:
    """Aggregate events into rows of dicts, most hits first."""
    delivered = Counter()
    hits = Counter()
    sources = defaultdict(set)
    carriers = defaultdict(Counter)
    for event in events:
        if event.get("event") == "steer_issued":
            delivered[_row_key(event)] += 1
        elif event.get("event") == "steer_hit" and event.get("attributed"):
            key = _row_key(event.get("issued", {}))
            hits[key] += 1
            sources[key].add(event.get("source_ip"))
            carriers[key][event.get("carrier", "?")] += 1
    rows = []
    for key in set(delivered) | set(hits):
        rows.append(
            {
                "profile": key[0],
                "payload": key[1],
                "listener": key[2],
                "delivered": delivered[key],
                "hits": hits[key],
                "sources": len(sources[key]),
                "carriers": dict(carriers[key]),
            }
        )
    rows.sort(key=lambda row: (-row["hits"], row["profile"], row["payload"]))
    return rows


def count_unattributed(events: list) -> int:
    """Number of steering-path requests that matched no issued code."""
    return sum(
        1
        for event in events
        if event.get("event") == "steer_hit" and not event.get("attributed")
    )


def format_matrix(rows: list, unattributed: int = 0) -> str:
    """Render rows as an aligned text table."""
    table = [HEADERS]
    for row in rows:
        carrier_text = " ".join(
            f"{name}:{count}" for name, count in sorted(row["carriers"].items())
        )
        table.append(
            (
                row["profile"],
                row["payload"],
                row["listener"],
                str(row["delivered"]),
                str(row["hits"]),
                str(row["sources"]),
                carrier_text or "-",
            )
        )
    widths = [max(len(line[index]) for line in table) for index in range(len(HEADERS))]
    lines = [
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths)).rstrip()
        for line in table
    ]
    if len(table) == 1:
        lines.append("(no steering codes issued in this log)")
    lines.append(f"Unattributed steering-path requests: {unattributed}")
    return "\n".join(lines)


def report(path: str) -> str:
    """Build the results matrix for one log file."""
    events = read_events(path)
    return format_matrix(build_matrix(events), count_unattributed(events))
