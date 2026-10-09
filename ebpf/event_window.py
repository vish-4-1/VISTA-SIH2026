"""Helpers for returning a useful, chronologically ordered event window."""

from __future__ import annotations

from typing import Any, Iterable


def select_recent_events(
    events: Iterable[dict[str, Any]], limit: int
) -> list[dict[str, Any]]:
    """Include the latest event of each type, then fill with the newest events."""
    if limit <= 0:
        return []

    indexed_events = list(enumerate(events))
    if len(indexed_events) <= limit:
        return [event for _, event in indexed_events]

    selected_indices: set[int] = set()
    selected_types: set[Any] = set()

    for index, event in reversed(indexed_events):
        event_type = event.get("eventType", "UNKNOWN")
        if event_type not in selected_types:
            selected_indices.add(index)
            selected_types.add(event_type)
            if len(selected_indices) == limit:
                break

    if len(selected_indices) < limit:
        for index, _ in reversed(indexed_events):
            if index not in selected_indices:
                selected_indices.add(index)
                if len(selected_indices) == limit:
                    break

    return [
        event
        for index, event in indexed_events
        if index in selected_indices
    ]
