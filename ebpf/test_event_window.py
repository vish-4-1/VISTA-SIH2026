import unittest

from event_window import select_recent_events


class SelectRecentEventsTests(unittest.TestCase):
    def test_keeps_latest_event_of_each_type_and_preserves_order(self) -> None:
        events = [
            {"eventType": "XFRM_OUT", "id": "out-old"},
            {"eventType": "SOCK_SEND", "id": "socket-1"},
            {"eventType": "XFRM_IN", "id": "in-old"},
            {"eventType": "SOCK_SEND", "id": "socket-2"},
            {"eventType": "XFRM_OUT", "id": "out-new"},
            {"eventType": "SOCK_SEND", "id": "socket-3"},
            {"eventType": "XFRM_IN", "id": "in-new"},
            {"eventType": "SOCK_SEND", "id": "socket-4"},
        ]

        selected = select_recent_events(events, limit=4)

        self.assertEqual(
            [event["id"] for event in selected],
            ["out-new", "socket-3", "in-new", "socket-4"],
        )

    def test_limit_and_empty_input(self) -> None:
        events = [
            {"eventType": "XFRM_OUT"},
            {"eventType": "XFRM_IN"},
            {"eventType": "SOCK_SEND"},
        ]

        self.assertEqual(len(select_recent_events(events, limit=2)), 2)
        self.assertEqual(select_recent_events(events, limit=0), [])
        self.assertEqual(select_recent_events([], limit=50), [])

    def test_preserves_all_types_when_the_limit_is_smaller_than_the_history(self) -> None:
        events = [
            {"eventType": "XFRM_OUT", "id": "out"},
            {"eventType": "SOCK_SEND", "id": "socket-old"},
            {"eventType": "XFRM_IN", "id": "in"},
            {"eventType": "SOCK_SEND", "id": "socket-new"},
        ]

        selected = select_recent_events(events, limit=3)

        self.assertEqual(
            {event["eventType"] for event in selected},
            {"XFRM_OUT", "XFRM_IN", "SOCK_SEND"},
        )
        self.assertEqual(
            [event["id"] for event in selected],
            ["out", "in", "socket-new"],
        )


if __name__ == "__main__":
    unittest.main()
