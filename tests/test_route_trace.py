import socket
import unittest
from unittest.mock import patch

from route_trace import _parse_icmp_response, run_manual_traceroute


def make_icmp_packet(icmp_type, icmp_code, destination, port):
    outer_ip = b"\x45" + b"\x00" * 19
    icmp_header = bytes((icmp_type, icmp_code)) + b"\x00" * 6
    original_ip = (
        b"\x45"
        + b"\x00" * 15
        + socket.inet_aton(destination)
    )
    udp_header = b"\x00\x00" + port.to_bytes(2, "big") + b"\x00" * 4
    return outer_ip + icmp_header + original_ip + udp_header


class FakeSocket:
    def __init__(self, responses=None):
        self.responses = responses or []
        self.sent_addresses = []
        self.closed = False

    def setsockopt(self, *_):
        pass

    def sendto(self, _, address):
        self.sent_addresses.append(address)

    def recvfrom(self, _):
        return self.responses.pop(0)

    def close(self):
        self.closed = True


class RouteTraceTests(unittest.TestCase):
    def test_parser_extracts_icmp_type_and_probe_destination(self):
        packet = make_icmp_packet(11, 0, "203.0.113.8", 33435)

        self.assertEqual(
            _parse_icmp_response(packet),
            (11, 0, "203.0.113.8", 33435),
        )

    def test_manual_trace_follows_ttl_exceeded_then_destination_unreachable(self):
        receiver = FakeSocket([
            (make_icmp_packet(11, 0, "203.0.113.8", 33435), ("10.0.0.1", 0)),
            (make_icmp_packet(3, 3, "203.0.113.8", 33436), ("203.0.113.8", 0)),
        ])
        sender = FakeSocket()

        with patch("route_trace.socket.gethostbyname", return_value="203.0.113.8"), \
                patch("route_trace.sys.platform", "linux"), \
                patch("route_trace.socket.socket", side_effect=[receiver, sender]), \
                patch("route_trace.select.select", side_effect=lambda *_: ([receiver], [], [])):
            results = run_manual_traceroute("example.com", max_hops=2)

        self.assertEqual([hop["ip"] for hop in results], ["10.0.0.1", "203.0.113.8"])
        self.assertEqual([address[1] for address in sender.sent_addresses], [33435, 33436])
        self.assertTrue(receiver.closed)
        self.assertTrue(sender.closed)


if __name__ == "__main__":
    unittest.main()
