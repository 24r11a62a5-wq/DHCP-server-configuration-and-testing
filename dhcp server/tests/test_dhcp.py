"""Automated DHCP configuration and handshake tests (lab mode)."""

from __future__ import annotations

import json
import socket
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from dhcp_client import DhcpClient
from dhcp_protocol import (
    MSG_ACK,
    MSG_DISCOVER,
    MSG_OFFER,
    MSG_REQUEST,
    OPT_DNS,
    OPT_DOMAIN,
    OPT_LEASE_TIME,
    OPT_MESSAGE_TYPE,
    OPT_ROUTER,
    OPT_SERVER_ID,
    OPT_SUBNET_MASK,
    DhcpPacket,
    bytes_to_ip,
    ip_to_int,
)
from dhcp_server import DhcpServer, LeaseStore, load_config


CONFIG_PATH = ROOT / "config" / "dhcp.json"


def free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class ConfigTests(unittest.TestCase):
    def test_config_loads_and_pool_is_valid(self):
        config = load_config(CONFIG_PATH)
        subnet = config["subnet"]
        start = ip_to_int(subnet["pool_start"])
        end = ip_to_int(subnet["pool_end"])
        self.assertLess(start, end)
        self.assertIn("interface_ip", config["server"])
        self.assertTrue(config["server"]["lab_mode"])
        self.assertGreater(subnet["lease_time_seconds"], 0)

    def test_reservations_are_outside_or_tracked(self):
        config = load_config(CONFIG_PATH)
        for mac, ip in config.get("reservations", {}).items():
            self.assertEqual(len(mac.split(":")), 6)
            self.assertEqual(len(ip.split(".")), 4)


class LeaseStoreTests(unittest.TestCase):
    def setUp(self):
        self.store = LeaseStore(
            "192.168.100.50",
            "192.168.100.52",
            {"aa:bb:cc:dd:ee:01": "192.168.100.10"},
        )

    def test_reservation(self):
        ip = self.store.allocate("aa:bb:cc:dd:ee:01")
        self.assertEqual(ip, "192.168.100.10")

    def test_pool_allocation_and_exhaustion(self):
        a = self.store.allocate("11:22:33:44:55:01")
        b = self.store.allocate("11:22:33:44:55:02")
        c = self.store.allocate("11:22:33:44:55:03")
        d = self.store.allocate("11:22:33:44:55:04")
        self.assertEqual(a, "192.168.100.50")
        self.assertEqual(b, "192.168.100.51")
        self.assertEqual(c, "192.168.100.52")
        self.assertIsNone(d)

    def test_same_mac_gets_same_ip(self):
        first = self.store.allocate("11:22:33:44:55:aa")
        second = self.store.allocate("11:22:33:44:55:aa")
        self.assertEqual(first, second)


class ProtocolTests(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        packet = DhcpPacket(
            xid=0xABCD1234,
            yiaddr="192.168.100.55",
            chaddr="aa:bb:cc:dd:ee:ff",
            options={OPT_MESSAGE_TYPE: bytes([MSG_OFFER]), OPT_SERVER_ID: bytes([192, 168, 100, 1])},
        )
        decoded = DhcpPacket.decode(packet.encode())
        self.assertEqual(decoded.xid, 0xABCD1234)
        self.assertEqual(decoded.yiaddr, "192.168.100.55")
        self.assertEqual(decoded.chaddr, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(decoded.message_type, MSG_OFFER)


class HandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        config = load_config(CONFIG_PATH)
        config = json.loads(json.dumps(config))  # deep copy
        config["server"]["lab_mode"] = True
        config["server"]["lab_port"] = free_udp_port()
        cls.port = config["server"]["lab_port"]
        cls.server = DhcpServer(config)
        cls.thread = cls.server.start_background(bind_host="127.0.0.1")
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        cls.thread.join(timeout=2)

    def test_full_discover_offer_request_ack(self):
        client = DhcpClient("127.0.0.1", self.port, "aa:bb:cc:dd:ee:10")
        ip, ack = client.obtain_lease()
        self.assertTrue(ip.startswith("192.168.100."))
        self.assertEqual(ack.message_type, MSG_ACK)
        self.assertEqual(bytes_to_ip(ack.options[OPT_SERVER_ID]), "192.168.100.1")
        self.assertEqual(bytes_to_ip(ack.options[OPT_SUBNET_MASK]), "255.255.255.0")
        self.assertEqual(bytes_to_ip(ack.options[OPT_ROUTER]), "192.168.100.1")
        self.assertIn(OPT_DNS, ack.options)
        self.assertEqual(ack.options[OPT_DOMAIN].decode("ascii"), "lab.local")
        self.assertEqual(struct_lease(ack.options[OPT_LEASE_TIME]), 3600)

    def test_reservation_mac_gets_fixed_ip(self):
        client = DhcpClient("127.0.0.1", self.port, "aa:bb:cc:dd:ee:01")
        ip, ack = client.obtain_lease()
        self.assertEqual(ip, "192.168.100.10")
        self.assertEqual(ack.yiaddr, "192.168.100.10")

    def test_offer_message_type(self):
        client = DhcpClient("127.0.0.1", self.port, "aa:bb:cc:dd:ee:99")
        offer = client.discover()
        self.assertEqual(offer.message_type, MSG_OFFER)
        self.assertNotEqual(offer.yiaddr, "0.0.0.0")


def struct_lease(raw: bytes) -> int:
    import struct

    return struct.unpack("!I", raw)[0]


if __name__ == "__main__":
    unittest.main(verbosity=2)
