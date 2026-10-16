"""DHCP test client (lab mode): DISCOVER -> OFFER -> REQUEST -> ACK."""

from __future__ import annotations

import argparse
import json
import logging
import random
import socket
from pathlib import Path
from typing import Optional, Tuple

from dhcp_protocol import (
    MSG_ACK,
    MSG_DISCOVER,
    MSG_NAMES,
    MSG_OFFER,
    MSG_REQUEST,
    OP_BOOTREQUEST,
    OPT_MESSAGE_TYPE,
    OPT_PARAM_REQUEST,
    OPT_REQUESTED_IP,
    OPT_SERVER_ID,
    DhcpPacket,
    bytes_to_ip,
    ip_to_bytes,
)

LOG = logging.getLogger("dhcp_client")


class DhcpClient:
    def __init__(
        self,
        server_host: str,
        server_port: int,
        mac: str,
        timeout: float = 2.0,
    ):
        self.server_host = server_host
        self.server_port = server_port
        self.mac = mac.lower()
        self.timeout = timeout

    def _socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        sock.bind(("127.0.0.1", 0))
        return sock

    def _send_recv(self, packet: DhcpPacket, expect_type: int) -> DhcpPacket:
        sock = self._socket()
        try:
            sock.sendto(packet.encode(), (self.server_host, self.server_port))
            LOG.info(
                "sent %s xid=0x%08x",
                MSG_NAMES.get(packet.message_type or 0),
                packet.xid,
            )
            data, _ = sock.recvfrom(4096)
            reply = DhcpPacket.decode(data)
            if reply.xid != packet.xid:
                raise RuntimeError(
                    f"XID mismatch: sent 0x{packet.xid:08x}, got 0x{reply.xid:08x}"
                )
            if reply.message_type != expect_type:
                raise RuntimeError(
                    f"Expected {MSG_NAMES[expect_type]}, got "
                    f"{MSG_NAMES.get(reply.message_type or 0, reply.message_type)}"
                )
            LOG.info(
                "got %s yiaddr=%s",
                MSG_NAMES.get(reply.message_type or 0),
                reply.yiaddr,
            )
            return reply
        finally:
            sock.close()

    def discover(self, xid: Optional[int] = None) -> DhcpPacket:
        xid = xid if xid is not None else random.randint(1, 0xFFFFFFFF)
        packet = DhcpPacket(
            op=OP_BOOTREQUEST,
            xid=xid,
            flags=0x8000,
            chaddr=self.mac,
            options={
                OPT_MESSAGE_TYPE: bytes([MSG_DISCOVER]),
                OPT_PARAM_REQUEST: bytes([1, 3, 6, 15, 51, 54]),
            },
        )
        return self._send_recv(packet, MSG_OFFER)

    def request(self, offer: DhcpPacket) -> DhcpPacket:
        server_id = offer.options.get(OPT_SERVER_ID)
        if not server_id:
            raise RuntimeError("OFFER missing server identifier")
        packet = DhcpPacket(
            op=OP_BOOTREQUEST,
            xid=offer.xid,
            flags=0x8000,
            chaddr=self.mac,
            options={
                OPT_MESSAGE_TYPE: bytes([MSG_REQUEST]),
                OPT_REQUESTED_IP: ip_to_bytes(offer.yiaddr),
                OPT_SERVER_ID: server_id,
                OPT_PARAM_REQUEST: bytes([1, 3, 6, 15, 51, 54]),
            },
        )
        return self._send_recv(packet, MSG_ACK)

    def obtain_lease(self) -> Tuple[str, DhcpPacket]:
        offer = self.discover()
        ack = self.request(offer)
        return ack.yiaddr, ack


def main() -> None:
    parser = argparse.ArgumentParser(description="DHCP lab test client")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).parent / "config" / "dhcp.json"),
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--mac", default="aa:bb:cc:dd:ee:10")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    with open(args.config, encoding="utf-8") as fh:
        config = json.load(fh)
    port = int(config["server"]["lab_port"])
    client = DhcpClient(args.host, port, args.mac)
    ip, ack = client.obtain_lease()
    print(f"Lease obtained: {args.mac} -> {ip}")
    print(f"Server: {bytes_to_ip(ack.options[OPT_SERVER_ID])}")
    print(f"Lease time option present: {51 in ack.options}")


if __name__ == "__main__":
    main()
