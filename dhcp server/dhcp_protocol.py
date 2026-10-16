"""Minimal DHCP (BOOTP) packet encode/decode helpers — RFC 2131/2132."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

DHCP_MAGIC = b"\x63\x82\x53\x63"

OP_BOOTREQUEST = 1
OP_BOOTREPLY = 2

MSG_DISCOVER = 1
MSG_OFFER = 2
MSG_REQUEST = 3
MSG_DECLINE = 4
MSG_ACK = 5
MSG_NAK = 6
MSG_RELEASE = 7
MSG_INFORM = 8

OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_DOMAIN = 15
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_MESSAGE_TYPE = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQUEST = 55
OPT_END = 255

MSG_NAMES = {
    MSG_DISCOVER: "DISCOVER",
    MSG_OFFER: "OFFER",
    MSG_REQUEST: "REQUEST",
    MSG_DECLINE: "DECLINE",
    MSG_ACK: "ACK",
    MSG_NAK: "NAK",
    MSG_RELEASE: "RELEASE",
    MSG_INFORM: "INFORM",
}


def ip_to_bytes(ip: str) -> bytes:
    return bytes(int(p) for p in ip.split("."))


def bytes_to_ip(data: bytes) -> str:
    return ".".join(str(b) for b in data)


def mac_to_bytes(mac: str) -> bytes:
    return bytes(int(p, 16) for p in mac.replace("-", ":").split(":"))


def bytes_to_mac(data: bytes, length: int = 6) -> str:
    return ":".join(f"{b:02x}" for b in data[:length])


def ip_to_int(ip: str) -> int:
    parts = [int(p) for p in ip.split(".")]
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def int_to_ip(value: int) -> str:
    return f"{(value >> 24) & 0xFF}.{(value >> 16) & 0xFF}.{(value >> 8) & 0xFF}.{value & 0xFF}"


@dataclass
class DhcpPacket:
    op: int = OP_BOOTREQUEST
    htype: int = 1
    hlen: int = 6
    hops: int = 0
    xid: int = 0
    secs: int = 0
    flags: int = 0
    ciaddr: str = "0.0.0.0"
    yiaddr: str = "0.0.0.0"
    siaddr: str = "0.0.0.0"
    giaddr: str = "0.0.0.0"
    chaddr: str = "00:00:00:00:00:00"
    sname: bytes = b""
    file: bytes = b""
    options: Dict[int, bytes] = field(default_factory=dict)

    @property
    def message_type(self) -> Optional[int]:
        raw = self.options.get(OPT_MESSAGE_TYPE)
        return raw[0] if raw else None

    def encode(self) -> bytes:
        chaddr = mac_to_bytes(self.chaddr).ljust(16, b"\x00")
        sname = self.sname.ljust(64, b"\x00")[:64]
        file_field = self.file.ljust(128, b"\x00")[:128]
        header = struct.pack(
            "!BBBBIHH4s4s4s4s16s64s128s",
            self.op,
            self.htype,
            self.hlen,
            self.hops,
            self.xid,
            self.secs,
            self.flags,
            ip_to_bytes(self.ciaddr),
            ip_to_bytes(self.yiaddr),
            ip_to_bytes(self.siaddr),
            ip_to_bytes(self.giaddr),
            chaddr,
            sname,
            file_field,
        )
        opts = bytearray(DHCP_MAGIC)
        for code, value in self.options.items():
            opts.append(code)
            opts.append(len(value))
            opts.extend(value)
        opts.append(OPT_END)
        while len(opts) < 64:
            opts.append(0)
        return header + bytes(opts)

    @classmethod
    def decode(cls, data: bytes) -> "DhcpPacket":
        if len(data) < 240:
            raise ValueError("DHCP packet too short")
        (
            op,
            htype,
            hlen,
            hops,
            xid,
            secs,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            sname,
            file_field,
        ) = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", data[:236])
        if data[236:240] != DHCP_MAGIC:
            raise ValueError("Missing DHCP magic cookie")

        options: Dict[int, bytes] = {}
        i = 240
        while i < len(data):
            code = data[i]
            i += 1
            if code == 0:
                continue
            if code == OPT_END:
                break
            if i >= len(data):
                break
            length = data[i]
            i += 1
            options[code] = data[i : i + length]
            i += length

        return cls(
            op=op,
            htype=htype,
            hlen=hlen,
            hops=hops,
            xid=xid,
            secs=secs,
            flags=flags,
            ciaddr=bytes_to_ip(ciaddr),
            yiaddr=bytes_to_ip(yiaddr),
            siaddr=bytes_to_ip(siaddr),
            giaddr=bytes_to_ip(giaddr),
            chaddr=bytes_to_mac(chaddr, hlen or 6),
            sname=sname.rstrip(b"\x00"),
            file=file_field.rstrip(b"\x00"),
            options=options,
        )


def build_options(
    message_type: int,
    server_ip: str,
    lease_time: int,
    netmask: str,
    gateway: str,
    dns_servers: List[str],
    domain: str = "",
    requested_ip: Optional[str] = None,
) -> Dict[int, bytes]:
    opts: Dict[int, bytes] = {
        OPT_MESSAGE_TYPE: bytes([message_type]),
        OPT_SERVER_ID: ip_to_bytes(server_ip),
        OPT_LEASE_TIME: struct.pack("!I", lease_time),
        OPT_SUBNET_MASK: ip_to_bytes(netmask),
        OPT_ROUTER: ip_to_bytes(gateway),
        OPT_DNS: b"".join(ip_to_bytes(ip) for ip in dns_servers),
    }
    if domain:
        opts[OPT_DOMAIN] = domain.encode("ascii")
    if requested_ip:
        opts[OPT_REQUESTED_IP] = ip_to_bytes(requested_ip)
    return opts


def parse_requested_ip(packet: DhcpPacket) -> Optional[str]:
    raw = packet.options.get(OPT_REQUESTED_IP)
    return bytes_to_ip(raw) if raw and len(raw) == 4 else None
