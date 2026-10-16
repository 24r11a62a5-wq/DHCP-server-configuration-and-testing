"""
Simple DHCP server for lab configuration and testing.

Lab mode (default): listens on high UDP port from config (6767) — no admin needed.
Production-like mode: set lab_mode=false and run elevated to bind UDP/67.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import threading
import time
from pathlib import Path
from typing import Dict, Optional, Set, Tuple

from dhcp_protocol import (
    MSG_ACK,
    MSG_DISCOVER,
    MSG_NAMES,
    MSG_NAK,
    MSG_OFFER,
    MSG_REQUEST,
    OP_BOOTREPLY,
    OPT_MESSAGE_TYPE,
    OPT_SERVER_ID,
    DhcpPacket,
    bytes_to_ip,
    build_options,
    int_to_ip,
    ip_to_bytes,
    ip_to_int,
    parse_requested_ip,
)

LOG = logging.getLogger("dhcp_server")


class LeaseStore:
    def __init__(self, pool_start: str, pool_end: str, reservations: Dict[str, str]):
        self.pool_start = ip_to_int(pool_start)
        self.pool_end = ip_to_int(pool_end)
        self.reservations = {k.lower(): v for k, v in reservations.items()}
        self.mac_to_ip: Dict[str, str] = {}
        self.ip_to_mac: Dict[str, str] = {}
        self.leases: Dict[str, float] = {}  # mac -> expiry epoch
        reserved_ips = set(self.reservations.values())
        self.available: Set[int] = {
            ip
            for ip in range(self.pool_start, self.pool_end + 1)
            if int_to_ip(ip) not in reserved_ips
        }
        self._lock = threading.Lock()

    def allocate(self, mac: str, preferred: Optional[str] = None) -> Optional[str]:
        mac = mac.lower()
        with self._lock:
            if mac in self.reservations:
                ip = self.reservations[mac]
                self.mac_to_ip[mac] = ip
                self.ip_to_mac[ip] = mac
                return ip

            if mac in self.mac_to_ip:
                return self.mac_to_ip[mac]

            if preferred:
                pref_int = ip_to_int(preferred)
                if (
                    self.pool_start <= pref_int <= self.pool_end
                    and pref_int in self.available
                    and preferred not in self.ip_to_mac
                ):
                    self.available.remove(pref_int)
                    self.mac_to_ip[mac] = preferred
                    self.ip_to_mac[preferred] = mac
                    return preferred

            if not self.available:
                return None

            ip_int = min(self.available)
            self.available.remove(ip_int)
            ip = int_to_ip(ip_int)
            self.mac_to_ip[mac] = ip
            self.ip_to_mac[ip] = mac
            return ip

    def commit(self, mac: str, ip: str, lease_seconds: int) -> bool:
        mac = mac.lower()
        with self._lock:
            owner = self.ip_to_mac.get(ip)
            if owner and owner != mac:
                return False
            if mac in self.reservations and self.reservations[mac] != ip:
                return False
            self.mac_to_ip[mac] = ip
            self.ip_to_mac[ip] = mac
            self.leases[mac] = time.time() + lease_seconds
            return True

    def release(self, mac: str) -> None:
        mac = mac.lower()
        with self._lock:
            ip = self.mac_to_ip.pop(mac, None)
            self.leases.pop(mac, None)
            if ip:
                self.ip_to_mac.pop(ip, None)
                if mac not in self.reservations:
                    self.available.add(ip_to_int(ip))


class DhcpServer:
    def __init__(self, config: dict):
        self.config = config
        subnet = config["subnet"]
        server = config["server"]
        self.server_ip = server["interface_ip"]
        self.lab_mode = bool(server.get("lab_mode", True))
        self.port = int(server["lab_port"] if self.lab_mode else server["listen_port"])
        self.lease_time = int(subnet["lease_time_seconds"])
        self.netmask = subnet["netmask"]
        self.gateway = subnet["gateway"]
        self.dns = list(subnet["dns_servers"])
        self.domain = subnet.get("domain_name", "")
        self.store = LeaseStore(
            subnet["pool_start"],
            subnet["pool_end"],
            config.get("reservations", {}),
        )
        self._sock: Optional[socket.socket] = None
        self._running = False

    def start(self, bind_host: str = "0.0.0.0") -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except OSError:
            pass
        self._sock.bind((bind_host, self.port))
        self._sock.settimeout(0.5)
        self._running = True
        mode = "LAB" if self.lab_mode else "STANDARD"
        LOG.info(
            "DHCP server listening on %s:%s (%s mode), pool %s-%s",
            bind_host,
            self.port,
            mode,
            self.config["subnet"]["pool_start"],
            self.config["subnet"]["pool_end"],
        )
        while self._running:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                self._handle(data, addr)
            except Exception:
                LOG.exception("Failed handling packet from %s", addr)

    def stop(self) -> None:
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def start_background(self, bind_host: str = "127.0.0.1") -> threading.Thread:
        thread = threading.Thread(target=self.start, kwargs={"bind_host": bind_host}, daemon=True)
        thread.start()
        # Wait briefly for bind
        time.sleep(0.1)
        return thread

    def _reply_addr(self, client_addr: Tuple[str, int], packet: DhcpPacket) -> Tuple[str, int]:
        if self.lab_mode:
            return client_addr
        # Broadcast replies are typical for Discover/Request before client has an IP
        return ("255.255.255.255", 68)

    def _handle(self, data: bytes, addr: Tuple[str, int]) -> None:
        packet = DhcpPacket.decode(data)
        msg = packet.message_type
        LOG.info(
            "<- %s from %s mac=%s xid=0x%08x",
            MSG_NAMES.get(msg or 0, msg),
            addr,
            packet.chaddr,
            packet.xid,
        )
        if msg == MSG_DISCOVER:
            self._send_offer(packet, addr)
        elif msg == MSG_REQUEST:
            self._send_ack_or_nak(packet, addr)

    def _send_offer(self, request: DhcpPacket, addr: Tuple[str, int]) -> None:
        preferred = parse_requested_ip(request)
        ip = self.store.allocate(request.chaddr, preferred)
        if not ip:
            LOG.warning("No addresses available for %s", request.chaddr)
            return
        reply = DhcpPacket(
            op=OP_BOOTREPLY,
            xid=request.xid,
            flags=request.flags,
            yiaddr=ip,
            siaddr=self.server_ip,
            giaddr=request.giaddr,
            chaddr=request.chaddr,
            options=build_options(
                MSG_OFFER,
                self.server_ip,
                self.lease_time,
                self.netmask,
                self.gateway,
                self.dns,
                self.domain,
            ),
        )
        self._send(reply, addr, request)

    def _send_ack_or_nak(self, request: DhcpPacket, addr: Tuple[str, int]) -> None:
        requested = parse_requested_ip(request) or (
            request.ciaddr if request.ciaddr != "0.0.0.0" else None
        )
        server_id = request.options.get(OPT_SERVER_ID)
        if server_id and bytes_to_ip(server_id) != self.server_ip:
            LOG.info("Ignoring REQUEST for other server %s", bytes_to_ip(server_id))
            return

        if not requested:
            self._send_nak(request, addr)
            return

        offered = self.store.allocate(request.chaddr, requested)
        if offered != requested or not self.store.commit(request.chaddr, requested, self.lease_time):
            self._send_nak(request, addr)
            return

        reply = DhcpPacket(
            op=OP_BOOTREPLY,
            xid=request.xid,
            flags=request.flags,
            yiaddr=requested,
            siaddr=self.server_ip,
            giaddr=request.giaddr,
            chaddr=request.chaddr,
            options=build_options(
                MSG_ACK,
                self.server_ip,
                self.lease_time,
                self.netmask,
                self.gateway,
                self.dns,
                self.domain,
            ),
        )
        self._send(reply, addr, request)
        LOG.info("Leased %s -> %s", request.chaddr, requested)

    def _send_nak(self, request: DhcpPacket, addr: Tuple[str, int]) -> None:
        reply = DhcpPacket(
            op=OP_BOOTREPLY,
            xid=request.xid,
            flags=request.flags,
            chaddr=request.chaddr,
            options={
                OPT_MESSAGE_TYPE: bytes([MSG_NAK]),
                OPT_SERVER_ID: ip_to_bytes(self.server_ip),
            },
        )
        self._send(reply, addr, request)
        LOG.info("NAK to %s", request.chaddr)

    def _send(self, reply: DhcpPacket, addr: Tuple[str, int], request: DhcpPacket) -> None:
        assert self._sock is not None
        dest = self._reply_addr(addr, request)
        payload = reply.encode()
        self._sock.sendto(payload, dest)
        LOG.info(
            "-> %s to %s yiaddr=%s",
            MSG_NAMES.get(reply.message_type or 0, reply.message_type),
            dest,
            reply.yiaddr,
        )


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab DHCP server")
    parser.add_argument(
        "--config",
        default=str(Path(__file__).parent / "config" / "dhcp.json"),
        help="Path to dhcp.json",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--standard", action="store_true", help="Use UDP/67 (needs admin)")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    config = load_config(Path(args.config))
    if args.standard:
        config["server"]["lab_mode"] = False

    server = DhcpServer(config)
    try:
        server.start(bind_host=args.host)
    except KeyboardInterrupt:
        LOG.info("Stopping...")
        server.stop()


if __name__ == "__main__":
    main()
