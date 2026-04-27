"""
Network scanner: discovers hosts via multicast, ARP, and ICMP ping.
Supports hop-count limiting to restrict how far discovery propagates.
"""

import ipaddress
import logging
import platform
import re
import socket
import struct
import subprocess
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# SSDP multicast address and port (works across routers with correct TTL)
MULTICAST_GROUP = "239.255.255.250"
MULTICAST_PORT = 1900
SSDP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n\r\n"
).encode()


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def get_local_interfaces() -> List[Dict]:
    """Return local network interfaces with ip/netmask/network information."""
    interfaces: List[Dict] = []
    try:
        try:
            import netifaces  # type: ignore
        except ImportError:
            import netifaces2 as netifaces  # type: ignore

        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip = addr.get("addr", "")
                netmask = addr.get("netmask", "")
                if not ip or ip.startswith("127.") or not netmask:
                    continue
                try:
                    network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                    interfaces.append(
                        {
                            "interface": iface,
                            "ip": ip,
                            "netmask": netmask,
                            "network": str(network),
                        }
                    )
                except ValueError:
                    pass
    except ImportError:
        # Fallback: derive network from hostname
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            if not local_ip.startswith("127."):
                network = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
                interfaces.append(
                    {
                        "interface": "default",
                        "ip": local_ip,
                        "netmask": "255.255.255.0",
                        "network": str(network),
                    }
                )
        except OSError:
            pass
    return interfaces


def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """Return True when *ip* responds to a ping within *timeout* seconds."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_hostname(ip: str) -> str:
    """Reverse-DNS lookup; returns *ip* on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip


def get_arp_table() -> Dict[str, str]:
    """Return a dict mapping IP address → MAC address from the OS ARP table."""
    table: Dict[str, str] = {}
    try:
        if platform.system().lower() == "windows":
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([\w-]+)", line)
                if m:
                    table[m.group(1)] = m.group(2).replace("-", ":")
        else:
            result = subprocess.run(
                ["arp", "-n"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+\w+\s+([\w:]+)", line)
                if m and m.group(2) not in ("00:00:00:00:00:00", "<incomplete>"):
                    table[m.group(1)] = m.group(2)
    except Exception as exc:
        logger.warning("ARP table unavailable: %s", exc)
    return table


# ---------------------------------------------------------------------------
# Multicast discovery
# ---------------------------------------------------------------------------

def multicast_discover(
    timeout: float = 5.0,
    hop_limit: int = 4,
    callback: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Broadcast an SSDP M-SEARCH message to the multicast group and collect
    unicast responses.

    *hop_limit* is set as the IP_MULTICAST_TTL so the packet may cross
    that many router hops before being discarded.
    """
    discovered: List[Dict] = []
    seen: set = set()
    lock = threading.Lock()

    def _receive(sock: socket.socket, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                sock.settimeout(0.5)
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                with lock:
                    if ip in seen:
                        continue
                    seen.add(ip)
                host = {
                    "ip": ip,
                    "hostname": resolve_hostname(ip),
                    "mac": "",
                    "method": "multicast",
                    "response": data.decode("utf-8", errors="replace")[:200],
                }
                with lock:
                    discovered.append(host)
                if callback:
                    callback(host)
            except socket.timeout:
                continue
            except OSError:
                break

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", hop_limit)
        )

        stop_event = threading.Event()
        t = threading.Thread(target=_receive, args=(sock, stop_event), daemon=True)
        t.start()

        sock.sendto(SSDP_DISCOVER, (MULTICAST_GROUP, MULTICAST_PORT))
        logger.info("Multicast discovery sent to %s:%s", MULTICAST_GROUP, MULTICAST_PORT)

        time.sleep(timeout)
        stop_event.set()
        t.join(timeout=2)
        sock.close()
    except PermissionError:
        logger.warning("Multicast discovery needs elevated privileges on this system.")
    except OSError as exc:
        logger.error("Multicast error: %s", exc)

    return discovered


# ---------------------------------------------------------------------------
# ICMP ping sweep
# ---------------------------------------------------------------------------

def scan_subnet(
    network: str,
    max_hosts: int = 254,
    timeout: float = 1.0,
    callback: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Discover hosts in *network* using two complementary methods:

    1. **ARP table** – any host that appears in the OS ARP cache and falls
       within *network* is reported immediately, regardless of whether it
       responds to ping.  This catches devices that block ICMP (smartphones,
       firewalled PCs, IoT devices, etc.).
    2. **ICMP ping sweep** – all host addresses in *network* (up to
       *max_hosts*) are probed concurrently via a thread pool.  Hosts already
       found through ARP are skipped so they are not reported twice.
    """
    discovered: List[Dict] = []
    seen: set = set()
    lock = threading.Lock()

    try:
        net_obj = ipaddress.IPv4Network(network, strict=False)
        hosts = list(net_obj.hosts())[:max_hosts]
    except ValueError as exc:
        logger.error("Invalid network %r: %s", network, exc)
        return []

    arp_table = get_arp_table()

    # --- Pass 1: report hosts already in the ARP cache -------------------
    for ip_str, mac in arp_table.items():
        try:
            if ipaddress.IPv4Address(ip_str) not in net_obj:
                continue
        except ValueError:
            continue
        host = {
            "ip": ip_str,
            "hostname": resolve_hostname(ip_str),
            "mac": mac,
            "method": "arp",
        }
        seen.add(ip_str)
        discovered.append(host)
        if callback:
            callback(host)

    # --- Pass 2: ICMP ping sweep for hosts not yet found -----------------
    semaphore = threading.Semaphore(50)

    def _probe(ip_addr: ipaddress.IPv4Address) -> None:
        ip_str = str(ip_addr)
        # Fast path: skip without acquiring the lock (re-checked under lock below).
        if ip_str in seen:
            return
        with semaphore:
            if not ping_host(ip_str, timeout):
                return
        host = {
            "ip": ip_str,
            "hostname": resolve_hostname(ip_str),
            "mac": arp_table.get(ip_str, ""),
            "method": "icmp",
        }
        with lock:
            if ip_str in seen:
                return
            seen.add(ip_str)
            discovered.append(host)
        if callback:
            callback(host)

    threads = [threading.Thread(target=_probe, args=(h,), daemon=True) for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 3)

    return discovered


# ---------------------------------------------------------------------------
# High-level scanner
# ---------------------------------------------------------------------------

class NetworkScanner:
    """
    Orchestrates multicast + ICMP discovery and enforces hop-count limits.
    """

    def __init__(self, hop_limit: int = 4) -> None:
        self.hop_limit = hop_limit
        self.hosts: Dict[str, Dict] = {}
        self.scanning = False
        self._callbacks: List[Callable] = []
        self._hosts_lock = threading.Lock()

    # ------------------------------------------------------------------
    def add_callback(self, cb: Callable) -> None:
        self._callbacks.append(cb)

    def _emit(self, event: str, data: Dict) -> None:
        for cb in self._callbacks:
            try:
                cb(event, data)
            except Exception as exc:
                logger.error("Callback error: %s", exc)

    # ------------------------------------------------------------------
    def _hop_distance(self, target_ip: str, local_ip: str) -> int:
        """
        Estimate hop count: 0 = local machine, 1 = same subnet, 2+ = routed.
        """
        try:
            tgt = ipaddress.IPv4Address(target_ip)
            for prefix in [24, 16, 8]:
                if tgt in ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False):
                    return 1
            return 2
        except ValueError:
            return 1

    # ------------------------------------------------------------------
    def scan(self, network: Optional[str] = None) -> Dict:
        """
        Run a full scan.  Returns ``{"hosts": {...}, "links": [...]}``.
        """
        self.scanning = True
        self.hosts = {}

        try:
            interfaces = get_local_interfaces()
            local_ip: str = ""

            # Register local interfaces
            for iface in interfaces:
                ip = iface["ip"]
                if not local_ip:
                    local_ip = ip
                self.hosts[ip] = {
                    "ip": ip,
                    "hostname": socket.gethostname(),
                    "mac": "",
                    "hop": 0,
                    "node_type": "local",
                }
                self._emit("host_found", self.hosts[ip])

            def _on_found(host: Dict) -> None:
                ip = host["ip"]
                hop = self._hop_distance(ip, local_ip) if local_ip else 1
                if hop > self.hop_limit:
                    return
                with self._hosts_lock:
                    if ip in self.hosts:
                        return
                    self.hosts[ip] = {**host, "hop": hop, "node_type": "remote"}
                self._emit("host_found", self.hosts[ip])

            # Multicast discovery (crosses routers up to hop_limit)
            multicast_discover(timeout=3.0, hop_limit=self.hop_limit, callback=_on_found)

            # ICMP sweep across target networks
            targets = [network] if network else [i["network"] for i in interfaces]
            for net in targets:
                scan_subnet(net, callback=_on_found)

            links = self._build_links(local_ip)
        finally:
            self.scanning = False

        return {"hosts": self.hosts, "links": links}

    # ------------------------------------------------------------------
    def _build_links(self, local_ip: str) -> List[Tuple[str, str]]:
        """Connect each discovered host back to the local machine or a gateway."""
        links: List[Tuple[str, str]] = []
        for ip, host in self.hosts.items():
            if ip == local_ip:
                continue
            links.append((local_ip, ip))
        return links


# ---------------------------------------------------------------------------
# Demo / mock data generator (used when a real scan is not appropriate)
# ---------------------------------------------------------------------------

def generate_demo_topology() -> Dict:
    """Return a realistic demo network topology for UI development/testing."""
    local = "192.168.1.100"
    gateway = "192.168.1.1"

    hosts = {
        local: {
            "ip": local,
            "hostname": "my-laptop",
            "mac": "aa:bb:cc:dd:ee:ff",
            "hop": 0,
            "node_type": "local",
        },
        gateway: {
            "ip": gateway,
            "hostname": "gateway.local",
            "mac": "00:11:22:33:44:55",
            "hop": 1,
            "node_type": "gateway",
        },
        "192.168.1.101": {
            "ip": "192.168.1.101",
            "hostname": "desktop-pc",
            "mac": "aa:bb:cc:00:11:22",
            "hop": 1,
            "node_type": "remote",
        },
        "192.168.1.102": {
            "ip": "192.168.1.102",
            "hostname": "macbook-pro",
            "mac": "aa:bb:cc:00:11:23",
            "hop": 1,
            "node_type": "remote",
        },
        "192.168.1.103": {
            "ip": "192.168.1.103",
            "hostname": "iphone-14",
            "mac": "aa:bb:cc:00:11:24",
            "hop": 1,
            "node_type": "remote",
        },
        "192.168.1.104": {
            "ip": "192.168.1.104",
            "hostname": "smart-tv",
            "mac": "aa:bb:cc:00:11:25",
            "hop": 1,
            "node_type": "remote",
        },
        "192.168.1.105": {
            "ip": "192.168.1.105",
            "hostname": "network-printer",
            "mac": "aa:bb:cc:00:11:26",
            "hop": 1,
            "node_type": "remote",
        },
        "192.168.1.106": {
            "ip": "192.168.1.106",
            "hostname": "raspberry-pi",
            "mac": "aa:bb:cc:00:11:27",
            "hop": 1,
            "node_type": "remote",
        },
        "10.0.0.10": {
            "ip": "10.0.0.10",
            "hostname": "web-server",
            "mac": "",
            "hop": 2,
            "node_type": "remote",
        },
        "10.0.0.20": {
            "ip": "10.0.0.20",
            "hostname": "db-server",
            "mac": "",
            "hop": 2,
            "node_type": "remote",
        },
        "10.0.0.30": {
            "ip": "10.0.0.30",
            "hostname": "mail-server",
            "mac": "",
            "hop": 2,
            "node_type": "remote",
        },
        "10.0.1.10": {
            "ip": "10.0.1.10",
            "hostname": "app-server-1",
            "mac": "",
            "hop": 3,
            "node_type": "remote",
        },
        "10.0.1.11": {
            "ip": "10.0.1.11",
            "hostname": "app-server-2",
            "mac": "",
            "hop": 3,
            "node_type": "remote",
        },
    }

    links = [
        # local → LAN
        (local, gateway),
        (local, "192.168.1.101"),
        (local, "192.168.1.102"),
        (local, "192.168.1.103"),
        (local, "192.168.1.104"),
        (local, "192.168.1.105"),
        (local, "192.168.1.106"),
        # gateway → remote servers (hop 2)
        (gateway, "10.0.0.10"),
        (gateway, "10.0.0.20"),
        (gateway, "10.0.0.30"),
        # web-server → app servers (hop 3)
        ("10.0.0.10", "10.0.1.10"),
        ("10.0.0.10", "10.0.1.11"),
    ]

    return {"hosts": hosts, "links": links}
