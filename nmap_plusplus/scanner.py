"""
Network scanner: discovers hosts via multicast, ARP, and ICMP ping.
Supports hop-count limiting to restrict how far discovery propagates.
"""

import ipaddress
import logging
import platform
import re
import shutil
import socket
import struct
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from typing import Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MAC OUI vendor table (first 3 octets of MAC address, uppercase, colon-sep)
# ---------------------------------------------------------------------------

OUI_TABLE: Dict[str, str] = {
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1C:42": "Parallels",
    "AC:DE:48": "Apple",
    "00:03:93": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:1B:63": "Apple",
    "00:1E:C2": "Apple",
    "00:23:12": "Apple",
    "00:25:BC": "Apple",
    "00:26:BB": "Apple",
    "3C:07:54": "Apple",
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:01:63": "Cisco",
    "00:01:96": "Cisco",
    "00:01:C7": "Cisco",
    "00:02:16": "Cisco",
    "00:0D:65": "Cisco",
    "00:14:A9": "Cisco",
    "00:17:5A": "Cisco",
    "00:1A:A1": "Cisco",
    "00:1B:2B": "Cisco",
    "00:1C:57": "Cisco",
    "00:21:A0": "Cisco",
    "00:22:0D": "Cisco",
    "00:23:BE": "Cisco",
    "00:24:13": "Cisco",
    "8C:8D:28": "Intel",
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0E:35": "Intel",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Samsung",
    "00:07:AB": "Samsung",
    "00:12:47": "Samsung",
    "00:15:99": "Samsung",
    "00:17:C9": "Samsung",
    "00:1A:8A": "Samsung",
    "F4:F5:DB": "Google",
    "54:60:09": "Google",
    "18:74:2E": "Amazon",
    "FC:65:DE": "Amazon",
    "A4:C0:E1": "Dell",
    "00:06:5B": "Dell",
    "00:08:74": "Dell",
    "00:0B:DB": "Dell",
    "00:0F:1F": "Dell",
    "00:11:43": "Dell",
    "00:12:3F": "Dell",
    "00:13:72": "Dell",
    "00:14:22": "Dell",
    "00:15:C5": "Dell",
    "00:16:F0": "HP",
    "00:17:08": "HP",
    "00:18:71": "HP",
    "00:19:BB": "HP",
    "00:1A:4B": "HP",
    "00:1B:78": "HP",
    "00:1C:C4": "HP",
    "00:1D:B3": "HP",
    "00:21:5A": "HP",
    "00:22:64": "HP",
    "04:7D:7B": "Lenovo",
    "00:09:2D": "Lenovo",
    "00:0B:AB": "Lenovo",
    "00:11:25": "Lenovo",
    "00:15:E9": "Lenovo",
    "00:1A:73": "Lenovo",
    "00:1B:B9": "Lenovo",
    "20:CF:30": "Netgear",
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "54:04:A6": "TP-Link",
    "50:C7:BF": "TP-Link",
    "00:1D:0F": "D-Link",
    "00:05:5D": "D-Link",
    "00:0F:3D": "D-Link",
    "00:11:95": "D-Link",
    "00:13:46": "D-Link",
    "00:15:E9": "D-Link",
    "00:17:9A": "D-Link",
    "00:19:5B": "D-Link",
    "00:1B:11": "D-Link",
    "00:1C:F0": "D-Link",
    "FC:EC:DA": "Ubiquiti",
    "00:27:22": "Ubiquiti",
    "04:18:D6": "Ubiquiti",
    "24:A4:3C": "Ubiquiti",
    "00:15:6D": "Ubiquiti",
    "04:92:26": "ASUS",
    "00:0E:A6": "ASUS",
    "00:11:2F": "ASUS",
    "00:13:D4": "ASUS",
    "00:15:F2": "ASUS",
    "00:17:31": "ASUS",
    "00:18:F3": "ASUS",
    "00:1A:92": "ASUS",
    "00:1D:60": "ASUS",
    "00:1E:8C": "ASUS",
    "00:1F:C6": "ASUS",
    "00:22:15": "ASUS",
    "00:23:54": "ASUS",
    "E0:CB:4E": "Huawei",
    "00:18:82": "Huawei",
    "00:19:70": "Huawei",
    "00:1E:10": "Huawei",
    "00:25:9E": "Huawei",
    "00:46:4B": "Aruba",
    "00:0B:86": "Aruba",
    "24:DE:C6": "Aruba",
    "94:B4:0F": "Microsoft",
    "00:03:FF": "Microsoft",
    "00:12:5A": "Microsoft",
    "00:15:5D": "Microsoft",
    "00:17:FA": "Microsoft",
    "00:50:F2": "Microsoft",
    "2C:6E:85": "Juniper",
    "00:10:DB": "Juniper",
    "00:12:1E": "Juniper",
    "00:14:F6": "Juniper",
    "00:17:CB": "Juniper",
    "00:19:E2": "Juniper",
    "00:1F:12": "Juniper",
    "00:21:59": "Juniper",
    "00:23:9C": "Juniper",
    "00:24:DC": "Juniper",
    "00:26:88": "Juniper",
}


def lookup_vendor(mac: str) -> str:
    """Return vendor name for a MAC address using OUI_TABLE, or empty string."""
    if not mac:
        return ""
    # Normalise to upper-case with colons
    normalised = mac.upper().replace("-", ":").replace(".", ":")
    parts = normalised.split(":")
    if len(parts) < 3:
        return ""
    oui = ":".join(parts[:3])
    return OUI_TABLE.get(oui, "")


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
                    "vendor": "",
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
            "vendor": lookup_vendor(mac),
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
            "vendor": lookup_vendor(arp_table.get(ip_str, "")),
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
    def scan(self, network: Optional[str] = None, phase_callback: Optional[Callable[[str], None]] = None) -> Dict:
        """
        Run a full scan.  Returns ``{"hosts": {...}, "links": [...]}``.
        *phase_callback* is called with phase name strings as discovery progresses.
        """
        self.scanning = True
        self.hosts = {}

        def _phase(name: str) -> None:
            if phase_callback:
                try:
                    phase_callback(name)
                except Exception as exc:
                    logger.error("Phase callback error: %s", exc)

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
            _phase("Multicast discovery")
            multicast_discover(timeout=3.0, hop_limit=self.hop_limit, callback=_on_found)

            # ARP + ICMP sweep across target networks
            _phase("ARP lookup")
            targets = [network] if network else [i["network"] for i in interfaces]
            for net in targets:
                scan_subnet(net, callback=_on_found)

            _phase("ICMP sweep")

            # mDNS discovery (optional, graceful fallback)
            _phase("mDNS discovery")
            try:
                for host in mdns_discover(timeout=2.0, callback=_on_found):
                    _on_found(host)
            except Exception as exc:
                logger.debug("mDNS discovery failed: %s", exc)

            # nmap integration (only when explicit network is given)
            if network:
                _phase("nmap scan")
                try:
                    for host in nmap_scan(network, hop_limit=self.hop_limit):
                        _on_found(host)
                except Exception as exc:
                    logger.debug("nmap scan failed: %s", exc)

            # IPv6 link-local discovery
            _phase("IPv6 discovery")
            try:
                for host in scan_ipv6_link_local(callback=_on_found):
                    _on_found(host)
            except Exception as exc:
                logger.debug("IPv6 discovery failed: %s", exc)

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


# ---------------------------------------------------------------------------
# mDNS / Bonjour discovery
# ---------------------------------------------------------------------------

def mdns_discover(
    timeout: float = 3.0,
    callback: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Discover hosts via mDNS/Bonjour using the zeroconf library.
    Returns [] gracefully when zeroconf is not installed.
    """
    try:
        from zeroconf import ServiceBrowser, Zeroconf  # type: ignore
    except ImportError:
        logger.debug("zeroconf not installed; skipping mDNS discovery")
        return []

    discovered: List[Dict] = []
    seen: set = set()
    lock = threading.Lock()

    class _Listener:
        def add_service(self, zc, service_type, name):  # type: ignore
            try:
                info = zc.get_service_info(service_type, name)
                if not info:
                    return
                addresses = info.parsed_addresses()
                for addr in addresses:
                    with lock:
                        if addr in seen:
                            continue
                        seen.add(addr)
                    host = {
                        "ip": addr,
                        "hostname": info.server or addr,
                        "mac": "",
                        "method": "mdns",
                    }
                    with lock:
                        discovered.append(host)
                    if callback:
                        callback(host)
            except Exception as exc:
                logger.debug("mDNS service info error: %s", exc)

        def remove_service(self, zc, service_type, name):
            pass

        def update_service(self, zc, service_type, name):
            pass

    zc = Zeroconf()
    listener = _Listener()
    services = ["_http._tcp.local.", "_smb._tcp.local.", "_ssh._tcp.local."]
    browsers = [ServiceBrowser(zc, svc, listener) for svc in services]
    time.sleep(timeout)
    zc.close()
    return discovered


# ---------------------------------------------------------------------------
# nmap integration
# ---------------------------------------------------------------------------

def nmap_scan(
    network: str,
    hop_limit: int = 4,
) -> List[Dict]:
    """
    Run nmap ping scan (-sn) against *network* and parse XML output.
    Returns [] when nmap is not found or the scan fails.
    """
    if not shutil.which("nmap"):
        logger.debug("nmap not found on PATH; skipping nmap scan")
        return []

    cmd = ["nmap", "-sn", "--max-ttl", str(hop_limit), network, "-oX", "-"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.warning("nmap exited with code %d", result.returncode)
            return []
    except Exception as exc:
        logger.warning("nmap execution failed: %s", exc)
        return []

    hosts: List[Dict] = []
    try:
        root = ET.fromstring(result.stdout)
        for host_elem in root.findall("host"):
            status = host_elem.find("status")
            if status is None or status.get("state") != "up":
                continue
            ip = ""
            hostname = ""
            mac = ""
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") == "ipv4":
                    ip = addr.get("addr", "")
                elif addr.get("addrtype") == "mac":
                    mac = addr.get("addr", "")
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")
            if ip:
                hosts.append({
                    "ip": ip,
                    "hostname": hostname or ip,
                    "mac": mac,
                    "vendor": lookup_vendor(mac),
                    "method": "nmap",
                })
    except ET.ParseError as exc:
        logger.warning("nmap XML parse error: %s", exc)

    return hosts


# ---------------------------------------------------------------------------
# IPv6 helpers
# ---------------------------------------------------------------------------

def ping6_host(ip: str, timeout: float = 1.0) -> bool:
    """Return True when *ip* responds to a ping6 within *timeout* seconds."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-6", "-n", "1", ip]
    else:
        cmd = ["ping6", "-c", "1", "-W", str(max(1, int(timeout))), ip]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def scan_ipv6_link_local(
    callback: Optional[Callable[[Dict], None]] = None,
) -> List[Dict]:
    """
    Discover IPv6 link-local neighbours.  Gracefully returns [] on failure.
    """
    discovered: List[Dict] = []
    try:
        # Try multicast ff02::1 ping to elicit NDP responses
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-6", "-n", "1", "ff02::1"]
        else:
            cmd = ["ping6", "-c", "1", "ff02::1"]

        subprocess.run(cmd, capture_output=True, timeout=5)

        # Read IPv6 neighbours from the OS neighbour cache
        if system == "windows":
            result = subprocess.run(
                ["netsh", "interface", "ipv6", "show", "neighbors"],
                capture_output=True, text=True, timeout=5,
            )
        else:
            result = subprocess.run(
                ["ip", "-6", "neigh", "show"],
                capture_output=True, text=True, timeout=5,
            )

        seen: set = set()
        for line in result.stdout.splitlines():
            # Extract fe80:: addresses
            m = re.search(r"(fe80:[0-9a-fA-F:%]+)", line)
            if not m:
                continue
            ip = m.group(1).split("%")[0]
            if ip in seen:
                continue
            seen.add(ip)
            host: Dict = {
                "ip": ip,
                "hostname": ip,
                "mac": "",
                "method": "ipv6_link_local",
            }
            discovered.append(host)
            if callback:
                try:
                    callback(host)
                except Exception:
                    pass
    except Exception as exc:
        logger.debug("IPv6 link-local discovery failed: %s", exc)
    return discovered
