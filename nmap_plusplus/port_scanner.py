"""
Port scanning and service/banner detection.
"""

import socket
import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

COMMON_PORTS: Dict[int, str] = {
    22:   "SSH",
    23:   "Telnet",
    25:   "SMTP",
    53:   "DNS",
    80:   "HTTP",
    110:  "POP3",
    143:  "IMAP",
    443:  "HTTPS",
    445:  "SMB",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9100: "Printer",
}

HTTP_PORTS = {80, 443, 8080, 8443}


def scan_ports(
    ip: str,
    ports: Optional[List[int]] = None,
    timeout: float = 0.5,
) -> List[Dict]:
    """
    Scan TCP ports on *ip*.  Returns a list of dicts for open ports only.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    results: List[Dict] = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            ret = sock.connect_ex((ip, port))
            sock.close()
            state = "open" if ret == 0 else "closed"
            if state == "open":
                results.append({
                    "port": port,
                    "service": COMMON_PORTS.get(port, "unknown"),
                    "state": state,
                })
        except Exception as exc:
            logger.debug("Port scan error %s:%d – %s", ip, port, exc)
    return results


def grab_banner(ip: str, port: int, timeout: float = 1.0) -> str:
    """
    Try to grab a banner from an open TCP port.
    For HTTP ports, send a HEAD request and return the first response line.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))

        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")

        data = sock.recv(256)
        sock.close()

        text = data.decode("utf-8", errors="replace").strip()
        # Return only the first line
        return text.split("\n")[0][:120]
    except Exception:
        return ""
