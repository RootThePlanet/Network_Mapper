"""Tests for nmap_plusplus.port_scanner."""

import socket
from unittest.mock import MagicMock, patch

import pytest

from nmap_plusplus.port_scanner import (
    COMMON_PORTS,
    grab_banner,
    scan_ports,
)
from nmap_plusplus.scanner import lookup_vendor


class TestScanPorts:
    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_open_port_included(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0   # 0 = open
        mock_socket_cls.return_value = mock_sock

        results = scan_ports("127.0.0.1", ports=[22])
        assert len(results) == 1
        assert results[0]["port"] == 22
        assert results[0]["state"] == "open"
        assert results[0]["service"] == "SSH"

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_closed_port_excluded(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 1   # non-zero = closed
        mock_socket_cls.return_value = mock_sock

        results = scan_ports("127.0.0.1", ports=[22])
        assert results == []

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_multiple_ports_mixed(self, mock_socket_cls):
        mock_sock = MagicMock()
        # 22=open, 80=closed
        mock_sock.connect_ex.side_effect = [0, 1]
        mock_socket_cls.return_value = mock_sock

        results = scan_ports("127.0.0.1", ports=[22, 80])
        open_ports = [r["port"] for r in results]
        assert 22 in open_ports
        assert 80 not in open_ports

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_service_unknown_for_nonstandard_port(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect_ex.return_value = 0
        mock_socket_cls.return_value = mock_sock

        results = scan_ports("127.0.0.1", ports=[12345])
        assert results[0]["service"] == "unknown"

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_exception_handled_gracefully(self, mock_socket_cls):
        mock_socket_cls.side_effect = Exception("no socket")
        # Should not raise
        results = scan_ports("127.0.0.1", ports=[22])
        assert results == []

    def test_default_ports_are_common_ports(self):
        with patch("nmap_plusplus.port_scanner.socket.socket") as mock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 1
            mock_cls.return_value = mock_sock
            scan_ports("127.0.0.1")
            assert mock_sock.connect_ex.call_count == len(COMMON_PORTS)


class TestLookupVendor:
    def test_known_oui_apple(self):
        assert lookup_vendor("AC:DE:48:00:11:22") == "Apple"

    def test_known_oui_cisco(self):
        assert lookup_vendor("00:00:0C:11:22:33") == "Cisco"

    def test_known_oui_raspberry_pi(self):
        assert lookup_vendor("B8:27:EB:00:00:01") == "Raspberry Pi"

    def test_known_oui_vmware(self):
        assert lookup_vendor("00:50:56:AA:BB:CC") == "VMware"

    def test_empty_mac(self):
        assert lookup_vendor("") == ""

    def test_unknown_oui(self):
        assert lookup_vendor("FF:FF:FF:00:00:00") == ""

    def test_dash_separator_normalised(self):
        assert lookup_vendor("AC-DE-48-00-11-22") == "Apple"


class TestGrabBanner:
    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_http_port_sends_head_request(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"
        mock_socket_cls.return_value = mock_sock

        result = grab_banner("127.0.0.1", 80)
        assert "HTTP" in result
        mock_sock.sendall.assert_called_once()

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_ssh_port_returns_banner(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"SSH-2.0-OpenSSH_8.0\r\n"
        mock_socket_cls.return_value = mock_sock

        result = grab_banner("127.0.0.1", 22)
        assert "SSH" in result

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_connection_failure_returns_empty(self, mock_socket_cls):
        mock_socket_cls.side_effect = Exception("refused")
        result = grab_banner("127.0.0.1", 22)
        assert result == ""

    @patch("nmap_plusplus.port_scanner.socket.socket")
    def test_banner_truncated_to_120(self, mock_socket_cls):
        mock_sock = MagicMock()
        long_line = b"A" * 200 + b"\n"
        mock_sock.recv.return_value = long_line
        mock_socket_cls.return_value = mock_sock

        result = grab_banner("127.0.0.1", 22)
        assert len(result) <= 120
