"""Tests for network_mapper.scanner."""

import ipaddress
from unittest.mock import MagicMock, patch

import pytest

from network_mapper.scanner import (
    generate_demo_topology,
    get_arp_table,
    get_local_interfaces,
    NetworkScanner,
    ping_host,
    resolve_hostname,
)


# ---------------------------------------------------------------------------
# get_local_interfaces
# ---------------------------------------------------------------------------

class TestGetLocalInterfaces:
    def test_returns_list(self):
        result = get_local_interfaces()
        assert isinstance(result, list)

    @patch("network_mapper.scanner.netifaces", create=True)
    def test_uses_netifaces_when_available(self, mock_netifaces):
        mock_netifaces.interfaces.return_value = ["eth0"]
        mock_netifaces.AF_INET = 2
        mock_netifaces.ifaddresses.return_value = {
            2: [{"addr": "192.168.1.50", "netmask": "255.255.255.0"}]
        }
        with patch.dict("sys.modules", {"netifaces": mock_netifaces}):
            result = get_local_interfaces()
        assert any(i["ip"] == "192.168.1.50" for i in result)

    def test_skips_loopback(self):
        result = get_local_interfaces()
        for iface in result:
            assert not iface["ip"].startswith("127.")


# ---------------------------------------------------------------------------
# ping_host
# ---------------------------------------------------------------------------

class TestPingHost:
    @patch("network_mapper.scanner.subprocess.run")
    def test_returns_true_on_zero_returncode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        assert ping_host("192.168.1.1") is True

    @patch("network_mapper.scanner.subprocess.run")
    def test_returns_false_on_nonzero_returncode(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        assert ping_host("192.168.1.2") is False

    @patch("network_mapper.scanner.subprocess.run", side_effect=Exception("timeout"))
    def test_returns_false_on_exception(self, _mock_run):
        assert ping_host("192.168.1.3") is False


# ---------------------------------------------------------------------------
# resolve_hostname
# ---------------------------------------------------------------------------

class TestResolveHostname:
    @patch("network_mapper.scanner.socket.gethostbyaddr", return_value=("myhost", [], []))
    def test_returns_hostname(self, _mock):
        assert resolve_hostname("192.168.1.1") == "myhost"

    @patch("network_mapper.scanner.socket.gethostbyaddr", side_effect=OSError)
    def test_returns_ip_on_failure(self, _mock):
        assert resolve_hostname("10.0.0.1") == "10.0.0.1"


# ---------------------------------------------------------------------------
# NetworkScanner
# ---------------------------------------------------------------------------

class TestNetworkScanner:
    def test_default_hop_limit(self):
        s = NetworkScanner()
        assert s.hop_limit == 4

    def test_custom_hop_limit(self):
        s = NetworkScanner(hop_limit=2)
        assert s.hop_limit == 2

    def test_initial_state(self):
        s = NetworkScanner()
        assert s.hosts == {}
        assert s.scanning is False

    def test_hop_distance_same_24_subnet(self):
        s = NetworkScanner()
        assert s._hop_distance("192.168.1.5", "192.168.1.100") == 1

    def test_hop_distance_different_subnet(self):
        s = NetworkScanner()
        assert s._hop_distance("10.0.0.1", "192.168.1.100") == 2

    def test_hop_distance_invalid_ip(self):
        s = NetworkScanner()
        # Should not raise; returns 1 as fallback
        result = s._hop_distance("not-an-ip", "192.168.1.1")
        assert result == 1

    def test_add_callback(self):
        s = NetworkScanner()
        cb = MagicMock()
        s.add_callback(cb)
        s._emit("host_found", {"ip": "1.2.3.4"})
        cb.assert_called_once_with("host_found", {"ip": "1.2.3.4"})

    def test_emit_handles_callback_exception(self):
        s = NetworkScanner()
        bad_cb = MagicMock(side_effect=RuntimeError("oops"))
        s.add_callback(bad_cb)
        # Should not propagate the exception
        s._emit("host_found", {})

    @patch("network_mapper.scanner.get_local_interfaces")
    @patch("network_mapper.scanner.multicast_discover", return_value=[])
    @patch("network_mapper.scanner.scan_subnet", return_value=[])
    @patch("network_mapper.scanner.socket.gethostname", return_value="test-host")
    def test_scan_adds_local_interface(
        self, _hn, _sub, _mc, mock_ifaces
    ):
        mock_ifaces.return_value = [
            {"ip": "192.168.1.1", "network": "192.168.1.0/24", "interface": "eth0"}
        ]
        s = NetworkScanner()
        result = s.scan()
        assert "192.168.1.1" in result["hosts"]
        assert result["hosts"]["192.168.1.1"]["hop"] == 0

    @patch("network_mapper.scanner.get_local_interfaces")
    @patch("network_mapper.scanner.multicast_discover", return_value=[])
    @patch("network_mapper.scanner.scan_subnet")
    @patch("network_mapper.scanner.socket.gethostname", return_value="test-host")
    def test_hop_limit_filters_far_hosts(
        self, _hn, mock_sub, _mc, mock_ifaces
    ):
        mock_ifaces.return_value = [
            {"ip": "10.0.0.1", "network": "10.0.0.0/24", "interface": "eth0"}
        ]

        # Simulate a host that appears 2 hops away (different subnet from local)
        far_host = {
            "ip": "172.16.0.5",
            "hostname": "far-host",
            "mac": "",
            "method": "icmp",
        }

        def fake_scan(net, **kwargs):
            cb = kwargs.get("callback")
            if cb:
                cb(far_host)
            return [far_host]

        mock_sub.side_effect = fake_scan

        s = NetworkScanner(hop_limit=1)
        result = s.scan()
        # 172.16.0.5 is 2 hops from 10.0.0.1 and hop_limit=1 → excluded
        assert "172.16.0.5" not in result["hosts"]

    def test_build_links_connects_to_local(self):
        s = NetworkScanner()
        s.hosts = {
            "192.168.1.1": {"hop": 0, "node_type": "local"},
            "192.168.1.2": {"hop": 1, "node_type": "remote"},
            "192.168.1.3": {"hop": 1, "node_type": "remote"},
        }
        links = s._build_links("192.168.1.1")
        link_set = set(links)
        assert ("192.168.1.1", "192.168.1.2") in link_set
        assert ("192.168.1.1", "192.168.1.3") in link_set
        assert ("192.168.1.1", "192.168.1.1") not in link_set


# ---------------------------------------------------------------------------
# generate_demo_topology
# ---------------------------------------------------------------------------

class TestGenerateDemoTopology:
    def test_returns_hosts_and_links(self):
        data = generate_demo_topology()
        assert "hosts" in data
        assert "links" in data

    def test_local_host_has_hop_zero(self):
        data = generate_demo_topology()
        local = next(
            (h for h in data["hosts"].values() if h["node_type"] == "local"), None
        )
        assert local is not None
        assert local["hop"] == 0

    def test_links_reference_valid_hosts(self):
        data = generate_demo_topology()
        host_ips = set(data["hosts"].keys())
        for a, b in data["links"]:
            assert a in host_ips, f"Link source {a} not in hosts"
            assert b in host_ips, f"Link target {b} not in hosts"

    def test_contains_multiple_hop_levels(self):
        data = generate_demo_topology()
        hops = {h["hop"] for h in data["hosts"].values()}
        assert len(hops) > 1, "Demo should contain hosts at different hop levels"

    def test_hop3_hosts_present(self):
        data = generate_demo_topology()
        assert any(h["hop"] == 3 for h in data["hosts"].values())
