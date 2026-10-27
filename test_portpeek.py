"""Tests for portpeek CLI tool."""

import io
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import portpeek


class TestAddressDecoding(unittest.TestCase):
    """Test hex address parsing for IPv4 and IPv6."""

    def test_decode_ipv4_hex(self):
        # 0100007F -> 127.0.0.1
        self.assertEqual(portpeek.decode_ipv4_hex("0100007F"), "127.0.0.1")
        # 00000000 -> 0.0.0.0
        self.assertEqual(portpeek.decode_ipv4_hex("00000000"), "0.0.0.0")
        # 0101A8C0 -> 192.168.1.1
        self.assertEqual(portpeek.decode_ipv4_hex("0101A8C0"), "192.168.1.1")

    def test_decode_ipv6_hex(self):
        # 00000000000000000000000000000000 -> ::
        self.assertEqual(
            portpeek.decode_ipv6_hex("00000000000000000000000000000000"), "::"
        )
        # 00000000000000000000000001000000 -> ::1
        self.assertEqual(
            portpeek.decode_ipv6_hex("00000000000000000000000001000000"), "::1"
        )

    def test_decode_invalid_hex(self):
        # Should gracefully return original string if invalid
        self.assertEqual(portpeek.decode_ipv4_hex("INVALID"), "INVALID")
        self.assertEqual(portpeek.decode_ipv6_hex("INVALID"), "INVALID")


class TestServiceResolution(unittest.TestCase):
    """Test port to service name resolution."""

    def test_known_services(self):
        self.assertEqual(portpeek.resolve_service_name(80, "tcp"), "http")
        self.assertEqual(portpeek.resolve_service_name(22, "tcp"), "ssh")

    def test_unknown_service(self):
        self.assertEqual(portpeek.resolve_service_name(64999, "tcp"), "unknown")


class TestProcParsing(unittest.TestCase):
    """Test parsing logic for /proc/net/tcp and /proc/net/tcp6."""

    SAMPLE_TCP_CONTENT = """  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff8baf83491280 100 0 0 10 0
   1: 00000000:0016 00000000:0000 01 00000000:00000000 00:00000000 00000000     0        0 54321 1 ffff8baf83491280 100 0 0 10 0
"""

    SAMPLE_TCP6_CONTENT = """  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 99999 1 ffff8baf8700da00 100 0 0 10 0
"""

    def test_parse_tcp_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(self.SAMPLE_TCP_CONTENT)
            tf_path = tf.name

        try:
            entries = portpeek.parse_proc_net_tcp_file(tf_path, is_ipv6=False)
            # Only line 0 has st=0A (LISTEN). Line 1 has st=01 (ESTABLISHED).
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry.proto, "tcp")
            self.assertEqual(entry.ip, "127.0.0.1")
            self.assertEqual(entry.port, 80)
            self.assertEqual(entry.service, "http")
            self.assertEqual(entry.inode, "12345")
        finally:
            os.remove(tf_path)

    def test_parse_tcp6_file(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf:
            tf.write(self.SAMPLE_TCP6_CONTENT)
            tf_path = tf.name

        try:
            entries = portpeek.parse_proc_net_tcp_file(tf_path, is_ipv6=True)
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry.proto, "tcp6")
            self.assertEqual(entry.ip, "::1")
            self.assertEqual(entry.port, 8080)  # 0x1F90 = 8080
            self.assertEqual(entry.inode, "99999")
        finally:
            os.remove(tf_path)

    def test_parse_nonexistent_file(self):
        entries = portpeek.parse_proc_net_tcp_file("/path/does/not/exist")
        self.assertEqual(entries, [])

    def test_get_listening_ports(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tf_v4:
            tf_v4.write(self.SAMPLE_TCP_CONTENT)
            tf_v4_path = tf_v4.name

        with tempfile.NamedTemporaryFile("w", delete=False) as tf_v6:
            tf_v6.write(self.SAMPLE_TCP6_CONTENT)
            tf_v6_path = tf_v6.name

        try:
            ports = portpeek.get_listening_ports(tcp_path=tf_v4_path, tcp6_path=tf_v6_path)
            self.assertEqual(len(ports), 2)
            self.assertEqual(ports[0].port, 80)
            self.assertEqual(ports[1].port, 8080)
        finally:
            os.remove(tf_v4_path)
            os.remove(tf_v6_path)


class TestPortRangeParsing(unittest.TestCase):
    """Test parsing of port ranges and single ports."""

    def test_valid_ranges(self):
        self.assertEqual(portpeek.parse_port_range("8000-8010"), (8000, 8010))
        self.assertEqual(portpeek.parse_port_range("8080"), (8080, 8080))
        self.assertEqual(portpeek.parse_port_range(" 22 - 25 "), (22, 25))

    def test_invalid_ranges(self):
        with self.assertRaises(ValueError):
            portpeek.parse_port_range("8010-8000")
        with self.assertRaises(ValueError):
            portpeek.parse_port_range("0-100")
        with self.assertRaises(ValueError):
            portpeek.parse_port_range("70000")
        with self.assertRaises(ValueError):
            portpeek.parse_port_range("abc-def")


class TestCheckAndScan(unittest.TestCase):
    """Test port checking and scanning logic with mocked sockets."""

    @patch("socket.socket")
    def test_check_port_in_use_when_connect_succeeds(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        # connect_ex returns 0 when port is listening/in use
        mock_sock.connect_ex.return_value = 0

        self.assertTrue(portpeek.check_port_in_use(80))

    @patch("socket.socket")
    def test_check_port_free_when_bind_succeeds(self, mock_socket_class):
        mock_sock = MagicMock()
        mock_socket_class.return_value.__enter__.return_value = mock_sock
        # connect_ex returns errno (e.g. 111 ECONNREFUSED)
        mock_sock.connect_ex.return_value = 111
        # bind succeeds without throwing
        mock_sock.bind.return_value = None

        self.assertFalse(portpeek.check_port_in_use(9999))

    @patch("portpeek.check_port_in_use")
    def test_scan_port_range(self, mock_check):
        mock_check.side_effect = lambda port, **kwargs: (port == 8001)
        results = portpeek.scan_port_range(8000, 8002)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0][0], 8000)
        self.assertFalse(results[0][1])
        self.assertEqual(results[1][0], 8001)
        self.assertTrue(results[1][1])
        self.assertEqual(results[2][0], 8002)
        self.assertFalse(results[2][1])


class TestCLIExecution(unittest.TestCase):
    """Test top-level CLI execution and argument parsing."""

    def test_main_no_args_shows_help(self):
        f = io.StringIO()
        with patch("sys.stdout", f):
            code = portpeek.main([])
            self.assertEqual(code, 1)

    @patch("portpeek.get_listening_ports")
    def test_cmd_list_output(self, mock_get):
        mock_get.return_value = [
            portpeek.ListeningPort("tcp", "0.0.0.0", 80, "http", "1234")
        ]
        f = io.StringIO()
        with patch("sys.stdout", f):
            code = portpeek.main(["list"])
            self.assertEqual(code, 0)
        output = f.getvalue()
        self.assertIn("http", output)
        self.assertIn("80", output)

    @patch("portpeek.check_port_in_use")
    def test_cmd_check_output(self, mock_check):
        mock_check.return_value = True
        f = io.StringIO()
        with patch("sys.stdout", f):
            code = portpeek.main(["check", "80"])
            self.assertEqual(code, 0)
        output = f.getvalue()
        self.assertIn("Port 80 (http) on 127.0.0.1: IN USE", output)

    @patch("portpeek.scan_port_range")
    def test_cmd_scan_output(self, mock_scan):
        mock_scan.return_value = [
            (8000, False, "unknown"),
            (8001, True, "unknown"),
        ]
        f = io.StringIO()
        with patch("sys.stdout", f):
            code = portpeek.main(["scan", "8000-8001"])
            self.assertEqual(code, 0)
        output = f.getvalue()
        self.assertIn("Scanning 2 port(s)", output)
        self.assertIn("8000     FREE", output)
        self.assertIn("8001     IN USE", output)


if __name__ == "__main__":
    unittest.main()
