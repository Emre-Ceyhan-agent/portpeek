#!/usr/bin/env python3
"""portpeek: Inspect listening ports, check port availability, and scan ranges.

A lightweight, zero-dependency CLI tool built with standard library Python 3.9+.
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys
from typing import NamedTuple, Optional, Sequence


TCP_STATE_LISTEN = "0A"


class ListeningPort(NamedTuple):
    """Represents a listening TCP socket entry."""

    proto: str
    ip: str
    port: int
    service: str
    inode: str


def decode_ipv4_hex(hex_str: str) -> str:
    """Decode an 8-character hex string from /proc/net/tcp into an IPv4 string."""
    try:
        val = int(hex_str, 16)
        packed = struct.pack("=I", val)
        return socket.inet_ntoa(packed)
    except Exception:
        return hex_str


def decode_ipv6_hex(hex_str: str) -> str:
    """Decode a 32-character hex string from /proc/net/tcp6 into an IPv6 string."""
    try:
        words = [int(hex_str[i : i + 8], 16) for i in range(0, 32, 8)]
        packed = struct.pack("=IIII", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except Exception:
        return hex_str


def resolve_service_name(port: int, proto: str = "tcp") -> str:
    """Resolve a port number to its common service name, or 'unknown' if not mapped."""
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return "unknown"


def parse_proc_net_tcp_file(
    filepath: str, is_ipv6: bool = False
) -> list[ListeningPort]:
    """Parse a /proc/net/tcp or /proc/net/tcp6 file and extract listening sockets.

    Args:
        filepath: Path to the proc net tcp file.
        is_ipv6: True if parsing tcp6 format.

    Returns:
        List of ListeningPort objects currently in LISTEN state.
    """
    if not os.path.exists(filepath):
        return []

    results: list[ListeningPort] = []
    try:
        with open(filepath, "r", encoding="ascii") as f:
            lines = f.readlines()
    except OSError:
        return []

    if not lines:
        return []

    # First line is header
    proto_label = "tcp6" if is_ipv6 else "tcp"
    for line in lines[1:]:
        fields = line.strip().split()
        if len(fields) < 10:
            continue

        local_addr_field = fields[1]
        state = fields[3]
        inode = fields[9]

        if state.upper() != TCP_STATE_LISTEN:
            continue

        if ":" not in local_addr_field:
            continue

        ip_hex, port_hex = local_addr_field.split(":", 1)
        try:
            port = int(port_hex, 16)
        except ValueError:
            continue

        if is_ipv6:
            ip = decode_ipv6_hex(ip_hex)
        else:
            ip = decode_ipv4_hex(ip_hex)

        service = resolve_service_name(port, "tcp")
        results.append(
            ListeningPort(
                proto=proto_label,
                ip=ip,
                port=port,
                service=service,
                inode=inode,
            )
        )

    return results


def get_listening_ports(
    tcp_path: str = "/proc/net/tcp",
    tcp6_path: str = "/proc/net/tcp6",
) -> list[ListeningPort]:
    """Collect listening TCP ports from both IPv4 and IPv6 proc tables."""
    ipv4_ports = parse_proc_net_tcp_file(tcp_path, is_ipv6=False)
    ipv6_ports = parse_proc_net_tcp_file(tcp6_path, is_ipv6=True)

    combined = ipv4_ports + ipv6_ports
    # Sort primarily by port number, then protocol, then ip
    combined.sort(key=lambda entry: (entry.port, entry.proto, entry.ip))
    return combined


def check_port_in_use(
    port: int, host: str = "127.0.0.1", timeout: float = 0.5
) -> bool:
    """Check whether a specific port is in use on the given host.

    A port is considered in use if an active connection can be established,
    or if attempting to bind to the port fails with EADDRINUSE or permission error.
    """
    # First test: attempt to connect to host:port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            res = s.connect_ex((host, port))
            if res == 0:
                return True
        except OSError:
            pass

    # Second test: attempt to bind to the port locally
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return False
        except OSError:
            return True


def scan_port_range(
    start_port: int,
    end_port: int,
    host: str = "127.0.0.1",
    timeout: float = 0.2,
) -> list[tuple[int, bool, str]]:
    """Scan a range of ports (inclusive) on host to check in-use status.

    Returns a list of tuples: (port, in_use, service_name).
    """
    results: list[tuple[int, bool, str]] = []
    for port in range(start_port, end_port + 1):
        in_use = check_port_in_use(port, host=host, timeout=timeout)
        service = resolve_service_name(port, "tcp")
        results.append((port, in_use, service))
    return results


def parse_port_range(range_str: str) -> tuple[int, int]:
    """Parse a port range string like '8000-8010' or a single port like '8080'.

    Raises:
        ValueError: If input format or port numbers are invalid.
    """
    if "-" in range_str:
        parts = range_str.split("-", 1)
        start = int(parts[0].strip())
        end = int(parts[1].strip())
    else:
        start = int(range_str.strip())
        end = start

    if not (1 <= start <= 65535 and 1 <= end <= 65535):
        raise ValueError("Port numbers must be between 1 and 65535.")
    if start > end:
        raise ValueError(f"Start port ({start}) cannot be greater than end port ({end}).")

    return start, end


def cmd_list(args: argparse.Namespace) -> int:
    """Execute the 'list' command."""
    ports = get_listening_ports()
    if not ports:
        print("No listening TCP sockets found in /proc/net/tcp{,6}.")
        return 0

    header_fmt = "{:<6} {:<24} {:<8} {:<16} {:<10}"
    row_fmt = "{:<6} {:<24} {:<8} {:<16} {:<10}"

    print(header_fmt.format("PROTO", "LOCAL ADDRESS", "PORT", "SERVICE", "INODE"))
    print("-" * 68)
    for entry in ports:
        print(
            row_fmt.format(
                entry.proto,
                entry.ip,
                str(entry.port),
                entry.service,
                entry.inode,
            )
        )
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Execute the 'check' command."""
    port = args.port
    if not (1 <= port <= 65535):
        print(f"Error: Port {port} is out of valid range (1-65535).", file=sys.stderr)
        return 1

    host = getattr(args, "host", "127.0.0.1")
    in_use = check_port_in_use(port, host=host)
    service = resolve_service_name(port, "tcp")
    status = "IN USE" if in_use else "FREE"

    print(f"Port {port} ({service}) on {host}: {status}")
    # Return exit code 0 if free, 1 if in use (or 0 for general inquiry; standard is 0 on successful check)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """Execute the 'scan' command."""
    try:
        start, end = parse_port_range(args.range)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    host = getattr(args, "host", "127.0.0.1")
    count = end - start + 1
    print(f"Scanning {count} port(s) on {host} ({start}..{end})...")

    results = scan_port_range(start, end, host=host)

    header_fmt = "{:<8} {:<10} {:<16}"
    row_fmt = "{:<8} {:<10} {:<16}"
    print(header_fmt.format("PORT", "STATUS", "SERVICE"))
    print("-" * 36)

    in_use_count = 0
    for port, in_use, service in results:
        status = "IN USE" if in_use else "FREE"
        if in_use:
            in_use_count += 1
        print(row_fmt.format(str(port), status, service))

    print("-" * 36)
    print(f"Scan complete: {in_use_count} in use, {count - in_use_count} free.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build and configure the argument parser."""
    parser = argparse.ArgumentParser(
        prog="portpeek",
        description="A small, complete, self-contained TCP port inspection CLI.",
    )
    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available subcommands",
        help="Subcommand to execute",
    )

    # Subcommand: list
    parser_list = subparsers.add_parser(
        "list",
        help="Show listening TCP ports by parsing /proc/net/tcp and /proc/net/tcp6",
    )
    parser_list.set_defaults(func=cmd_list)

    # Subcommand: check
    parser_check = subparsers.add_parser(
        "check",
        help="Check whether a port is free or in use on 127.0.0.1",
    )
    parser_check.add_argument(
        "port",
        type=int,
        help="Port number to check (1-65535)",
    )
    parser_check.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Target host IP (default: 127.0.0.1)",
    )
    parser_check.set_defaults(func=cmd_check)

    # Subcommand: scan
    parser_scan = subparsers.add_parser(
        "scan",
        help="Probe a port or range of ports (e.g. 8000-8010)",
    )
    parser_scan.add_argument(
        "range",
        type=str,
        help="Port or port range like '8080' or '8000-8010'",
    )
    parser_scan.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Target host IP (default: 127.0.0.1)",
    )
    parser_scan.set_defaults(func=cmd_scan)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not hasattr(args, "func"):
        parser.print_help()
        return 1

    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
