# portpeek

A small, complete, self-contained Python CLI tool to inspect listening TCP ports, check port availability, and scan port ranges.

Built with pure Python 3.9+ standard library with **zero external dependencies**.

## Features

- **`portpeek list`**: Inspects listening TCP sockets directly by parsing `/proc/net/tcp` and `/proc/net/tcp6`, formatting addresses (IPv4 & IPv6), and resolving port numbers to standard service names (e.g. `22` -> `ssh`, `80` -> `http`, `5432` -> `postgresql`).
- **`portpeek check PORT`**: Checks whether a specific port is free or currently in use on `127.0.0.1` (or custom `--host`).
- **`portpeek scan RANGE`**: Probes a port range (e.g. `8000-8010`) or single port, providing a tabular summary of port status and service mappings.
- **Pure Standard Library**: Requires no `pip` packages; runs on standard Python 3.9+.
- **Clean Architecture**: Complete type annotations, thorough docstrings, and an isolated unit test suite that does not require network privileges.

---

## Installation & Requirements

- Linux operating system with `/proc` filesystem (for `list` command)
- Python 3.9 or higher
- No external packages required

Make the script executable:
```bash
chmod +x portpeek
# Or run with python3:
python3 portpeek.py --help
```

---

## Usage Examples

### 1. List Listening TCP Ports
Parses Linux `/proc/net/tcp` and `/proc/net/tcp6`:
```bash
./portpeek list
```
**Example Output:**
```text
PROTO  LOCAL ADDRESS            PORT     SERVICE          INODE     
--------------------------------------------------------------------
tcp    0.0.0.0                  22       ssh              5577      
tcp6   ::                       22       ssh              6519      
tcp    0.0.0.0                  80       http             11158     
tcp6   ::                       80       http             11159     
tcp    127.0.0.1                5432     postgresql       12901     
tcp    127.0.0.1                6379     redis            9838      
```

### 2. Check Port Availability
Check if a port is in use or available on `127.0.0.1`:
```bash
./portpeek check 5432
# Output: Port 5432 (postgresql) on 127.0.0.1: IN USE

./portpeek check 8088
# Output: Port 8088 (unknown) on 127.0.0.1: FREE
```

Optional `--host` flag:
```bash
./portpeek check 80 --host 127.0.0.1
```

### 3. Scan a Range of Ports
Probe a port range (such as `8000-8010`):
```bash
./portpeek scan 8000-8005
```
**Example Output:**
```text
Scanning 6 port(s) on 127.0.0.1 (8000..8005)...
PORT     STATUS     SERVICE         
------------------------------------
8000     FREE       unknown         
8001     FREE       unknown         
8002     FREE       unknown         
8003     FREE       unknown         
8004     FREE       unknown         
8005     FREE       unknown         
------------------------------------
Scan complete: 0 in use, 6 free.
```

---

## Running Tests

The test suite uses Python's standard `unittest` framework and uses mocked socket operations and synthetic proc files, requiring no network privileges or specific ports to be open.

Run all tests via:
```bash
python3 -m unittest
```
Or with verbose output:
```bash
python3 -m unittest -v test_portpeek.py
```
