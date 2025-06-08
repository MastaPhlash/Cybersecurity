"""
scanner.py
Core scanning logic and validation helpers for the Python Port Scanner.
"""
import socket
import subprocess
from ipaddress import ip_address
from typing import Optional, List, Dict
import os
import logging

def validate_ip(ip_str: str) -> bool:
    """Validate an IP address string."""
    try:
        ip_address(ip_str)
        return True
    except ValueError:
        return False

def validate_port(port_str: str) -> bool:
    """Validate a port number string (1-65535)."""
    try:
        port = int(port_str)
        return 1 <= port <= 65535
    except ValueError:
        return False

def parse_ports(port_input: str) -> Optional[List[int]]:
    """
    Parse a port input string (e.g., '22,80,443' or '20-25,80,443') into a sorted list of unique ports.
    Returns None if invalid.
    """
    ports = set()
    try:
        for part in port_input.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                start, end = int(start), int(end)
                if not (1 <= start <= end <= 65535):
                    return None
                ports.update(range(start, end + 1))
            elif part:
                port = int(part)
                if not (1 <= port <= 65535):
                    return None
                ports.add(port)
        return sorted(ports)
    except Exception:
        return None

def is_host_alive(ip: str) -> bool:
    """Ping a host to check if it is alive."""
    try:
        param = '-c' if os.name != 'nt' else '-n'
        result = subprocess.run(['ping', param, '1', str(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return result.returncode == 0
    except Exception:
        return False

def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """Attempt to grab a banner from a TCP service."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), port))
            try:
                banner = s.recv(1024)
                return banner.decode(errors='ignore').strip()
            except Exception:
                return None
    except Exception:
        return None

def resolve_hostname(ip: str) -> Optional[str]:
    """Resolve an IP address to a hostname, if possible."""
    try:
        if not any(c.isalpha() for c in str(ip)):
            return socket.gethostbyaddr(str(ip))[0]
    except Exception:
        pass
    return None

def nmap_scan(ip: str, ports: str = "1-1024", args: str = "-sV") -> Optional[str]:
    """
    Run an Nmap scan on the given IP and port range.
    Args:
        ip: Target IP address or hostname.
        ports: Port range string (e.g., "22,80,443" or "1-1024").
        args: Additional Nmap arguments (default: version detection).
    Returns:
        Nmap output as a string, or None if Nmap is not installed or fails.
    """
    import shutil
    nmap_path = shutil.which("nmap")
    if not nmap_path:
        return None  # Nmap not installed
    try:
        cmd = [nmap_path, args, "-p", ports, ip]
        # Flatten args if passed as a string
        flat_cmd = []
        for part in cmd:
            if isinstance(part, str) and part.startswith('-') and ' ' in part:
                flat_cmd.extend(part.split())
            else:
                flat_cmd.append(part)
        result = subprocess.run(flat_cmd, capture_output=True, text=True, timeout=60)
        if result.returncode == 0:
            return result.stdout
        else:
            return result.stderr
    except Exception as e:
        logging.error(f"Nmap scan failed: {e}")
        return None
