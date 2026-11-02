"""Target validation: stops the scanner being used against internal or cloud-metadata addresses."""
import ipaddress
import os
import socket
from urllib.parse import urlparse

# Lab mode lets you scan localhost / private IPs (your own test apps). Set VSCAN_LAB_MODE=0 when deploying.
LAB_MODE = os.environ.get("VSCAN_LAB_MODE", "1") == "1"
STRICT = os.environ.get("VSCAN_STRICT", "0") == "1"
ALLOWED_HOSTS = {"localhost", "127.0.0.1", "testphp.vulnweb.com"}

def check_target(raw):
    """Return (url, host, is_loopback). Raises ValueError if the target is not allowed."""
    url = raw.strip()
    if "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if STRICT and parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Strict mode: only allowlisted lab targets can be scanned")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Enter a valid http:// or https:// URL")

    try:
        ips = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(parsed.hostname, None)}
    except socket.gaierror:
        raise ValueError(f"Cannot resolve {parsed.hostname}")

    if any(ip.is_link_local for ip in ips):
        raise ValueError("Link-local / cloud metadata addresses are always blocked")
    internal = any(ip.is_private or ip.is_loopback or ip.is_reserved for ip in ips)
    if internal and not LAB_MODE:
        raise ValueError("Private/internal addresses are blocked (lab mode is off)")
    return url, parsed.hostname, all(ip.is_loopback for ip in ips)