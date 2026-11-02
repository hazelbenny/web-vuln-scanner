"""Ownership verification: active tests only run if the site owner proves control of the target."""
import hashlib
import os
import secrets
from urllib.parse import urlparse

import requests

SECRET_FILE = ".vscan_secret"
VERIFY_PATH = "/.well-known/vscan-verify.txt"


def _secret():
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write(secrets.token_hex(32))
    return open(SECRET_FILE).read()


def token_for(host):
    return hashlib.sha256((_secret() + host).encode()).hexdigest()[:24]


def is_verified(url, host, loopback):
    """Loopback targets (your own machine) are trusted. Others must serve the token."""
    if loopback:
        return True
    token = token_for(host)
    base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
    try:
        r = requests.get(base + VERIFY_PATH, timeout=6, allow_redirects=False)
        if token in r.text:
            return True
        r = requests.get(base + "/", timeout=6, allow_redirects=False)
        return token in r.text and "vscan-verification" in r.text
    except requests.RequestException:
        return False