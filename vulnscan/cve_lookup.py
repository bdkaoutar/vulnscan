# vulnscan/cve_lookup.py
import os
import requests
from typing import Optional, Dict, Any
from .cache import get_cached, set_cached, init_db

OSV_API = "https://api.osv.dev/v1/query"

# initialize DB at import time (harmless if already created)
init_db()

def query_osv_package(pkg_type: str, pkg_name: str, version: str, timeout: int = 10) -> Dict[str, Any]:
    """
    Query OSV for a specific package+version.

    Returns the parsed JSON response (possibly an empty dict if none).
    Caching: results are cached in sqlite by key 'osv:<pkg_type>:<pkg_name>:<version>'.
    """
    key = f"osv:{pkg_type}:{pkg_name}:{version}"
    cached = get_cached(key)
    if cached is not None:
        return cached

    payload = {"package": {"name": pkg_name, "ecosystem": pkg_type}, "version": version}
    resp = requests.post(OSV_API, json=payload, timeout=timeout)
    # If API returns non-JSON, raise for visibility in tests / logs
    resp.raise_for_status()
    data = resp.json()
    # store raw API response in cache (could choose to normalize first)
    set_cached(key, data)
    return data
