# vulnscan/service_detect.py
import asyncio
from typing import Tuple
import ssl

async def grab_banner(host: str, port: int, timeout=2.0) -> str:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        # Try sending protocol-specific probes for common services
        if port == 80 or port == 8080:
            writer.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        elif port == 443:
            # Use ssl to handshake then send HTTP GET
            writer.close()
            # fallback to plain TLS handshake using ssl library (simpler to call requests)
            return "TLS service (port 443)"
        else:
            # generic TCP probe: send newline to elicit banner
            writer.write(b"\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(1024), timeout)
        writer.close()
        await writer.wait_closed()
        return data.decode(errors="ignore").strip()
    except Exception as e:
        return f"<no-banner> ({e})"

def detect_sync(host: str, port: int, timeout=2.0):
    return asyncio.run(grab_banner(host, port, timeout))

import subprocess
import xml.etree.ElementTree as ET

def nmap_service_detect(host: str, ports):
    port_str = ",".join(map(str, ports))
    cmd = ["nmap", "-sV", "-p", port_str, "-oX", "-oN", "/dev/null", host]
    # Simpler: nmap -sV -p 22,80 -oX -
    cmd = ["nmap", "-sV", "-p", port_str, "-oX", "-", host]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    xml_out = proc.stdout
    root = ET.fromstring(xml_out)
    findings = {}
    for port in root.findall(".//port"):
        pnum = int(port.get('portid'))
        svc = port.find('service')
        if svc is not None:
            name = svc.get('name')
            product = svc.get('product')
            version = svc.get('version')
            findings[pnum] = {"name": name, "product": product, "version": version}
    return findings


import re

def parse_banner_product_version(banner: str):
    # Try common patterns: "Product/Version", "Product Version", "Product_8.4"
    patterns = [
        r"(?P<prod>[A-Za-z0-9_\-]+)[/ _-](?P<ver>\d+\.\d+(?:\.\d+)?)",
        r"(?P<prod>[A-Za-z0-9_\-]+)\s+version\s+(?P<ver>\d+\.\d+(?:\.\d+)?)",
    ]
    for pat in patterns:
        m = re.search(pat, banner, re.IGNORECASE)
        if m:
            return m.group("prod").lower(), m.group("ver")
    return None, None

""" mappings.json: a small mapping file with common service->package names"""