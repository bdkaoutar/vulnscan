import asyncio
from typing import List, Tuple

DEFAULT_PORTS = [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5900, 8080]

async def _scan_port(host: str, port: int, sem: asyncio.Semaphore, timeout: float = 1.0) -> Tuple[int, bool]:
    async with sem:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return port, True
        except Exception:
            return port, False

async def scan_host(host: str, ports: List[int] = None, concurrency: int = 500, timeout: float = 1.0):
    ports = ports or DEFAULT_PORTS
    sem = asyncio.Semaphore(concurrency)
    tasks = [_scan_port(host, p, sem, timeout) for p in ports]
    results = await asyncio.gather(*tasks)
    open_ports = sorted([p for p, ok in results if ok])
    return open_ports

def scan(host: str, ports: List[int] = None, concurrency: int = 500, timeout: float = 1.0):
    return asyncio.run(scan_host(host, ports, concurrency, timeout))

if __name__ == '__main__':
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m vulnscan.scanner <host>")
        raise SystemExit(1)
    host = sys.argv[1]
    print("Open ports:", scan(host))
