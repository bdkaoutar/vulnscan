from  vulnscan.vulnscan.scanner import scan
from vulnscan.vulnscan.service_detect import detect_sync

open_ports = scan("192.168.80.147", ports=[21, 22, 25, 53 ,80, 110, 143, 443,8080])
for open_port in open_ports:
    print(open_port, detect_sync("192.168.80.147", open_port))