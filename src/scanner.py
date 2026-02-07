import os
import subprocess
import json
from datetime import datetime

class NmapScanner:
    def __init__(self, target, ports="1-1000"):
        self.target = target
        self.ports = ports
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.scan_file = f"scans/{self.target}_{self.timestamp}.xml"

    def run_scan(self):
        """Runs Nmap scan on target"""
        print(f"[*] Starting scan on {self.target}...")
        command = [
            "nmap", "-p", self.ports, "-sV", "-oX", self.scan_file, self.target
        ]
        
        # In a real environment, we'd run the command. 
        # For portfolio purposes, we'll simulate output if nmap isn't installed.
        try:
            subprocess.run(command, check=True)
            print(f"[+] Scan completed. Saved to {self.scan_file}")
            return self.scan_file
        except FileNotFoundError:
            print("[!] Nmap not installed. Simulating scan result...")
            self._simulate_scan()
            return self.scan_file

    def _simulate_scan(self):
        """Creates dummy XML for demonstration"""
        os.makedirs("scans", exist_ok=True)
        dummy_xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -p {self.ports} -sV -oX {self.scan_file} {self.target}" start="1670000000">
<host>
<status state="up"/>
<address addr="{self.target}" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.2p1"/></port>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0"/></port>
</ports>
</host>
</nmaprun>"""
        
        with open(self.scan_file, "w") as f:
            f.write(dummy_xml)

if __name__ == "__main__":
    scanner = NmapScanner("192.168.1.1")
    scanner.run_scan()
