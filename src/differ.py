import xml.etree.ElementTree as ET
import sys

class ScanDiffer:
    def __init__(self, current_file, baseline_file):
        self.current_file = current_file
        self.baseline_file = baseline_file

    def parse_nmap_xml(self, file_path):
        """Extracts open ports from Nmap XML"""
        tree = ET.parse(file_path)
        root = tree.getroot()
        open_ports = set()
        
        for host in root.findall('host'):
            for ports in host.findall('ports'):
                for port in ports.findall('port'):
                    state = port.find('state').get('state')
                    if state == 'open':
                        portid = port.get('portid')
                        service = port.find('service').get('name') if port.find('service') is not None else "unknown"
                        open_ports.add(f"{portid}/{service}")
        return open_ports

    def compare(self):
        """Compares current scan against baseline"""
        current_ports = self.parse_nmap_xml(self.current_file)
        baseline_ports = self.parse_nmap_xml(self.baseline_file)

        new_ports = current_ports - baseline_ports
        closed_ports = baseline_ports - current_ports

        if new_ports:
            print(f"[ALERT] New ports detected: {new_ports}")
            # Here we would trigger the alert.py module
            return True
        
        print("[*] No new ports detected.")
        return False

# Example usage for testing
if __name__ == "__main__":
    # Create dummy files for testing logic
    with open("baseline.xml", "w") as f: f.write('<nmaprun><host><ports><port portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>')
    with open("current.xml", "w") as f: f.write('<nmaprun><host><ports><port portid="80"><state state="open"/><service name="http"/></port><port portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>')
    
    differ = ScanDiffer("current.xml", "baseline.xml")
    differ.compare()
