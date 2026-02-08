
import xml.etree.ElementTree as ET
import logging
from typing import Set

logger = logging.getLogger(__name__)

class ScanDiffer:
    def __init__(self, current_file: str, baseline_file: str):
        self.current_file = current_file
        self.baseline_file = baseline_file

    def parse_nmap_xml(self, file_path: str) -> Set[str]:
        """Extracts open ports from Nmap XML"""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            open_ports = set()
            
            for host in root.findall('host'):
                for ports in host.findall('ports'):
                    for port in ports.findall('port'):
                        state_elem = port.find('state')
                        if state_elem is not None and state_elem.get('state') == 'open':
                            portid = port.get('portid')
                            service_elem = port.find('service')
                            service = service_elem.get('name') if service_elem is not None else "unknown"
                            open_ports.add(f"{portid}/{service}")
            return open_ports
        except ET.ParseError as e:
            logger.error(f"Failed to parse XML file {file_path}: {e}")
            return set()
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
            return set()

    def compare(self) -> bool:
        """Compares current scan against baseline. Returns True if changes detected."""
        current_ports = self.parse_nmap_xml(self.current_file)
        baseline_ports = self.parse_nmap_xml(self.baseline_file)

        new_ports = current_ports - baseline_ports
        closed_ports = baseline_ports - current_ports
        
        logger.info(f"Current open ports: {len(current_ports)}")
        logger.info(f"Baseline open ports: {len(baseline_ports)}")

        if new_ports:
            col_red = "\033[91m"
            col_reset = "\033[0m"
            logger.warning(f"{col_red}[ALERT] New ports detected: {new_ports}{col_reset}")
            return True
        
        if closed_ports:
            logger.info(f"Ports closed since baseline: {closed_ports}")
        
        logger.info("No new ports detected.")
        return False

if __name__ == "__main__":
    # Create dummy files for testing logic
    with open("baseline.xml", "w") as f: f.write('<nmaprun><host><ports><port portid="80"><state state="open"/><service name="http"/></port></ports></host></nmaprun>')
    with open("current.xml", "w") as f: f.write('<nmaprun><host><ports><port portid="80"><state state="open"/><service name="http"/></port><port portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>')
    
    logging.basicConfig(level=logging.INFO)
    differ = ScanDiffer("current.xml", "baseline.xml")
    differ.compare()
