
import argparse
import logging
import sys
import os
import shutil
from scanner import NmapScanner
from differ import ScanDiffer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("autorecon.log")
    ]
)
logger = logging.getLogger("AutoRecon")

def main():
    parser = argparse.ArgumentParser(description="AutoRecon: Security Surveillance Tool")
    parser.add_argument("--target", required=True, help="Target IP or subnet to scan")
    parser.add_argument("--ports", default="1-1000", help="Port range to scan (default: 1-1000)")
    parser.add_argument("--baseline", action="store_true", help="Run as baseline scan (overwrite existing)")
    parser.add_argument("--history-dir", default="scans", help="Directory to store scan artifacts")
    
    args = parser.parse_args()
    
    # Ensure history directory exists
    os.makedirs(args.history_dir, exist_ok=True)
    
    logger.info(f"Starting AutoRecon for target: {args.target}")
    
    # Initialize Scanner
    try:
        scanner = NmapScanner(target=args.target, ports=args.ports, output_dir=args.history_dir)
        current_scan_file = scanner.run_scan()
        logger.info(f"Scan completed: {current_scan_file}")
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        sys.exit(1)
        
    # Baseline Management
    baseline_file = os.path.join(args.history_dir, f"baseline_{args.target}.xml")
    
    if args.baseline:
        logger.info("Running in baseline calibration mode.")
        if os.path.exists(current_scan_file):
            shutil.copy(current_scan_file, baseline_file)
            logger.info(f"Baseline updated at {baseline_file}")
        sys.exit(0)

    if not os.path.exists(baseline_file):
        logger.warning(f"No baseline found at {baseline_file}. Creating new baseline from current scan.")
        shutil.copy(current_scan_file, baseline_file)
        sys.exit(0)

    # Compare with Baseline
    logger.info("Comparing against baseline...")
    try:
        differ = ScanDiffer(current_file=current_scan_file, baseline_file=baseline_file)
        changes_detected = differ.compare()
        
        if changes_detected:
            # In a real environment, we'd send an alert here (e.g., Slack, PagerDuty)
            logger.critical("SECURITY ALERT: Changes detected in infrastructure!")
            sys.exit(1) # Exit with error code to signal CI/CD pipeline
        else:
            logger.info("No changes detected. Infrastructure is stable.")
            
    except Exception as e:
        logger.error(f"Comparison failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
