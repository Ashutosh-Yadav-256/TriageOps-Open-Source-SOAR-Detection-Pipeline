import argparse
import sys
import logging
from pathlib import Path

from .log_parser import LogParser
from .ioc_extractor import IOCExtractor
from .threat_intel import ThreatIntelClient
from .report_generator import ReportGenerator

BANNER = r"""
=========================================================
  ____   ___    _    ____    _____ _   _  ____ ___ _   _ _____ 
 / ___| / _ \  / \  |  _ \  | ____| \ | |/ ___|_ _| \ | | ____|
 \___ \| | | |/ _ \ | |_) | |  _| |  \| | |  _ | ||  \| |  _|  
  ___) | |_| / ___ \|  _ <  | |___| |\  | |_| || || |\  | |___ 
 |____/ \___/_/   \_\_| \_\ |_____|_| \_|\____|___|_| \_|_____|
=========================================================
       Security Orchestration, Automation & Response
=========================================================
"""

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def main():
    parser = argparse.ArgumentParser(description="SOAR Engine Automation Pipeline")
    parser.add_argument("--input", type=str, required=True, help="Path to JSON log file")
    parser.add_argument("--output", type=str, default="./reports", help="Output directory for reports")
    parser.add_argument("--dry-run", action="store_true", help="Skip live API calls")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    setup_logging(args.verbose)
    
    logger = logging.getLogger("soar_engine.main")
    
    print(BANNER)
    
    if not Path(args.input).exists():
        logger.error(f"Input file not found: {args.input}")
        print(f"[-] Error: Input file not found: {args.input}")
        sys.exit(1)
        
    try:
        print("[*] Stage 1/4: Parsing Logs...")
        parser_obj = LogParser()
        events = parser_obj.parse_file(args.input)
        
        if not events:
            print("[-] No events parsed. Exiting.")
            sys.exit(1)
            
        print("[*] Stage 2/4: Extracting IOCs...")
        extractor = IOCExtractor()
        ioc_collection = extractor.extract(events)
        
        print(f"[*] Stage 3/4: Threat Intel Enrichment {'(DRY RUN)' if args.dry_run else ''}...")
        ti_client = ThreatIntelClient(dry_run=args.dry_run)
        threat_results = ti_client.bulk_lookup(ioc_collection)
        
        print("[*] Stage 4/4: Generating Reports...")
        generator = ReportGenerator(args.output)
        md_path, json_path = generator.generate(events, ioc_collection, threat_results, args.input)
        
        threat_matches = sum(1 for r in threat_results if r['found'])
        print("\n=========================================================")
        print("                   ANALYSIS SUMMARY")
        print("=========================================================")
        print(f"  Total Events Analyzed : {len(events)}")
        print(f"  Total IOCs Extracted  : {ioc_collection.get_total_count()}")
        print(f"  Threat Intel Matches  : {threat_matches}")
        print(f"  Report (Markdown)     : {md_path}")
        print(f"  Report (JSON)         : {json_path}")
        print("=========================================================")
        print("[+] Pipeline completed successfully.")
        
        sys.exit(0)
        
    except Exception as e:
        logger.error(f"Pipeline failed: {e}", exc_info=True)
        print(f"\n[-] Error: Pipeline failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
