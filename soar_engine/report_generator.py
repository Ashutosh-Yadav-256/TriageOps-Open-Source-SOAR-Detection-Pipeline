import os
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Tuple
from pathlib import Path

from .log_parser import LogEvent
from .ioc_extractor import IOCCollection

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def _determine_severity(self, events: List[LogEvent], threat_results: List[Dict[str, Any]]) -> str:
        if any(res['found'] for res in threat_results):
            return "CRITICAL"
            
        amsi_bypass_keywords = ['amsiInitFailed', 'AmsiScanBuffer']
        for event in events:
            if event.command_line:
                if any(kw.lower() in event.command_line.lower() for kw in amsi_bypass_keywords):
                    return "CRITICAL"
                    
        high_keywords = ['Net.WebClient', 'DownloadString', 'DownloadFile', 'Invoke-WebRequest', '-enc', '-EncodedCommand']
        for event in events:
            if event.command_line:
                if any(kw.lower() in event.command_line.lower() for kw in high_keywords):
                    return "HIGH"
                    
        med_keywords = ['-ExecutionPolicy Bypass', '-ep bypass', 'Invoke-Expression', 'IEX']
        for event in events:
            if event.command_line:
                if any(kw.lower() in event.command_line.lower() for kw in med_keywords):
                    return "MEDIUM"
                    
        return "LOW"

    def _generate_remediation_steps(self, ioc_collection: IOCCollection, threat_results: List[Dict[str, Any]], severity: str) -> List[str]:
        steps = []
        if severity == "CRITICAL":
            steps.append("CRITICAL: Assume compromise and initiate Incident Response protocol immediately.")
            
        if len(ioc_collection.ips) > 0 or len(ioc_collection.domains) > 0:
            steps.append("Block malicious IPs and domains at the perimeter firewall/web proxy.")
            steps.append("Review network logs for potential lateral movement from affected hosts.")
            
        if len(ioc_collection.md5_hashes) > 0 or len(ioc_collection.sha256_hashes) > 0:
            steps.append("Quarantine endpoints where malicious file hashes were detected.")
            steps.append("Perform full AV/EDR scans on all endpoints to locate malicious binaries.")
            
        steps.append("Review proxy logs and downloaded content for identified download cradles.")
        return steps if steps else ["No specific remediation steps identified. Continue monitoring."]

    def generate(self, events: List[LogEvent], ioc_collection: IOCCollection, threat_results: List[Dict[str, Any]], log_file: str) -> Tuple[str, str]:
        logger.info("Generating reports...")
        severity = self._determine_severity(events, threat_results)
        timestamp_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        
        md_filename = f"IR-{timestamp_str}-{severity}.md"
        json_filename = f"IR-{timestamp_str}-{severity}.json"
        
        md_path = os.path.join(self.output_dir, md_filename)
        json_path = os.path.join(self.output_dir, json_filename)
        
        affected_hosts = list(set(e.computer for e in events if e.computer))
        remediation_steps = self._generate_remediation_steps(ioc_collection, threat_results, severity)
        
        report_data = {
            "incident_id": f"IR-{timestamp_str}",
            "timestamp": timestamp_str,
            "severity": severity,
            "summary": {
                "source_file": log_file,
                "total_events": len(events)
            },
            "affected_hosts": affected_hosts,
            "iocs": {
                "ips": ioc_collection.ips,
                "domains": ioc_collection.domains,
                "urls": ioc_collection.urls,
                "hashes": ioc_collection.md5_hashes + ioc_collection.sha1_hashes + ioc_collection.sha256_hashes
            },
            "threat_intel_matches": [r for r in threat_results if r['found']],
            "events_analyzed": len(events),
            "triage": severity,
            "remediation_steps": remediation_steps
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=4)
            
        md_content = []
        md_content.append(f"# Incident Report: IR-{timestamp_str}")
        md_content.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        md_content.append(f"**Severity:** `{severity}`\n")
        
        md_content.append("## Incident Summary")
        md_content.append(f"- **Source File:** {log_file}")
        md_content.append(f"- **Total Events Analyzed:** {len(events)}")
        md_content.append(f"- **Affected Hosts:** {', '.join(affected_hosts) if affected_hosts else 'None detected'}\n")
        
        md_content.append("## IOC Summary")
        md_content.append("| Type | Count |")
        md_content.append("|---|---|")
        md_content.append(f"| IPv4 Addresses | {len(ioc_collection.ips)} |")
        md_content.append(f"| Domains | {len(ioc_collection.domains)} |")
        md_content.append(f"| URLs | {len(ioc_collection.urls)} |")
        md_content.append(f"| Hashes | {len(ioc_collection.md5_hashes) + len(ioc_collection.sha1_hashes) + len(ioc_collection.sha256_hashes)} |\n")
        
        md_content.append("## Threat Intelligence Findings")
        if any(r['found'] for r in threat_results):
            md_content.append("| IOC | Type | Status | Malware | Confidence | Tags |")
            md_content.append("|---|---|---|---|---|---|")
            for res in threat_results:
                if res['found'] and res['threat_data']:
                    data = res['threat_data'][0]
                    malware = data.get('malware_printable', 'N/A')
                    conf = data.get('confidence_level', 'N/A')
                    tags = ', '.join(data.get('tags', []))
                    md_content.append(f"| {res['ioc']} | {res['ioc_type']} | Match | {malware} | {conf}% | {tags} |")
            md_content.append("\n")
        else:
            md_content.append("*No Threat Intelligence matches found.*\n")
            
        md_content.append("## Detection Matches")
        md_content.append("Suspicious events identified during analysis:\n")
        suspicious_count = 0
        for evt in events:
            if evt.command_line and any(kw in evt.command_line.lower() for kw in ['bypass', 'download', 'encoded', 'invoke', 'amsi']):
                md_content.append(f"- **Host:** {evt.computer} | **Process:** {evt.process_name}")
                md_content.append(f"  - `CMD`: {evt.command_line[:200]}{'...' if len(evt.command_line) > 200 else ''}")
                suspicious_count += 1
        if suspicious_count == 0:
            md_content.append("*No significantly suspicious command lines detected.*\n")
        else:
            md_content.append("\n")
            
        md_content.append("## Triage Assessment")
        md_content.append(f"The severity of this incident is classified as **{severity}** based on the findings.\n")
        
        md_content.append("## Remediation Steps")
        for step in remediation_steps:
            md_content.append(f"- {step}")
        md_content.append("\n")
        
        md_content.append("## Raw Evidence")
        md_content.append("```text")
        for evt in events[:10]:
            if evt.command_line:
                md_content.append(f"[{evt.timestamp}] {evt.computer} - {evt.process_name} - CMD: {evt.command_line[:150]}")
        if len(events) > 10:
            md_content.append(f"... and {len(events) - 10} more events")
        md_content.append("```\n")
        
        md_content.append("---\n*SOAR Engine Automated Analysis*")
        
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(md_content))
            
        logger.info(f"Reports generated: {md_path}, {json_path}")
        return md_path, json_path
