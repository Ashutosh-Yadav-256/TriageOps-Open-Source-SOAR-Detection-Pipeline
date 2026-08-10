import time
import logging
import requests
from typing import Dict, Any, List

from .ioc_extractor import IOCCollection

logger = logging.getLogger(__name__)

class ThreatIntelClient:
    def __init__(self, dry_run: bool = False, timeout: int = 15):
        self.dry_run = dry_run
        self.timeout = timeout
        self.api_url = "https://threatfox-api.abuse.ch/api/v1/"
        self.headers = {"Content-Type": "application/json"}

    def _query(self, data: Dict[str, Any]) -> Dict[str, Any]:
        if self.dry_run:
            logger.debug(f"[DRY-RUN] Simulating API query for: {data}")
            return {'query_status': 'no_result', 'message': 'Simulated dry-run response'}
        
        try:
            response = requests.post(self.api_url, json=data, headers=self.headers, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"ThreatFox API timeout after {self.timeout}s")
        except requests.exceptions.ConnectionError:
            logger.error("ThreatFox API connection error")
        except requests.exceptions.RequestException as e:
            logger.error(f"ThreatFox API request exception: {e}")
        except Exception as e:
            logger.error(f"Unexpected error calling ThreatFox API: {e}")
        
        return {'query_status': 'error'}

    def search_ioc(self, ioc: str) -> Dict[str, Any]:
        logger.debug(f"Searching IOC: {ioc}")
        return self._query({"query": "search_ioc", "search_term": ioc})

    def search_hash(self, hash_value: str) -> Dict[str, Any]:
        logger.debug(f"Searching hash: {hash_value}")
        return self._query({"query": "search_hash", "hash": hash_value})

    def bulk_lookup(self, ioc_collection: IOCCollection) -> List[Dict[str, Any]]:
        results = []
        flattened_iocs = ioc_collection.get_flattened()
        
        logger.info(f"Starting bulk lookup for {len(flattened_iocs)} IOCs...")
        
        for ioc_value, ioc_type in flattened_iocs:
            if ioc_type in ['md5', 'sha1', 'sha256']:
                resp = self.search_hash(ioc_value)
            else:
                resp = self.search_ioc(ioc_value)
                
            found = resp.get('query_status') == 'ok'
            
            results.append({
                'ioc': ioc_value,
                'ioc_type': ioc_type,
                'found': found,
                'threat_data': resp.get('data', []) if found else None
            })
            
            if not self.dry_run and len(flattened_iocs) > 1:
                time.sleep(1)
                
        logger.info(f"Completed bulk lookup. Found {sum(1 for r in results if r['found'])} malicious IOCs.")
        return results
