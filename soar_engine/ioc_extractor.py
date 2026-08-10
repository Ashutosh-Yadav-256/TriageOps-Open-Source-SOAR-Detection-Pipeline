import re
import ipaddress
import logging
from dataclasses import dataclass, field
from typing import List, Union, Tuple, Set

from .log_parser import LogEvent

logger = logging.getLogger(__name__)

@dataclass
class IOCCollection:
    ips: List[str] = field(default_factory=list)
    domains: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    md5_hashes: List[str] = field(default_factory=list)
    sha1_hashes: List[str] = field(default_factory=list)
    sha256_hashes: List[str] = field(default_factory=list)
    emails: List[str] = field(default_factory=list)

    def get_total_count(self) -> int:
        return sum(len(getattr(self, k)) for k in self.__dict__)

    def get_flattened(self) -> List[Tuple[str, str]]:
        flat = []
        for ip in self.ips: flat.append((ip, 'ip'))
        for domain in self.domains: flat.append((domain, 'domain'))
        for url in self.urls: flat.append((url, 'url'))
        for md5 in self.md5_hashes: flat.append((md5, 'md5'))
        for sha1 in self.sha1_hashes: flat.append((sha1, 'sha1'))
        for sha256 in self.sha256_hashes: flat.append((sha256, 'sha256'))
        for email in self.emails: flat.append((email, 'email'))
        return flat

class IOCExtractor:
    NON_DOMAIN_EXTENSIONS = {
        'exe', 'dll', 'sys', 'ps1', 'bat', 'cmd', 'vbs', 'js', 'msi',
        'tmp', 'log', 'txt', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'zip',
        'rar', 'json', 'xml', 'yml', 'yaml', 'csv', 'ini', 'cfg', 'conf',
        'png', 'jpg', 'gif', 'bmp', 'ico', 'db', 'dat', 'local'
    }

    PRIVATE_NETWORKS = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('169.254.0.0/16'),
        ipaddress.ip_network('0.0.0.0/8'),
    ]

    def __init__(self):
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b')
        self.url_pattern = re.compile(r'https?://[^\s"\'>)]+') 
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.email_pattern = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')

        self.benign_domains = {
            'microsoft.com', 'windows.com', 'google.com', 'localhost',
            'schema.microsoft.com', 'schemas.microsoft.com',
            'windowsupdate.com', 'bing.com', 'live.com', 'office.com',
            'corp.local', 'wkstn-01.corp.local', 'wkstn-02.corp.local',
            'wkstn-03.corp.local', 'wkstn-04.corp.local',
            'srv-01.corp.local', 'srv-02.corp.local'
        }

    def _is_private_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in self.PRIVATE_NETWORKS)
        except ValueError:
            return True

    def _is_benign_domain(self, domain_str: str) -> bool:
        domain_lower = domain_str.lower()
        tld = domain_lower.rsplit('.', 1)[-1] if '.' in domain_lower else ''
        if tld in self.NON_DOMAIN_EXTENSIONS:
            return True
        parts = domain_str.split('.')
        if len(parts) >= 3 and any(p[0].isupper() for p in parts if p):
            return True
        return any(domain_lower.endswith(bd) or domain_lower == bd for bd in self.benign_domains)

    def extract(self, input_data: Union[List[LogEvent], List[str]]) -> IOCCollection:
        logger.info(f"Extracting IOCs from {len(input_data)} items")
        collection = IOCCollection()
        
        ips_set: Set[str] = set()
        domains_set: Set[str] = set()
        urls_set: Set[str] = set()
        md5_set: Set[str] = set()
        sha1_set: Set[str] = set()
        sha256_set: Set[str] = set()
        emails_set: Set[str] = set()

        text_corpus = []

        for item in input_data:
            if isinstance(item, LogEvent):
                if item.source_ip: ips_set.add(item.source_ip)
                if item.dest_ip: ips_set.add(item.dest_ip)
                if item.hash_md5: md5_set.add(item.hash_md5.lower())
                if item.hash_sha256: sha256_set.add(item.hash_sha256.lower())
                
                parts = filter(None, [
                    item.command_line, 
                    item.parent_command_line, 
                    item.process_path, 
                    item.user
                ])
                text_corpus.extend(parts)
            elif isinstance(item, str):
                text_corpus.append(item)

        for text in text_corpus:
            ips_set.update(self.ip_pattern.findall(text))
            domains_set.update(self.domain_pattern.findall(text))
            urls_set.update(self.url_pattern.findall(text))
            md5_set.update(x.lower() for x in self.md5_pattern.findall(text))
            sha1_set.update(x.lower() for x in self.sha1_pattern.findall(text))
            sha256_set.update(x.lower() for x in self.sha256_pattern.findall(text))
            emails_set.update(x.lower() for x in self.email_pattern.findall(text))

        collection.ips = list(filter(lambda ip: not self._is_private_ip(ip), ips_set))
        collection.domains = list(filter(lambda d: not self._is_benign_domain(d) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', d), domains_set))
        collection.urls = list(urls_set)
        collection.md5_hashes = list(md5_set)
        collection.sha1_hashes = list(sha1_set)
        collection.sha256_hashes = list(sha256_set)
        collection.emails = list(emails_set)

        logger.info(f"Extracted {collection.get_total_count()} valid IOCs")
        return collection
