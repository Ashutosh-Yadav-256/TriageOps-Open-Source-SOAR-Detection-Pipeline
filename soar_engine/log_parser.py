import json
import logging
from dataclasses import dataclass
from typing import List, Optional, Dict, Any

logger = logging.getLogger(__name__)

@dataclass
class LogEvent:
    timestamp: Optional[str] = None
    event_id: Optional[int] = None
    computer: Optional[str] = None
    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_process_path: Optional[str] = None
    parent_command_line: Optional[str] = None
    user: Optional[str] = None
    source_ip: Optional[str] = None
    source_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    protocol: Optional[str] = None
    raw_event: Optional[Dict[str, Any]] = None

class LogParser:
    def __init__(self):
        pass

    def parse_file(self, file_path: str) -> List[LogEvent]:
        logger.info(f"Parsing log file: {file_path}")
        events = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content.startswith('['):
                    data = json.loads(content)
                    if isinstance(data, list):
                        for item in data:
                            parsed_event = self._parse_sysmon_event(item)
                            if parsed_event:
                                events.append(parsed_event)
                else:
                    for line_num, line in enumerate(content.splitlines(), start=1):
                        if line.strip():
                            try:
                                item = json.loads(line)
                                parsed_event = self._parse_sysmon_event(item)
                                if parsed_event:
                                    events.append(parsed_event)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Malformed JSON on line {line_num}: {e}")
        except FileNotFoundError:
            logger.error(f"File not found: {file_path}")
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
        
        logger.info(f"Parsed {len(events)} events from {file_path}")
        return events

    def _parse_sysmon_event(self, raw_data: Dict[str, Any]) -> Optional[LogEvent]:
        try:
            event_data_node = raw_data.get('EventData', raw_data)
            system_node = raw_data.get('System', raw_data)
            
            event_id = system_node.get('EventID')
            if isinstance(event_id, dict) and '$' in event_id:
                event_id = int(event_id['$'])
            elif event_id is not None:
                event_id = int(event_id)
                
            if event_id not in [1, 3]:
                return None
                
            ts = None
            time_created = system_node.get('TimeCreated')
            if isinstance(time_created, dict):
                ts = time_created.get('SystemTime')
            elif time_created:
                ts = time_created
            else:
                ts = system_node.get('UtcTime')
                
            event = LogEvent(
                timestamp=ts,
                event_id=event_id,
                computer=system_node.get('Computer'),
                raw_event=raw_data
            )

            if event_id == 1:
                event.process_path = event_data_node.get('Image')
                event.process_name = event.process_path.split('\\')[-1] if event.process_path else None
                event.command_line = event_data_node.get('CommandLine')
                event.parent_process_path = event_data_node.get('ParentImage')
                event.parent_process_name = event.parent_process_path.split('\\')[-1] if event.parent_process_path else None
                event.parent_command_line = event_data_node.get('ParentCommandLine')
                event.user = event_data_node.get('User')
                
                hashes = event_data_node.get('Hashes', '')
                if hashes:
                    for h in hashes.split(','):
                        k_v = h.split('=')
                        if len(k_v) == 2:
                            algo, val = k_v[0].strip().upper(), k_v[1].strip()
                            if algo == 'MD5':
                                event.hash_md5 = val
                            elif algo == 'SHA256':
                                event.hash_sha256 = val

            elif event_id == 3:
                event.process_path = event_data_node.get('Image')
                event.process_name = event.process_path.split('\\')[-1] if event.process_path else None
                event.user = event_data_node.get('User')
                event.protocol = event_data_node.get('Protocol')
                event.source_ip = event_data_node.get('SourceIp')
                
                sport = event_data_node.get('SourcePort')
                if sport: event.source_port = int(sport)
                
                event.dest_ip = event_data_node.get('DestinationIp')
                
                dport = event_data_node.get('DestinationPort')
                if dport: event.dest_port = int(dport)

            return event
        except Exception as e:
            logger.debug(f"Failed to parse event: {e}")
            return None
