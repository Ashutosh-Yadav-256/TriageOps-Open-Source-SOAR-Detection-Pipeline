import os
import sys
import yaml
import uuid
import re
from typing import Dict, Any, List, Tuple

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'

def is_valid_uuid(val: str) -> bool:
    try:
        uuid.UUID(str(val))
        return True
    except ValueError:
        return False

def validate_rule(rule: Dict[str, Any], filepath: str) -> Tuple[bool, List[str]]:
    errors = []
    
    required_fields = ['title', 'id', 'status', 'description', 'author', 'date', 'logsource', 'detection', 'level', 'tags']
    for field in required_fields:
        if field not in rule:
            errors.append(f"Missing required field: '{field}'")
            
    if not errors:
        if not is_valid_uuid(rule['id']):
            errors.append(f"Field 'id' must be a valid UUID, got: {rule['id']}")
            
        valid_statuses = ['experimental', 'test', 'stable', 'deprecated', 'unsupported']
        if rule.get('status') not in valid_statuses:
            errors.append(f"Invalid status: {rule.get('status')}. Must be one of: {', '.join(valid_statuses)}")
            
        valid_levels = ['informational', 'low', 'medium', 'high', 'critical']
        if rule.get('level') not in valid_levels:
            errors.append(f"Invalid level: {rule.get('level')}. Must be one of: {', '.join(valid_levels)}")
            
        tags = rule.get('tags', [])
        if not isinstance(tags, list):
            errors.append("Field 'tags' must be a list")
        elif not any(tag.startswith('attack.') for tag in tags):
            errors.append("Field 'tags' must contain at least one 'attack.*' tag")
            
        logsource = rule.get('logsource', {})
        if not isinstance(logsource, dict):
            errors.append("Field 'logsource' must be a dictionary")
        elif 'category' not in logsource and not ('product' in logsource and 'service' in logsource):
            errors.append("Field 'logsource' must have 'category' OR ('product' AND 'service')")
            
        detection = rule.get('detection', {})
        if not isinstance(detection, dict):
            errors.append("Field 'detection' must be a dictionary")
        elif 'condition' not in detection:
            errors.append("Field 'detection' must contain a 'condition' field")
            
    return len(errors) == 0, errors

def main():
    rules_dir = "sigma-rules"
    if not os.path.exists(rules_dir):
        print(f"{Colors.YELLOW}Warning: Directory '{rules_dir}' does not exist. Skipping validation.{Colors.RESET}")
        return 0

    all_passed = True
    processed_count = 0

    print(f"{Colors.CYAN}Starting Sigma Rule Validation...{Colors.RESET}")
    print(f"Scanning directory: {rules_dir}\n")

    for root, _, files in os.walk(rules_dir):
        for file in files:
            if file.endswith(('.yml', '.yaml')):
                filepath = os.path.join(root, file)
                processed_count += 1
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        rule = yaml.safe_load(f)
                    
                    if not isinstance(rule, dict):
                        print(f"{Colors.RED}[FAIL]{Colors.RESET} {filepath} - Invalid YAML structure (not a dictionary)")
                        all_passed = False
                        continue
                        
                    is_valid, errors = validate_rule(rule, filepath)
                    
                    if is_valid:
                        print(f"{Colors.GREEN}[PASS]{Colors.RESET} {filepath}")
                    else:
                        print(f"{Colors.RED}[FAIL]{Colors.RESET} {filepath}")
                        for err in errors:
                            print(f"       - {err}")
                        all_passed = False
                except yaml.YAMLError as e:
                    print(f"{Colors.RED}[FAIL]{Colors.RESET} {filepath} - YAML Parsing Error:")
                    print(f"       {e}")
                    all_passed = False
                except Exception as e:
                    print(f"{Colors.RED}[FAIL]{Colors.RESET} {filepath} - Unexpected Error: {e}")
                    all_passed = False

    print(f"\n{Colors.CYAN}Validation Complete.{Colors.RESET}")
    print(f"Total rules processed: {processed_count}")
    
    if processed_count == 0:
        print(f"{Colors.YELLOW}No rules found to validate.{Colors.RESET}")
        return 0
        
    if all_passed:
        print(f"{Colors.GREEN}All rules passed validation!{Colors.RESET}")
        return 0
    else:
        print(f"{Colors.RED}Some rules failed validation.{Colors.RESET}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
