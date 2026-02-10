import json
import logging
import os
import re
from datetime import datetime
from logging.handlers import RotatingFileHandler

class HoneyLogger:
    def __init__(self, log_dir='logs', log_file='banking_logs.json'):
        self.log_dir = log_dir
        self.log_file = os.path.join(log_dir, log_file)
        
        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

        self._setup_logging()

        # Attack patterns
        self.patterns = {
            'sqli': [
                r"(\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER)\b)",
                r"('|\"|;|--|\/\*|\*\/)",
                r"(\bOR\s+1\s*=\s*1\b)",
                r"(\bAND\s+1\s*=\s*1\b)"
            ],
            'xss': [
                r"(<script.*?>.*?<\/script>)",
                r"(javascript:)",
                r"(onerror\s*=\s*)",
                r"(onload\s*=\s*)",
                r"(onclick\s*=\s*)",
                r"(<img\s+src=)",
                r"(<iframe\s+src=)"
            ],
            'cmd_injection': [
                r"(;|&&|\|\||`|\$\(.*\))",
                r"(\b(cat|ls|pwd|whoami|id|net|wget|curl|ping)\b)"
            ],
            'path_traversal': [
                r"(\.\.\/|\.\.\\)",
                r"(%2e%2e%2f|%2e%2e%5c)",
                r"(\/etc\/passwd|\/windows\/system32)"
            ]
        }

    def _setup_logging(self):
        # Configure JSON logging
        self.logger = logging.getLogger('HoneyLogger')
        self.logger.setLevel(logging.INFO)
        
        # Avoid duplicate handlers
        if not self.logger.handlers:
            handler = RotatingFileHandler(
                self.log_file, 
                maxBytes=10*1024*1024, # 10MB
                backupCount=5,
                encoding='utf-8'
            )
            # Custom formatter to just print the JSON
            handler.setFormatter(logging.Formatter('%(message)s'))
            self.logger.addHandler(handler)

    def _detect_attacks(self, data_str):
        """Scan input string for attack patterns"""
        detected = []
        if not data_str:
            return detected
            
        data_lower = str(data_str).lower()
        
        for attack_type, regex_list in self.patterns.items():
            for pattern in regex_list:
                if re.search(pattern, data_lower, re.IGNORECASE):
                    detected.append(attack_type)
                    break 
        
        return list(set(detected))

    def log_event(self, timestamp, ip, endpoint, method, event_type, details, severity='low'):
        """
        Log a structured event.
        - Detects attacks in 'details' automatically if event_type is generic 'request'
        - Calculates severity based on detected attacks
        """
        
        # Consolidate detail values for scanning
        scan_content = ""
        if isinstance(details, dict):
            scan_content = " ".join([str(v) for v in details.values()])
        elif isinstance(details, str):
            scan_content = details

        # Auto-detect attacks
        detected_attacks = self._detect_attacks(scan_content)
        
        if detected_attacks:
             # Escalating severity if attack found
             severity = 'high'
             if event_type == 'request':
                 event_type = 'attack_detected'
             details['detected_attacks'] = detected_attacks

        # Ensure details is a dict
        if not isinstance(details, dict):
            details = {"payload": str(details)}

        log_entry = {
            "timestamp": timestamp,
            "ip": ip,
            "endpoint": endpoint,
            "method": method,
            "event_type": event_type,
            "severity": severity,
            "details": details
        }
        
        try:
            self.logger.info(json.dumps(log_entry))
        except Exception as e:
            # Fallback print if logging fails
            print(f"Logging error: {e}")

        return log_entry
