#!/usr/bin/env python3
"""
Real-World IoC Extractor
Extracts indicators from attack logs for threat intelligence
"""

import re
import sys
import json
from datetime import datetime
from collections import Counter

class RealWorldIoCExtractor:
    def __init__(self):
        self.iocs = {
            'malicious_ips': set(),
            'targeted_users': set(),
            'attack_patterns': set(),
            'timeline': [],
        }
    
    def extract_ips(self, text):
        """Extract attacker IPs"""
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        return set(re.findall(pattern, text))
    
    def extract_targeted_users(self, text):
        """Extract usernames being attacked"""
        patterns = [
            r'for (\S+) from',
            r'user=(\S+)',
            r'user (\S+)',
        ]
        users = set()
        for pattern in patterns:
            users.update(re.findall(pattern, text))
        return {u for u in users if len(u) > 1 and len(u) < 30}
    
    def extract_attack_patterns(self, text):
        """Classify attack types"""
        patterns = set()
        if re.search(r'Failed password', text):
            patterns.add('Brute Force SSH')
        if re.search(r"' OR '1'='1|UNION SELECT", text, re.IGNORECASE):
            patterns.add('SQL Injection')
        if re.search(r'<script|alert\(', text, re.IGNORECASE):
            patterns.add('XSS')
        if re.search(r'\.\./\.\./', text):
            patterns.add('Directory Traversal')
        return patterns
    
    def analyze_log(self, logfile):
        """Analyze log file and extract IoCs"""
        with open(logfile, 'r') as f:
            content = f.read()
        
        self.iocs['malicious_ips'] = self.extract_ips(content)
        self.iocs['targeted_users'] = self.extract_targeted_users(content)
        self.iocs['attack_patterns'] = self.extract_attack_patterns(content)
        
        # Build timeline
        lines = content.strip().split('\n')
        for line in lines[:20]:
            timestamp_match = re.search(r'\[(\d+/\w+/\d+:\d+:\d+)', line)
            if timestamp_match:
                self.iocs['timeline'].append({
                    'time': timestamp_match.group(1),
                    'event': line[:100]
                })
    
    def generate_report(self, output_format='text'):
        """Generate threat report"""
        report = []
        report.append("="*60)
        report.append("REAL-WORLD IoC EXTRACTION REPORT")
        report.append(f"Generated: {datetime.now()}")
        report.append("="*60)
        
        report.append("\n📌 ATTACKER INFRASTRUCTURE")
        report.append(f"   Malicious IPs detected: {len(self.iocs['malicious_ips'])}")
        for ip in self.iocs['malicious_ips']:
            report.append(f"   - {ip}")
        
        report.append("\n🎯 TARGETED ASSETS")
        report.append(f"   Usernames targeted: {len(self.iocs['targeted_users'])}")
        for user in self.iocs['targeted_users']:
            report.append(f"   - {user}")
        
        report.append("\n⚔️ ATTACK PATTERNS")
        for pattern in self.iocs['attack_patterns']:
            report.append(f"   - {pattern}")
        
        report.append("\n⏱️ INCIDENT TIMELINE (First 10 events)")
        for event in self.iocs['timeline'][:10]:
            report.append(f"   [{event['time']}] {event['event'][:80]}...")
        
        report.append("\n" + "="*60)
        report.append("RECOMMENDATIONS")
        report.append("1. Block identified malicious IPs at firewall level")
        report.append("2. Review accounts that were targeted for compromise")
        report.append("3. Implement rate limiting for authentication endpoints")
        report.append("4. Deploy WAF rules to block SQL injection patterns")
        report.append("="*60)
        
        return '\n'.join(report)
    
    def export_json(self):
        """Export IoCs as JSON for integration"""
        return json.dumps({
            'malicious_ips': list(self.iocs['malicious_ips']),
            'targeted_users': list(self.iocs['targeted_users']),
            'attack_patterns': list(self.iocs['attack_patterns']),
            'timestamp': datetime.now().isoformat()
        }, indent=2)

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 ioc_extractor.py <log_file>")
        print("\nTry with sample logs:")
        print("  python3 ioc_extractor.py sample_logs/brute_force_attack.log")
        print("  python3 ioc_extractor.py sample_logs/web_attack.log")
        sys.exit(1)
    
    logfile = sys.argv[1]
    extractor = RealWorldIoCExtractor()
    
    try:
        extractor.analyze_log(logfile)
        print(extractor.generate_report())
        
        # Save JSON
        json_output = extractor.export_json()
        with open('ioc_report.json', 'w') as f:
            f.write(json_output)
        print("\n✅ JSON report saved to: ioc_report.json")
        
    except FileNotFoundError:
        print(f"File not found: {logfile}")

if __name__ == '__main__':
    main()
