# IoC Extractor Lab

Real-world IoC (Indicators of Compromise) extraction using actual attack patterns.

## Attack Scenarios Included

### 1. SSH Brute Force Attack
- Multiple failed login attempts from malicious IPs
- Targeted usernames: root, admin, ubuntu, dell
- Realistic attacker behavior

### 2. Web Application Attack
- SQL injection attempts (`' OR '1'='1`)
- XSS attempts (`<script>alert(1)</script>`)
- Directory traversal (`../../etc/passwd`)
- File injection

## Run the Lab

```bash
# Install dependencies (none needed, uses Python standard library)
python3 ioc_extractor.py sample_logs/brute_force_attack.log

python3 ioc_extractor.py sample_logs/web_attack.log
