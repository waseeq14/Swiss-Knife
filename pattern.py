# pattern.py

# Patterns for Identifying Sensitive Information
SENSITIVE_PATTERNS = [
    r'(?i)username\s*[:=]\s*[\'"].+?[\'"]',
    r'(?i)password\s*[:=]\s*[\'"].+?[\'"]',
    r'(?i)secret\s*[:=]\s*[\'"].+?[\'"]',
    r'(?i)token\s*[:=]\s*[\'"].+?[\'"]',
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'[\w-]+@([\w-]+\.)+[\w-]+',  # Email addresses
    r'password\s*=\s*["\'].*["\']',  # Password assignments
    r'api[_-]?key["\']?\s*[:=]\s*["\'][a-zA-Z0-9]{32}["\']',  # API keys
]