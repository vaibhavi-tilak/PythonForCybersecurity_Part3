# Cybersecurity with Python - Part 3: Utilizing Regular Expressions in Python for Pattern Identification

Welcome to Part 3 of the **Cybersecurity with Python** series! In this tutorial, we explore how to use Python’s powerful **regular expressions (RegEx)** module to extract critical patterns from text, such as IP addresses in log files and Personally Identifiable Information (PII) in codebases.

---

## Introduction

Regular Expressions (RegEx) provide a flexible and efficient way to search, match, and manipulate textual data. The Python `re` module makes it easy to define custom patterns to identify data like IP addresses or sensitive PII data such as emails and phone numbers.

---
![Alt text](https://github.com/vaibhavi-tilak/PythonForCybersecurity_Part3/blob/main/image.png)

## Table of Contents

1. [Identifying IP Addresses in Log Files](#identifying-ip-addresses-in-log-files)  
2. [Detecting PII Data in Code](#detecting-pii-data-in-code)  

---

## Identifying IP Addresses in Log Files

Network logs often contain IP addresses which are essential for security monitoring, incident response, and troubleshooting. This section shows how to extract and validate IPv4 addresses even if log data is unstructured.

### RegEx Pattern for IPv4 Addresses

An IPv4 address follows the format: `xxx.xxx.xxx.xxx` where each `xxx` is a number from 0 to 255.

```

import re

def extract_ip_addresses(log_data):
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ip_addresses = re.findall(ip_pattern, log_data)
return ip_addresses

```

### IP Validation

The above pattern may capture invalid IPs (e.g., `256.300.1.2`). Using the `ipaddress` module ensures only valid IPs are kept:

```

import ipaddress

def validate_ip(ip_addresses):
valid_ips = []
for ip in ip_addresses:
try:
ipaddress.IPv4Address(ip)  \# Raises ValueError if invalid
valid_ips.append(ip)
except ValueError:
continue
return valid_ips

```

### Full Example: Extract & Validate IPs from a Log File

```

import re
import ipaddress

def extract_ip_addresses(log_data):
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
return re.findall(ip_pattern, log_data)

def validate_ip(ip_addresses):
valid_ips = []
for ip in ip_addresses:
try:
ipaddress.IPv4Address(ip)
valid_ips.append(ip)
except ValueError:
pass
return valid_ips

# Read log data

with open("Logfile.txt", "r") as file:
log_data = file.read()

# Extract and validate IPs

raw_ips = extract_ip_addresses(log_data)
valid_ips = validate_ip(raw_ips)

print("Extracted \& Validated IP Addresses:")
for ip in sorted(set(valid_ips)):
print(ip)

```

---

## Detecting PII Data in Code

PII such as emails, phone numbers, and Social Security Numbers (SSNs) may sometimes leak into source code. RegEx helps locate these sensitive details for remediation.

### Common PII Patterns

| Data Type    | Regex Pattern                                  |
|--------------|-----------------------------------------------|
| Email        | `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`  |
| Phone Number | `\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`                |
| SSN          | `\b\d{3}-\d{2}-\d{4}\b`                        |

### PII Detection Function

```

import re

def detect_pii(code_text):
patterns = {
"Email": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
"Phone Number": r'$?\d{3}$?[-.\s]?\d{3}[-.\s]?\d{4}',
"SSN": r'\b\d{3}-\d{2}-\d{4}\b'
}

    pii_found = {}
    for key, pattern in patterns.items():
        matches = re.findall(pattern, code_text)
        if matches:
            pii_found[key] = matches
    
    return pii_found
```

### Example Usage

```

code_sample = """
user_email = "john.doe@example.com"
phone_number = "(123) 456-7890"
ssn = "987-65-4321"
"""

pii_data = detect_pii(code_sample)
print("Detected PII Data:", pii_data)

```
## Summary

Regular expressions offer a powerful way to identify patterns in data—crucial for cybersecurity tasks such as:

- Extracting valid IP addresses from logs for monitoring and investigation
- Detecting sensitive PII in code to enhance compliance and security  

Leveraging Python’s `re` module combined with validation libraries enables robust and scalable solutions.

---




# *Happy Coding!*  
*— Vai (Vaibhavi Tilak)*


### How to use

1. Save your logs to `Logfile.txt` in the repository root.  
2. Run the Python scripts to extract and validate IP addresses.  
3. Use the PII detection function to scan code or text data for sensitive information.


