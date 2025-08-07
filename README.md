<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# make a README.md file for  this code also add a picture in it Cybersecurity with Python- Part 3 : Utilizing Regular Expressions in Python for Pattern Identification

[](https://medium.com/@vaibhavitilak17?source=post_page---byline--bbf0bd8037aa---------------------------------------)
[Vaibhavi Tilak](https://medium.com/@vaibhavitilak17?source=post_page---byline--bbf0bd8037aa---------------------------------------)
3 min read
·
Apr 16, 2025
[](https://medium.com/plans?dimension=post_audio_button&postId=bbf0bd8037aa&source=upgrade_membership---post_audio_button-----------------------------------------)
Introduction to Regular Expressions (RegEx)
Regular Expressions (RegEx) in Python provide a powerful way to search, match, and manipulate text. The re module in Python allows developers to define patterns to extract specific types of data, such as IP addresses in log analysis or Personally Identifiable Information (PII) in codebases.
Press enter or click to view image in full size
In this article, we will explore two practical applications of RegEx in Python:
Identifying IP addresses in log files for security monitoring.
Detecting PII data within code to enhance security and compliance.

1. Identifying IP Addresses in Log Files
Analyzing logs is crucial for identifying security incidents, monitoring network activity, and troubleshooting issues. One of the key aspects of log analysis is extracting IP addresses from log entries.
RegEx Pattern for IPv4 Address, when the logfile is not formatted
An IPv4 address follows the format: xxx.xxx.xxx.xxx, where each xxx is a number ranging from 0 to 255. The corresponding RegEx pattern to capture an IPv4 address is:
import re

def extract_ip_addresses(log_data):
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ip_addresses = re.findall(ip_pattern, log_data)
return ip_addresses
Explanation of the RegEx Pattern:
(?:[0-9]{1,3}\.){3}: Matches three groups of 1-3 digits followed by a dot.
[0-9]{1,3}: Matches the last set of 1-3 digits.
\b: Ensures the match is a standalone word.
Filtering Valid IPs
Since the pattern may also match invalid IPs (e.g., 256.300.1.2), further validation can be done using Python’s ipaddress module.
import ipaddress

def validate_ip(ip_addresses):
return [ip for ip in ip_addresses if all(0 <= int(octet) <= 255 for octet in ip.split('.'))]
import re
import ipaddress
def extract_ip_addresses(log_data):
\# Regex pattern to match IPv4 addresses
ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
ip_addresses = re.findall(ip_pattern, log_data)
return ip_addresses
def validate_ip(ip_addresses):
\# Validate each IP using the ipaddress library for 100% correctness
valid_ips = []
for ip in ip_addresses:
try:
ipaddress.IPv4Address(ip)  \# Raises ValueError if invalid
valid_ips.append(ip)
except ValueError:
continue
return valid_ips

# Read the log file

with open("Logfile.txt", "r") as file:
log_data = file.read()

# Extract IPs

raw_ips = extract_ip_addresses(log_data)

# Validate IPs

valid_ips = validate_ip(raw_ips)

# Display the result

print("Extracted \& Validated IP Addresses:")
for ip in sorted(set(valid_ips)):
print(ip)
2. Detecting PII Data in Code
PII data such as email addresses, phone numbers, and Social Security Numbers (SSNs) can accidentally be stored in code repositories, leading to security risks. RegEx can help identify such sensitive data.
RegEx Pattern for PII Detection
Common PII patterns include:
Email Addresses: [a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}
Phone Numbers (US Format): $?\d{3}$?[-.\s]?\d{3}[-.\s]?\d{4}
SSNs (US Format): \b\d{3}-\d{2}-\d{4}\b
Python Code to Detect PII
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
    
# Example Code Snippet

code_sample = """
user_email = "john.doe@example.com"
phone_number = "(123) 456-7890"
ssn = "987-65-4321"
"""\# Detect PII in Code
pii_data = detect_pii(code_sample)
print("Detected PII Data:", pii_data)
Explanation:
The function detect_pii scans the given text using multiple RegEx patterns.
It returns any detected PII, which can then be flagged for remediation.
Regular Expressions in Python are an essential tool for pattern recognition. Whether analyzing logs for security incidents or ensuring compliance by detecting PII in code, RegEx provides an efficient and scalable solution. Implementing these techniques can help strengthen security monitoring and data protection efforts.

```markdown
# Cybersecurity with Python - Part 3: Utilizing Regular Expressions in Python for Pattern Identification

Welcome to Part 3 of the **Cybersecurity with Python** series! In this tutorial, we explore how to use Python’s powerful **regular expressions (RegEx)** module to extract critical patterns from text, such as IP addresses in log files and Personally Identifiable Information (PII) in codebases.

---

## Introduction

Regular Expressions (RegEx) provide a flexible and efficient way to search, match, and manipulate textual data. The Python `re` module makes it easy to define custom patterns to identify data like IP addresses or sensitive PII data such as emails and phone numbers.

---

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

---

## Summary

Regular expressions offer a powerful way to identify patterns in data—crucial for cybersecurity tasks such as:

- Extracting valid IP addresses from logs for monitoring and investigation
- Detecting sensitive PII in code to enhance compliance and security  

Leveraging Python’s `re` module combined with validation libraries enables robust and scalable solutions.

---

## Visual Overview

![Regular Expressions in Python for Security](https://miro.medium.com/max/1400/1*CPiEj0KdSChn1-U7-KVUBA.png)

*Example of RegEx pattern matching in Python*

---

## References & Further Reading

- [Python re module documentation](https://docs.python.org/3/library/re.html)  
- [Python ipaddress module](https://docs.python.org/3/library/ipaddress.html)  
- [Medium article by Vaibhavi Tilak](https://medium.com/@vaibhavitilak17)

---

*Happy Coding!*  
*— Vai (Vaibhavi Tilak)*

---

### How to use

1. Save your logs to `Logfile.txt` in the repository root.  
2. Run the Python scripts to extract and validate IP addresses.  
3. Use the PII detection function to scan code or text data for sensitive information.

---

If you want help with adding more advanced examples or integrating these scripts into your security workflow, feel free to ask!
```

<div style="text-align: center">⁂</div>

[^1]: https://medium.com/@vaibhavitilak17

