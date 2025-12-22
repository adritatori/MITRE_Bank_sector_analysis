# NIDS Classification Guide for MITRE ATT&CK Techniques

## Overview

This document provides a comprehensive classification of MITRE ATT&CK techniques based on their detectability by Network Intrusion Detection Systems (NIDS). The classification helps security teams understand which adversary techniques generate observable network traffic and can be detected through network monitoring.

## Classification Methodology

### Classification Categories

#### YES - Network Observable
Techniques that **definitively** generate network traffic that NIDS can observe and analyze.

**Criteria:**
- Requires network communication (Command & Control, data transfer, remote access)
- Uses identifiable network protocols (HTTP, DNS, SMB, RDP, SSH, FTP, etc.)
- Involves traffic between hosts or to external servers
- Network artifacts are consistently present when technique is used

**Examples:**
- `T1105` - Ingress Tool Transfer: File downloads over HTTP/FTP/SMB
- `T1071.001` - Web Protocols: C2 communications via HTTP/HTTPS
- `T1021.001` - Remote Desktop Protocol: RDP connections on port 3389
- `T1566.001` - Spearphishing Attachment: SMTP email traffic

#### PARTIAL - Context Dependent
Techniques that **may or may not** generate network traffic depending on implementation or configuration.

**Criteria:**
- Has both network-based and local-only variants
- Network component is optional or situational
- Detection depends on adversary's implementation choices
- May involve local operations that could be performed remotely

**Examples:**
- `T1078` - Valid Accounts: Local login (no network) vs remote login (network observable)
- `T1110` - Brute Force: Local password cracking vs remote authentication attempts
- `T1562.004` - Disable Firewall: Local change, but may cause observable traffic pattern changes
- `T1204.001` - Malicious Link: Click generates HTTP requests to malicious URLs

#### NO - Host-Based Only
Techniques that are **purely local** operations with no inherent network component.

**Criteria:**
- Local file operations only
- Registry/memory manipulation
- Process-level activities
- No network communication required or generated
- NIDS cannot observe these activities

**Examples:**
- `T1112` - Modify Registry: Local Windows Registry changes
- `T1055` - Process Injection: Memory-based code injection
- `T1059.001` - PowerShell: Local script execution
- `T1070.004` - File Deletion: Local file system operations

## Network Artifacts by Technique Type

### Command & Control (C2) Techniques
| Technique | Network Artifact | Detection Opportunity |
|-----------|------------------|----------------------|
| Web Protocols (T1071.001) | HTTP/HTTPS POST/GET to C2 | Unusual domains, beaconing patterns, suspicious user-agents |
| DNS (T1071.004) | High volume DNS queries | Long subdomains, TXT record queries, unusual query patterns |
| Protocol Tunneling (T1572) | Encapsulated protocols | Protocol on wrong port, nested protocols |
| Non-Standard Port (T1571) | Known protocol on unusual port | Port/protocol mismatch, non-ephemeral high ports |

### Lateral Movement Techniques
| Technique | Network Artifact | Detection Opportunity |
|-----------|------------------|----------------------|
| RDP (T1021.001) | RDP on port 3389 | Unusual source/destination pairs, off-hours access |
| SMB/Admin Shares (T1021.002) | SMB on ports 445/139 | Admin share access, multiple failed authentications |
| SSH (T1021.004) | SSH on port 22 | Unusual SSH sessions, key-based auth from new sources |
| WinRM (T1021.006) | HTTP(S) on 5985/5986 | PowerShell remoting traffic, unusual endpoints |

### Exfiltration Techniques
| Technique | Network Artifact | Detection Opportunity |
|-----------|------------------|----------------------|
| Exfiltration Over C2 (T1041) | Large outbound transfers | Volume anomalies, encrypted uploads to C2 |
| Alternative Protocols (T1048) | DNS/ICMP tunneling | Oversized packets, unusual protocol usage patterns |
| Automated Exfiltration (T1020) | Scheduled large transfers | Regular beacon intervals with data uploads |

### Initial Access Techniques
| Technique | Network Artifact | Detection Opportunity |
|-----------|------------------|----------------------|
| Spearphishing Attachment (T1566.001) | SMTP with attachments | Suspicious attachment types, sender reputation |
| Spearphishing Link (T1566.002) | SMTP + HTTP redirects | Malicious URLs, redirect chains, suspicious domains |
| Exploit Public-Facing App | HTTP exploitation attempts | SQL injection, XSS, buffer overflow patterns |

### Discovery Techniques
| Technique | Network Artifact | Detection Opportunity |
|-----------|------------------|----------------------|
| Network Scanning (T1046) | SYN scans, service probes | Port sweeps, rapid connection attempts |
| Remote System Discovery (T1018) | NetBIOS, LDAP, ARP | Enumeration traffic, unusual query volumes |
| Network Share Discovery (T1135) | SMB/CIFS queries | Share enumeration, null session attempts |
| Network Sniffing (T1040) | Promiscuous mode | ARP spoofing indicators, unusual traffic patterns |

## NIDS Detection Strategies

### Signature-Based Detection
- **Protocol violations**: Malformed packets, non-standard protocol usage
- **Known malware C2**: IP/domain blacklists, known C2 beacons
- **Exploit patterns**: CVE-specific signatures, shellcode patterns

### Anomaly-Based Detection
- **Traffic volume**: Unusual upload/download volumes
- **Timing patterns**: Beaconing intervals, regular scheduled activity
- **Protocol anomalies**: Wrong port usage, unexpected protocols
- **Geolocation**: Connections to suspicious countries/ASNs

### Behavioral Detection
- **Lateral movement**: Unusual internal host-to-host communication
- **Data staging**: Large internal file transfers before exfiltration
- **Reconnaissance**: Port scanning, service enumeration patterns
- **Authentication**: Multiple failed logins, credential spraying

## Statistical Summary

Based on analysis of 217 MITRE ATT&CK techniques relevant to banking sector threats:

```
Classification Breakdown:
┌────────────┬───────┬─────────┐
│ Category   │ Count │ Percent │
├────────────┼───────┼─────────┤
│ YES        │    18 │   8.3%  │
│ PARTIAL    │    56 │  25.8%  │
│ NO         │   143 │  65.9%  │
└────────────┴───────┴─────────┘
```

### Key Findings

1. **Network Observable (YES - 8.3%)**: Only 18 techniques consistently generate network traffic. These should be high-priority targets for NIDS monitoring.

2. **Context Dependent (PARTIAL - 25.8%)**: 56 techniques may generate network traffic depending on implementation. These require both network and host-based monitoring.

3. **Host-Based Only (NO - 65.9%)**: The majority (143 techniques) are purely host-based and cannot be detected by NIDS alone. These require endpoint detection and response (EDR) solutions.

### Implications for Defense

**NIDS Alone is Insufficient**: With 66% of techniques being host-based, network monitoring must be complemented with:
- Endpoint Detection and Response (EDR)
- Security Information and Event Management (SIEM)
- Host-based Intrusion Detection Systems (HIDS)
- Application monitoring and logging

**Layered Defense Required**: Effective threat detection requires:
1. **Network Layer**: NIDS for C2, lateral movement, exfiltration
2. **Host Layer**: EDR for execution, persistence, privilege escalation
3. **Application Layer**: WAF, API monitoring, database activity monitoring
4. **Identity Layer**: IAM monitoring, authentication analytics

**High-Value NIDS Targets**: Focus network monitoring on:
- Command & Control communications (highest ROI)
- Lateral movement attempts
- Data exfiltration activities
- Initial access attempts (phishing, exploitation)

## Recommended NIDS Rules

### Priority 1 - Command & Control Detection
```
alert http any any -> any any (msg:"Possible C2 Beacon"; flow:established,to_server; content:"POST"; http_method; byte_test:4,<,100,0,relative; threshold:type both,track by_src,count 10,seconds 300; classtype:trojan-activity; sid:1000001;)

alert dns any any -> any 53 (msg:"Possible DNS Tunneling"; dsize:>100; threshold:type both,track by_src,count 50,seconds 60; classtype:trojan-activity; sid:1000002;)
```

### Priority 2 - Lateral Movement Detection
```
alert smb any any -> any 445 (msg:"SMB Admin Share Access"; smb.share:"C$","ADMIN$","IPC$"; threshold:type both,track by_src,count 5,seconds 300; classtype:attempted-admin; sid:1000003;)

alert rdp any any -> any 3389 (msg:"Multiple RDP Connections"; threshold:type both,track by_src,count 5,seconds 300; classtype:attempted-admin; sid:1000004;)
```

### Priority 3 - Exfiltration Detection
```
alert tcp any any -> any any (msg:"Large Outbound Transfer"; byte_test:4,>,10485760,0,relative; threshold:type threshold,track by_src,count 1,seconds 60; classtype:policy-violation; sid:1000005;)
```

## Tools and Technologies

### Recommended NIDS Solutions
- **Suricata**: Open-source IDS/IPS with protocol analysis
- **Snort**: Popular signature-based NIDS
- **Zeek (Bro)**: Network security monitoring platform
- **Cisco Firepower**: Commercial NGFW with IPS
- **Palo Alto Networks**: Advanced threat prevention

### Complementary Technologies
- **NetFlow/IPFIX**: Network flow analysis for anomaly detection
- **Full Packet Capture**: Forensic analysis capability
- **Threat Intelligence Feeds**: IP/domain reputation data
- **Machine Learning**: Behavioral anomaly detection

## Usage Instructions

### Accessing the Data

The complete NIDS classification is available in:
```
banking_analysis_nids_classified_YYYYMMDD_HHMMSS.csv
```

### CSV Column Descriptions

| Column | Description |
|--------|-------------|
| `technique_id` | MITRE ATT&CK technique identifier |
| `name` | Technique name |
| `description` | Full technique description |
| `tactics_str` | MITRE ATT&CK tactics |
| `platforms` | Affected platforms |
| `NIDS_Classification` | YES / PARTIAL / NO classification |
| `NIDS_Reasoning` | Brief explanation of classification (max 15 words) |
| `Network_Artifact` | Specific network indicators NIDS would observe |

### Filtering Examples

**Get all network-observable techniques:**
```bash
grep ",YES," banking_analysis_nids_classified_*.csv
```

**Get partial techniques requiring context:**
```bash
grep ",PARTIAL," banking_analysis_nids_classified_*.csv
```

**Get techniques by tactic (e.g., command-and-control):**
```bash
grep "command-and-control" banking_analysis_nids_classified_*.csv | grep ",YES,"
```

### Python Analysis Example
```python
import pandas as pd

df = pd.read_csv('banking_analysis_nids_classified_*.csv')

# Get all YES techniques with network artifacts
nids_detectable = df[df['NIDS_Classification'] == 'YES'][
    ['technique_id', 'name', 'Network_Artifact']
]

# Analyze by tactic
c2_techniques = df[df['tactics_str'].str.contains('command-and-control', na=False)]
print(f"C2 Techniques - NIDS Detectable: {len(c2_techniques[c2_techniques['NIDS_Classification']=='YES'])}")
```

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [MITRE ATT&CK for ICS](https://attack.mitre.org/techniques/ics/)
- [Suricata Rules Documentation](https://suricata.readthedocs.io/en/latest/rules/)
- [Zeek Network Security Monitor](https://zeek.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)

## Contributing

To update or refine classifications:
1. Review technique descriptions in MITRE ATT&CK
2. Update `nids_classifier.py` with new mappings
3. Re-run: `python3 nids_classifier.py`
4. Validate output against known attack patterns

## Version History

- **v1.0** (2025-12-22): Initial NIDS classification of 217 banking sector techniques
  - 18 YES (network observable)
  - 56 PARTIAL (context dependent)
  - 143 NO (host-based only)

---

**Classification Date**: 2025-12-22
**Techniques Analyzed**: 217
**Framework Version**: MITRE ATT&CK v15
**Focus**: Banking Sector Threats
