#!/usr/bin/env python3
"""
NIDS Classification for MITRE ATT&CK Techniques
Classifies techniques based on network traffic observability
"""

import pandas as pd
from datetime import datetime

def classify_technique(technique_id, name, description):
    """
    Classify MITRE ATT&CK technique for NIDS detectability
    Returns: (classification, reasoning, network_artifact)
    """

    # YES - Generates network traffic
    network_techniques = {
        'T1105': ('YES', 'File transfer over network protocols', 'HTTP/HTTPS, FTP, SMB traffic with file transfers'),
        'T1071.001': ('YES', 'C2 using HTTP/HTTPS web protocols', 'HTTP/HTTPS POST/GET requests to C2 servers'),
        'T1021.001': ('YES', 'Remote desktop protocol connections', 'RDP traffic on port 3389, encrypted session data'),
        'T1018': ('YES', 'Network scanning and enumeration commands', 'ICMP, ARP, NetBIOS, LDAP queries for host discovery'),
        'T1566.001': ('YES', 'Email with malicious attachments', 'SMTP traffic with attachments, email headers'),
        'T1566.002': ('YES', 'Email with malicious links', 'SMTP traffic, HTTP redirects, DNS queries'),
        'T1071': ('YES', 'Application layer C2 protocols', 'HTTP/HTTPS, DNS, FTP, SMTP protocol anomalies'),
        'T1020': ('YES', 'Automated data collection and exfiltration', 'Large outbound data transfers, unusual protocols'),
        'T1041': ('YES', 'Data exfiltration over C2 channel', 'Encrypted outbound traffic, large data volumes'),
        'T1048': ('YES', 'Exfiltration over alternative protocols', 'DNS tunneling, ICMP tunneling, non-standard ports'),
        'T1071.004': ('YES', 'C2 using DNS protocol', 'High volume DNS queries, long domain names, TXT records'),
        'T1021.002': ('YES', 'SMB/Windows Admin Shares access', 'SMB traffic on ports 445/139, authentication attempts'),
        'T1021.004': ('YES', 'SSH remote access', 'SSH traffic on port 22, encrypted sessions'),
        'T1021.006': ('YES', 'Windows Remote Management', 'WinRM traffic on ports 5985/5986, HTTP(S) protocol'),
        'T1219': ('YES', 'Remote access software usage', 'TeamViewer, VNC, AnyDesk network traffic'),
        'T1572': ('YES', 'Protocol tunneling for C2', 'Encapsulated protocols, unusual port/protocol combinations'),
        'T1090': ('YES', 'Proxy usage for C2', 'Traffic to known proxy IPs, SOCKS/HTTP proxy protocols'),
        'T1571': ('YES', 'Non-standard ports for C2', 'Known protocols on unusual ports, custom protocols'),
        'T1095': ('YES', 'Non-application layer protocols', 'Raw socket traffic, custom network protocols'),
        'T1110': ('PARTIAL', 'Brute force can be local or remote', 'Multiple failed auth attempts via SMB, RDP, SSH, LDAP'),
        'T1110.001': ('PARTIAL', 'Password guessing, may use network auth', 'Failed authentication attempts over network protocols'),
        'T1110.002': ('PARTIAL', 'Password cracking, local or remote', 'High volume authentication attempts if network-based'),
        'T1110.003': ('PARTIAL', 'Password spraying against network services', 'Multiple login attempts across accounts, SMB, LDAP, HTTP'),
        'T1046': ('YES', 'Network port and service scanning', 'SYN scans, service probes, port sweep traffic'),
        'T1049': ('PARTIAL', 'Network connection enumeration, local or remote', 'NetBIOS, SMB queries if remote, none if local commands'),
        'T1016': ('PARTIAL', 'Network config discovery, usually local', 'DHCP requests, ARP queries if network enumeration occurs'),
        'T1135': ('PARTIAL', 'Network share discovery', 'SMB/CIFS queries, NetBIOS enumeration traffic'),
        'T1040': ('YES', 'Network sniffing and packet capture', 'Promiscuous mode traffic, ARP spoofing indicators'),
        'T1557': ('YES', 'Man-in-the-middle attacks', 'ARP spoofing, DNS spoofing, rogue DHCP responses'),
        'T1557.001': ('YES', 'LLMNR/NBT-NS poisoning', 'Spoofed LLMNR/NBT-NS responses, name resolution anomalies'),
        'T1557.002': ('YES', 'ARP cache poisoning', 'Duplicate ARP responses, MAC address conflicts'),
        # FIXES - Previously misclassified
        'T1550.002': ('YES', 'Pass the hash authentication over network', 'NTLM authentication attempts, SMB, LDAP traffic'),
        'T1570': ('YES', 'Lateral tool transfer between systems', 'SMB, RDP, SSH file transfers between internal hosts'),
        'T1030': ('YES', 'Data exfiltration with size limits', 'Multiple small outbound transfers, staged data uploads'),
        'T1573.001': ('YES', 'Encrypted C2 network traffic', 'TLS/SSL encrypted sessions, custom encryption over network'),
        'T1090.002': ('YES', 'External proxy for C2 traffic', 'Connections to proxy servers, forwarded C2 traffic'),
        'T1132.001': ('YES', 'Encoded C2 network traffic', 'Base64, hex encoded payloads in HTTP/DNS/other protocols'),
    }

    # NO - Host-based only
    host_only_techniques = {
        'T1562.001': ('NO', 'Disabling security tools is local host activity', ''),
        'T1070.004': ('NO', 'Local file deletion operations only', ''),
        'T1140': ('NO', 'Local file deobfuscation and decoding', ''),
        'T1218.011': ('NO', 'Local process execution via rundll32', ''),
        'T1553.002': ('NO', 'Code signing is local file operation', ''),
        'T1112': ('NO', 'Registry modification is local to host', ''),
        'T1027.010': ('NO', 'Command obfuscation in local shell', ''),
        'T1036.005': ('NO', 'File renaming and placement locally', ''),
        'T1055': ('NO', 'Process injection is memory-based, local', ''),
        'T1027.013': ('NO', 'File encryption is local operation', ''),
        'T1082': ('NO', 'Local system information gathering', ''),
        'T1027.002': ('NO', 'Software packing is local file operation', ''),
        'T1543.003': ('NO', 'Windows service creation is local', ''),
        'T1055.001': ('NO', 'DLL injection into local processes', ''),
        'T1053.005': ('NO', 'Scheduled task creation locally', ''),
        'T1204.002': ('NO', 'User execution of malicious file locally', ''),
        'T1059.001': ('NO', 'PowerShell execution on local host', ''),
        'T1059.003': ('NO', 'Command shell execution locally', ''),
        'T1547.001': ('NO', 'Registry run keys are local persistence', ''),
        'T1036.004': ('NO', 'Service masquerading is local operation', ''),
        'T1562.004': ('PARTIAL', 'Firewall changes local, may block network detection', 'Sudden drop in expected network traffic patterns'),
        'T1057': ('NO', 'Local process enumeration', ''),
        'T1106': ('NO', 'Native API calls are local operations', ''),
        'T1518.001': ('NO', 'Local security software enumeration', ''),
        'T1059.005': ('NO', 'Visual Basic execution locally', ''),
        'T1553.005': ('NO', 'MOTW bypass is local file attribute', ''),
        'T1218.007': ('NO', 'Msiexec execution is local', ''),
        'T1078': ('PARTIAL', 'Valid accounts used locally or remotely', 'Successful auth from unusual locations, off-hours logins'),
        'T1078.002': ('PARTIAL', 'Domain accounts use network authentication', 'Kerberos, LDAP authentication traffic, AD queries'),
        'T1588.002': ('NO', 'Tool acquisition during reconnaissance', ''),
        'T1583.001': ('PARTIAL', 'Domain acquisition may involve network activity', 'DNS registration traffic, domain registrar communications'),
        'T1033': ('NO', 'Local user discovery commands', ''),
        'T1027': ('NO', 'File obfuscation is local operation', ''),
        'T1218.010': ('NO', 'Regsvr32 local proxy execution', ''),
        'T1564.001': ('NO', 'Hidden files are local attributes', ''),
        'T1218.005': ('NO', 'Mshta local execution', ''),
        'T1036.003': ('NO', 'Renaming utilities is local operation', ''),
        'T1218.001': ('NO', 'CHM file execution locally', ''),
        'T1070.006': ('NO', 'Timestomping is local file modification', ''),
        'T1070.001': ('NO', 'Clearing event logs locally', ''),
        'T1005': ('NO', 'Data collection from local filesystem', ''),
        'T1204.001': ('PARTIAL', 'Clicking malicious link triggers network', 'HTTP requests to malicious URLs, redirects, downloads'),
        'T1059.007': ('PARTIAL', 'JavaScript execution, may fetch remote content', 'HTTP requests if script downloads additional payloads'),
        'T1620': ('NO', 'Reflective code loading in memory', ''),
        'T1202': ('NO', 'Indirect command execution locally', ''),
        'T1036.006': ('NO', 'Filename manipulation is local', ''),
        'T1220': ('NO', 'XSL script processing locally', ''),
        'T1027.003': ('NO', 'Steganography in local files', ''),
        'T1027.007': ('NO', 'Dynamic API resolution in memory', ''),
        'T1562.013': ('PARTIAL', 'Network device firewall changes', 'Changes visible in firewall logs, SNMP, config backups'),
        'T1562.003': ('NO', 'Impairing command history locally', ''),
        'T1070': ('NO', 'Indicator removal from local system', ''),
        'T1218.008': ('NO', 'Odbcconf local execution', ''),
        'T1218': ('NO', 'System binary proxy execution locally', ''),
        'T1218.003': ('NO', 'CMSTP local execution', ''),
        'T1027.009': ('NO', 'Embedded payloads in local files', ''),
        'T1070.003': ('NO', 'Clearing command history locally', ''),
        'T1222.001': ('NO', 'File permission changes locally', ''),
        'T1480.002': ('NO', 'Mutex checking in local memory', ''),
        'T1012': ('NO', 'Registry queries are local', ''),
        'T1083': ('NO', 'File and directory discovery locally', ''),
        'T1074.001': ('NO', 'Local data staging in filesystem', ''),
        'T1542.003': ('NO', 'Bootkit modifies local boot sectors', ''),
        'T1036': ('NO', 'Masquerading is local file operation', ''),
    }

    # Check if technique is in our mapping
    if technique_id in network_techniques:
        return network_techniques[technique_id]
    elif technique_id in host_only_techniques:
        return host_only_techniques[technique_id]

    # Additional pattern-based classification for unmapped techniques
    name_lower = name.lower()
    desc_lower = description.lower()

    # Network indicators
    network_keywords = [
        'remote', 'network', 'protocol', 'c2', 'command and control',
        'exfiltration', 'download', 'upload', 'http', 'dns', 'ftp',
        'smb', 'rdp', 'ssh', 'lateral movement', 'communication'
    ]

    # Host-based indicators
    host_keywords = [
        'registry', 'process', 'memory', 'file', 'local', 'execution',
        'api', 'dll', 'service', 'scheduled task', 'powershell',
        'command shell', 'obfuscation', 'encoding', 'packing'
    ]

    network_score = sum(1 for kw in network_keywords if kw in name_lower or kw in desc_lower)
    host_score = sum(1 for kw in host_keywords if kw in name_lower or kw in desc_lower)

    if network_score > host_score and network_score > 0:
        return ('PARTIAL', 'May involve network communication based on implementation', 'Protocol-specific traffic if network variant used')
    else:
        return ('NO', 'Primarily local host-based operations', '')

def main():
    # Read the CSV
    input_file = 'banking_analysis_accurate_20251221_234823_full.csv'
    df = pd.read_csv(input_file)

    print(f"Processing {len(df)} MITRE ATT&CK techniques...")

    # Apply classification
    classifications = []
    for idx, row in df.iterrows():
        tech_id = row['technique_id']
        name = row['name']
        desc = row['description']

        classification, reasoning, artifact = classify_technique(tech_id, name, desc)
        classifications.append({
            'NIDS_Classification': classification,
            'NIDS_Reasoning': reasoning,
            'Network_Artifact': artifact
        })

        if (idx + 1) % 10 == 0:
            print(f"  Processed {idx + 1}/{len(df)} techniques...")

    # Add new columns
    df_classifications = pd.DataFrame(classifications)
    df_enhanced = pd.concat([df, df_classifications], axis=1)

    # Generate output filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = f'banking_analysis_nids_classified_{timestamp}.csv'

    # Save enhanced CSV
    df_enhanced.to_csv(output_file, index=False)

    # Print summary statistics
    print("\n" + "="*80)
    print("NIDS CLASSIFICATION SUMMARY")
    print("="*80)

    class_counts = df_enhanced['NIDS_Classification'].value_counts()
    total = len(df_enhanced)

    print(f"\nTotal Techniques Analyzed: {total}")
    print(f"\nClassification Breakdown:")
    print(f"  YES (Network Observable):     {class_counts.get('YES', 0):3d} ({class_counts.get('YES', 0)/total*100:5.1f}%)")
    print(f"  PARTIAL (Context Dependent):  {class_counts.get('PARTIAL', 0):3d} ({class_counts.get('PARTIAL', 0)/total*100:5.1f}%)")
    print(f"  NO (Host-Based Only):         {class_counts.get('NO', 0):3d} ({class_counts.get('NO', 0)/total*100:5.1f}%)")

    print(f"\nOutput saved to: {output_file}")
    print("\n" + "="*80)

    # Display sample of each classification type
    print("\nSAMPLE CLASSIFICATIONS:\n")

    for classification in ['YES', 'PARTIAL', 'NO']:
        print(f"\n{classification} - Sample Techniques:")
        print("-" * 80)
        sample = df_enhanced[df_enhanced['NIDS_Classification'] == classification].head(3)
        for _, row in sample.iterrows():
            print(f"  {row['technique_id']:12s} {row['name']}")
            print(f"    Reasoning: {row['NIDS_Reasoning']}")
            if row['Network_Artifact']:
                print(f"    Artifact:  {row['Network_Artifact']}")
            print()

if __name__ == '__main__':
    main()
