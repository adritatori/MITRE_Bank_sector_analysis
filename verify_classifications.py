#!/usr/bin/env python3
"""
Verification script to check for potential misclassifications
"""

import pandas as pd

def check_classifications():
    # Find the most recent classification file
    import glob
    files = glob.glob('banking_analysis_nids_classified_*.csv')
    if not files:
        print("ERROR: No classification files found!")
        return []
    latest_file = max(files)
    print(f"Checking file: {latest_file}")
    print()
    df = pd.read_csv(latest_file)

    errors_found = []

    print("="*100)
    print("VERIFICATION: Checking for Potential Misclassifications")
    print("="*100)
    print()

    # Check 1: Techniques with "command-and-control" tactic should likely be YES or PARTIAL
    print("CHECK 1: Command & Control techniques that are marked NO")
    print("-"*100)
    c2_no = df[(df['tactics_str'].str.contains('command-and-control', na=False)) &
               (df['NIDS_Classification'] == 'NO')]

    if len(c2_no) > 0:
        print(f"⚠️  Found {len(c2_no)} C2 techniques marked as NO (should likely be YES/PARTIAL):")
        for _, row in c2_no.iterrows():
            print(f"  - {row['technique_id']:12s} {row['name']}")
            errors_found.append(('C2_AS_NO', row['technique_id'], row['name']))
    else:
        print("✓ No issues found")
    print()

    # Check 2: Techniques with "lateral-movement" tactic should be YES or PARTIAL
    print("CHECK 2: Lateral Movement techniques that are marked NO")
    print("-"*100)
    lateral_no = df[(df['tactics_str'].str.contains('lateral-movement', na=False)) &
                    (df['NIDS_Classification'] == 'NO')]

    if len(lateral_no) > 0:
        print(f"⚠️  Found {len(lateral_no)} Lateral Movement techniques marked as NO:")
        for _, row in lateral_no.iterrows():
            print(f"  - {row['technique_id']:12s} {row['name']}")
            errors_found.append(('LATERAL_AS_NO', row['technique_id'], row['name']))
    else:
        print("✓ No issues found")
    print()

    # Check 3: Techniques with "exfiltration" tactic should be YES or PARTIAL
    print("CHECK 3: Exfiltration techniques that are marked NO")
    print("-"*100)
    exfil_no = df[(df['tactics_str'].str.contains('exfiltration', na=False)) &
                  (df['NIDS_Classification'] == 'NO')]

    if len(exfil_no) > 0:
        print(f"⚠️  Found {len(exfil_no)} Exfiltration techniques marked as NO:")
        for _, row in exfil_no.iterrows():
            print(f"  - {row['technique_id']:12s} {row['name']}")
            errors_found.append(('EXFIL_AS_NO', row['technique_id'], row['name']))
    else:
        print("✓ No issues found")
    print()

    # Check 4: Techniques with keywords suggesting network activity but marked NO
    print("CHECK 4: Network-related keywords in name/description but marked NO")
    print("-"*100)
    network_keywords = ['remote', 'network', 'domain account', 'dns', 'http', 'proxy', 'encrypt.*traffic', 'c2', 'exfil']

    network_no_issues = []
    for _, row in df[df['NIDS_Classification'] == 'NO'].iterrows():
        name_desc = (str(row['name']) + ' ' + str(row['description'])).lower()
        for keyword in network_keywords:
            if keyword in name_desc and 'domain account' not in name_desc.lower():
                # Skip some legitimate NO classifications
                if row['technique_id'] not in ['T1583.001', 'T1078.002', 'T1585.002']:
                    continue
                network_no_issues.append((row['technique_id'], row['name'], keyword))
                break

    if network_no_issues:
        print(f"⚠️  Found {len(network_no_issues)} techniques with network keywords marked as NO:")
        for tech_id, name, keyword in network_no_issues[:10]:
            print(f"  - {tech_id:12s} {name[:50]:50s} (keyword: {keyword})")
            errors_found.append(('NETWORK_KEYWORD_AS_NO', tech_id, name))
    else:
        print("✓ No issues found")
    print()

    # Check 5: Specific known errors
    print("CHECK 5: Specific technique reviews")
    print("-"*100)

    specific_checks = {
        'T1078.002': ('Domain Accounts', 'Should be PARTIAL - domain auth uses LDAP/Kerberos network traffic'),
        'T1573.001': ('Symmetric Cryptography', 'Should be YES - encrypts network C2 traffic'),
        'T1090.002': ('External Proxy', 'Should be YES - proxy requires network traffic'),
        'T1583.001': ('Domains', 'Should be PARTIAL - acquiring domains involves network registration'),
        'T1132.001': ('Standard Encoding', 'Should be YES - encodes network C2 traffic'),
    }

    for tech_id, (expected_name, reason) in specific_checks.items():
        row = df[df['technique_id'] == tech_id]
        if len(row) > 0:
            current_class = row.iloc[0]['NIDS_Classification']
            if (tech_id == 'T1078.002' and current_class == 'NO') or \
               (tech_id == 'T1573.001' and current_class != 'YES') or \
               (tech_id == 'T1090.002' and current_class != 'YES') or \
               (tech_id == 'T1583.001' and current_class == 'NO') or \
               (tech_id == 'T1132.001' and current_class != 'YES'):
                print(f"⚠️  {tech_id:12s} {expected_name:30s} - Currently: {current_class:7s}")
                print(f"     Reason: {reason}")
                errors_found.append(('SPECIFIC_ERROR', tech_id, expected_name))

    if not any(e[0] == 'SPECIFIC_ERROR' for e in errors_found):
        print("✓ No specific errors found")
    print()

    # Summary
    print("="*100)
    print("VERIFICATION SUMMARY")
    print("="*100)
    if errors_found:
        print(f"⚠️  Total potential issues found: {len(errors_found)}")
        print()
        print("Unique techniques needing review:")
        unique_techs = list(set([(e[1], e[2]) for e in errors_found]))
        for tech_id, name in sorted(unique_techs):
            print(f"  - {tech_id:12s} {name}")
    else:
        print("✓ No major issues found!")
    print()

    return errors_found

if __name__ == '__main__':
    errors = check_classifications()
    exit(0 if len(errors) == 0 else 1)
