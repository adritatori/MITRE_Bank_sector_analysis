#!/usr/bin/env python3
"""
Extended NIDS Classification Table Generator
Creates a formatted table with Classification, Reasoning, and Network Artifacts
"""

import csv
import sys
from datetime import datetime

def create_extended_table():
    input_file = 'banking_analysis_nids_classified_20251222_003800.csv'
    output_file = f'banking_nids_extended_analysis_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    # Read the original CSV
    with open(input_file, 'r', encoding='utf-8') as infile:
        reader = csv.DictReader(infile)
        data = list(reader)

    # Separate by NIDS classification
    yes_detectable = []
    partial_detectable = []
    not_detectable = []

    for row in data:
        classification = row['NIDS_Classification'].strip()

        extended_row = {
            'Technique_ID': row['technique_id'],
            'Technique_Name': row['name'],
            'Tactic': row['tactics_str'],
            'Classification': classification,
            'Reasoning': row['NIDS_Reasoning'],
            'Network_Artifact': row['Network_Artifact'],
            'Priority': row['frequency_category'],
            'Score': row['total_score'],
            'Threat_Groups': row['groups'],
            'Associated_Software': row['software']
        }

        if classification == 'YES':
            yes_detectable.append(extended_row)
        elif classification == 'PARTIAL':
            partial_detectable.append(extended_row)
        else:  # NO
            not_detectable.append(extended_row)

    # Write extended CSV
    fieldnames = [
        'Technique_ID', 'Technique_Name', 'Tactic', 'Classification',
        'Reasoning', 'Network_Artifact', 'Priority', 'Score',
        'Threat_Groups', 'Associated_Software'
    ]

    with open(output_file, 'w', encoding='utf-8', newline='') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=fieldnames)
        writer.writeheader()

        # Write in order: YES, PARTIAL, NO
        writer.writerows(yes_detectable)
        writer.writerows(partial_detectable)
        writer.writerows(not_detectable)

    # Generate summary statistics
    print(f"Extended NIDS Classification Analysis")
    print(f"=" * 70)
    print(f"Output file: {output_file}")
    print(f"\nSummary Statistics:")
    print(f"  Total Techniques: {len(data)}")
    print(f"  YES (Network Detectable): {len(yes_detectable)}")
    print(f"  PARTIAL (Partially Detectable): {len(partial_detectable)}")
    print(f"  NO (Not Network Detectable): {len(not_detectable)}")
    print(f"\nDetection Coverage:")
    print(f"  Fully Detectable: {len(yes_detectable)/len(data)*100:.1f}%")
    print(f"  Partially Detectable: {len(partial_detectable)/len(data)*100:.1f}%")
    print(f"  Not Detectable: {len(not_detectable)/len(data)*100:.1f}%")

    # Show network detectable techniques
    print(f"\n{'='*70}")
    print(f"Network Detectable Techniques (YES):")
    print(f"{'='*70}")
    for i, technique in enumerate(yes_detectable, 1):
        print(f"\n{i}. {technique['Technique_ID']}: {technique['Technique_Name']}")
        print(f"   Classification: {technique['Classification']}")
        print(f"   Reasoning: {technique['Reasoning']}")
        print(f"   Network Artifact: {technique['Network_Artifact']}")
        print(f"   Priority: {technique['Priority']} | Score: {technique['Score']}")
        if technique['Threat_Groups']:
            print(f"   Threat Groups: {technique['Threat_Groups']}")

    # Show partially detectable
    print(f"\n{'='*70}")
    print(f"Partially Detectable Techniques (PARTIAL):")
    print(f"{'='*70}")
    for i, technique in enumerate(partial_detectable, 1):
        print(f"\n{i}. {technique['Technique_ID']}: {technique['Technique_Name']}")
        print(f"   Classification: {technique['Classification']}")
        print(f"   Reasoning: {technique['Reasoning']}")
        print(f"   Network Artifact: {technique['Network_Artifact']}")
        print(f"   Priority: {technique['Priority']} | Score: {technique['Score']}")
        if technique['Threat_Groups']:
            print(f"   Threat Groups: {technique['Threat_Groups']}")

    return output_file

if __name__ == '__main__':
    try:
        output = create_extended_table()
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
