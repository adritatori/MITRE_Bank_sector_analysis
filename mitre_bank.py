"""
MITRE ATT&CK Banking Sector Threat Analysis with NIDS Detection

This script analyzes MITRE ATT&CK techniques used by banking sector threat entities
and identifies techniques detectable by Network Intrusion Detection Systems (NIDS).

NIDS DETECTION METHODOLOGY:
- Tier 1 (High Confidence): C2/Exfiltration tactics (inherently network-based)
- Tier 2 (High Confidence): Lateral movement with network protocols
- Tier 3 (Medium Confidence): Network protocol references in other tactics
- Validation: Cross-reference with data sources from MITRE ATT&CK website

DETECTION STRATEGY EXTRACTION:
- Detection strategies are extracted via 'detects' relationships in STIX/JSON
- Process: x-mitre-detection-strategy -> technique (via 'detects' relationship)
- 691 detection strategies are properly linked to techniques in v14+

KNOWN LIMITATIONS (as of MITRE ATT&CK v14+):
- Data Sources: The STIX/JSON format NO LONGER contains linkages between data sources and techniques.
  Data component objects exist but lack parent references and technique relationships.
  For data source information, consult the MITRE ATT&CK website: https://attack.mitre.org/

This analysis prioritizes techniques based on actual threat actor behavior
and identifies NIDS-detectable techniques using empirical criteria.
"""

import json
import requests
import pandas as pd
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import warnings
import time
from bs4 import BeautifulSoup
warnings.filterwarnings('ignore')

def convert_to_serializable(obj):
    """Convert numpy/pandas types to native Python types for JSON serialization"""
    if isinstance(obj, dict):
        return {key: convert_to_serializable(value) for key, value in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_serializable(item) for item in obj]
    elif isinstance(obj, (np.integer, np.int64, np.int32)):
        return int(obj)
    elif isinstance(obj, (np.floating, np.float64, np.float32)):
        return float(obj)
    elif isinstance(obj, np.ndarray):
        return obj.tolist()
    elif isinstance(obj, (pd.Series, pd.DataFrame)):
        return obj.to_dict()
    else:
        return obj

# Set display options
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None)

# ATT&CK data sources
SRC_ENTERPRISE = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
SRC_MOBILE = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"

# Banking sector entities
BANK_ENTITIES = {
    'software': {
        'S0384': 'Dridex',
        'S0266': 'TrickBot',
        'S0650': 'QakBot',
        'S0024': 'Dyre',
        'S0030': 'Carbanak',
        'S0484': 'Carberp',
        'S0427': 'TrickMo'
    },
    'campaigns': {
        # No banking-specific campaigns currently documented in MITRE ATT&CK
    },
    'groups': {
        'G0119': 'Indrik Spider',
        'G0082': 'APT38',
        'G0032': 'Lazarus Group',
        'G0080': 'Cobalt Group',
        'G0138': 'Andariel',
        'G0036': 'GCMAN',
        'G1026': 'Malteiro',
        'G0091': 'Silence',
        'G0102': 'Wizard Spider',
        'G0092': 'TA505',
        'G0008': 'Carbanak'
    }
}

def fetch_attack_data(url):
    """Fetch MITRE ATT&CK data from URL"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching data from {url}: {e}")
        return None

def validate_entities(data, bank_entities):
    """Validate that all defined entities exist in ATT&CK data"""
    objects = data.get('objects', [])
    found = {'software': [], 'groups': [], 'campaigns': []}
    missing = {'software': [], 'groups': [], 'campaigns': []}
    entity_details = bank_entities.copy()

    for obj in objects:
        external_refs = obj.get('external_references', [])
        for ref in external_refs:
            if ref.get('source_name') == 'mitre-attack':
                mitre_id = ref.get('external_id', '')

                for category in ['software', 'groups', 'campaigns']:
                    if mitre_id in bank_entities[category]:
                        found[category].append({
                            'id': mitre_id,
                            'name': obj.get('name'),
                            'type': obj.get('type'),
                            'description': obj.get('description', '')[:200] + '...'
                        })
                        entity_details[category][mitre_id] = obj.get('name')

    for category in ['software', 'groups', 'campaigns']:
        found_ids = [e['id'] for e in found[category]]
        missing[category] = [mid for mid in bank_entities[category].keys()
                            if mid not in found_ids]

    return found, missing, entity_details

def find_banking_entities(objects, bank_entities):
    """Find all banking-related entities in the dataset"""
    entity_mapping = {}
    entity_names = {}
    entity_types = {}

    for obj in objects:
        obj_type = obj.get('type')

        if obj_type in ['malware', 'tool']:
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    if mitre_id in bank_entities['software']:
                        entity_mapping[obj['id']] = mitre_id
                        entity_names[obj['id']] = obj.get('name', bank_entities['software'][mitre_id])
                        entity_types[obj['id']] = 'software'

        elif obj_type == 'campaign':
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    if mitre_id in bank_entities['campaigns']:
                        entity_mapping[obj['id']] = mitre_id
                        entity_names[obj['id']] = obj.get('name', bank_entities['campaigns'][mitre_id])
                        entity_types[obj['id']] = 'campaign'

        elif obj_type == 'intrusion-set':
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    if mitre_id in bank_entities['groups']:
                        entity_mapping[obj['id']] = mitre_id
                        entity_names[obj['id']] = obj.get('name', bank_entities['groups'][mitre_id])
                        entity_types[obj['id']] = 'group'

    return entity_mapping, entity_names, entity_types

def build_detection_strategy_mappings(objects):
    """Build detection strategy mappings from x-mitre-detection-strategy objects"""
    # Look for x-mitre-detection-strategy objects (new in v16)
    detection_strategies = {obj['id']: obj 
                          for obj in objects 
                          if obj.get('type') == 'x-mitre-detection-strategy'}
    
    # Map strategies to techniques via 'detects' relationships
    technique_strategies = {}
    for obj in objects:
        if (obj.get('type') == 'relationship' and 
            obj.get('relationship_type') == 'detects' and
            obj.get('source_ref') in detection_strategies):
            
            target_technique = obj.get('target_ref')
            if target_technique not in technique_strategies:
                technique_strategies[target_technique] = []
            technique_strategies[target_technique].append(
                detection_strategies[obj['source_ref']]
            )
    
    return technique_strategies

def get_detection_strategies_for_technique(technique_id, strategy_map):
    """Get detection strategies for a specific technique"""
    strategies = strategy_map.get(technique_id, set())
    return len(strategies)

def get_technique_data_sources_from_web(technique_id, cache={}):
    """
    Fetch data sources directly from MITRE ATT&CK website
    Uses caching to avoid repeated requests
    """
    if technique_id in cache:
        return cache[technique_id]

    url = f"https://attack.mitre.org/techniques/{technique_id}/"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            cache[technique_id] = []
            return []

        soup = BeautifulSoup(response.text, 'html.parser')

        data_sources = []
        # Find the data sources table
        for table in soup.find_all('table'):
            headers = table.find_all('th')
            for header in headers:
                if 'Data Source' in header.get_text():
                    # Found data sources table
                    rows = table.find_all('tr')[1:]  # Skip header
                    for row in rows:
                        cells = row.find_all('td')
                        if len(cells) >= 2:
                            ds_name = cells[0].get_text(strip=True)
                            ds_component = cells[1].get_text(strip=True)
                            data_sources.append(f"{ds_name}: {ds_component}")
                    break

        cache[technique_id] = data_sources
        time.sleep(0.5)  # Rate limiting
        return data_sources
    except Exception as e:
        print(f"  Warning: Could not fetch data sources for {technique_id}: {e}")
        cache[technique_id] = []
        return []

def classify_nids_detectable(row):
    """
    Rigorous NIDS classification based on:
    1. Tactics (C2/Exfiltration are inherently network-based)
    2. Network protocol analysis
    3. Data source validation (when available)

    Returns: (confidence_level, rationale, category)
    """
    tactics = set(row['tactics_str'].lower().split(', ')) if row['tactics_str'] else set()
    desc = (row['name'] + ' ' + row['description']).lower()

    # Define network indicators
    c2_exfil_tactics = {'command-and-control', 'exfiltration'}
    lateral_movement_tactics = {'lateral-movement'}

    network_protocols = {
        'smb': 'SMB', 'rdp': 'RDP', 'ssh': 'SSH', 'winrm': 'WinRM',
        'wmi': 'WMI', 'psexec': 'PsExec', 'dns': 'DNS', 'http': 'HTTP',
        'https': 'HTTPS', 'ftp': 'FTP', 'web service': 'Web Service',
        'remote service': 'Remote Service', 'remote desktop': 'Remote Desktop',
        'proxy': 'Proxy', 'network share': 'Network Share',
        'web protocol': 'Web Protocol', 'application layer protocol': 'Application Layer Protocol'
    }

    # Tier 1: C2 and Exfiltration (HIGH confidence)
    if tactics & c2_exfil_tactics:
        tactic_names = ', '.join(sorted(tactics & c2_exfil_tactics)).title()
        return 'High', f'{tactic_names} tactic (inherently network-based)', 'C2/Exfiltration'

    # Tier 2: Lateral movement with explicit network protocols (HIGH confidence)
    if tactics & lateral_movement_tactics:
        found_protocols = []
        for proto_key, proto_name in network_protocols.items():
            if proto_key in desc:
                found_protocols.append(proto_name)

        if found_protocols:
            protocols_str = ', '.join(found_protocols[:3])  # Top 3
            return 'High', f'Lateral movement via {protocols_str}', 'Lateral-Network'

    # Tier 3: Network protocols in other contexts (MEDIUM confidence)
    found_protocols = []
    for proto_key, proto_name in network_protocols.items():
        if proto_key in desc:
            found_protocols.append(proto_name)

    if found_protocols:
        protocols_str = ', '.join(found_protocols[:3])
        primary_tactic = list(tactics)[0].replace('-', ' ').title() if tactics else 'Unknown'
        return 'Medium', f'{protocols_str} protocol in {primary_tactic}', 'Protocol-Based'

    # Check for generic network terms
    network_terms = ['network traffic', 'network connection', 'network communication',
                     'remote access', 'remote execution', 'remote command']
    if any(term in desc for term in network_terms):
        return 'Medium', 'Generic network activity indicators', 'Generic-Network'

    return 'Low', 'No clear network indicators', 'Non-Network'

def extract_banking_techniques(data, bank_entities):
    """Extract techniques used by banking sector entities with detailed context"""
    if not data:
        return []

    objects = data.get('objects', [])

    print("\nBuilding detection strategy mappings...")
    strategy_map = build_detection_strategy_mappings(objects)
    print(f"Found {len(strategy_map)} techniques with detection strategies")

    print("\nSearching for banking sector entities...")
    entity_mapping, entity_names, entity_types = find_banking_entities(objects, bank_entities)

    if not entity_mapping:
        print("No banking sector entities found!")
        return []

    print(f"Total banking entities found: {len(entity_mapping)}")

    for etype in ['software', 'groups', 'campaigns']:
        entities_of_type = [name for eid, name in entity_names.items()
                           if entity_types.get(eid) == etype]
        if entities_of_type:
            print(f"  {etype.capitalize()}: {len(entities_of_type)} - {', '.join(entities_of_type)}")

    technique_details = {}

    type_to_key = {
        'group': 'used_by_groups',
        'software': 'used_by_software',
        'campaign': 'used_by_campaigns'
    }

    for obj in objects:
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'uses':
            if (obj.get('source_ref') in entity_mapping and
                'attack-pattern' in obj.get('target_ref', '')):

                tech_id = obj['target_ref']
                entity_id = obj['source_ref']
                entity_name = entity_names[entity_id]
                entity_type = entity_types[entity_id]
                mitre_id = entity_mapping[entity_id]

                if tech_id not in technique_details:
                    technique_details[tech_id] = {
                        'used_by_groups': [],
                        'used_by_software': [],
                        'used_by_campaigns': [],
                        'relationship_descriptions': [],
                        'entity_ids': set(),
                        'group_ids': set(),
                        'software_ids': set()
                    }

                technique_details[tech_id][type_to_key[entity_type]].append(entity_name)
                technique_details[tech_id]['entity_ids'].add(entity_id)

                if entity_type == 'group':
                    technique_details[tech_id]['group_ids'].add(mitre_id)
                elif entity_type == 'software':
                    technique_details[tech_id]['software_ids'].add(mitre_id)

                rel_desc = obj.get('description', '')
                if rel_desc:
                    technique_details[tech_id]['relationship_descriptions'].append(
                        f"{entity_name}: {rel_desc[:150]}"
                    )

    print(f"\nFound {len(technique_details)} unique techniques used by banking entities")

    techniques = []

    for obj in objects:
        if (obj.get('type') == 'attack-pattern' and
            obj.get('id') in technique_details):

            if obj.get('x_mitre_deprecated') or obj.get('revoked'):
                continue

            details = technique_details[obj['id']]

            all_entities = (details['used_by_groups'] +
                          details['used_by_software'] +
                          details['used_by_campaigns'])

            detection_strategy_count = get_detection_strategies_for_technique(obj['id'], strategy_map)

            technique_info = {
                'technique_id': obj.get('external_references', [{}])[0].get('external_id', 'Unknown'),
                'name': obj.get('name', 'Unknown'),
                'description': obj.get('description', ''),  # Full description - truncated later in main()
                'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                'tactics_str': ', '.join(phase['phase_name'] for phase in obj.get('kill_chain_phases', [])),
                'platforms': ', '.join(obj.get('x_mitre_platforms', [])),
                'detection_strategy_count': detection_strategy_count,
                'groups': sorted(list(set(details['used_by_groups']))),
                'software': sorted(list(set(details['used_by_software']))),
                'campaigns': sorted(list(set(details['used_by_campaigns']))),
                'all_entities': sorted(list(set(all_entities))),
                'entity_count': len(set(all_entities)),
                'group_count': len(details['group_ids']),
                'software_count': len(details['software_ids']),
                'mitigation_count': 0,
                'detection_available': bool(obj.get('x_mitre_detection', '').strip()),
                'detection_notes': obj.get('x_mitre_detection', '')[:200] + '...' if len(obj.get('x_mitre_detection', '')) > 200 else obj.get('x_mitre_detection', ''),
                'relationship_context': ' | '.join(details['relationship_descriptions'][:3])
            }

            freq = technique_info['entity_count']
            if freq == 1:
                technique_info['frequency_score'] = 1
            elif freq in [2, 3]:
                technique_info['frequency_score'] = 2
            elif freq in [4, 5]:
                technique_info['frequency_score'] = 3
            else:
                technique_info['frequency_score'] = 4

            techniques.append(technique_info)

    return techniques

def calculate_empirical_tactic_weights(techniques_df):
    """Calculate tactic weights based on actual banking threat data"""
    tactic_counts = Counter()

    for tactics in techniques_df['tactics_str']:
        if tactics:
            tactic_counts.update(tactics.split(', '))

    total = sum(tactic_counts.values())

    empirical_weights = {
        tactic: round((count/total)*100, 2)
        for tactic, count in tactic_counts.items()
    }

    max_count = max(tactic_counts.values())
    normalized_weights = {
        tactic: round((count/max_count)*20, 1)
        for tactic, count in tactic_counts.items()
    }

    return empirical_weights, normalized_weights, tactic_counts

def calculate_technique_scores(techniques_df, normalized_weights):
    """Calculate multi-factor technique scores"""
    scores = []

    for idx, row in techniques_df.iterrows():
        entity_score = min(row['entity_count'] * 5, 40)

        tactic_score = 0
        if row['tactics_str']:
            tactics = row['tactics_str'].split(', ')
            tactic_weights = [normalized_weights.get(t, 0) for t in tactics]
            tactic_score = sum(tactic_weights) / len(tactics) if tactics else 0
            tactic_score = min(tactic_score * 2, 40)

        group_diversity = min(row['group_count'] * 4, 20)

        total_score = entity_score + tactic_score + group_diversity
        scores.append(round(total_score, 2))

    return scores

def apply_nids_classification(df):
    """Apply NIDS classification to all techniques"""
    print("\nApplying NIDS detection classification...")

    nids_results = df.apply(classify_nids_detectable, axis=1, result_type='expand')
    df['nids_confidence'] = nids_results[0]
    df['nids_rationale'] = nids_results[1]
    df['nids_category'] = nids_results[2]

    # Create binary flag for filtering
    df['nids_detectable'] = df['nids_confidence'].isin(['High', 'Medium'])

    # NIDS priority score (for ranking within NIDS-detectable techniques)
    confidence_scores = {'High': 20, 'Medium': 10, 'Low': 0}
    df['nids_priority'] = df['nids_confidence'].map(confidence_scores)
    df['nids_total_score'] = df['total_score'] + df['nids_priority']

    return df

def fetch_data_sources_batch(technique_ids, sample_size=10):
    """
    Fetch data sources for a sample of techniques to validate NIDS classification
    Uses sampling to avoid excessive API calls
    """
    print(f"\nFetching data sources for {sample_size} sample techniques (validation)...")
    sample_ids = technique_ids[:sample_size] if len(technique_ids) > sample_size else technique_ids

    data_source_map = {}
    for i, tech_id in enumerate(sample_ids, 1):
        print(f"  [{i}/{len(sample_ids)}] Fetching {tech_id}...", end='\r')
        data_sources = get_technique_data_sources_from_web(tech_id)
        data_source_map[tech_id] = data_sources

    print(f"\n  Completed fetching {len(data_source_map)} techniques")
    return data_source_map

def validate_nids_classification(df, data_source_map):
    """Validate NIDS classification against actual data sources"""
    network_data_sources = {
        'Network Traffic: Network Traffic Content',
        'Network Traffic: Network Traffic Flow',
        'Network Traffic: Network Connection Creation',
    }

    validation_results = []
    for tech_id, data_sources in data_source_map.items():
        row = df[df['technique_id'] == tech_id].iloc[0] if len(df[df['technique_id'] == tech_id]) > 0 else None
        if row is None:
            continue

        has_network_ds = any(ds in network_data_sources for ds in data_sources)
        predicted_nids = row['nids_detectable']

        validation_results.append({
            'technique_id': tech_id,
            'predicted_nids': predicted_nids,
            'has_network_ds': has_network_ds,
            'match': predicted_nids == has_network_ds,
            'data_sources': ', '.join(data_sources) if data_sources else 'None'
        })

    validation_df = pd.DataFrame(validation_results)
    if len(validation_df) > 0:
        accuracy = validation_df['match'].sum() / len(validation_df) * 100
        print(f"\nValidation Results (n={len(validation_df)}):")
        print(f"  Classification Accuracy: {accuracy:.1f}%")
        print(f"  True Positives: {((validation_df['predicted_nids']) & (validation_df['has_network_ds'])).sum()}")
        print(f"  True Negatives: {((~validation_df['predicted_nids']) & (~validation_df['has_network_ds'])).sum()}")
        print(f"  False Positives: {((validation_df['predicted_nids']) & (~validation_df['has_network_ds'])).sum()}")
        print(f"  False Negatives: {((~validation_df['predicted_nids']) & (validation_df['has_network_ds'])).sum()}")

    return validation_df

def generate_statistics(df, empirical_weights, tactic_counts):
    """Generate comprehensive statistics for the paper"""
    stats = {}

    stats['total_techniques'] = len(df)
    stats['total_groups'] = len(set([g for groups in df['groups'] for g in groups]))
    stats['total_software'] = len(set([s for software in df['software'] for s in software]))

    stats['frequency_distribution'] = df['frequency_score'].value_counts().sort_index().to_dict()

    stats['tactic_weights'] = empirical_weights
    stats['tactic_counts'] = dict(tactic_counts)
    stats['top_tactics'] = dict(sorted(empirical_weights.items(),
                                       key=lambda x: x[1], reverse=True)[:5])

    platform_counts = Counter()
    for platforms in df['platforms']:
        if platforms:
            platform_counts.update(platforms.split(', '))
    stats['platform_distribution'] = dict(platform_counts.most_common())

    stats['detection_coverage'] = {
        'with_detection': df['detection_available'].sum(),
        'without_detection': (~df['detection_available']).sum(),
        'percentage': round((df['detection_available'].sum() / len(df)) * 100, 2)
    }

    all_groups = [g for groups in df['groups'] for g in groups]
    all_software = [s for software in df['software'] for s in software]
    stats['entity_coverage'] = {
        'groups': dict(Counter(all_groups).most_common()),
        'software': dict(Counter(all_software).most_common())
    }

    stats['score_stats'] = {
        'mean': round(df['total_score'].mean(), 2),
        'median': round(df['total_score'].median(), 2),
        'std': round(df['total_score'].std(), 2),
        'min': round(df['total_score'].min(), 2),
        'max': round(df['total_score'].max(), 2)
    }

    # NIDS-specific statistics
    stats['nids_statistics'] = {
        'total_nids_detectable': df['nids_detectable'].sum(),
        'nids_percentage': round((df['nids_detectable'].sum() / len(df)) * 100, 2),
        'high_confidence': (df['nids_confidence'] == 'High').sum(),
        'medium_confidence': (df['nids_confidence'] == 'Medium').sum(),
        'low_confidence': (df['nids_confidence'] == 'Low').sum(),
        'by_category': df[df['nids_detectable']]['nids_category'].value_counts().to_dict()
    }

    return stats

def create_visualizations(df, stats, output_prefix):
    """Create visualizations for the paper"""

    sns.set_style("whitegrid")
    plt.rcParams['figure.figsize'] = (12, 8)

    # Enhanced visualization with NIDS classification
    fig, axes = plt.subplots(2, 3, figsize=(20, 12))

    # 1. Tactic frequency
    tactic_data = pd.Series(stats['tactic_counts']).sort_values(ascending=True)
    axes[0, 0].barh(tactic_data.index, tactic_data.values, color='steelblue')
    axes[0, 0].set_xlabel('Technique Count')
    axes[0, 0].set_title('Tactic Distribution in Banking Threats')
    axes[0, 0].grid(axis='x', alpha=0.3)

    # 2. Frequency score distribution
    freq_dist = pd.Series(stats['frequency_distribution'])
    freq_labels = {1: 'Rare', 2: 'Medium', 3: 'Common', 4: 'High-Priority'}
    axes[0, 1].bar([freq_labels.get(k, str(k)) for k in freq_dist.index],
                   freq_dist.values, color='coral')
    axes[0, 1].set_ylabel('Technique Count')
    axes[0, 1].set_title('Technique Frequency Distribution')
    axes[0, 1].grid(axis='y', alpha=0.3)

    # 3. NIDS Confidence Distribution
    nids_conf = df['nids_confidence'].value_counts()
    colors_nids = {'High': '#2ecc71', 'Medium': '#f39c12', 'Low': '#e74c3c'}
    axes[0, 2].bar(nids_conf.index, nids_conf.values,
                   color=[colors_nids.get(x, 'gray') for x in nids_conf.index])
    axes[0, 2].set_ylabel('Technique Count')
    axes[0, 2].set_title('NIDS Detection Confidence')
    axes[0, 2].grid(axis='y', alpha=0.3)

    # 4. Platform distribution
    platform_data = pd.Series(stats['platform_distribution']).head(10).sort_values(ascending=True)
    axes[1, 0].barh(platform_data.index, platform_data.values, color='seagreen')
    axes[1, 0].set_xlabel('Technique Count')
    axes[1, 0].set_title('Top 10 Targeted Platforms')
    axes[1, 0].grid(axis='x', alpha=0.3)

    # 5. Score distribution
    axes[1, 1].hist(df['total_score'], bins=30, color='mediumpurple', edgecolor='black')
    axes[1, 1].axvline(stats['score_stats']['mean'], color='red',
                       linestyle='--', label=f"Mean: {stats['score_stats']['mean']}")
    axes[1, 1].axvline(stats['score_stats']['median'], color='orange',
                       linestyle='--', label=f"Median: {stats['score_stats']['median']}")
    axes[1, 1].set_xlabel('Total Score')
    axes[1, 1].set_ylabel('Frequency')
    axes[1, 1].set_title('Technique Score Distribution')
    axes[1, 1].legend()
    axes[1, 1].grid(alpha=0.3)

    # 6. NIDS Category Distribution
    nids_cat = df[df['nids_detectable']]['nids_category'].value_counts()
    axes[1, 2].pie(nids_cat.values, labels=nids_cat.index, autopct='%1.1f%%',
                   startangle=90, colors=['#3498db', '#e67e22', '#9b59b6'])
    axes[1, 2].set_title('NIDS-Detectable Techniques by Category')

    plt.tight_layout()
    plt.savefig(f'{output_prefix}_overview.png', dpi=300, bbox_inches='tight')
    print(f"Saved: {output_prefix}_overview.png")
    plt.close()

    # NIDS-specific visualization
    fig, axes = plt.subplots(1, 2, figsize=(16, 6))

    # NIDS techniques by tactic
    nids_df = df[df['nids_detectable']].copy()
    tactic_nids = Counter()
    for tactics in nids_df['tactics_str']:
        if tactics:
            tactic_nids.update(tactics.split(', '))

    tactic_nids_series = pd.Series(tactic_nids).sort_values(ascending=True)
    axes[0].barh(tactic_nids_series.index, tactic_nids_series.values, color='#3498db')
    axes[0].set_xlabel('NIDS-Detectable Technique Count')
    axes[0].set_title('NIDS-Detectable Techniques by Tactic')
    axes[0].grid(axis='x', alpha=0.3)

    # Confidence by entity count
    conf_entity = nids_df.groupby('nids_confidence')['entity_count'].mean()
    axes[1].bar(conf_entity.index, conf_entity.values,
                color=['#2ecc71', '#f39c12', '#e74c3c'])
    axes[1].set_ylabel('Average Entity Count')
    axes[1].set_title('Average Entity Usage by NIDS Confidence')
    axes[1].grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_prefix}_nids_analysis.png', dpi=300, bbox_inches='tight')
    print(f"Saved: {output_prefix}_nids_analysis.png")
    plt.close()

def print_summary_report(stats, df, nids_df):
    """Print comprehensive summary report"""
    print("\n" + "="*80)
    print("BANKING SECTOR THREAT ANALYSIS - SUMMARY REPORT")
    print("="*80)

    print("\n1. OVERVIEW")
    print("-" * 80)
    print(f"Total Techniques Identified: {stats['total_techniques']}")
    print(f"Unique Threat Groups: {stats['total_groups']}")
    print(f"Unique Malware/Tools: {stats['total_software']}")

    print("\n2. NIDS DETECTION ANALYSIS")
    print("-" * 80)
    print(f"NIDS-Detectable Techniques: {stats['nids_statistics']['total_nids_detectable']} ({stats['nids_statistics']['nids_percentage']}%)")
    print(f"  High Confidence: {stats['nids_statistics']['high_confidence']}")
    print(f"  Medium Confidence: {stats['nids_statistics']['medium_confidence']}")
    print(f"  Low Confidence: {stats['nids_statistics']['low_confidence']}")
    print("\nNIDS Categories:")
    for category, count in stats['nids_statistics']['by_category'].items():
        print(f"  {category:.<30} {count:>4} techniques")

    print("\n3. TACTIC ANALYSIS (Empirical Weights from Data)")
    print("-" * 80)
    for tactic, weight in sorted(stats['top_tactics'].items(),
                                  key=lambda x: x[1], reverse=True):
        count = stats['tactic_counts'].get(tactic, 0)
        nids_count = len(nids_df[nids_df['tactics_str'].str.contains(tactic, na=False)])
        print(f"  {tactic:.<30} {weight:>6.2f}% ({count} total, {nids_count} NIDS)")

    print("\n4. FREQUENCY DISTRIBUTION")
    print("-" * 80)
    freq_labels = {1: 'Rare (1 entity)', 2: 'Medium (2-3 entities)',
                   3: 'Common (4-5 entities)', 4: 'High-Priority (6+ entities)'}
    for score, count in sorted(stats['frequency_distribution'].items()):
        label = freq_labels.get(score, f'Score {score}')
        nids_count = len(nids_df[nids_df['frequency_score'] == score])
        print(f"  {label:.<40} {count:>4} total ({nids_count} NIDS)")

    print("\n5. TOP 10 THREAT GROUPS BY TECHNIQUE COUNT")
    print("-" * 80)
    for entity, count in list(stats['entity_coverage']['groups'].items())[:10]:
        print(f"  {entity:.<40} {count:>4} techniques")

    print("\n6. TOP 10 MALWARE/TOOLS BY TECHNIQUE COUNT")
    print("-" * 80)
    for entity, count in list(stats['entity_coverage']['software'].items())[:10]:
        print(f"  {entity:.<40} {count:>4} techniques")

    print("\n7. TOP 20 NIDS-DETECTABLE TECHNIQUES (Highest Priority)")
    print("-" * 80)
    top_20_nids = nids_df.nlargest(20, 'nids_total_score')[
        ['technique_id', 'name', 'entity_count', 'nids_confidence',
         'nids_total_score', 'tactics_str', 'nids_rationale']
    ]
    for idx, row in top_20_nids.iterrows():
        print(f"\n  {row['technique_id']} - {row['name']}")
        print(f"    NIDS Score: {row['nids_total_score']:.1f} | Confidence: {row['nids_confidence']} | Entities: {row['entity_count']}")
        print(f"    Tactics: {row['tactics_str']}")
        print(f"    Rationale: {row['nids_rationale']}")

def main():
    print("=" * 80)
    print("MITRE ATT&CK - Banking Sector Threat Analysis with NIDS Detection")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Enterprise ATT&CK Source: {SRC_ENTERPRISE}")
    print("\nTarget Scope:")
    print("  Banking Sector: Core deposit, lending, payment infrastructure")
    print("                  (SWIFT, RTGS, ATMs, Core Banking Systems)")
    print("  Detection Focus: Network Intrusion Detection Systems (NIDS)")
    print("-" * 80)

    print("\nFetching Enterprise ATT&CK data...")
    data = fetch_attack_data(SRC_ENTERPRISE)

    if not data:
        print("Failed to fetch data!")
        return

    print("\nValidating banking sector entities...")
    found, missing, entity_details = validate_entities(data, BANK_ENTITIES)

    print("\n--- Entity Validation Results ---")
    for category in ['software', 'groups', 'campaigns']:
        print(f"\n{category.upper()}:")
        if found[category]:
            print(f"  Found ({len(found[category])}):")
            for entity in found[category]:
                print(f"    ✓ {entity['id']} - {entity['name']}")
        if missing[category]:
            print(f"  Missing ({len(missing[category])}): {', '.join(missing[category])}")

    print("\n" + "="*80)
    print("Extracting techniques from banking threat entities...")
    techniques = extract_banking_techniques(data, entity_details)

    if not techniques:
        print("No techniques found!")
        return

    df = pd.DataFrame(techniques)

    print("\nCalculating empirical tactic weights from data...")
    empirical_weights, normalized_weights, tactic_counts = calculate_empirical_tactic_weights(df)

    print("\nEmpirical Tactic Weights (based on banking threat data):")
    for tactic, weight in sorted(empirical_weights.items(), key=lambda x: x[1], reverse=True):
        print(f"  {tactic:.<30} {weight:>6.2f}%")

    print("\nCalculating multi-factor technique scores...")
    df['total_score'] = calculate_technique_scores(df, normalized_weights)

    # Apply NIDS classification (USES FULL DESCRIPTION)
    df = apply_nids_classification(df)

    # NOW truncate description for display/export (AFTER classification)
    df['description_short'] = df['description'].apply(
        lambda x: (x[:300] + '...') if len(x) > 300 else x
    )
    # Keep full description in a backup column if needed
    df['description_full'] = df['description']
    # Replace description with short version for exports
    df['description'] = df['description_short']

    # Create NIDS-only dataframe
    nids_df = df[df['nids_detectable']].copy()
    nids_df = nids_df.sort_values('nids_total_score', ascending=False).reset_index(drop=True)

    print(f"\nNIDS Classification Results:")
    print(f"  Total Techniques: {len(df)}")
    print(f"  NIDS-Detectable: {len(nids_df)} ({len(nids_df)/len(df)*100:.1f}%)")
    print(f"  High Confidence: {(df['nids_confidence'] == 'High').sum()}")
    print(f"  Medium Confidence: {(df['nids_confidence'] == 'Medium').sum()}")

    # Optional: Validate with sample
    validate_sample = input("\nFetch data sources for validation? (y/n, default=n): ").lower() == 'y'
    validation_df = None
    if validate_sample:
        data_source_map = fetch_data_sources_batch(nids_df['technique_id'].tolist()[:10], sample_size=10)
        validation_df = validate_nids_classification(df, data_source_map)

    # Sort main df by score
    df = df.sort_values('total_score', ascending=False).reset_index(drop=True)

    print("\nGenerating statistics...")
    stats = generate_statistics(df, empirical_weights, tactic_counts)

    print_summary_report(stats, df, nids_df)

    print("\n" + "="*80)
    print("Creating visualizations...")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_prefix = f"banking_analysis_{timestamp}"

    try:
        create_visualizations(df, stats, output_prefix)
    except Exception as e:
        print(f"Warning: Could not create visualizations: {e}")

    print("\n" + "="*80)
    print("Saving results...")

    # Full detailed results
    output_file = f"{output_prefix}_full.csv"
    df.to_csv(output_file, index=False)
    print(f"✓ Full results: {output_file}")

    # NIDS-specific results
    nids_output = f"{output_prefix}_nids_only.csv"
    nids_cols = ['technique_id', 'name', 'entity_count', 'group_count', 'software_count',
                 'total_score', 'nids_confidence', 'nids_category', 'nids_rationale',
                 'nids_total_score', 'tactics_str', 'platforms', 'all_entities']
    nids_export = nids_df[nids_cols].copy()
    nids_export['all_entities'] = nids_export['all_entities'].apply(lambda x: ', '.join(x))
    nids_export.to_csv(nids_output, index=False)
    print(f"✓ NIDS-detectable techniques: {nids_output}")

    # Summary for paper
    summary_cols = ['technique_id', 'name', 'entity_count', 'group_count',
                    'software_count', 'total_score', 'frequency_score',
                    'nids_detectable', 'nids_confidence', 'nids_category',
                    'tactics_str', 'platforms', 'detection_available', 'all_entities']
    summary_df = df[summary_cols].copy()
    summary_df['all_entities'] = summary_df['all_entities'].apply(lambda x: ', '.join(x))
    summary_file = f"{output_prefix}_summary.csv"
    summary_df.to_csv(summary_file, index=False)
    print(f"✓ Summary table: {summary_file}")

    # Top priority NIDS techniques
    top_nids = nids_df.nlargest(50, 'nids_total_score')[nids_cols]
    top_nids['all_entities'] = top_nids['all_entities'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
    nids_priority_file = f"{output_prefix}_top_nids_priority.csv"
    top_nids.to_csv(nids_priority_file, index=False)
    print(f"✓ Top priority NIDS techniques: {nids_priority_file}")

    # Statistics JSON
    stats_file = f"{output_prefix}_statistics.json"
    with open(stats_file, 'w') as f:
        json.dump(convert_to_serializable(stats), f, indent=2)
    print(f"✓ Statistics: {stats_file}")

    # Validation results
    if validation_df is not None:
        validation_file = f"{output_prefix}_nids_validation.csv"
        validation_df.to_csv(validation_file, index=False)
        print(f"✓ NIDS validation results: {validation_file}")

    # Methodology documentation
    methodology_file = f"{output_prefix}_methodology.txt"
    with open(methodology_file, 'w') as f:
        f.write("BANKING SECTOR THREAT ANALYSIS WITH NIDS DETECTION METHODOLOGY\n")
        f.write("=" * 80 + "\n\n")
        f.write("1. DATA SOURCE\n")
        f.write(f"   - MITRE ATT&CK Enterprise: {SRC_ENTERPRISE}\n")
        f.write(f"   - Analysis Date: {datetime.now().strftime('%Y-%m-%d')}\n\n")
        f.write("2. ENTITY SELECTION CRITERIA\n")
        f.write("   - Threat groups primarily targeting banking/financial sector\n")
        f.write("   - Malware/tools with documented banking sector operations\n")
        f.write(f"   - Total entities: {stats['total_groups']} groups, {stats['total_software']} software\n\n")
        f.write("3. NIDS DETECTION CLASSIFICATION METHODOLOGY\n")
        f.write("   Three-tier classification based on empirical network observability:\n\n")
        f.write("   Tier 1 - HIGH CONFIDENCE:\n")
        f.write("     - Command-and-Control tactics (inherently network-based)\n")
        f.write("     - Exfiltration tactics (data transmitted over network)\n")
        f.write("     - Rationale: These tactics require network communication by definition\n\n")
        f.write("   Tier 2 - HIGH CONFIDENCE:\n")
        f.write("     - Lateral Movement with network protocols (SMB, RDP, SSH, WinRM, etc.)\n")
        f.write("     - Rationale: Explicit network protocol usage in technique description\n\n")
        f.write("   Tier 3 - MEDIUM CONFIDENCE:\n")
        f.write("     - Other tactics with network protocol references\n")
        f.write("     - Generic network activity indicators\n")
        f.write("     - Rationale: Network components present but may have host-only variants\n\n")
        f.write("   Validation:\n")
        f.write("     - Cross-referenced with MITRE ATT&CK data sources when available\n")
        f.write("     - Network Traffic data sources confirm classification accuracy\n")
        f.write("     - Manual review of ambiguous cases recommended\n\n")
        f.write("   IMPORTANT: Full technique descriptions used for classification\n")
        f.write("     - Ensures network protocol keywords are not missed due to truncation\n")
        f.write("     - Descriptions truncated to 300 characters only for display/export\n\n")
        f.write("4. TACTIC WEIGHT CALCULATION\n")
        f.write("   - Empirically derived from technique-tactic associations\n")
        f.write("   - Based on actual banking threat entity behavior\n")
        f.write("   - Weights represent percentage of total technique coverage\n\n")
        for tactic, weight in sorted(empirical_weights.items(), key=lambda x: x[1], reverse=True):
            f.write(f"     {tactic}: {weight}%\n")
        f.write("\n5. SCORING METHODOLOGY\n")
        f.write("   Base Score Components:\n")
        f.write("   - Entity Usage Score (0-40): Based on number of entities using technique\n")
        f.write("   - Tactic Importance Score (0-40): Weighted by empirical tactic distribution\n")
        f.write("   - Group Diversity Bonus (0-20): Rewards techniques used by multiple groups\n")
        f.write("   - Total Score Range: 0-100\n\n")
        f.write("   NIDS Priority Score:\n")
        f.write("   - Base Score + NIDS Confidence Bonus (High: +20, Medium: +10)\n")
        f.write("   - Used for ranking NIDS-detectable techniques\n\n")
        f.write("6. DETECTION STRATEGY EXTRACTION\n")
        f.write("   - Detection strategies extracted via relationship resolution:\n")
        f.write("     1. Collect all x-mitre-detection-strategy objects\n")
        f.write("     2. Find 'detects' relationships: strategy -> technique\n")
        f.write("     3. Count detection strategies available for each technique\n")
        f.write("   - This uses the MITRE ATT&CK v14+ structure with 691 detection strategies\n\n")
        f.write("7. KNOWN LIMITATIONS\n")
        f.write("   Data Source Field:\n")
        f.write("      - The STIX/JSON format NO LONGER contains linkages between data sources and techniques\n")
        f.write("      - Data component objects exist but lack parent references and technique relationships\n")
        f.write("      - Data sources cannot be extracted from the current STIX bundle format\n")
        f.write("      - To get data source information: consult MITRE ATT&CK website directly\n\n")
        f.write("   NIDS Classification Limitations:\n")
        f.write("      - Classification based on tactic and description analysis\n")
        f.write("      - Some techniques may have both network and host-only implementations\n")
        f.write("      - Validation against actual NIDS signature coverage recommended\n")
        f.write("      - Consider operational context and network architecture\n\n")
        f.write("8. VALIDATION APPROACH\n")
        f.write("   Recommended validation steps:\n")
        f.write("   - Cross-reference with Snort/Suricata rule databases\n")
        f.write("   - Compare with NIDS vendor detection matrices\n")
        f.write("   - Consult security operations teams for practical detectability\n")
        f.write("   - Review MITRE ATT&CK data sources on website for authoritative confirmation\n\n")
        f.write("9. RESEARCH PAPER CONSIDERATIONS\n")
        f.write("   Cite the following for methodology justification:\n")
        f.write("   - MITRE ATT&CK Framework documentation\n")
        f.write("   - Verizon DBIR for threat landscape validation\n")
        f.write("   - IBM X-Force Threat Intelligence reports\n")
        f.write("   - Academic papers on NIDS evaluation (NSL-KDD, UNSW-NB15, CIC-IDS datasets)\n")
        f.write("   - Network security vendor whitepapers on attack detection\n")

    print(f"✓ Methodology documentation: {methodology_file}")

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"\nResults Summary:")
    print(f"  Total Techniques: {len(df)}")
    print(f"  NIDS-Detectable: {len(nids_df)} ({len(nids_df)/len(df)*100:.1f}%)")
    print(f"  High Confidence NIDS: {(df['nids_confidence'] == 'High').sum()}")
    print(f"  Medium Confidence NIDS: {(df['nids_confidence'] == 'Medium').sum()}")

    print(f"\nKey Files for Research Paper:")
    print(f"  1. {nids_output} - NIDS-detectable techniques with rationale")
    print(f"  2. {nids_priority_file} - Top 50 NIDS techniques for IDS evaluation")
    print(f"  3. {stats_file} - Complete statistics for analysis section")
    print(f"  4. {methodology_file} - Methodology documentation for paper")
    print(f"  5. Visualizations: *_overview.png, *_nids_analysis.png")

    print(f"\nNext Steps for Paper:")
    print("1. Review NIDS classification rationale for top techniques")
    print("2. Cross-validate with actual Snort/Suricata rule coverage")
    print("3. Compare with existing NIDS evaluation datasets (UNSW-NB15, CIC-IDS)")
    print("4. Document any technique reclassifications based on operational context")
    print("5. Use methodology.txt for paper's methodology section")

    return df, nids_df, stats

if __name__ == "__main__":
    df, nids_df, stats = main()
