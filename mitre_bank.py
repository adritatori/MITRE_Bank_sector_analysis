import json
import requests
import pandas as pd
from collections import Counter
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import networkx as nx
from pyvis.network import Network
import numpy as np
import warnings
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

                # Check each category
                for category in ['software', 'groups', 'campaigns']:
                    if mitre_id in bank_entities[category]:
                        found[category].append({
                            'id': mitre_id,
                            'name': obj.get('name'),
                            'type': obj.get('type'),
                            'description': obj.get('description', '')[:200] + '...'
                        })
                        # Update with actual name from ATT&CK
                        entity_details[category][mitre_id] = obj.get('name')

    # Find missing entities
    for category in ['software', 'groups', 'campaigns']:
        found_ids = [e['id'] for e in found[category]]
        missing[category] = [mid for mid in bank_entities[category].keys()
                            if mid not in found_ids]

    return found, missing, entity_details

def find_banking_entities(objects, bank_entities):
    """Find all banking-related entities in the dataset"""
    entity_mapping = {}  # STIX ID -> MITRE ID
    entity_names = {}    # STIX ID -> Entity Name
    entity_types = {}    # STIX ID -> Entity Type (software/group/campaign)

    for obj in objects:
        obj_type = obj.get('type')

        # Check for software/malware/tools
        if obj_type in ['malware', 'tool']:
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    if mitre_id in bank_entities['software']:
                        entity_mapping[obj['id']] = mitre_id
                        entity_names[obj['id']] = obj.get('name', bank_entities['software'][mitre_id])
                        entity_types[obj['id']] = 'software'

        # Check for campaigns
        elif obj_type == 'campaign':
            external_refs = obj.get('external_references', [])
            for ref in external_refs:
                if ref.get('source_name') == 'mitre-attack':
                    mitre_id = ref.get('external_id', '')
                    if mitre_id in bank_entities['campaigns']:
                        entity_mapping[obj['id']] = mitre_id
                        entity_names[obj['id']] = obj.get('name', bank_entities['campaigns'][mitre_id])
                        entity_types[obj['id']] = 'campaign'

        # Check for groups
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

def extract_banking_techniques(data, bank_entities):
    """Extract techniques used by banking sector entities with detailed context"""
    if not data:
        return []

    objects = data.get('objects', [])

    # Find all banking-related entities
    print("\nSearching for banking sector entities...")
    entity_mapping, entity_names, entity_types = find_banking_entities(objects, bank_entities)

    if not entity_mapping:
        print("No banking sector entities found!")
        return []

    print(f"Total banking entities found: {len(entity_mapping)}")

    # Print found entities by type
    for etype in ['software', 'groups', 'campaigns']:
        entities_of_type = [name for eid, name in entity_names.items()
                           if entity_types.get(eid) == etype]
        if entities_of_type:
            print(f"  {etype.capitalize()}: {len(entities_of_type)} - {', '.join(entities_of_type)}")

    # Track technique usage with detailed context
    technique_details = {}

    # Map entity types to correct dictionary keys
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

                # Categorize by entity type using the mapping
                technique_details[tech_id][type_to_key[entity_type]].append(entity_name)
                technique_details[tech_id]['entity_ids'].add(entity_id)

                if entity_type == 'group':
                    technique_details[tech_id]['group_ids'].add(mitre_id)
                elif entity_type == 'software':
                    technique_details[tech_id]['software_ids'].add(mitre_id)

                # Capture relationship description if available
                rel_desc = obj.get('description', '')
                if rel_desc:
                    technique_details[tech_id]['relationship_descriptions'].append(
                        f"{entity_name}: {rel_desc[:150]}"
                    )

    print(f"\nFound {len(technique_details)} unique techniques used by banking entities")

    # Extract full technique information
    techniques = []

    for obj in objects:
        if (obj.get('type') == 'attack-pattern' and
            obj.get('id') in technique_details):

            # Skip revoked or deprecated techniques
            if obj.get('x_mitre_deprecated') or obj.get('revoked'):
                continue

            details = technique_details[obj['id']]

            # Get all unique entities
            all_entities = (details['used_by_groups'] +
                          details['used_by_software'] +
                          details['used_by_campaigns'])

            # Get technique info
            technique_info = {
                'technique_id': obj.get('external_references', [{}])[0].get('external_id', 'Unknown'),
                'name': obj.get('name', 'Unknown'),
                'description': obj.get('description', '')[:300] + '...' if len(obj.get('description', '')) > 300 else obj.get('description', ''),
                'tactics': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                'tactics_str': ', '.join(phase['phase_name'] for phase in obj.get('kill_chain_phases', [])),
                'platforms': ', '.join(obj.get('x_mitre_platforms', [])),
                'data_sources': ', '.join([ds.get('data_source_name', '') for ds in obj.get('x_mitre_data_sources', [])]),
                'groups': sorted(list(set(details['used_by_groups']))),
                'software': sorted(list(set(details['used_by_software']))),
                'campaigns': sorted(list(set(details['used_by_campaigns']))),
                'all_entities': sorted(list(set(all_entities))),
                'entity_count': len(set(all_entities)),
                'group_count': len(details['group_ids']),
                'software_count': len(details['software_ids']),
                'mitigation_count': 0,  # Will be populated later
                'detection_available': bool(obj.get('x_mitre_detection', '')),
                'detection_notes': obj.get('x_mitre_detection', '')[:200] + '...' if len(obj.get('x_mitre_detection', '')) > 200 else obj.get('x_mitre_detection', ''),
                'relationship_context': ' | '.join(details['relationship_descriptions'][:3])  # Top 3 contexts
            }

            # Calculate frequency score
            freq = technique_info['entity_count']
            if freq == 1:
                technique_info['frequency_score'] = 1  # Rare
            elif freq in [2, 3]:
                technique_info['frequency_score'] = 2  # Medium
            elif freq in [4, 5]:
                technique_info['frequency_score'] = 3  # Common
            else:
                technique_info['frequency_score'] = 4  # High-priority

            techniques.append(technique_info)

    return techniques

def calculate_empirical_tactic_weights(techniques_df):
    """Calculate tactic weights based on actual banking threat data"""
    tactic_counts = Counter()

    # Count tactic occurrences
    for tactics in techniques_df['tactics_str']:
        if tactics:
            tactic_counts.update(tactics.split(', '))

    total = sum(tactic_counts.values())

    # Calculate percentage-based weights
    empirical_weights = {
        tactic: round((count/total)*100, 2)
        for tactic, count in tactic_counts.items()
    }

    # Also calculate normalized 1-20 scale for scoring
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
        # Base score from entity usage (0-40 points)
        entity_score = min(row['entity_count'] * 5, 40)

        # Tactic importance score (0-40 points)
        tactic_score = 0
        if row['tactics_str']:
            tactics = row['tactics_str'].split(', ')
            tactic_weights = [normalized_weights.get(t, 0) for t in tactics]
            tactic_score = sum(tactic_weights) / len(tactics) if tactics else 0
            tactic_score = min(tactic_score * 2, 40)  # Scale to 0-40

        # Group diversity bonus (0-20 points)
        group_diversity = min(row['group_count'] * 4, 20)

        # Total score
        total_score = entity_score + tactic_score + group_diversity
        scores.append(round(total_score, 2))

    return scores

def generate_statistics(df, empirical_weights, tactic_counts):
    """Generate comprehensive statistics for the paper"""
    stats = {}

    # Basic counts
    stats['total_techniques'] = len(df)
    stats['total_groups'] = len(set([g for groups in df['groups'] for g in groups]))
    stats['total_software'] = len(set([s for software in df['software'] for s in software]))

    # Frequency distribution
    stats['frequency_distribution'] = df['frequency_score'].value_counts().sort_index().to_dict()

    # Tactic analysis
    stats['tactic_weights'] = empirical_weights
    stats['tactic_counts'] = dict(tactic_counts)
    stats['top_tactics'] = dict(sorted(empirical_weights.items(),
                                       key=lambda x: x[1], reverse=True)[:5])

    # Platform analysis
    platform_counts = Counter()
    for platforms in df['platforms']:
        if platforms:
            platform_counts.update(platforms.split(', '))
    stats['platform_distribution'] = dict(platform_counts.most_common())

    # Detection coverage
    stats['detection_coverage'] = {
        'with_detection': df['detection_available'].sum(),
        'without_detection': (~df['detection_available']).sum(),
        'percentage': round((df['detection_available'].sum() / len(df)) * 100, 2)
    }

    # Entity coverage
    all_groups = [g for groups in df['groups'] for g in groups]
    all_software = [s for software in df['software'] for s in software]
    stats['entity_coverage'] = {
        'groups': dict(Counter(all_groups).most_common()),
        'software': dict(Counter(all_software).most_common())
    }

    # Score distribution
    stats['score_stats'] = {
        'mean': round(df['total_score'].mean(), 2),
        'median': round(df['total_score'].median(), 2),
        'std': round(df['total_score'].std(), 2),
        'min': round(df['total_score'].min(), 2),
        'max': round(df['total_score'].max(), 2)
    }

    return stats

def create_visualizations(df, stats, output_prefix):
    """Create visualizations for the paper"""

    # Set style
    sns.set_style("whitegrid")
    plt.rcParams['figure.figsize'] = (12, 8)

    # 1. Tactic Distribution
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))

    # Tactic frequency
    tactic_data = pd.Series(stats['tactic_counts']).sort_values(ascending=True)
    axes[0, 0].barh(tactic_data.index, tactic_data.values, color='steelblue')
    axes[0, 0].set_xlabel('Technique Count')
    axes[0, 0].set_title('Tactic Distribution in Banking Threats')
    axes[0, 0].grid(axis='x', alpha=0.3)

    # Frequency score distribution
    freq_dist = pd.Series(stats['frequency_distribution'])
    freq_labels = {1: 'Rare', 2: 'Medium', 3: 'Common', 4: 'High-Priority'}
    axes[0, 1].bar([freq_labels.get(k, str(k)) for k in freq_dist.index],
                   freq_dist.values, color='coral')
    axes[0, 1].set_ylabel('Technique Count')
    axes[0, 1].set_title('Technique Frequency Distribution')
    axes[0, 1].grid(axis='y', alpha=0.3)

    # Platform distribution
    platform_data = pd.Series(stats['platform_distribution']).head(10).sort_values(ascending=True)
    axes[1, 0].barh(platform_data.index, platform_data.values, color='seagreen')
    axes[1, 0].set_xlabel('Technique Count')
    axes[1, 0].set_title('Top 10 Targeted Platforms')
    axes[1, 0].grid(axis='x', alpha=0.3)

    # Score distribution
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

    plt.tight_layout()
    plt.savefig(f'{output_prefix}_overview.png', dpi=300, bbox_inches='tight')
    print(f"Saved: {output_prefix}_overview.png")
    plt.close()

    # 2. Entity Coverage Heatmap
    entity_coverage = []
    for idx, row in df.iterrows():
        for group in row['groups']:
            entity_coverage.append({
                'technique': row['technique_id'],
                'entity': group,
                'type': 'Group'
            })
        for software in row['software']:
            entity_coverage.append({
                'technique': row['technique_id'],
                'entity': software,
                'type': 'Software'
            })

    if entity_coverage:
        coverage_df = pd.DataFrame(entity_coverage)
        pivot_table = coverage_df.pivot_table(
            index='entity',
            columns='technique',
            aggfunc='size',
            fill_value=0
        )

        plt.figure(figsize=(20, 10))
        sns.heatmap(pivot_table, cmap='YlOrRd', cbar_kws={'label': 'Usage'})
        plt.title('Banking Threat Entity-Technique Coverage Matrix')
        plt.xlabel('Technique ID')
        plt.ylabel('Threat Entity')
        plt.tight_layout()
        plt.savefig(f'{output_prefix}_heatmap.png', dpi=300, bbox_inches='tight')
        print(f"Saved: {output_prefix}_heatmap.png")
        plt.close()

def print_summary_report(stats, df):
    """Print comprehensive summary report"""
    print("\n" + "="*80)
    print("BANKING SECTOR THREAT ANALYSIS - SUMMARY REPORT")
    print("="*80)

    print("\n1. OVERVIEW")
    print("-" * 80)
    print(f"Total Techniques Identified: {stats['total_techniques']}")
    print(f"Unique Threat Groups: {stats['total_groups']}")
    print(f"Unique Malware/Tools: {stats['total_software']}")

    print("\n2. TACTIC ANALYSIS (Empirical Weights from Data)")
    print("-" * 80)
    for tactic, weight in sorted(stats['top_tactics'].items(),
                                  key=lambda x: x[1], reverse=True):
        count = stats['tactic_counts'].get(tactic, 0)
        print(f"  {tactic:.<30} {weight:>6.2f}% ({count} techniques)")

    print("\n3. FREQUENCY DISTRIBUTION")
    print("-" * 80)
    freq_labels = {1: 'Rare (1 entity)', 2: 'Medium (2-3 entities)',
                   3: 'Common (4-5 entities)', 4: 'High-Priority (6+ entities)'}
    for score, count in sorted(stats['frequency_distribution'].items()):
        label = freq_labels.get(score, f'Score {score}')
        print(f"  {label:.<40} {count:>4} techniques")

    print("\n4. DETECTION COVERAGE")
    print("-" * 80)
    print(f"  Techniques with Detection Guidance: {stats['detection_coverage']['with_detection']}")
    print(f"  Techniques without Detection Guidance: {stats['detection_coverage']['without_detection']}")
    print(f"  Coverage Percentage: {stats['detection_coverage']['percentage']}%\n")

    print("\n5. TOP 10 THREAT GROUPS BY TECHNIQUE COUNT")
    print("-" * 80)
    for entity, count in list(stats['entity_coverage']['groups'].items())[:10]:
        print(f"  {entity:.<40} {count:>4} techniques")

    print("\n6. TOP 10 MALWARE/TOOLS BY TECHNIQUE COUNT")
    print("-" * 80)
    for entity, count in list(stats['entity_coverage']['software'].items())[:10]:
        print(f"  {entity:.<40} {count:>4} techniques")

    print("\n7. TECHNIQUE SCORE STATISTICS")
    print("-" * 80)
    for metric, value in stats['score_stats'].items():
        print(f"  {metric.capitalize():.<20} {value:>8.2f}")

    print("\n8. TOP 15 HIGHEST PRIORITY TECHNIQUES")
    print("-" * 80)
    top_15 = df.nlargest(15, 'total_score')[['technique_id', 'name', 'entity_count',
                                               'total_score', 'tactics_str']]
    for idx, row in top_15.iterrows():
        print(f"\n  {row['technique_id']} - {row['name']}")
        print(f"    Score: {row['total_score']} | Used by {row['entity_count']} entities")
        print(f"    Tactics: {row['tactics_str']}")

def main():
    print("=" * 80)
    print("MITRE ATT&CK - Banking Sector Threat Analysis")
    print("=" * 80)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Enterprise ATT&CK Source: {SRC_ENTERPRISE}")
    print("\nTarget Scope:")
    print("  Banking Sector: Core deposit, lending, payment infrastructure")
    print("                  (SWIFT, RTGS, ATMs, Core Banking Systems)")
    print("  Financial Sector: Non-banking financial entities")
    print("-" * 80)

    # Fetch data
    print("\nFetching Enterprise ATT&CK data...")
    data = fetch_attack_data(SRC_ENTERPRISE)

    if not data:
        print("Failed to fetch data!")
        return

    # Validate entities
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

    # Extract techniques
    print("\n" + "="*80)
    print("Extracting techniques from banking threat entities...")
    techniques = extract_banking_techniques(data, entity_details)

    if not techniques:
        print("No techniques found!")
        return

    # Create DataFrame
    df = pd.DataFrame(techniques)

    # Calculate empirical tactic weights
    print("\nCalculating empirical tactic weights from data...")
    empirical_weights, normalized_weights, tactic_counts = calculate_empirical_tactic_weights(df)

    print("\nEmpirical Tactic Weights (based on banking threat data):")
    for tactic, weight in sorted(empirical_weights.items(), key=lambda x: x[1], reverse=True):
        print(f"  {tactic:.<30} {weight:>6.2f}%")

    # Calculate technique scores
    print("\nCalculating multi-factor technique scores...")
    df['total_score'] = calculate_technique_scores(df, normalized_weights)

    # Sort by score
    df = df.sort_values('total_score', ascending=False).reset_index(drop=True)

    # Generate statistics
    print("\nGenerating statistics...")
    stats = generate_statistics(df, empirical_weights, tactic_counts)

    # Print summary report
    print_summary_report(stats, df)

    # Create visualizations
    print("\n" + "="*80)
    print("Creating visualizations...")
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_prefix = f"banking_analysis_{timestamp}"

    try:
        create_visualizations(df, stats, output_prefix)
    except Exception as e:
        print(f"Warning: Could not create visualizations: {e}")

    # Save results
    print("\n" + "="*80)
    print("Saving results...")

    # Full detailed results
    output_file = f"{output_prefix}_full.csv"
    df.to_csv(output_file, index=False)
    print(f"✓ Full results: {output_file}")

    # Summary for paper
    summary_cols = ['technique_id', 'name', 'entity_count', 'group_count',
                    'software_count', 'total_score', 'frequency_score',
                    'tactics_str', 'platforms', 'detection_available', 'all_entities']
    summary_df = df[summary_cols].copy()
    summary_df['all_entities'] = summary_df['all_entities'].apply(lambda x: ', '.join(x))
    summary_file = f"{output_prefix}_summary.csv"
    summary_df.to_csv(summary_file, index=False)
    print(f"✓ Summary table: {summary_file}")

    # Top priority techniques
    top_priority = df.nlargest(50, 'total_score')[summary_cols]
    top_priority['all_entities'] = top_priority['all_entities'].apply(lambda x: ', '.join(x) if isinstance(x, list) else x)
    priority_file = f"{output_prefix}_top_priority.csv"
    top_priority.to_csv(priority_file, index=False)
    print(f"✓ Top priority techniques: {priority_file}")

    # Statistics JSON
    stats_file = f"{output_prefix}_statistics.json"
    with open(stats_file, 'w') as f:
        json.dump(convert_to_serializable(stats), f, indent=2)
    print(f"✓ Statistics: {stats_file}")

    # Methodology documentation
    methodology_file = f"{output_prefix}_methodology.txt"
    with open(methodology_file, 'w') as f:
        f.write("BANKING SECTOR THREAT ANALYSIS METHODOLOGY\n")
        f.write("=" * 80 + "\n\n")
        f.write("1. DATA SOURCE\n")
        f.write(f"   - MITRE ATT&CK Enterprise: {SRC_ENTERPRISE}\n")
        f.write(f"   - Analysis Date: {datetime.now().strftime('%Y-%m-%d')}\n\n")
        f.write("2. ENTITY SELECTION CRITERIA\n")
        f.write("   - Threat groups primarily targeting banking/financial sector\n")
        f.write("   - Malware/tools with documented banking sector operations\n")
        f.write(f"   - Total entities: {stats['total_groups']} groups, {stats['total_software']} software\n\n")
        f.write("3. TACTIC WEIGHT CALCULATION\n")
        f.write("   - Empirically derived from technique-tactic associations\n")
        f.write("   - Based on actual banking threat entity behavior\n")
        f.write("   - Weights represent percentage of total technique coverage\n\n")
        for tactic, weight in sorted(empirical_weights.items(), key=lambda x: x[1], reverse=True):
            f.write(f"     {tactic}: {weight}%\n")
        f.write("\n4. SCORING METHODOLOGY\n")
        f.write("   - Entity Usage Score (0-40): Based on number of entities using technique\n")
        f.write("   - Tactic Importance Score (0-40): Weighted by empirical tactic distribution\n")
        f.write("   - Group Diversity Bonus (0-20): Rewards techniques used by multiple groups\n")
        f.write("   - Total Score Range: 0-100\n\n")
        f.write("5. VALIDATION\n")
        f.write("   - Cross-reference with industry threat reports recommended\n")
        f.write("   - Sources: Verizon DBIR, IBM X-Force, Mandiant M-Trends\n")

    print(f"✓ Methodology documentation: {methodology_file}")

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print(f"\nNext Steps for Paper:")
    print("1. Review {stats_file} for statistical analysis")
    print("2. Use visualizations from *_overview.png and *_heatmap.png")
    print("3. Cross-validate tactic weights with Verizon DBIR/IBM X-Force reports")
    print("4. Compare findings with energy sector paper for comparative analysis")
    print("5. Use methodology.txt to document your approach in paper")

    return df, stats

if __name__ == "__main__":
    df, stats = main()
