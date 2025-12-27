"""
MITRE ATT&CK Banking Sector - Individual Paper Visualizations
Professional monotone color scheme for academic papers
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from datetime import datetime

# Professional monotone color palette
COLORS = {
    'primary': '#2c3e50',      # Dark blue-gray
    'secondary': '#34495e',    # Medium blue-gray
    'accent': '#4a6785',       # Steel blue
    'light': '#7f8c8d',        # Light gray
    'highlight': '#5d6d7e',    # Slate gray
    'navy': '#1e3a5f',         # Navy blue
    'steel': '#4682b4',        # Steel blue
    'slate': '#708090',        # Slate gray
    'lightblue': '#b0c4de',    # Light steel blue
}

# Set professional style
plt.rcParams['font.family'] = 'serif'
plt.rcParams['font.size'] = 11
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['xtick.labelsize'] = 10
plt.rcParams['ytick.labelsize'] = 10
plt.rcParams['legend.fontsize'] = 10
plt.rcParams['figure.titlesize'] = 16

def viz_1_tactic_distribution(stats, output_dir='./'):
    """
    Visualization 1: Tactic Distribution in Banking Threats
    Shows the frequency of each MITRE ATT&CK tactic
    """
    plt.figure(figsize=(10, 6))

    tactic_data = pd.Series(stats['tactic_counts']).sort_values(ascending=True)

    # Create horizontal bar chart
    bars = plt.barh(tactic_data.index, tactic_data.values,
                     color=COLORS['navy'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.xlabel('Number of Techniques', fontweight='bold')
    plt.ylabel('MITRE ATT&CK Tactic', fontweight='bold')
    plt.title('Tactic Distribution in Banking Sector Threats',
              fontweight='bold', pad=20)

    # Add value labels on bars
    for i, bar in enumerate(bars):
        width = bar.get_width()
        plt.text(width + 0.5, bar.get_y() + bar.get_height()/2,
                f'{int(width)}', ha='left', va='center', fontsize=10)

    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_1_tactic_distribution.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_2_frequency_categories(stats, output_dir='./'):
    """
    Visualization 2: Technique Frequency Categories
    Shows distribution of techniques by usage frequency
    """
    plt.figure(figsize=(9, 6))

    freq_dist = pd.Series(stats['frequency_distribution'])
    freq_labels = {
        1: 'Rare\n(1 entity)',
        2: 'Medium\n(2-3 entities)',
        3: 'Common\n(4-5 entities)',
        4: 'High-Priority\n(6+ entities)'
    }

    labels = [freq_labels.get(k, str(k)) for k in sorted(freq_dist.index)]
    values = [freq_dist[k] for k in sorted(freq_dist.index)]

    colors_gradient = [COLORS['lightblue'], COLORS['steel'],
                       COLORS['accent'], COLORS['navy']]

    bars = plt.bar(labels, values, color=colors_gradient,
                    edgecolor=COLORS['primary'], linewidth=1.2)

    plt.ylabel('Number of Techniques', fontweight='bold')
    plt.xlabel('Frequency Category', fontweight='bold')
    plt.title('Technique Frequency Distribution by Entity Usage',
              fontweight='bold', pad=20)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom', fontsize=11, fontweight='bold')

    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_2_frequency_categories.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_3_detection_coverage(df, output_dir='./'):
    """
    Visualization 3: MITRE Detection Notes Availability
    Shows percentage of techniques with detection guidance
    """
    plt.figure(figsize=(8, 6))

    det_counts = df['detection_available'].value_counts()
    labels = ['With Detection\nGuidance', 'Without Detection\nGuidance']
    values = [det_counts.get(True, 0), det_counts.get(False, 0)]
    percentages = [v/sum(values)*100 for v in values]

    bars = plt.bar(labels, values,
                    color=[COLORS['navy'], COLORS['slate']],
                    edgecolor=COLORS['primary'], linewidth=1.2)

    plt.ylabel('Number of Techniques', fontweight='bold')
    plt.title('MITRE Detection Notes Availability for Banking Threats',
              fontweight='bold', pad=20)

    # Add value and percentage labels
    for i, bar in enumerate(bars):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}\n({percentages[i]:.1f}%)',
                ha='center', va='bottom', fontsize=11, fontweight='bold')

    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_3_detection_coverage.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_4_platform_distribution(stats, output_dir='./'):
    """
    Visualization 4: Targeted Platform Distribution
    Shows the top platforms targeted by banking threats
    """
    plt.figure(figsize=(10, 7))

    platform_data = pd.Series(stats['platform_distribution']).head(12).sort_values(ascending=True)

    bars = plt.barh(platform_data.index, platform_data.values,
                     color=COLORS['accent'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.xlabel('Number of Techniques', fontweight='bold')
    plt.ylabel('Platform', fontweight='bold')
    plt.title('Top 12 Platforms Targeted by Banking Sector Threats',
              fontweight='bold', pad=20)

    # Add value labels
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height()/2,
                f'{int(width)}', ha='left', va='center', fontsize=10)

    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_4_platform_distribution.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_5_score_distribution(df, stats, output_dir='./'):
    """
    Visualization 5: Technique Priority Score Distribution
    Histogram showing the distribution of calculated threat scores
    """
    plt.figure(figsize=(10, 6))

    plt.hist(df['total_score'], bins=25, color=COLORS['steel'],
             edgecolor=COLORS['primary'], linewidth=1.2, alpha=0.8)

    # Add mean and median lines
    mean_score = stats['score_stats']['mean']
    median_score = stats['score_stats']['median']

    plt.axvline(mean_score, color=COLORS['navy'], linestyle='--', linewidth=2.5,
                label=f'Mean: {mean_score:.1f}')
    plt.axvline(median_score, color=COLORS['slate'], linestyle=':', linewidth=2.5,
                label=f'Median: {median_score:.1f}')

    plt.xlabel('Priority Score', fontweight='bold')
    plt.ylabel('Number of Techniques', fontweight='bold')
    plt.title('Distribution of Technique Priority Scores',
              fontweight='bold', pad=20)
    plt.legend(loc='upper right', framealpha=0.9)
    plt.grid(alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_5_score_distribution.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_6_top_techniques(df, output_dir='./'):
    """
    Visualization 6: Top 15 Techniques by Priority Score
    Shows the highest-priority techniques for banking sector
    """
    plt.figure(figsize=(12, 8))

    top_15 = df.nlargest(15, 'total_score')

    # Create labels with technique ID and abbreviated name
    labels = []
    for _, row in top_15.iterrows():
        name = row['name']
        if len(name) > 30:
            name = name[:27] + '...'
        labels.append(f"{row['technique_id']}: {name}")

    y_pos = np.arange(len(labels))

    bars = plt.barh(y_pos, top_15['total_score'].values,
                     color=COLORS['navy'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.yticks(y_pos, labels[::-1])
    plt.xlabel('Priority Score', fontweight='bold')
    plt.ylabel('Technique', fontweight='bold')
    plt.title('Top 15 Banking Threat Techniques by Priority Score',
              fontweight='bold', pad=20)

    # Add score labels
    for i, bar in enumerate(bars):
        width = bar.get_width()
        plt.text(width + 0.5, bar.get_y() + bar.get_height()/2,
                f'{width:.1f}', ha='left', va='center', fontsize=9)

    plt.gca().invert_yaxis()
    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_6_top_techniques.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_7_entity_type_distribution(stats, output_dir='./'):
    """
    Visualization 7: Threat Entity Type Coverage
    Compares groups vs software/malware in banking threats
    """
    plt.figure(figsize=(8, 6))

    labels = ['Threat Groups', 'Malware/Tools']
    values = [stats['total_groups'], stats['total_software']]

    bars = plt.bar(labels, values,
                    color=[COLORS['navy'], COLORS['accent']],
                    edgecolor=COLORS['primary'], linewidth=1.2)

    plt.ylabel('Number of Entities', fontweight='bold')
    plt.title('Banking Sector Threat Entities by Type',
              fontweight='bold', pad=20)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom',
                fontsize=12, fontweight='bold')

    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_7_entity_type_distribution.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_8_top_threat_groups(stats, output_dir='./'):
    """
    Visualization 8: Top Threat Groups by Technique Count
    Shows the most active threat groups targeting banking sector
    """
    plt.figure(figsize=(10, 7))

    top_groups = dict(list(stats['entity_coverage']['groups'].items())[:12])
    groups_series = pd.Series(top_groups).sort_values(ascending=True)

    bars = plt.barh(groups_series.index, groups_series.values,
                     color=COLORS['navy'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.xlabel('Number of Techniques', fontweight='bold')
    plt.ylabel('Threat Group', fontweight='bold')
    plt.title('Top 12 Threat Groups Targeting Banking Sector',
              fontweight='bold', pad=20)

    # Add value labels
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height()/2,
                f'{int(width)}', ha='left', va='center', fontsize=10)

    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_8_top_threat_groups.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_9_top_malware(stats, output_dir='./'):
    """
    Visualization 9: Top Malware/Tools by Technique Count
    Shows the most sophisticated banking malware
    """
    plt.figure(figsize=(10, 7))

    top_software = dict(list(stats['entity_coverage']['software'].items())[:12])
    software_series = pd.Series(top_software).sort_values(ascending=True)

    bars = plt.barh(software_series.index, software_series.values,
                     color=COLORS['accent'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.xlabel('Number of Techniques', fontweight='bold')
    plt.ylabel('Malware/Tool', fontweight='bold')
    plt.title('Top 12 Banking Malware/Tools by Technique Count',
              fontweight='bold', pad=20)

    # Add value labels
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.3, bar.get_y() + bar.get_height()/2,
                f'{int(width)}', ha='left', va='center', fontsize=10)

    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_9_top_malware.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_10_tactic_percentage(stats, output_dir='./'):
    """
    Visualization 10: Tactic Distribution as Percentages
    Shows relative importance of each tactic in banking threats
    """
    plt.figure(figsize=(10, 6))

    tactic_weights = stats['tactic_weights']
    tactics_df = pd.DataFrame(list(tactic_weights.items()),
                              columns=['Tactic', 'Percentage']).sort_values('Percentage', ascending=True)

    bars = plt.barh(tactics_df['Tactic'], tactics_df['Percentage'],
                     color=COLORS['steel'], edgecolor=COLORS['primary'], linewidth=1.2)

    plt.xlabel('Percentage of Total Techniques (%)', fontweight='bold')
    plt.ylabel('MITRE ATT&CK Tactic', fontweight='bold')
    plt.title('Tactic Distribution by Percentage in Banking Threats',
              fontweight='bold', pad=20)

    # Add percentage labels
    for bar in bars:
        width = bar.get_width()
        plt.text(width + 0.2, bar.get_y() + bar.get_height()/2,
                f'{width:.1f}%', ha='left', va='center', fontsize=10)

    plt.grid(axis='x', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_10_tactic_percentage.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_11_entity_count_distribution(df, output_dir='./'):
    """
    Visualization 11: Distribution of Entity Count per Technique
    Shows how many entities use each technique
    """
    plt.figure(figsize=(10, 6))

    entity_counts = df['entity_count'].value_counts().sort_index()

    bars = plt.bar(entity_counts.index, entity_counts.values,
                    color=COLORS['navy'], edgecolor=COLORS['primary'],
                    linewidth=1.2, width=0.8)

    plt.xlabel('Number of Entities Using Technique', fontweight='bold')
    plt.ylabel('Number of Techniques', fontweight='bold')
    plt.title('Distribution of Entity Usage per Technique',
              fontweight='bold', pad=20)

    # Add value labels on bars
    for bar in bars:
        height = bar.get_height()
        if height > 0:
            plt.text(bar.get_x() + bar.get_width()/2., height,
                    f'{int(height)}', ha='center', va='bottom', fontsize=9)

    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_11_entity_count_distribution.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_12_techniques_per_tactic(df, output_dir='./'):
    """
    Visualization 12: Average Techniques per Tactic Category
    Shows complexity of techniques by number of tactics they span
    """
    plt.figure(figsize=(9, 6))

    tactics_per_technique = df['tactics'].apply(len)
    tactic_count_dist = tactics_per_technique.value_counts().sort_index()

    bars = plt.bar(tactic_count_dist.index, tactic_count_dist.values,
                    color=COLORS['accent'], edgecolor=COLORS['primary'],
                    linewidth=1.2, width=0.7)

    plt.xlabel('Number of Tactics per Technique', fontweight='bold')
    plt.ylabel('Number of Techniques', fontweight='bold')
    plt.title('Technique Complexity: Tactics Span per Technique',
              fontweight='bold', pad=20)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom',
                fontsize=11, fontweight='bold')

    plt.xticks(tactic_count_dist.index)
    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_12_techniques_per_tactic.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_13_score_components(df, output_dir='./'):
    """
    Visualization 13: Score Distribution by Frequency Category
    Box plot showing score ranges for each frequency category
    """
    plt.figure(figsize=(10, 6))

    freq_labels = {1: 'Rare', 2: 'Medium', 3: 'Common', 4: 'High-Priority'}
    df_plot = df.copy()
    df_plot['freq_label'] = df_plot['frequency_score'].map(freq_labels)

    # Create box plot
    categories = ['Rare', 'Medium', 'Common', 'High-Priority']
    data_to_plot = [df_plot[df_plot['freq_label'] == cat]['total_score'].values
                    for cat in categories]

    bp = plt.boxplot(data_to_plot, labels=categories, patch_artist=True,
                     widths=0.6, showmeans=True,
                     meanprops=dict(marker='D', markerfacecolor=COLORS['navy'],
                                   markeredgecolor=COLORS['navy'], markersize=6))

    # Color the boxes
    colors_gradient = [COLORS['lightblue'], COLORS['steel'],
                       COLORS['accent'], COLORS['navy']]
    for patch, color in zip(bp['boxes'], colors_gradient):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
        patch.set_edgecolor(COLORS['primary'])
        patch.set_linewidth(1.5)

    # Style whiskers, caps, and medians
    for whisker in bp['whiskers']:
        whisker.set(color=COLORS['primary'], linewidth=1.5)
    for cap in bp['caps']:
        cap.set(color=COLORS['primary'], linewidth=1.5)
    for median in bp['medians']:
        median.set(color='darkred', linewidth=2)

    plt.ylabel('Priority Score', fontweight='bold')
    plt.xlabel('Frequency Category', fontweight='bold')
    plt.title('Score Distribution by Technique Frequency Category',
              fontweight='bold', pad=20)
    plt.grid(axis='y', alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_13_score_components.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_14_group_software_comparison(df, output_dir='./'):
    """
    Visualization 14: Comparison of Group vs Software Technique Usage
    Scatter plot showing relationship between groups and software per technique
    """
    plt.figure(figsize=(10, 7))

    scatter = plt.scatter(df['group_count'], df['software_count'],
                         s=df['total_score']*3, alpha=0.6,
                         c=df['total_score'], cmap='Blues',
                         edgecolors=COLORS['primary'], linewidth=0.5)

    plt.xlabel('Number of Threat Groups Using Technique', fontweight='bold')
    plt.ylabel('Number of Malware/Tools Using Technique', fontweight='bold')
    plt.title('Threat Group vs Malware Usage per Technique\n(bubble size = priority score)',
              fontweight='bold', pad=20)

    # Add colorbar
    cbar = plt.colorbar(scatter, label='Priority Score')
    cbar.set_label('Priority Score', fontweight='bold')

    plt.grid(alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_14_group_software_comparison.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def viz_15_cumulative_coverage(df, output_dir='./'):
    """
    Visualization 15: Cumulative Coverage by Top Techniques
    Shows how many techniques needed to cover X% of total priority
    """
    plt.figure(figsize=(10, 6))

    # Sort by score and calculate cumulative percentage
    df_sorted = df.sort_values('total_score', ascending=False).reset_index(drop=True)
    cumulative_score = df_sorted['total_score'].cumsum()
    cumulative_percentage = (cumulative_score / cumulative_score.max()) * 100

    plt.plot(range(1, len(cumulative_percentage) + 1), cumulative_percentage,
             color=COLORS['navy'], linewidth=2.5)

    # Add reference lines
    plt.axhline(y=50, color=COLORS['slate'], linestyle='--', linewidth=1.5,
                label='50% Coverage', alpha=0.7)
    plt.axhline(y=80, color=COLORS['accent'], linestyle='--', linewidth=1.5,
                label='80% Coverage', alpha=0.7)
    plt.axhline(y=90, color=COLORS['steel'], linestyle='--', linewidth=1.5,
                label='90% Coverage', alpha=0.7)

    plt.xlabel('Number of Top Techniques', fontweight='bold')
    plt.ylabel('Cumulative Priority Coverage (%)', fontweight='bold')
    plt.title('Cumulative Priority Coverage by Top Techniques',
              fontweight='bold', pad=20)
    plt.legend(loc='lower right', framealpha=0.9)
    plt.grid(alpha=0.3, linestyle='--')
    plt.tight_layout()

    filename = f'{output_dir}viz_15_cumulative_coverage.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight', facecolor='white')
    print(f"✓ Saved: {filename}")
    plt.close()


def generate_all_visualizations(df, stats, output_dir='./'):
    """
    Generate all individual visualizations for the paper
    """
    print("\n" + "="*80)
    print("GENERATING INDIVIDUAL PAPER VISUALIZATIONS")
    print("="*80)
    print(f"Color scheme: Professional monotone (Navy blue, Steel blue, Slate gray)")
    print(f"Output directory: {output_dir}")
    print(f"Total visualizations: 15")
    print("-"*80)

    viz_functions = [
        (viz_1_tactic_distribution, "Tactic Distribution"),
        (viz_2_frequency_categories, "Frequency Categories"),
        (viz_3_detection_coverage, "Detection Coverage"),
        (viz_4_platform_distribution, "Platform Distribution"),
        (viz_5_score_distribution, "Score Distribution"),
        (viz_6_top_techniques, "Top Techniques"),
        (viz_7_entity_type_distribution, "Entity Type Distribution"),
        (viz_8_top_threat_groups, "Top Threat Groups"),
        (viz_9_top_malware, "Top Malware"),
        (viz_10_tactic_percentage, "Tactic Percentages"),
        (viz_11_entity_count_distribution, "Entity Count Distribution"),
        (viz_12_techniques_per_tactic, "Techniques per Tactic"),
        (viz_13_score_components, "Score Components"),
        (viz_14_group_software_comparison, "Group vs Software"),
        (viz_15_cumulative_coverage, "Cumulative Coverage"),
    ]

    for i, (func, name) in enumerate(viz_functions, 1):
        print(f"\n[{i}/15] Generating: {name}...")
        try:
            if func in [viz_1_tactic_distribution, viz_2_frequency_categories,
                       viz_4_platform_distribution, viz_7_entity_type_distribution,
                       viz_8_top_threat_groups, viz_9_top_malware,
                       viz_10_tactic_percentage]:
                func(stats, output_dir)
            elif func == viz_5_score_distribution:
                func(df, stats, output_dir)
            else:
                func(df, output_dir)
        except Exception as e:
            print(f"  ✗ Error: {e}")
            continue

    print("\n" + "="*80)
    print("VISUALIZATION GENERATION COMPLETE")
    print("="*80)
    print(f"\nAll visualizations saved with 300 DPI for publication quality")
    print(f"Color scheme: Monotone blue/gray palette")
    print(f"Font: Serif for academic paper compatibility")


if __name__ == "__main__":
    # This script requires data from mitre_bank_accurate.py
    # Run mitre_bank_accurate.py first to generate the data

    print("="*80)
    print("MITRE BANKING THREAT ANALYSIS - PAPER VISUALIZATIONS")
    print("="*80)
    print("\nThis script generates individual, publication-ready visualizations")
    print("from the MITRE banking sector threat analysis data.")
    print("\nRequirements:")
    print("  1. Run 'mitre_bank_accurate.py' first to generate data files")
    print("  2. Ensure CSV and JSON files are in the same directory")
    print("\nOr import this module and call:")
    print("  generate_all_visualizations(df, stats, output_dir='./visualizations/')")
    print("="*80)
