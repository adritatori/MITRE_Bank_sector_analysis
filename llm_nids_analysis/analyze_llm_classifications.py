#!/usr/bin/env python3
"""
LLM NIDS Classification Analysis
Analyzes classifications from Claude, Grok, GPT, and Gemini on MITRE ATT&CK technique detectability
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
from collections import Counter
import os

# Set style with monotone colors (navy blue, gray theme)
plt.style.use('seaborn-v0_8-darkgrid')
COLORS = {
    'primary': '#1e3a5f',      # Navy blue
    'secondary': '#4a6fa5',    # Medium blue
    'tertiary': '#6b8cae',     # Light blue
    'gray_dark': '#2d3436',    # Dark gray
    'gray_medium': '#636e72',  # Medium gray
    'gray_light': '#b2bec3',   # Light gray
    'yes': '#1e3a5f',          # Navy blue for YES
    'no': '#636e72',           # Gray for NO
    'partial': '#4a6fa5',      # Medium blue for PARTIAL
}

def load_data(csv_path):
    """Load and prepare the CSV data"""
    df = pd.read_csv(csv_path)
    print(f"Total rows in CSV: {len(df)}")

    # Filter to only rows with LLM classifications
    df_filtered = df[df['Claude Classification'].notna() &
                     df['Gork Classification'].notna() &
                     df['GPT Classification'].notna() &
                     df['Gemini Classification'].notna()].copy()

    print(f"Techniques with LLM classifications: {len(df_filtered)}")
    return df_filtered

def get_model_classifications(df):
    """Extract classification columns for each model"""
    models = {
        'Claude': 'Claude Classification',
        'Grok': 'Gork Classification',  # Note: Spelled as "Gork" in CSV
        'GPT': 'GPT Classification',
        'Gemini': 'Gemini Classification'
    }
    return models

def analyze_per_model_distribution(df, models, output_dir):
    """Analyze and visualize classification distribution per model"""
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle('Classification Distribution per LLM Model',
                 fontsize=16, fontweight='bold', color=COLORS['primary'])

    axes = axes.flatten()

    stats = {}
    for idx, (model_name, col_name) in enumerate(models.items()):
        counts = df[col_name].value_counts()
        stats[model_name] = counts.to_dict()

        # Create bar plot
        ax = axes[idx]
        categories = ['YES', 'NO', 'PARTIAL']
        values = [counts.get(cat, 0) for cat in categories]
        colors_list = [COLORS['yes'], COLORS['no'], COLORS['partial']]

        bars = ax.bar(categories, values, color=colors_list, edgecolor=COLORS['gray_dark'], linewidth=1.5)

        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom', fontsize=11, fontweight='bold')

        ax.set_title(f'{model_name}', fontsize=13, fontweight='bold', color=COLORS['primary'])
        ax.set_ylabel('Count', fontsize=11)
        ax.set_ylim(0, max(values) * 1.15)
        ax.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/01_per_model_distribution.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 01_per_model_distribution.png")
    plt.close()

    return stats

def analyze_model_agreement(df, models, output_dir):
    """Analyze how often models agree with each other"""
    model_names = list(models.keys())
    agreement_matrix = np.zeros((len(model_names), len(model_names)))

    for i, model1 in enumerate(model_names):
        for j, model2 in enumerate(model_names):
            if i == j:
                agreement_matrix[i][j] = 100.0
            else:
                col1 = models[model1]
                col2 = models[model2]
                agreements = (df[col1] == df[col2]).sum()
                agreement_matrix[i][j] = (agreements / len(df)) * 100

    # Create heatmap
    fig, ax = plt.subplots(figsize=(10, 8))
    sns.heatmap(agreement_matrix, annot=True, fmt='.1f',
                xticklabels=model_names, yticklabels=model_names,
                cmap='Blues', cbar_kws={'label': 'Agreement %'},
                vmin=0, vmax=100, linewidths=0.5, linecolor=COLORS['gray_dark'])

    plt.title('Model Agreement Matrix (%)', fontsize=14, fontweight='bold',
             color=COLORS['primary'], pad=20)
    plt.xlabel('Model', fontsize=12, fontweight='bold')
    plt.ylabel('Model', fontsize=12, fontweight='bold')
    plt.tight_layout()
    plt.savefig(f'{output_dir}/02_model_agreement_matrix.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 02_model_agreement_matrix.png")
    plt.close()

    return agreement_matrix

def calculate_consensus(row, models):
    """Calculate consensus classification for a row"""
    classifications = [row[col] for col in models.values()]
    count = Counter(classifications)

    # Check for majority (3/4 or 4/4)
    most_common = count.most_common(1)[0]
    if most_common[1] >= 3:  # At least 3 models agree
        return most_common[0], most_common[1]
    else:
        # No consensus - return the max agreement count (usually 2 for 2-2 splits)
        return 'NO_CONSENSUS', most_common[1]

def analyze_consensus(df, models, output_dir):
    """Analyze consensus among models using 3/4 majority rule"""
    # Calculate consensus for each technique
    consensus_results = []
    for idx, row in df.iterrows():
        consensus, agreement_count = calculate_consensus(row, models)
        consensus_results.append({
            'technique_id': row['technique_id'],
            'name': row['name'],
            'consensus': consensus,
            'agreement_count': agreement_count,
            'claude': row[models['Claude']],
            'grok': row[models['Grok']],
            'gpt': row[models['GPT']],
            'gemini': row[models['Gemini']]
        })

    consensus_df = pd.DataFrame(consensus_results)

    # Save consensus results to CSV
    consensus_df.to_csv(f'{output_dir}/consensus_classifications.csv', index=False)
    print(f"✓ Saved: consensus_classifications.csv")

    # Visualize consensus distribution
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))

    # Plot 1: Consensus classification distribution
    consensus_counts = consensus_df['consensus'].value_counts()
    categories = ['YES', 'NO', 'PARTIAL', 'NO_CONSENSUS']
    values = [consensus_counts.get(cat, 0) for cat in categories]
    colors_list = [COLORS['yes'], COLORS['no'], COLORS['partial'], COLORS['gray_light']]

    bars1 = ax1.bar(categories, values, color=colors_list, edgecolor=COLORS['gray_dark'], linewidth=1.5)
    for bar in bars1:
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}\n({height/len(df)*100:.1f}%)',
               ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax1.set_title('Consensus Classification Distribution', fontsize=13, fontweight='bold',
                 color=COLORS['primary'])
    ax1.set_ylabel('Number of Techniques', fontsize=11)
    ax1.grid(axis='y', alpha=0.3)

    # Plot 2: Agreement level distribution
    agreement_counts = consensus_df['agreement_count'].value_counts().sort_index()
    bars2 = ax2.bar(agreement_counts.index, agreement_counts.values,
                   color=COLORS['secondary'], edgecolor=COLORS['gray_dark'], linewidth=1.5)
    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}',
               ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax2.set_title('Agreement Level Distribution', fontsize=13, fontweight='bold',
                 color=COLORS['primary'])
    ax2.set_xlabel('Number of Models in Agreement', fontsize=11)
    ax2.set_ylabel('Number of Techniques', fontsize=11)
    ax2.set_xticks([0, 1, 2, 3, 4])
    ax2.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/03_consensus_analysis.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 03_consensus_analysis.png")
    plt.close()

    return consensus_df

def analyze_disagreement_patterns(df, models, consensus_df, output_dir):
    """Analyze patterns in disagreements"""
    # Find techniques with disagreement
    disagreements = consensus_df[consensus_df['agreement_count'] == 2]

    if len(disagreements) > 0:
        # Analyze disagreement patterns
        pattern_counts = {}
        for idx, row in disagreements.iterrows():
            classifications = [row['claude'], row['grok'], row['gpt'], row['gemini']]
            pattern = '-'.join(sorted(classifications))
            pattern_counts[pattern] = pattern_counts.get(pattern, 0) + 1

        # Visualize top disagreement patterns
        fig, ax = plt.subplots(figsize=(12, 6))
        patterns = list(pattern_counts.keys())[:10]  # Top 10
        counts = [pattern_counts[p] for p in patterns]

        bars = ax.barh(patterns, counts, color=COLORS['tertiary'],
                      edgecolor=COLORS['gray_dark'], linewidth=1.5)
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2.,
                   f'{int(width)}',
                   ha='left', va='center', fontsize=10, fontweight='bold',
                   bbox=dict(boxstyle='round,pad=0.3', facecolor='white', alpha=0.7))

        ax.set_title('Top Disagreement Patterns (2-2 Splits)',
                    fontsize=13, fontweight='bold', color=COLORS['primary'])
        ax.set_xlabel('Number of Techniques', fontsize=11)
        ax.set_ylabel('Classification Pattern', fontsize=11)
        ax.grid(axis='x', alpha=0.3)

        plt.tight_layout()
        plt.savefig(f'{output_dir}/04_disagreement_patterns.png', dpi=300, bbox_inches='tight')
        print(f"✓ Saved: 04_disagreement_patterns.png")
        plt.close()

def analyze_2_2_splits_detailed(df, models, consensus_df, output_dir):
    """Detailed analysis of 2-2 split cases"""
    # Find all NO_CONSENSUS cases
    no_consensus = consensus_df[consensus_df['consensus'] == 'NO_CONSENSUS'].copy()

    if len(no_consensus) == 0:
        return

    # Analyze split patterns
    split_data = []
    for idx, row in no_consensus.iterrows():
        classifications = {
            'Claude': row['claude'],
            'Grok': row['grok'],
            'GPT': row['gpt'],
            'Gemini': row['gemini']
        }
        count = Counter(classifications.values())

        # Determine split type
        if len(count) == 2 and list(count.values()) == [2, 2]:
            split_type = f"{list(count.keys())[0]} vs {list(count.keys())[1]}"
        else:
            split_type = "Mixed"

        split_data.append({
            'technique_id': row['technique_id'],
            'name': row['name'],
            'split_type': split_type,
            'pattern': dict(count),
            **classifications
        })

    split_df = pd.DataFrame(split_data)

    # Save detailed CSV
    split_df.to_csv(f'{output_dir}/2-2_split_techniques.csv', index=False)
    print(f"✓ Saved: 2-2_split_techniques.csv")

    # Create visualization
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 8))

    # Left plot: Split type distribution
    split_type_counts = split_df['split_type'].value_counts()
    colors_split = [COLORS['tertiary']] * len(split_type_counts)

    bars1 = ax1.barh(range(len(split_type_counts)), split_type_counts.values,
                     color=colors_split, edgecolor=COLORS['gray_dark'], linewidth=1.5)
    ax1.set_yticks(range(len(split_type_counts)))
    ax1.set_yticklabels(split_type_counts.index, fontsize=10)

    for i, bar in enumerate(bars1):
        width = bar.get_width()
        ax1.text(width, bar.get_y() + bar.get_height()/2.,
                f' {int(width)}', ha='left', va='center',
                fontsize=10, fontweight='bold')

    ax1.set_title('2-2 Split Types', fontsize=13, fontweight='bold', color=COLORS['primary'])
    ax1.set_xlabel('Number of Techniques', fontsize=11)
    ax1.grid(axis='x', alpha=0.3)

    # Right plot: Model pair agreement in split cases
    model_pairs = {
        'Claude-Grok': 0,
        'Claude-GPT': 0,
        'Claude-Gemini': 0,
        'Grok-GPT': 0,
        'Grok-Gemini': 0,
        'GPT-Gemini': 0
    }

    for idx, row in split_df.iterrows():
        if row['Claude'] == row['Grok']:
            model_pairs['Claude-Grok'] += 1
        if row['Claude'] == row['GPT']:
            model_pairs['Claude-GPT'] += 1
        if row['Claude'] == row['Gemini']:
            model_pairs['Claude-Gemini'] += 1
        if row['Grok'] == row['GPT']:
            model_pairs['Grok-GPT'] += 1
        if row['Grok'] == row['Gemini']:
            model_pairs['Grok-Gemini'] += 1
        if row['GPT'] == row['Gemini']:
            model_pairs['GPT-Gemini'] += 1

    pairs = list(model_pairs.keys())
    counts = list(model_pairs.values())

    bars2 = ax2.bar(range(len(pairs)), counts, color=COLORS['secondary'],
                    edgecolor=COLORS['gray_dark'], linewidth=1.5)
    ax2.set_xticks(range(len(pairs)))
    ax2.set_xticklabels(pairs, rotation=45, ha='right')

    for bar in bars2:
        height = bar.get_height()
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{int(height)}', ha='center', va='bottom',
                fontsize=10, fontweight='bold')

    ax2.set_title('Model Pair Agreements in Split Cases', fontsize=13,
                 fontweight='bold', color=COLORS['primary'])
    ax2.set_ylabel('Agreement Count', fontsize=11)
    ax2.grid(axis='y', alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/06_2-2_split_analysis.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 06_2-2_split_analysis.png")
    plt.close()

    # Create a detailed table visualization
    fig, ax = plt.subplots(figsize=(16, max(10, len(split_df) * 0.4)))

    # Prepare data for table
    table_data = []
    for idx, row in split_df.head(20).iterrows():  # Show top 20
        table_data.append([
            row['technique_id'],
            row['name'][:30] + '...' if len(row['name']) > 30 else row['name'],
            row['Claude'],
            row['Grok'],
            row['GPT'],
            row['Gemini']
        ])

    # Create table
    table = ax.table(cellText=table_data,
                    colLabels=['Technique ID', 'Name', 'Claude', 'Grok', 'GPT', 'Gemini'],
                    cellLoc='left',
                    loc='center',
                    colWidths=[0.12, 0.35, 0.13, 0.13, 0.13, 0.14])

    table.auto_set_font_size(False)
    table.set_fontsize(9)
    table.scale(1, 2)

    # Color code the cells
    for i in range(len(table_data)):
        for j in range(2, 6):  # Model columns
            cell = table[(i+1, j)]
            value = table_data[i][j]
            if value == 'YES':
                cell.set_facecolor(COLORS['yes'])
                cell.set_text_props(color='white', weight='bold')
            elif value == 'NO':
                cell.set_facecolor(COLORS['no'])
                cell.set_text_props(color='white', weight='bold')
            elif value == 'PARTIAL':
                cell.set_facecolor(COLORS['partial'])
                cell.set_text_props(color='white', weight='bold')

    # Header styling
    for j in range(6):
        cell = table[(0, j)]
        cell.set_facecolor(COLORS['primary'])
        cell.set_text_props(color='white', weight='bold')

    ax.axis('off')
    ax.set_title(f'2-2 Split Techniques Detail (Showing {min(20, len(split_df))} of {len(split_df)})',
                fontsize=14, fontweight='bold', color=COLORS['primary'], pad=20)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/07_2-2_split_details.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 07_2-2_split_details.png")
    plt.close()

    return split_df

def analyze_by_tactic(df, models, consensus_df, output_dir):
    """Analyze consensus by MITRE ATT&CK tactic"""
    # Merge consensus with original data
    df_merged = df.merge(consensus_df[['technique_id', 'consensus']], on='technique_id')

    # Extract primary tactic (first one listed)
    df_merged['primary_tactic'] = df_merged['tactics_str'].apply(lambda x: x.split(',')[0].strip() if pd.notna(x) else 'unknown')

    # Count consensus types by tactic
    tactic_consensus = df_merged.groupby(['primary_tactic', 'consensus']).size().unstack(fill_value=0)

    # Plot top tactics
    top_tactics = df_merged['primary_tactic'].value_counts().head(10).index
    # Only select tactics that exist in the index
    valid_tactics = [t for t in top_tactics if t in tactic_consensus.index]
    tactic_consensus_top = tactic_consensus.loc[valid_tactics]

    fig, ax = plt.subplots(figsize=(14, 8))
    # Ensure columns exist
    available_cols = [col for col in ['YES', 'NO', 'PARTIAL'] if col in tactic_consensus_top.columns]
    if available_cols:
        tactic_consensus_top[available_cols].plot(
            kind='bar', stacked=True, ax=ax,
            color=[COLORS[col.lower()] for col in available_cols],
            edgecolor=COLORS['gray_dark'], linewidth=1.0
        )

    ax.set_title('Consensus Classification by MITRE ATT&CK Tactic (Top 10)',
                fontsize=13, fontweight='bold', color=COLORS['primary'])
    ax.set_xlabel('Tactic', fontsize=11)
    ax.set_ylabel('Number of Techniques', fontsize=11)
    ax.legend(title='Consensus', framealpha=0.9)
    ax.grid(axis='y', alpha=0.3)
    plt.xticks(rotation=45, ha='right')

    plt.tight_layout()
    plt.savefig(f'{output_dir}/05_consensus_by_tactic.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 05_consensus_by_tactic.png")
    plt.close()

def generate_summary_stats(df, models, consensus_df, stats, output_dir):
    """Generate summary statistics report"""
    total_techniques = len(df)

    # Model stats
    model_stats_text = "PER MODEL STATISTICS\n" + "="*60 + "\n\n"
    for model_name, counts in stats.items():
        total = sum(counts.values())
        model_stats_text += f"{model_name}:\n"
        model_stats_text += f"  YES:     {counts.get('YES', 0):4d} ({counts.get('YES', 0)/total*100:5.1f}%)\n"
        model_stats_text += f"  NO:      {counts.get('NO', 0):4d} ({counts.get('NO', 0)/total*100:5.1f}%)\n"
        model_stats_text += f"  PARTIAL: {counts.get('PARTIAL', 0):4d} ({counts.get('PARTIAL', 0)/total*100:5.1f}%)\n"
        model_stats_text += f"  Total:   {total:4d}\n\n"

    # Consensus stats
    consensus_counts = consensus_df['consensus'].value_counts()
    agreement_counts = consensus_df['agreement_count'].value_counts()

    consensus_stats_text = "\nCONSENSUS STATISTICS (3/4 Majority Rule)\n" + "="*60 + "\n\n"
    consensus_stats_text += f"Total Banking-Sector Techniques Analyzed: {total_techniques}\n\n"
    consensus_stats_text += "Consensus Results:\n"
    consensus_stats_text += f"  YES (Detectable):        {consensus_counts.get('YES', 0):4d} ({consensus_counts.get('YES', 0)/total_techniques*100:5.1f}%)\n"
    consensus_stats_text += f"  NO (Not Detectable):     {consensus_counts.get('NO', 0):4d} ({consensus_counts.get('NO', 0)/total_techniques*100:5.1f}%)\n"
    consensus_stats_text += f"  PARTIAL (Conditional):   {consensus_counts.get('PARTIAL', 0):4d} ({consensus_counts.get('PARTIAL', 0)/total_techniques*100:5.1f}%)\n"
    consensus_stats_text += f"  NO_CONSENSUS (2-2 tie):  {consensus_counts.get('NO_CONSENSUS', 0):4d} ({consensus_counts.get('NO_CONSENSUS', 0)/total_techniques*100:5.1f}%)\n\n"

    consensus_stats_text += "Agreement Levels:\n"
    consensus_stats_text += f"  4/4 models agree:  {agreement_counts.get(4, 0):4d} ({agreement_counts.get(4, 0)/total_techniques*100:5.1f}%)\n"
    consensus_stats_text += f"  3/4 models agree:  {agreement_counts.get(3, 0):4d} ({agreement_counts.get(3, 0)/total_techniques*100:5.1f}%)\n"
    consensus_stats_text += f"  2-2 split:         {agreement_counts.get(2, 0):4d} ({agreement_counts.get(2, 0)/total_techniques*100:5.1f}%)\n\n"

    # Key insights
    insights_text = "\nKEY INSIGHTS\n" + "="*60 + "\n\n"

    high_confidence = agreement_counts.get(4, 0) + agreement_counts.get(3, 0)
    insights_text += f"• High Confidence Classifications (3+ models agree): {high_confidence} ({high_confidence/total_techniques*100:.1f}%)\n"

    detectable = consensus_counts.get('YES', 0) + consensus_counts.get('PARTIAL', 0)
    insights_text += f"• Detectable Techniques (YES + PARTIAL): {detectable} ({detectable/total_techniques*100:.1f}%)\n"

    not_detectable = consensus_counts.get('NO', 0)
    insights_text += f"• Not Detectable Techniques: {not_detectable} ({not_detectable/total_techniques*100:.1f}%)\n"

    # Model comparison
    most_yes = max(stats.items(), key=lambda x: x[1].get('YES', 0))
    most_no = max(stats.items(), key=lambda x: x[1].get('NO', 0))

    insights_text += f"\n• Most Optimistic Model (most YES): {most_yes[0]} ({most_yes[1].get('YES', 0)} YES)\n"
    insights_text += f"• Most Conservative Model (most NO): {most_no[0]} ({most_no[1].get('NO', 0)} NO)\n"

    # Save report
    full_report = model_stats_text + consensus_stats_text + insights_text
    with open(f'{output_dir}/summary_report.txt', 'w') as f:
        f.write(full_report)

    print(f"✓ Saved: summary_report.txt")
    print("\n" + "="*60)
    print(full_report)

def create_overview_visualization(df, models, consensus_df, stats, output_dir):
    """Create a comprehensive overview visualization"""
    fig = plt.figure(figsize=(18, 10))
    gs = fig.add_gridspec(3, 3, hspace=0.3, wspace=0.3)

    # Overall title
    fig.suptitle('LLM NIDS Classification Analysis - Banking Sector (210 Techniques)',
                fontsize=16, fontweight='bold', color=COLORS['primary'], y=0.98)

    # 1. Total techniques count
    ax1 = fig.add_subplot(gs[0, 0])
    ax1.text(0.5, 0.5, f"{len(df)}", ha='center', va='center',
            fontsize=48, fontweight='bold', color=COLORS['primary'])
    ax1.text(0.5, 0.2, "Total Techniques\nAnalyzed", ha='center', va='center',
            fontsize=12, color=COLORS['gray_dark'])
    ax1.axis('off')
    ax1.set_xlim(0, 1)
    ax1.set_ylim(0, 1)

    # 2. Consensus distribution pie
    ax2 = fig.add_subplot(gs[0, 1])
    consensus_counts = consensus_df['consensus'].value_counts()
    labels = [f"{k}\n{v}" for k, v in consensus_counts.items()]
    colors = [COLORS['yes'], COLORS['no'], COLORS['partial'], COLORS['gray_light']][:len(consensus_counts)]
    ax2.pie(consensus_counts.values, labels=labels, colors=colors, autopct='%1.1f%%',
           startangle=90, textprops={'fontsize': 10, 'fontweight': 'bold'})
    ax2.set_title('Consensus Distribution', fontsize=11, fontweight='bold', color=COLORS['primary'])

    # 3. Agreement level
    ax3 = fig.add_subplot(gs[0, 2])
    agreement_counts = consensus_df['agreement_count'].value_counts().sort_index()
    high_conf = agreement_counts.get(3, 0) + agreement_counts.get(4, 0)
    pct = high_conf / len(df) * 100
    ax3.text(0.5, 0.5, f"{pct:.1f}%", ha='center', va='center',
            fontsize=42, fontweight='bold', color=COLORS['secondary'])
    ax3.text(0.5, 0.2, "High Confidence\n(3+ models agree)", ha='center', va='center',
            fontsize=11, color=COLORS['gray_dark'])
    ax3.axis('off')
    ax3.set_xlim(0, 1)
    ax3.set_ylim(0, 1)

    # 4-7. Model distributions (2x2 grid)
    for idx, (model_name, col_name) in enumerate(models.items()):
        row = 1 + idx // 2
        col = idx % 2
        ax = fig.add_subplot(gs[row, col])

        counts = df[col_name].value_counts()
        categories = ['YES', 'NO', 'PARTIAL']
        values = [counts.get(cat, 0) for cat in categories]
        colors_list = [COLORS['yes'], COLORS['no'], COLORS['partial']]

        bars = ax.bar(categories, values, color=colors_list, edgecolor=COLORS['gray_dark'], linewidth=1.0)
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}', ha='center', va='bottom', fontsize=9, fontweight='bold')

        ax.set_title(f'{model_name}', fontsize=11, fontweight='bold', color=COLORS['primary'])
        ax.set_ylim(0, max(values) * 1.15)
        ax.grid(axis='y', alpha=0.3)
        ax.tick_params(labelsize=9)

    # 8. Model comparison (all models)
    ax8 = fig.add_subplot(gs[2, :])

    model_data = []
    for model_name, col_name in models.items():
        counts = df[col_name].value_counts()
        model_data.append({
            'Model': model_name,
            'YES': counts.get('YES', 0),
            'NO': counts.get('NO', 0),
            'PARTIAL': counts.get('PARTIAL', 0)
        })

    comparison_df = pd.DataFrame(model_data)
    x = np.arange(len(comparison_df))
    width = 0.25

    ax8.bar(x - width, comparison_df['YES'], width, label='YES',
           color=COLORS['yes'], edgecolor=COLORS['gray_dark'], linewidth=1.0)
    ax8.bar(x, comparison_df['NO'], width, label='NO',
           color=COLORS['no'], edgecolor=COLORS['gray_dark'], linewidth=1.0)
    ax8.bar(x + width, comparison_df['PARTIAL'], width, label='PARTIAL',
           color=COLORS['partial'], edgecolor=COLORS['gray_dark'], linewidth=1.0)

    ax8.set_xlabel('LLM Model', fontsize=11, fontweight='bold')
    ax8.set_ylabel('Number of Techniques', fontsize=11, fontweight='bold')
    ax8.set_title('Model-by-Model Comparison', fontsize=12, fontweight='bold', color=COLORS['primary'])
    ax8.set_xticks(x)
    ax8.set_xticklabels(comparison_df['Model'])
    ax8.legend(framealpha=0.9)
    ax8.grid(axis='y', alpha=0.3)

    plt.savefig(f'{output_dir}/00_comprehensive_overview.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved: 00_comprehensive_overview.png")
    plt.close()

def main():
    """Main analysis pipeline"""
    # Configuration
    csv_path = '../banking_analysis_accurate_20251227_182232_full.csv'
    output_dir = '.'

    print("\n" + "="*60)
    print("LLM NIDS CLASSIFICATION ANALYSIS - BANKING SECTOR")
    print("="*60 + "\n")

    # Load data
    df = load_data(csv_path)
    models = get_model_classifications(df)

    print(f"\nAnalyzing classifications from {len(models)} models:")
    for model in models.keys():
        print(f"  • {model}")

    print(f"\nGenerating visualizations and analysis...\n")

    # Run analyses
    stats = analyze_per_model_distribution(df, models, output_dir)
    agreement_matrix = analyze_model_agreement(df, models, output_dir)
    consensus_df = analyze_consensus(df, models, output_dir)
    analyze_disagreement_patterns(df, models, consensus_df, output_dir)
    analyze_2_2_splits_detailed(df, models, consensus_df, output_dir)
    analyze_by_tactic(df, models, consensus_df, output_dir)
    create_overview_visualization(df, models, consensus_df, stats, output_dir)
    generate_summary_stats(df, models, consensus_df, stats, output_dir)

    print("\n" + "="*60)
    print("ANALYSIS COMPLETE!")
    print("="*60)
    print(f"\nAll visualizations and reports saved to: {os.path.abspath(output_dir)}/")
    print("\nGenerated files:")
    print("  • 00_comprehensive_overview.png - Complete analysis dashboard")
    print("  • 01_per_model_distribution.png - Individual model classifications")
    print("  • 02_model_agreement_matrix.png - Inter-model agreement heatmap")
    print("  • 03_consensus_analysis.png - Consensus results and agreement levels")
    print("  • 04_disagreement_patterns.png - Analysis of model disagreements")
    print("  • 05_consensus_by_tactic.png - Consensus breakdown by MITRE tactic")
    print("  • 06_2-2_split_analysis.png - 2-2 split types and model pair agreements")
    print("  • 07_2-2_split_details.png - Detailed table of 2-2 split techniques")
    print("  • consensus_classifications.csv - Full consensus results dataset")
    print("  • 2-2_split_techniques.csv - Detailed data on 2-2 split cases")
    print("  • summary_report.txt - Detailed statistical summary")
    print()

if __name__ == '__main__':
    main()
