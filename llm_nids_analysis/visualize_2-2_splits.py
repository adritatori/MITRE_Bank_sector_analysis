#!/usr/bin/env python3
"""
Visualize 2-2 Split Cases - Where LLMs Were Evenly Divided
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from collections import Counter

# Color scheme
COLORS = {
    'primary': '#1e3a5f',
    'secondary': '#4a6fa5',
    'yes': '#2ecc71',
    'no': '#e74c3c',
    'partial': '#f39c12',
}

def load_splits():
    """Load 2-2 split cases"""
    df = pd.read_csv('2-2_splits.csv')
    print(f"Loaded {len(df)} 2-2 split cases")
    return df

def categorize_split_pattern(row):
    """Categorize the split pattern"""
    classifications = sorted([row['claude'], row['grok'], row['gpt'], row['gemini']])
    pattern = '-'.join(classifications)

    # Identify pattern type
    if pattern == "NO-NO-PARTIAL-PARTIAL":
        return "NO-NO vs PARTIAL-PARTIAL"
    elif pattern == "PARTIAL-PARTIAL-YES-YES":
        return "PARTIAL-PARTIAL vs YES-YES"
    elif pattern == "PARTIAL-YES-PARTIAL-YES":
        return "PARTIAL-YES mixed"
    elif pattern == "NO-NO-YES-YES":
        return "NO-NO vs YES-YES"
    elif pattern == "NO-PARTIAL-NO-PARTIAL":
        return "NO-PARTIAL mixed"
    elif pattern == "NO-PARTIAL-YES-YES":
        return "NO-PARTIAL vs YES-YES"
    elif pattern == "NO-NO-PARTIAL-YES":
        return "NO-NO-PARTIAL-YES (3-way)"
    else:
        return pattern

def visualize_split_patterns(df):
    """Create visualization of split patterns"""
    # Categorize each split
    df['pattern_category'] = df.apply(categorize_split_pattern, axis=1)

    # Count patterns
    pattern_counts = df['pattern_category'].value_counts()

    # Create figure with multiple subplots
    fig = plt.figure(figsize=(16, 10))
    gs = fig.add_gridspec(2, 2, hspace=0.3, wspace=0.3)

    # Overall title
    fig.suptitle('2-2 Split Analysis: Even LLM Disagreement on NIDS Detectability',
                fontsize=16, fontweight='bold', color=COLORS['primary'])

    # Plot 1: Pattern distribution
    ax1 = fig.add_subplot(gs[0, :])
    bars = ax1.barh(range(len(pattern_counts)), pattern_counts.values,
                    color=COLORS['secondary'], edgecolor=COLORS['primary'], linewidth=1.5)
    ax1.set_yticks(range(len(pattern_counts)))
    ax1.set_yticklabels(pattern_counts.index)
    ax1.set_xlabel('Number of Techniques', fontsize=12, fontweight='bold')
    ax1.set_title('Distribution of 2-2 Split Patterns', fontsize=13, fontweight='bold')
    ax1.grid(axis='x', alpha=0.3)

    # Add value labels
    for i, (bar, val) in enumerate(zip(bars, pattern_counts.values)):
        ax1.text(val + 0.2, bar.get_y() + bar.get_height()/2,
                f'{val} ({val/len(df)*100:.1f}%)',
                va='center', fontsize=10, fontweight='bold')

    # Plot 2: Model agreement pairs
    ax2 = fig.add_subplot(gs[1, 0])

    # Count which models tend to agree
    agreement_pairs = []
    models = ['claude', 'grok', 'gpt', 'gemini']

    for idx, row in df.iterrows():
        for i in range(len(models)):
            for j in range(i+1, len(models)):
                if row[models[i]] == row[models[j]]:
                    pair = f"{models[i].title()}-{models[j].title()}"
                    agreement_pairs.append(pair)

    pair_counts = Counter(agreement_pairs).most_common(10)

    pairs = [p[0] for p in pair_counts]
    counts = [p[1] for p in pair_counts]

    bars2 = ax2.barh(range(len(pairs)), counts,
                     color=COLORS['primary'], edgecolor='black', linewidth=1.0)
    ax2.set_yticks(range(len(pairs)))
    ax2.set_yticklabels(pairs)
    ax2.set_xlabel('Agreement Frequency', fontsize=11)
    ax2.set_title('Model Pairing in 2-2 Splits', fontsize=12, fontweight='bold')
    ax2.grid(axis='x', alpha=0.3)

    for bar, val in zip(bars2, counts):
        ax2.text(val + 0.3, bar.get_y() + bar.get_height()/2,
                f'{val}', va='center', fontsize=9, fontweight='bold')

    # Plot 3: Classification distribution in splits
    ax3 = fig.add_subplot(gs[1, 1])

    all_classifications = []
    for col in ['claude', 'grok', 'gpt', 'gemini']:
        all_classifications.extend(df[col].tolist())

    class_counts = Counter(all_classifications)

    categories = ['YES', 'PARTIAL', 'NO']
    values = [class_counts.get(cat, 0) for cat in categories]
    colors_list = [COLORS['yes'], COLORS['partial'], COLORS['no']]

    bars3 = ax3.bar(categories, values, color=colors_list,
                    edgecolor='black', linewidth=1.5)
    ax3.set_ylabel('Total Count Across All Models', fontsize=11)
    ax3.set_title('Classification Distribution in 2-2 Splits', fontsize=12, fontweight='bold')
    ax3.grid(axis='y', alpha=0.3)

    for bar in bars3:
        height = bar.get_height()
        ax3.text(bar.get_x() + bar.get_width()/2., height,
               f'{int(height)}\n({height/(len(df)*4)*100:.1f}%)',
               ha='center', va='bottom', fontsize=10, fontweight='bold')

    plt.savefig('06_2-2_split_analysis.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: 06_2-2_split_analysis.png")
    plt.close()

def create_detailed_heatmap(df):
    """Create heatmap showing all 2-2 splits"""
    fig, ax = plt.subplots(figsize=(10, 14))

    # Prepare data for heatmap
    techniques = df['technique_id'].tolist()
    models = ['Claude', 'Grok', 'GPT', 'Gemini']

    # Create numeric matrix (YES=2, PARTIAL=1, NO=0)
    data_matrix = []
    for idx, row in df.iterrows():
        row_values = []
        for model in ['claude', 'grok', 'gpt', 'gemini']:
            val = row[model]
            if val == 'YES':
                row_values.append(2)
            elif val == 'PARTIAL':
                row_values.append(1)
            else:
                row_values.append(0)
        data_matrix.append(row_values)

    # Create heatmap
    cmap = sns.color_palette([COLORS['no'], COLORS['partial'], COLORS['yes']], as_cmap=True)
    sns.heatmap(data_matrix, annot=False, fmt='d', cmap=cmap,
                xticklabels=models, yticklabels=[f"{t} - {n[:30]}" for t, n in zip(df['technique_id'], df['name'])],
                cbar_kws={'label': 'Classification', 'ticks': [0, 1, 2]},
                vmin=0, vmax=2, linewidths=0.5, linecolor='white',
                ax=ax)

    # Update colorbar labels
    colorbar = ax.collections[0].colorbar
    colorbar.set_ticks([0.33, 1, 1.67])
    colorbar.set_ticklabels(['NO', 'PARTIAL', 'YES'])

    ax.set_title('All 2-2 Split Cases: Model Classifications\n(21 Techniques with Even Disagreement)',
                fontsize=13, fontweight='bold', color=COLORS['primary'], pad=20)
    ax.set_xlabel('LLM Model', fontsize=11, fontweight='bold')
    ax.set_ylabel('MITRE ATT&CK Technique', fontsize=11, fontweight='bold')

    plt.tight_layout()
    plt.savefig('07_2-2_split_heatmap.png', dpi=300, bbox_inches='tight')
    print("✓ Saved: 07_2-2_split_heatmap.png")
    plt.close()

def generate_stats(df):
    """Generate statistics about 2-2 splits"""
    print("\n" + "="*60)
    print("2-2 SPLIT STATISTICS")
    print("="*60 + "\n")

    print(f"Total techniques with 2-2 splits: {len(df)}")
    print(f"Percentage of all 210 techniques: {len(df)/210*100:.1f}%\n")

    # Pattern distribution
    df['pattern_category'] = df.apply(categorize_split_pattern, axis=1)
    pattern_counts = df['pattern_category'].value_counts()

    print("Split Pattern Distribution:")
    for pattern, count in pattern_counts.items():
        print(f"  {pattern}: {count} ({count/len(df)*100:.1f}%)")

    # Classification breakdown
    all_classifications = []
    for col in ['claude', 'grok', 'gpt', 'gemini']:
        all_classifications.extend(df[col].tolist())

    class_counts = Counter(all_classifications)
    total_class = sum(class_counts.values())

    print("\nClassification Distribution (across all 4 models × 21 techniques):")
    for cls in ['YES', 'PARTIAL', 'NO']:
        count = class_counts.get(cls, 0)
        print(f"  {cls}: {count} ({count/total_class*100:.1f}%)")

    print("\n" + "="*60)

def main():
    df = load_splits()
    visualize_split_patterns(df)
    create_detailed_heatmap(df)
    generate_stats(df)

    print("\n✓ Analysis complete!")
    print("\nGenerated files:")
    print("  • 06_2-2_split_analysis.png - Pattern distribution and model pairing")
    print("  • 07_2-2_split_heatmap.png - Heatmap of all 2-2 split classifications")

if __name__ == '__main__':
    main()
