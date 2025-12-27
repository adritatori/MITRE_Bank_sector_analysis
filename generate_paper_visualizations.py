"""
Runner script to generate all paper visualizations
This integrates with mitre_bank_accurate.py to create individual visualizations
"""

import sys
import os

# Import the main analysis module
from mitre_bank_accurate import main as run_analysis

# Import visualization functions
from mitre_bank_paper_visualizations import generate_all_visualizations

def main():
    """
    Main function to run analysis and generate visualizations
    """
    print("="*80)
    print("MITRE BANKING SECTOR THREAT ANALYSIS")
    print("INDIVIDUAL PAPER VISUALIZATIONS GENERATOR")
    print("="*80)

    # Step 1: Run the main analysis to get data
    print("\nStep 1: Running MITRE ATT&CK analysis...")
    print("-"*80)
    df, stats = run_analysis()

    # Step 2: Create output directory for visualizations
    output_dir = './paper_visualizations/'
    os.makedirs(output_dir, exist_ok=True)
    print(f"\nStep 2: Creating visualization output directory: {output_dir}")

    # Step 3: Generate all visualizations
    print("\nStep 3: Generating individual visualizations...")
    print("-"*80)
    generate_all_visualizations(df, stats, output_dir)

    print("\n" + "="*80)
    print("COMPLETE!")
    print("="*80)
    print(f"\nAll visualizations saved to: {output_dir}")
    print(f"Total files: 15 publication-ready PNG files")
    print(f"\nVisualization List:")
    print("  1. viz_1_tactic_distribution.png - Tactic frequency in banking threats")
    print("  2. viz_2_frequency_categories.png - Technique usage frequency categories")
    print("  3. viz_3_detection_coverage.png - MITRE detection notes availability")
    print("  4. viz_4_platform_distribution.png - Top targeted platforms")
    print("  5. viz_5_score_distribution.png - Priority score distribution")
    print("  6. viz_6_top_techniques.png - Top 15 techniques by priority")
    print("  7. viz_7_entity_type_distribution.png - Groups vs malware comparison")
    print("  8. viz_8_top_threat_groups.png - Top threat groups")
    print("  9. viz_9_top_malware.png - Top banking malware")
    print(" 10. viz_10_tactic_percentage.png - Tactic distribution percentages")
    print(" 11. viz_11_entity_count_distribution.png - Entity usage distribution")
    print(" 12. viz_12_techniques_per_tactic.png - Technique complexity analysis")
    print(" 13. viz_13_score_components.png - Score by frequency category")
    print(" 14. viz_14_group_software_comparison.png - Group vs software usage")
    print(" 15. viz_15_cumulative_coverage.png - Cumulative priority coverage")
    print("\nAll visualizations use professional monotone color scheme (navy/blue/gray)")
    print("300 DPI resolution for publication quality")
    print("="*80)

if __name__ == "__main__":
    main()
