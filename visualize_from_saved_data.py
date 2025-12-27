"""
Generate paper visualizations from previously saved analysis data
Use this if you already have CSV and JSON files from a previous analysis run
"""

import pandas as pd
import json
import glob
import os
from mitre_bank_paper_visualizations import generate_all_visualizations

def load_latest_data(data_dir='./'):
    """
    Load the most recent analysis data from saved files
    """
    # Find the most recent CSV file
    csv_files = glob.glob(f'{data_dir}banking_analysis_accurate_*_full.csv')
    if not csv_files:
        raise FileNotFoundError(
            "No analysis CSV files found. Please run mitre_bank_accurate.py first."
        )

    latest_csv = sorted(csv_files)[-1]
    print(f"Loading data from: {latest_csv}")

    # Load CSV
    df = pd.read_csv(latest_csv)

    # Convert string lists back to actual lists
    for col in ['all_entities', 'groups', 'software', 'tactics']:
        if col in df.columns:
            df[col] = df[col].apply(
                lambda x: x.split(', ') if isinstance(x, str) and x else []
            )

    # Find corresponding stats JSON file
    base_name = latest_csv.replace('_full.csv', '')
    stats_file = f"{base_name}_statistics.json"

    if not os.path.exists(stats_file):
        raise FileNotFoundError(
            f"Stats file not found: {stats_file}"
        )

    print(f"Loading statistics from: {stats_file}")
    with open(stats_file, 'r') as f:
        stats = json.load(f)

    return df, stats, base_name

def main():
    """
    Main function to load existing data and generate visualizations
    """
    print("="*80)
    print("PAPER VISUALIZATIONS FROM SAVED DATA")
    print("="*80)

    try:
        # Load the latest data
        print("\nLoading saved analysis data...")
        df, stats, base_name = load_latest_data()

        print(f"\nData loaded successfully:")
        print(f"  Techniques: {len(df)}")
        print(f"  Threat Groups: {stats['total_groups']}")
        print(f"  Malware/Tools: {stats['total_software']}")

        # Create output directory
        output_dir = './paper_visualizations/'
        os.makedirs(output_dir, exist_ok=True)
        print(f"\nOutput directory: {output_dir}")

        # Generate visualizations
        print("\nGenerating visualizations...")
        print("-"*80)
        generate_all_visualizations(df, stats, output_dir)

        print("\n" + "="*80)
        print("COMPLETE!")
        print("="*80)
        print(f"\nAll visualizations saved to: {output_dir}")

    except FileNotFoundError as e:
        print(f"\nError: {e}")
        print("\nPlease run 'python mitre_bank_accurate.py' first to generate data files.")
        return 1
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0

if __name__ == "__main__":
    exit(main())
