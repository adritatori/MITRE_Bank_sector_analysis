# LLM NIDS Classification Analysis

This folder contains comprehensive analysis of LLM classifications for MITRE ATT&CK technique detectability by Network Intrusion Detection Systems (NIDS).

## Overview

Four Large Language Models (Claude, Grok, GPT, and Gemini) were asked to evaluate whether each banking-sector MITRE ATT&CK technique is detectable by NIDS. This analysis aggregates their responses using a consensus mechanism.

## Consensus Methodology

**3/4 Majority Rule**: If at least 3 out of 4 LLMs agree on a classification (YES, NO, or PARTIAL), that becomes the consensus classification. Cases with 2-2 splits are marked as "NO_CONSENSUS".

## Key Findings

- **Total Techniques Analyzed**: 210 (banking-sector specific)
- **High Confidence Rate**: 90.0% (3+ models agree)
- **Perfect Agreement**: 61.4% (all 4 models agree)
- **Detectable Techniques**: 25.7% (YES + PARTIAL)
- **Not Detectable**: 64.3%

### Model Characteristics

- **Most Optimistic**: Gemini (54 YES classifications)
- **Most Conservative**: Grok (151 NO classifications)
- **Model Agreement**: 66-72% pairwise agreement between models

## Generated Files

### Visualizations

1. **00_comprehensive_overview.png** - Dashboard showing all key metrics
2. **01_per_model_distribution.png** - Individual model classification breakdowns
3. **02_model_agreement_matrix.png** - Heatmap of inter-model agreement rates
4. **03_consensus_analysis.png** - Consensus distribution and agreement levels
5. **05_consensus_by_tactic.png** - Consensus breakdown by MITRE ATT&CK tactic

### Data Files

- **consensus_classifications.csv** - Complete dataset with consensus results for each technique
- **summary_report.txt** - Detailed statistical summary report

## Analysis Script

**analyze_llm_classifications.py** - Python script that performs the analysis and generates all visualizations

### Requirements
- pandas
- matplotlib
- seaborn
- numpy

### Usage
```bash
python3 analyze_llm_classifications.py
```

## Color Scheme

All visualizations use a professional monotone color scheme:
- **Navy Blue** (#1e3a5f) - YES classifications
- **Gray** (#636e72) - NO classifications
- **Medium Blue** (#4a6fa5) - PARTIAL classifications

This matches the aesthetic of previous MITRE bank paper visualizations.

## Insights

1. **High Model Agreement**: With 90.0% high-confidence classifications, the LLMs show strong consistency in evaluating NIDS detectability.

2. **Most Techniques Are Not Network-Detectable**: The majority (64.3%) of banking-sector ATT&CK techniques operate locally (file operations, registry modifications, process injection, etc.) and thus leave no network footprint.

3. **Model Variation**: Gemini tends to be more optimistic about detectability (25.7% YES), while Grok is more conservative (71.9% NO). Claude and GPT fall in the middle.

4. **Network-Based Techniques**: About 1/4 (25.7%) of techniques produce detectable or conditionally detectable network artifacts (primarily C2 communications, file transfers, and web protocols).

## Applications

This consensus-based classification can be used to:
- Prioritize NIDS deployment for techniques with confirmed network visibility
- Identify gaps where host-based detection is required
- Guide defensive strategy based on LLM expertise aggregation
- Benchmark individual LLM performance against consensus
