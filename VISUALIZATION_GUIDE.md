# MITRE Banking Sector Analysis - Visualization Guide

## Overview
This document describes all 15 individual visualizations created for the research paper on banking sector threats based on MITRE ATT&CK data.

**Color Scheme**: Professional monotone blue/gray palette
**Resolution**: 300 DPI (publication quality)
**Font**: Serif (academic paper compatible)

---

## Color Palette

All visualizations use a consistent, professional monotone color scheme:

| Color Name | Hex Code | RGB | Usage |
|------------|----------|-----|-------|
| Dark Blue-Gray | `#2c3e50` | (44, 62, 80) | Primary borders, text emphasis |
| Medium Blue-Gray | `#34495e` | (52, 73, 94) | Secondary elements |
| Steel Blue | `#4682b4` | (70, 130, 180) | Main bars, primary data |
| Slate Gray | `#708090` | (112, 128, 144) | Alternative bars, secondary data |
| Light Steel Blue | `#b0c4de` | (176, 196, 222) | Light bars, backgrounds |
| Navy Blue | `#1e3a5f` | (30, 58, 95) | High-priority elements, emphasis |
| Accent Blue | `#4a6785` | (74, 103, 133) | Medium-priority elements |
| Light Gray | `#7f8c8d` | (127, 140, 141) | Supporting elements |

---

## Visualizations

### 1. Tactic Distribution (viz_1_tactic_distribution.png)

**Purpose**: Shows the frequency of each MITRE ATT&CK tactic in banking threats

**Type**: Horizontal bar chart

**Key Insights**:
- Defense Evasion is the most common tactic (62 techniques, 24.90%)
- Discovery is second (30 techniques, 12.05%)
- Highlights which attack phases are most prevalent

**Color**: Navy Blue (`#1e3a5f`) bars with dark border

**Best For**: Understanding tactic priorities in banking attacks

---

### 2. Frequency Categories (viz_2_frequency_categories.png)

**Purpose**: Distribution of techniques by entity usage frequency

**Type**: Vertical bar chart

**Key Insights**:
- 81 techniques are "Rare" (used by 1 entity)
- 30 techniques are "High-Priority" (used by 6+ entities)
- Shows technique adoption patterns

**Colors**: Gradient from light to dark:
- Rare: Light Steel Blue (`#b0c4de`)
- Medium: Steel Blue (`#4682b4`)
- Common: Accent Blue (`#4a6785`)
- High-Priority: Navy Blue (`#1e3a5f`)

**Best For**: Identifying widely-adopted vs niche techniques

---

### 3. Detection Coverage (viz_3_detection_coverage.png)

**Purpose**: Shows availability of MITRE detection guidance for techniques

**Type**: Vertical bar chart

**Key Insights**:
- Percentage of techniques with detection notes
- Gap analysis for detection guidance
- Identifies areas needing more detection research

**Colors**:
- With Detection: Navy Blue (`#1e3a5f`)
- Without Detection: Slate Gray (`#708090`)

**Best For**: Assessing detection capability gaps

---

### 4. Platform Distribution (viz_4_platform_distribution.png)

**Purpose**: Top 12 platforms targeted by banking threats

**Type**: Horizontal bar chart

**Key Insights**:
- Windows is the primary target platform
- Shows cross-platform attack surface
- Identifies platform-specific defensive priorities

**Color**: Accent Blue (`#4a6785`) bars

**Best For**: Platform-specific security planning

---

### 5. Score Distribution (viz_5_score_distribution.png)

**Purpose**: Distribution of calculated priority scores across all techniques

**Type**: Histogram with statistical markers

**Key Insights**:
- Mean and median priority scores
- Score distribution pattern (normal, skewed, etc.)
- Helps identify scoring thresholds

**Colors**:
- Bars: Steel Blue (`#4682b4`)
- Mean line: Navy Blue (`#1e3a5f`) dashed
- Median line: Slate Gray (`#708090`) dotted

**Best For**: Understanding overall threat landscape scoring

---

### 6. Top Techniques (viz_6_top_techniques.png)

**Purpose**: Top 15 techniques ranked by priority score

**Type**: Horizontal bar chart

**Key Insights**:
- Highest-priority techniques for banking sector
- Includes technique IDs and names
- Direct actionable intelligence

**Color**: Navy Blue (`#1e3a5f`) bars

**Best For**: Prioritized defense planning, SOC focus areas

---

### 7. Entity Type Distribution (viz_7_entity_type_distribution.png)

**Purpose**: Comparison of threat groups vs malware/tools

**Type**: Vertical bar chart

**Key Insights**:
- 12 threat groups vs 11 malware/tools tracked
- Balance of entity types in dataset
- Scope of threat landscape

**Colors**:
- Threat Groups: Navy Blue (`#1e3a5f`)
- Malware/Tools: Accent Blue (`#4a6785`)

**Best For**: Understanding threat actor vs tool landscape

---

### 8. Top Threat Groups (viz_8_top_threat_groups.png)

**Purpose**: Top 12 threat groups by technique count

**Type**: Horizontal bar chart

**Key Insights**:
- Lazarus Group leads with 93 techniques
- Shows sophistication levels of different groups
- Helps prioritize threat intelligence focus

**Color**: Navy Blue (`#1e3a5f`) bars

**Best For**: Threat actor intelligence, attribution analysis

---

### 9. Top Malware (viz_9_top_malware.png)

**Purpose**: Top 12 banking malware/tools by technique count

**Type**: Horizontal bar chart

**Key Insights**:
- QakBot leads with 71 techniques
- TrickBot second with 55 techniques
- Shows malware sophistication and capabilities

**Color**: Accent Blue (`#4a6785`) bars

**Best For**: Malware family prioritization, AV/EDR tuning

---

### 10. Tactic Percentages (viz_10_tactic_percentage.png)

**Purpose**: Relative importance of each tactic as percentages

**Type**: Horizontal bar chart

**Key Insights**:
- Same as viz_1 but showing percentages instead of counts
- Defense Evasion: 24.90%
- Easier for comparing relative importance

**Color**: Steel Blue (`#4682b4`) bars

**Best For**: High-level strategic planning, executive briefings

---

### 11. Entity Count Distribution (viz_11_entity_count_distribution.png)

**Purpose**: Shows how many entities use each technique

**Type**: Vertical bar chart

**Key Insights**:
- Distribution of technique adoption
- Long tail vs widely-adopted techniques
- Helps identify common vs specialized techniques

**Color**: Navy Blue (`#1e3a5f`) bars

**Best For**: Understanding technique adoption patterns

---

### 12. Techniques per Tactic (viz_12_techniques_per_tactic.png)

**Purpose**: Technique complexity analysis - tactics spanned per technique

**Type**: Vertical bar chart

**Key Insights**:
- Most techniques span 1-2 tactics
- Multi-tactic techniques are more complex
- Shows versatility of techniques

**Color**: Accent Blue (`#4a6785`) bars

**Best For**: Understanding attack technique complexity

---

### 13. Score Components (viz_13_score_components.png)

**Purpose**: Box plot showing score ranges by frequency category

**Type**: Box plot

**Key Insights**:
- Score distribution within each frequency category
- High-Priority techniques have highest scores
- Shows correlation between usage and priority

**Colors**: Gradient boxes matching frequency colors:
- Rare: Light Steel Blue (`#b0c4de`)
- Medium: Steel Blue (`#4682b4`)
- Common: Accent Blue (`#4a6785`)
- High-Priority: Navy Blue (`#1e3a5f`)
- Median lines: Dark red for visibility

**Best For**: Statistical analysis, validating scoring methodology

---

### 14. Group vs Software Comparison (viz_14_group_software_comparison.png)

**Purpose**: Scatter plot showing relationship between group and software usage

**Type**: Scatter plot with bubble size

**Key Insights**:
- Bubble size = priority score
- Shows techniques used by both groups and malware
- Identifies cross-entity common techniques

**Colors**: Blue gradient (`Blues` colormap) based on priority score

**Best For**: Identifying techniques requiring broad defensive coverage

---

### 15. Cumulative Coverage (viz_15_cumulative_coverage.png)

**Purpose**: Shows how many techniques needed for X% priority coverage

**Type**: Cumulative line chart

**Key Insights**:
- Top 50 techniques provide ~50% coverage
- Top 100 techniques provide ~80% coverage
- Helps prioritize defensive efforts

**Colors**:
- Main line: Navy Blue (`#1e3a5f`)
- 50% line: Slate Gray (`#708090`)
- 80% line: Accent Blue (`#4a6785`)
- 90% line: Steel Blue (`#4682b4`)

**Best For**: Resource allocation, defensive prioritization

---

## Usage Recommendations

### For Paper Sections:

1. **Introduction/Background**: Use viz_1, viz_7, viz_10
2. **Methodology**: Use viz_5, viz_13
3. **Results - Threat Landscape**: Use viz_8, viz_9
4. **Results - Technique Analysis**: Use viz_2, viz_6, viz_11
5. **Results - Platform Analysis**: Use viz_4
6. **Results - Detection Gap Analysis**: Use viz_3
7. **Discussion**: Use viz_14, viz_15
8. **Conclusions**: Use viz_6, viz_15

### Figure Size Recommendations:

- **Full-page figures**: viz_6, viz_8, viz_9, viz_14, viz_15
- **Half-page figures**: viz_1, viz_2, viz_3, viz_4, viz_5, viz_10
- **Quarter-page/inline**: viz_7, viz_11, viz_12

### Combining Visualizations:

Consider creating multi-panel figures:
- **Panel A+B**: viz_1 + viz_10 (same data, different views)
- **Panel A+B**: viz_8 + viz_9 (groups and malware comparison)
- **Panel A+B**: viz_2 + viz_13 (frequency categories with score distribution)

---

## Technical Details

**Generated with**: Python 3.x, matplotlib, seaborn, pandas
**Format**: PNG
**Resolution**: 300 DPI
**Color mode**: RGB
**Grid**: Light gray dotted grid (alpha=0.3) for readability
**Fonts**: Serif family (11pt body, 12pt labels, 14pt titles)

---

## File Locations

All visualizations are saved in: `./paper_visualizations/`

**Naming convention**: `viz_[number]_[description].png`

## Regenerating Visualizations

To regenerate all visualizations with updated data:

```bash
# Option 1: Run full analysis + visualizations
python generate_paper_visualizations.py

# Option 2: Use existing saved data
python visualize_from_saved_data.py
```

To customize individual visualizations, edit `mitre_bank_paper_visualizations.py`

---

## Color Accessibility

The chosen monotone blue/gray palette:
- ✓ Printer-friendly (grayscale conversion)
- ✓ Colorblind-safe (single hue variations)
- ✓ Professional academic appearance
- ✓ High contrast for readability
- ✓ Suitable for both screen and print

---

*Generated: 2025-12-27*
*Source: MITRE ATT&CK Enterprise v16*
*Banking Sector Entities: 12 Groups, 11 Malware/Tools, 210 Techniques*
