# MITRE ATT&CK Data Source Extraction - Technical Findings

## Investigation Summary
Date: 2025-12-16
Investigated: `enterprise-attack.json` from MITRE CTI GitHub repository

## Current STIX/JSON Data Structure

### Objects Found:
- **24,771 total objects** in the STIX bundle
  - 835 attack-patterns (techniques)
  - 38 x-mitre-data-source objects
  - 109 x-mitre-data-component objects
  - 1,739 x-mitre-analytic objects
  - 691 x-mitre-detection-strategy objects
  - 20,048 relationship objects

### Critical Finding: NO Linkages Between Data Sources and Techniques

#### 1. Data Component Objects (109 total)
- **ALL 109 data components have NO parent data source references**
- Field `x_mitre_data_source_ref` exists but is empty/None for every component
- Cannot resolve component -> data source relationship

#### 2. Technique Objects (835 total)
- **NO techniques have the `x_mitre_data_sources` field** (confirmed deprecated)
- Techniques have NO embedded data source information
- Cannot extract data sources directly from techniques

#### 3. Detects Relationships (691 total)
- **ALL 691 'detects' relationships connect detection-strategies to techniques**
- Source: x-mitre-detection-strategy objects
- Target: attack-pattern objects
- **ZERO 'detects' relationships from data components**

#### 4. Analytics Objects (1,739 total)
- Have NO `x_mitre_data_source_ref` or `x_mitre_data_component_ref` fields
- Have NO relationships to techniques in the STIX bundle
- Cannot be used for data source extraction

## Attempted Extraction Methods

### Method 1: Old Field (Deprecated)
```python
# DOES NOT WORK - field no longer exists
technique.get('x_mitre_data_sources', [])
```
**Result:** Field not present in any techniques

### Method 2: Component -> Source Resolution
```python
# DOES NOT WORK - parent references are empty
for component in components:
    parent_ref = component.get('x_mitre_data_source_ref')  # Always None/empty!
```
**Result:** All parent references are null

### Method 3: Detects Relationships
```python
# DOES NOT WORK - detects use detection-strategies, not components
for rel in relationships:
    if rel['relationship_type'] == 'detects':
        # source is x-mitre-detection-strategy, NOT x-mitre-data-component
```
**Result:** No component-to-technique linkages exist

## Conclusion

**The current MITRE ATT&CK STIX/JSON format (enterprise-attack.json) does NOT contain
the necessary linkages to map data sources to techniques.**

The data source objects and data component objects exist in the bundle, but:
1. Components are not linked to their parent data sources
2. Components are not linked to techniques
3. Techniques do not reference data sources

## Alternative Solutions

### Option 1: MITRE ATT&CK Website API
The MITRE ATT&CK website may expose data source information via their web API or Navigator JSON format.

### Option 2: Use Detection Strategies
Instead of data sources, use the 691 detection strategy objects that ARE properly linked to techniques:
```python
for rel in relationships:
    if rel['relationship_type'] == 'detects' and rel['source'] starts with 'x-mitre-detection-strategy':
        # This works! 691 linkages available
```

### Option 3: Manual Mapping
Create a manual mapping file based on the MITRE ATT&CK website data.

### Option 4: Use TAXII Server
The MITRE ATT&CK TAXII server might provide data in a different format with proper linkages.

## Recommendation

**Update the analysis code to:**
1. Remove the data source extraction attempt (it cannot work with current data)
2. Optionally add detection strategy extraction as an alternative
3. Clearly document this limitation in the methodology
4. Direct users to the MITRE ATT&CK website for data source information

**The core analysis (technique prioritization based on threat actor usage) remains valid
and unaffected by this limitation.**
