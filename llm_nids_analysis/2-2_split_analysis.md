# LLM 2-2 Split Analysis: Cases of Even Disagreement

## Overview
This report details the 21 techniques where LLMs were evenly split (2 agreed, 2 disagreed) on NIDS detectability classification.

## Summary Statistics
- **Total 2-2 Splits**: 21 out of 210 techniques (10.0%)
- These cases represent the highest uncertainty in detectability assessment
- No majority consensus could be reached (neither 3/4 nor 4/4 agreement)

## Split Patterns Analysis

### Pattern 1: PARTIAL-PARTIAL vs YES-YES (4 cases)
**Indicates**: Disagreement on whether detection is conditional or full

1. **T1105 - Ingress Tool Transfer**
   - Claude: PARTIAL, Grok: PARTIAL | GPT: YES, Gemini: YES
   - Split: Is detection conditional or comprehensive?

2. **T1087.002 - Domain Account**
   - Claude: PARTIAL, Grok: PARTIAL | GPT: YES, Gemini: YES
   - Split: Account enumeration - partial vs full detection

3. **T1505.003 - Web Shell**
   - Claude: PARTIAL, Grok: PARTIAL | GPT: YES, Gemini: YES
   - Split: Web shell detection confidence level

4. **T1018 - Remote System Discovery**
   - Claude: PARTIAL, Gemini: PARTIAL | Grok: YES, GPT: YES
   - Split: Network scanning detection reliability

### Pattern 2: NO-NO vs PARTIAL-PARTIAL (9 cases)
**Indicates**: Disagreement on whether any detection is possible

5. **T1218.007 - Msiexec**
   - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

6. **T1218.005 - Mshta**
   - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

7. **T1218.003 - CMSTP**
   - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

8. **T1220 - XSL Script Processing**
   - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

9. **T1185 - Browser Session Hijacking**
   - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

10. **T1027.003 - Steganography**
    - Grok: NO, GPT: NO | Claude: PARTIAL, Gemini: PARTIAL

11. **T1486 - Data Encrypted for Impact**
    - Grok: NO, GPT: NO | Claude: PARTIAL, Gemini: PARTIAL

12. **T1657 - Financial Theft**
    - Grok: NO, GPT: NO | Claude: PARTIAL, Gemini: PARTIAL

13. **T1539 - Steal Web Session Cookie**
    - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: PARTIAL

### Pattern 3: PARTIAL-NO-NO-PARTIAL (1 case)
**Indicates**: Split views on partial detection

14. **T1069 - Permission Groups Discovery**
    - Claude: PARTIAL, GPT: PARTIAL | Grok: NO, Gemini: NO
    - Split: Detection of permission enumeration

### Pattern 4: PARTIAL-YES-PARTIAL-YES (4 cases)
**Indicates**: Disagreement between PARTIAL and YES (all see detectability)

15. **T1189 - Drive-by Compromise**
    - Claude: PARTIAL, GPT: PARTIAL | Grok: YES, Gemini: YES

16. **T1204.001 - Malicious Link**
    - Claude: PARTIAL, GPT: PARTIAL | Grok: YES, Gemini: YES

17. **T1558.003 - Kerberoasting**
    - Claude: PARTIAL, GPT: PARTIAL | Grok: YES, Gemini: YES

18. **T1008 - Fallback Channels**
    - GPT: PARTIAL, Grok: PARTIAL | Claude: YES, Gemini: YES

### Pattern 5: PARTIAL-NO-YES-YES (1 case)
**Indicates**: Three-way split (one NO, one PARTIAL, two YES)

19. **T1203 - Exploitation for Client Execution**
    - Grok: NO | Claude: PARTIAL | GPT: YES, Gemini: YES

### Pattern 6: NO-NO-PARTIAL-YES (1 case)
**Indicates**: Maximum disagreement (NO, PARTIAL, YES all represented)

20. **T1608.001 - Upload Malware**
    - Claude: NO, Grok: NO | GPT: PARTIAL, Gemini: YES

### Pattern 7: NO-NO-YES-YES (1 case)
**Indicates**: Binary split (completely detectable vs not detectable)

21. **T1590 - Gather Victim Network Information**
    - Claude: NO, Grok: NO | GPT: YES, Gemini: YES

## Key Insights

### 1. Most Common Split Pattern
**NO-NO vs PARTIAL-PARTIAL** (9 cases, 42.9%)
- Disagreement centers on whether limited detection is possible
- Suggests ambiguity in what constitutes "partial" detection

### 2. Technique Categories with Most Disagreement
- **Signed Binary Proxy Execution** (T1218 sub-techniques): 5 cases
  - Msiexec, Mshta, CMSTP all show 2-2 splits
  - Indicates uncertainty in detecting LOLBin abuse

- **Credential Access/Theft**: 3 cases
  - Browser hijacking, cookie theft, Kerberoasting
  - Mixed views on detection capabilities

### 3. Model Pairing Patterns
- **Claude + Grok** frequently align (conservative)
- **GPT + Gemini** frequently align (more optimistic on detection)
- Suggests underlying differences in threat detection philosophy

### 4. Banking Sector Implications
These 21 techniques require **additional scrutiny** because:
- No clear consensus on detectability
- May need custom detection rules
- Should be prioritized for empirical testing
- Detection confidence varies significantly

## Recommendations

1. **Prioritize Empirical Testing**: These 21 techniques should be tested in actual banking environments to resolve uncertainty

2. **Develop Custom Detection Rules**: For techniques in the NO-NO vs PARTIAL-PARTIAL category, explore whether partial detection is achievable

3. **Review Detection Baselines**: The 2-2 splits may indicate gaps in current detection methodologies

4. **Cross-Reference with Banking Incidents**: Check if these techniques appear in actual banking sector breaches to validate real-world detectability

5. **Consider Context**: Some splits may reflect legitimate differences in detection capability based on:
   - Network architecture
   - Monitoring tools deployed
   - Security maturity level

## Technical Details by Pattern

### LOLBin Execution (Signed Binary Proxy Execution)
- **Techniques**: T1218.007, T1218.005, T1218.003, T1220
- **Challenge**: Legitimate tools used for malicious purposes
- **Detection Issue**: Distinguishing benign from malicious use

### Credential Access
- **Techniques**: T1185, T1539, T1558.003
- **Challenge**: Detection of subtle credential harvesting
- **Split Reason**: Depends on logging depth and behavioral analysis

### Data Exfiltration Preparation
- **Techniques**: T1027.003 (Steganography), T1486 (Encryption), T1657 (Financial Theft)
- **Challenge**: Encrypted/hidden data difficult to inspect
- **Split Reason**: Depends on DLP capabilities and traffic analysis

## Conclusion

The 21 techniques with 2-2 splits represent the "gray area" of NIDS detectability in banking environments. They require:
- Enhanced monitoring strategies
- Context-aware detection rules
- Continuous validation against real-world attacks
- Investment in advanced detection capabilities (behavioral analytics, ML-based detection)

These cases highlight that detectability is not binary but exists on a spectrum influenced by:
- Security stack sophistication
- Monitoring coverage
- Baseline behavior establishment
- Threat intelligence integration
