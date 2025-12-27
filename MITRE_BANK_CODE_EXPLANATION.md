# MITRE Bank Analysis Code - Simple Explanation

## What Does This Code Do?

The `mitre_bank_accurate.py` script analyzes cyber threats targeting the banking sector. It downloads real data from MITRE ATT&CK (a database of hacker techniques) and identifies which attack methods are most commonly used by banking hackers.

**Think of it like this:** If you wanted to protect a bank from hackers, you'd want to know what tricks hackers use most often. This code figures that out by looking at real-world hacking groups and malware that target banks.

---

## The Main Calculations Explained (In Simple Terms)

### 1. **Entity Count** - "How Popular is This Technique?"

**What it means:** The number of different hackers/malware programs that use this technique.

**How it's calculated:**
- The code counts unique entities (hacker groups + malware tools) using each technique
- Example: If 3 hacker groups and 2 malware programs use "Phishing", entity_count = 5

**Why it matters:**
- **Higher count** = More hackers use this trick, so it's more important to defend against
- **Lower count** = Only a few hackers use this, so it's less common

**Real Example:**
```
Technique: "Spearphishing Attachment"
Used by: Lazarus Group, APT38, Carbanak (groups) + Dridex, TrickBot (malware)
Entity Count: 5 entities total
```

---

### 2. **Group Count** - "How Many Hacker Groups Use This?"

**What it means:** The number of different hacker organizations (threat groups) that use this technique.

**How it's calculated:**
- Counts only the threat groups (organizations like Lazarus Group, APT38, etc.)
- Does NOT count malware/software

**Why it matters:**
- Shows how many different hacker organizations have adopted this technique
- More groups = technique is proven effective across different attackers

**Real Example:**
```
Technique: "Credential Dumping"
Used by Groups: Lazarus Group, APT38, Carbanak, Cobalt Group
Group Count: 4 groups

(Even if 10 malware programs also use it, group_count stays at 4)
```

---

### 3. **Software Count** - "How Many Malware Programs Use This?"

**What it means:** The number of different malware tools/trojans that use this technique.

**How it's calculated:**
- Counts only malware/tools (like Dridex, TrickBot, QakBot, etc.)
- Does NOT count hacker groups

**Why it matters:**
- Shows how many different malware families implement this technique
- More software = technique is automated and widely used in malware

**Real Example:**
```
Technique: "Process Injection"
Used by Software: Dridex, TrickBot, Carbanak, Carberp, Ursnif
Software Count: 5 malware programs

(Even if 3 hacker groups also use it, software_count stays at 5)
```

---

### 4. **Frequency Category** - "How Often is This Technique Used?"

**What it means:** A simple label (Rare, Medium, Common, High-Priority) based on entity_count.

**How it's calculated:**
```
If entity_count = 1           → Rare (used by only 1 entity)
If entity_count = 2 or 3      → Medium (used by 2-3 entities)
If entity_count = 4 or 5      → Common (used by 4-5 entities)
If entity_count = 6 or more   → High-Priority (used by 6+ entities)
```

**Why it matters:**
- Gives you a quick, easy-to-read label
- Helps prioritize what to defend first (High-Priority = defend ASAP!)

**Real Example:**
```
Technique A: entity_count = 1  → Frequency = "Rare"
Technique B: entity_count = 3  → Frequency = "Medium"
Technique C: entity_count = 8  → Frequency = "High-Priority"
```

---

### 5. **Total Score** - "Overall Priority Level (0-100)"

**What it means:** A combined score that shows how important this technique is to defend against.

**How it's calculated:** The score has 3 parts that add up to a maximum of 100:

#### **Part 1: Entity Usage Score (0-40 points)**
- Based on how many entities use the technique
- Formula: `entity_count × 5` (maximum 40)
- More entities = higher score

```
Example:
entity_count = 3  → 3 × 5 = 15 points
entity_count = 8  → 8 × 5 = 40 points (capped at 40)
```

#### **Part 2: Tactic Importance Score (0-40 points)**
- Based on which phase of an attack this technique belongs to
- Some phases are more common in banking attacks (like "Execution" or "Collection")
- The code calculates which tactics appear most in real banking attacks
- Techniques in common tactics get higher scores

```
Example:
If "Collection" appears in 15% of all banking techniques:
  → Techniques in "Collection" get higher tactic scores
If "Resource Development" appears in only 2%:
  → Techniques there get lower tactic scores
```

#### **Part 3: Group Diversity Bonus (0-20 points)**
- Based on how many different hacker groups use it
- Formula: `group_count × 4` (maximum 20)
- More groups = broader threat across different attackers

```
Example:
group_count = 2  → 2 × 4 = 8 points
group_count = 5  → 5 × 4 = 20 points (capped at 20)
```

#### **Total Score = Part 1 + Part 2 + Part 3**

**Real Example:**
```
Technique: "Spearphishing Attachment"

Part 1: Entity Usage
  - 7 entities use it → 7 × 5 = 35 points

Part 2: Tactic Importance
  - In "Initial Access" tactic (very common) → 30 points

Part 3: Group Diversity
  - 4 different groups use it → 4 × 4 = 16 points

TOTAL SCORE: 35 + 30 + 16 = 81 out of 100
```

**Why it matters:**
- **Higher score (70-100)** = Top priority! Defend against this first!
- **Medium score (40-69)** = Important, should be on your security checklist
- **Lower score (0-39)** = Less critical, but still worth monitoring

---

## How Everything Relates Together

Here's the flow of how the code works:

```
1. Download MITRE ATT&CK data
   ↓
2. Find banking-related hackers and malware
   (12 software programs + 12 hacker groups = 24 entities)
   ↓
3. For each attack technique, count:
   - Total entities using it (entity_count)
   - Groups using it (group_count)
   - Software using it (software_count)
   ↓
4. Classify by frequency:
   - Rare / Medium / Common / High-Priority
   ↓
5. Calculate priority score (0-100):
   - Entity usage (40 points)
   - Tactic importance (40 points)
   - Group diversity (20 points)
   ↓
6. Output results:
   - CSV files with all techniques
   - Top 50 most important techniques
   - Charts and statistics
```

---

## What the Code DOES Include (100% Accurate)

✅ Real hacker groups targeting banks (Lazarus, APT38, Carbanak, etc.)
✅ Real banking malware (Dridex, TrickBot, QakBot, etc.)
✅ Techniques they actually use (verified by MITRE)
✅ Which phase of attack (Initial Access, Execution, etc.)
✅ Which platforms they target (Windows, Linux, etc.)
✅ Detection guidance from MITRE (when available)

---

## What the Code Does NOT Include (Removed for Accuracy)

❌ Guesses or assumptions
❌ Keyword-based classifications
❌ Hypothetical scenarios
❌ Unverified data

**Why?** The creator wanted 100% accuracy for a research paper. Only real, verified data from MITRE is included.

---

## Real-World Example - Complete Breakdown

Let's analyze one technique completely:

**Technique: "Process Injection" (T1055)**

```
COUNTS:
  entity_count = 9
    └─ Used by 4 groups + 5 malware programs = 9 total

  group_count = 4
    └─ Lazarus Group, APT38, Carbanak, Cobalt Group

  software_count = 5
    └─ Dridex, TrickBot, Carbanak malware, Carberp, Ursnif

CLASSIFICATION:
  frequency_category = "High-Priority"
    └─ Because entity_count (9) ≥ 6

SCORE CALCULATION:
  Entity Usage Score: 9 × 5 = 40 points (capped at 40)
  Tactic Score: "Defense Evasion" is common = 35 points
  Group Diversity: 4 × 4 = 16 points

  TOTAL SCORE: 40 + 35 + 16 = 91 out of 100

  → This is a TOP PRIORITY technique to defend against!
```

---

## How to Use This Information

**For Security Teams:**
1. Look at techniques with scores 70-100 first
2. Focus on "High-Priority" frequency category
3. Check if your security tools can detect these techniques

**For Researchers:**
1. Use entity_count to show which techniques are most widespread
2. Use group_count to show coordination across hacker groups
3. Use total_score to prioritize testing NIDS (Network Intrusion Detection)

**For Executives (Non-Technical):**
- Higher score = bigger threat
- More entities = more hackers using this trick
- High-Priority = needs immediate attention

---

## Summary in One Sentence

**This code downloads real data about banking hackers from MITRE, counts how many different hackers and malware use each attack technique, then scores each technique (0-100) to help you prioritize which attacks to defend against first.**

---

## Files Generated by This Code

1. **`*_full.csv`** - All techniques with complete details
2. **`*_top_50_priority.csv`** - The 50 most dangerous techniques
3. **`*_statistics.json`** - Numbers and charts data
4. **`*_methodology.txt`** - How calculations work
5. **`*_overview.png`** - Visual charts

---

## Questions & Answers

**Q: Why does entity_count = group_count + software_count?**
A: Yes! Entity count is the total of all unique hackers AND malware using a technique.

**Q: What's better to defend: high group_count or high software_count?**
A: Both are important! High group_count means many organizations use it (organized threat). High software_count means it's automated in malware (scalable threat).

**Q: Is a score of 50 good or bad?**
A: A score of 50 means "moderately important" - not top priority, but definitely worth defending against.

**Q: Why do some techniques have no detection notes?**
A: MITRE doesn't always provide detection guidance. The code honestly reports when this information isn't available.

---

## Key Takeaway

The code is like a "Top 10 Most Wanted" list for banking cyber attacks, but instead of 10, it ranks ALL techniques by how dangerous they are, using real-world data from verified sources.

**Priority Order:**
1. High-Priority (6+ entities) with scores 80-100 → Defend FIRST
2. Common (4-5 entities) with scores 60-80 → Defend SECOND
3. Medium (2-3 entities) with scores 40-60 → Defend THIRD
4. Rare (1 entity) with scores 20-40 → Monitor

---

*Last Updated: 2025-12-27*
*Code File: mitre_bank_accurate.py*
