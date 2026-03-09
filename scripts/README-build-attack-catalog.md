# Build Attack Catalog Script

**Script:** `scripts/build-attack-catalog.py`
**Purpose:** Automatically generate SQL to populate attack catalog and compliance mappings from Python attack modules

---

## Quick Start

```bash
# 1. Generate SQL
python3 scripts/build-attack-catalog.py > /tmp/catalog.sql

# 2. Apply to database
sudo -u postgres psql alfred_admin -f /tmp/catalog.sql

# Alternative: One-liner (pipe directly)
python3 scripts/build-attack-catalog.py 2>/dev/null | sudo -u postgres psql alfred_admin
```

---

## Usage

### Generate SQL

```bash
# Output SQL to stdout
python3 scripts/build-attack-catalog.py

# Save to file
python3 scripts/build-attack-catalog.py > /tmp/catalog.sql

# Verbose mode (show parsing details)
python3 scripts/build-attack-catalog.py --verbose
```

### Validate Catalog

```bash
# Run validation checks without generating SQL
python3 scripts/build-attack-catalog.py --validate
```

Validation checks:
- Required fields present (attack_id, category, description)
- Unique attack_id values
- Valid category values
- Valid severity values
- Valid target_types values

### Apply to Database

```bash
# Direct pipe (recommended for updates)
python3 scripts/build-attack-catalog.py 2>/dev/null | sudo -u postgres psql alfred_admin

# Via file
python3 scripts/build-attack-catalog.py > /tmp/catalog.sql
sudo -u postgres psql alfred_admin -f /tmp/catalog.sql

# Remote database
python3 scripts/build-attack-catalog.py > /tmp/catalog.sql
psql -h cp.quigs.com -U keystone_admin -d keystone -f /tmp/catalog.sql
```

---

## What It Does

### Scans Attack Modules

Recursively scans `redteam/attacks/*/*.py` for Attack subclasses and extracts:

**From class attributes:**
- `name` → `attack_id` (e.g., "api.account_lockout_bypass")
- `category` → `category` (e.g., "api", "infrastructure")
- `description` → `description` (or docstring first line)
- `severity` → `default_severity` (Severity.HIGH → "high")
- `target_types` → `target_types` array (default: ["app"])

**From docstrings/comments:**
- Compliance framework references:
  - "NIST SP 800-171 3.1.8" → framework="NIST-800-171-Rev2", control="3.1.8"
  - "PCI DSS Requirement 7" → framework="PCI-DSS", control="7"
  - "NIST CSF PR.AC-1" → framework="NIST-CSF", control="PR.AC-1"

### Generates SQL

**Tables populated:**
1. `blueteam.attack_catalog` - Attack module metadata
2. `blueteam.attack_compliance` - Compliance framework mappings

**SQL Features:**
- Uses `ON CONFLICT DO UPDATE` for idempotency
- Safe to run multiple times
- Updates existing entries with new metadata
- Transaction-wrapped (BEGIN/COMMIT)

---

## Example Output

### Attack Catalog Entry

```sql
INSERT INTO blueteam.attack_catalog (
    attack_id, name, category, description, default_severity, target_types
) VALUES (
    'infrastructure.file_permissions',
    'infrastructure.file_permissions',
    'infrastructure',
    'Check for insecure file permissions on critical system files',
    'high',
    ARRAY['app', 'wordpress', 'generic']::VARCHAR[]
)
ON CONFLICT (attack_id) DO UPDATE SET
    name = EXCLUDED.name,
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    default_severity = EXCLUDED.default_severity,
    target_types = EXCLUDED.target_types,
    updated_at = CURRENT_TIMESTAMP;
```

### Compliance Mapping Entry

```sql
INSERT INTO blueteam.attack_compliance (
    attack_id, framework, control_id, description
) VALUES (
    'compliance.pci_access_control',
    'PCI-DSS',
    '7',
    'PCI DSS 4.0 Requirement 7 — Access Restriction'
)
ON CONFLICT (attack_id, framework, control_id) DO UPDATE SET
    description = EXCLUDED.description;
```

---

## Statistics (Current)

```
Total Attacks:      116 modules
Categories:         13 (api, compliance, ai, wordpress, web, infrastructure, etc.)
Severities:         critical=19, high=56, medium=36, low=3, info=2
Compliance Maps:    6 (PCI-DSS)
```

Category breakdown:
- api: 22
- compliance: 22
- ai: 15
- wordpress: 14
- web: 13
- infrastructure: 8
- cve: 7
- cloud: 3
- secrets: 3
- dns: 3
- malware: 3
- exposure: 2
- static: 1

---

## Compliance Framework Support

Currently supports automatic extraction for:

| Framework | Pattern | Example |
|-----------|---------|---------|
| NIST 800-171 Rev 2 | `NIST SP 800-171 X.Y.Z` | "NIST SP 800-171 3.1.8" |
| NIST CSF | `NIST CSF XX.XX-N` | "NIST CSF PR.AC-1" |
| PCI-DSS | `PCI DSS Requirement N` | "PCI DSS Requirement 7" |
| CMMC | `CMMC Level N XX.Y.Z` | "CMMC Level 3 AC.1.001" |

To add compliance references to attack modules:
1. Add to class docstring or module docstring
2. Use framework name + control ID
3. Re-run build script to update catalog

---

## Workflow

### Initial Setup

```bash
# 1. Create schema
sudo -u postgres psql alfred_admin -f sql/05-scan-registry-schema.sql

# 2. Populate catalog
python3 scripts/build-attack-catalog.py | sudo -u postgres psql alfred_admin
```

### After Adding New Attacks

```bash
# Re-run catalog builder (idempotent)
python3 scripts/build-attack-catalog.py | sudo -u postgres psql alfred_admin
```

### After Modifying Attack Metadata

```bash
# Validate changes first
python3 scripts/build-attack-catalog.py --validate

# Update catalog
python3 scripts/build-attack-catalog.py | sudo -u postgres psql alfred_admin
```

---

## Troubleshooting

### Module Not Detected

**Symptom:** Attack module exists but not in catalog

**Causes:**
- Not inheriting from `Attack` base class
- Missing `name` attribute
- File is `__init__.py`

**Solution:** Check that class inherits Attack and has required attributes.

### Incomplete Metadata Warning

**Symptom:** `✗ module_name.py: incomplete metadata`

**Causes:**
- Missing `name` attribute
- Missing `category` attribute

**Solution:** Add required class attributes:
```python
class MyAttack(Attack):
    name = "category.attack_name"
    category = "category"
    severity = Severity.HIGH
    description = "Attack description"
```

### Compliance References Not Extracted

**Symptom:** Attack has compliance reference but not in attack_compliance table

**Causes:**
- Pattern not matching (check format)
- Reference in code comment instead of docstring
- Framework not supported

**Solution:**
1. Add to module or class docstring
2. Use supported framework pattern
3. Run with `--verbose` to see parsing details

### Duplicate Control IDs

**Symptom:** Same control ID appearing multiple times

**Causes:**
- Multiple patterns matching same reference
- Version numbers being extracted as control IDs

**Solution:** Pattern is designed to avoid this. If it occurs, file a bug.

---

## Integration

### With Scan Results

After running a security scan, query attack catalog for metadata:

```sql
-- Get attack metadata for scan results
SELECT
    sr.attack_id,
    ac.category,
    ac.default_severity,
    ac.description,
    sr.status
FROM scan_results sr
JOIN blueteam.attack_catalog ac ON sr.attack_id = ac.attack_id;
```

### With Compliance Tracking

Map findings to compliance controls:

```sql
-- Which controls are tested by which attacks?
SELECT
    ac.control_id,
    ac.framework,
    COUNT(*) AS attack_count,
    ARRAY_AGG(ac.attack_id) AS attacks
FROM blueteam.attack_compliance ac
GROUP BY ac.framework, ac.control_id
ORDER BY ac.framework, ac.control_id;
```

### With Dashboard

Use catalog to filter/group attack results:

```sql
-- Critical findings by category
SELECT
    ac.category,
    COUNT(*) AS finding_count
FROM findings f
JOIN blueteam.attack_catalog ac ON f.attack_id = ac.attack_id
WHERE f.status = 'vulnerable'
  AND f.severity = 'critical'
GROUP BY ac.category
ORDER BY finding_count DESC;
```

---

## Version History

- **1.0** (2026-03-08) - Initial release
  - AST-based Python parsing
  - NIST 800-171, PCI-DSS, NIST CSF, CMMC support
  - Validation mode
  - Idempotent SQL generation
  - 116 attack modules cataloged

---

## Future Enhancements

Planned features:
- [ ] CWE mapping extraction
- [ ] MITRE ATT&CK technique mapping
- [ ] ISO 27001 control mapping
- [ ] OWASP Top 10 mapping
- [ ] Automated scheduling (run on git commit)
- [ ] Diff output (show what changed)
- [ ] JSON export format
- [ ] Web UI for catalog browsing
