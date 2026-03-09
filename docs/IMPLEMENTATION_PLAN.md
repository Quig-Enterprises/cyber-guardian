# Implementation Plan: Ideal Report Structure

**Version:** 1.0
**Created:** 2026-03-08
**Branch:** feature/ideal-report-structure
**Reference:** docs/IDEAL_REPORT_STRUCTURE.md

---

## Implementation Phases

### Phase 1: Database Schema (Foundation)
**Priority:** CRITICAL
**Dependencies:** None
**Estimated Effort:** 2-3 hours

**Tasks:**
1. Create new schema file: `sql/05-scan-registry-schema.sql`
   - `blueteam.scans` table
   - `blueteam.attack_catalog` table
   - `blueteam.attack_compliance` table
   - `blueteam.scan_attacks` table
   - `blueteam.findings` table
   - `blueteam.mitigation_findings` (linking table)
   - `blueteam.scan_comparisons` table
   - All indexes and foreign keys

2. Create migration script: `sql/migrate-to-scan-registry.sql`
   - Preserve existing mitigation_projects data
   - Create backward compatibility views
   - Map existing data to new schema

3. Apply schema to Alfred database
   - Test on development database first
   - Validate constraints and indexes
   - Verify migration preserves data

4. Update database permissions
   - Grant alfred_admin access to new tables
   - Update blueteam schema grants

**Deliverables:**
- [x] sql/05-scan-registry-schema.sql
- [ ] sql/migrate-to-scan-registry.sql
- [ ] Schema applied to Alfred database
- [ ] Migration tested and verified

---

### Phase 2: Attack Catalog Population
**Priority:** HIGH
**Dependencies:** Phase 1
**Estimated Effort:** 2-3 hours

**Tasks:**
1. Create catalog builder script: `scripts/build-attack-catalog.py`
   - Scan all attack modules in `redteam/attacks/`
   - Extract: name, category, description, severity
   - Extract target_types from class attributes
   - Generate SQL INSERT statements

2. Extract compliance mappings
   - Parse docstrings for NIST/framework references
   - Parse comments for control IDs
   - Create attack_compliance entries

3. Populate catalog table
   - Run catalog builder
   - Insert into blueteam.attack_catalog
   - Insert into blueteam.attack_compliance

4. Create catalog update workflow
   - Add pre-commit hook to regenerate catalog
   - Document manual update process
   - Add validation tests

**Deliverables:**
- [ ] scripts/build-attack-catalog.py
- [ ] Attack catalog populated
- [ ] Compliance mappings populated
- [ ] Catalog update documentation

---

### Phase 3: Enhanced Report Generation
**Priority:** HIGH
**Dependencies:** Phase 1, Phase 2
**Estimated Effort:** 3-4 hours

**Tasks:**
1. Update config.yaml structure
   - Add target.name field
   - Add target.environment field (production/staging/dev)
   - Add target.type field (app/wordpress/static/cloud)
   - Add execution.operator field

2. Create new reporter: `redteam/reporters/hierarchical_json.py`
   - Generate scan_metadata section
   - Generate hierarchical attacks array with nested variants
   - Include attack descriptions from catalog
   - Include compliance mappings
   - Add scan_config snapshot
   - Maintain backward compatibility with flat findings array

3. Update runner to use new reporter
   - Generate unique scan_id (UUID or timestamp-based)
   - Capture config snapshot
   - Pass target metadata to reporter
   - Track execution metadata (start/end times)

4. Update JsonReporter for backward compatibility
   - Keep existing format as fallback
   - Add deprecation warning
   - Plan removal in v2.0

**Deliverables:**
- [ ] Updated config.yaml structure
- [ ] redteam/reporters/hierarchical_json.py
- [ ] Updated redteam/runner.py
- [ ] Backward compatibility maintained
- [ ] Generated report validated

---

### Phase 4: Database Integration
**Priority:** HIGH
**Dependencies:** Phase 2, Phase 3
**Estimated Effort:** 2-3 hours

**Tasks:**
1. Create scan importer: `scripts/import-scan-to-db.py`
   - Parse hierarchical JSON report
   - Insert into blueteam.scans
   - Insert into blueteam.scan_attacks
   - Insert into blueteam.findings
   - Link to attack_catalog
   - Handle duplicate scans gracefully

2. Update mitigation import workflow
   - Create findings first
   - Link findings to mitigation_issues via mitigation_findings
   - Preserve existing mitigation workflow
   - Maintain backward compatibility

3. Create API endpoints for scan data
   - `/api/scans/list` - List all scans
   - `/api/scans/{id}` - Get scan details
   - `/api/scans/{id}/findings` - Get findings for scan
   - `/api/scans/compare?baseline={id}&current={id}` - Compare scans

4. Update dashboard to consume new APIs
   - Add scan selector dropdown
   - Show scan metadata (target, date, duration)
   - Display hierarchical attack results
   - Link findings to mitigation issues

**Deliverables:**
- [ ] scripts/import-scan-to-db.py
- [ ] Updated import workflow
- [ ] New API endpoints
- [ ] Dashboard integration
- [ ] Data integrity verified

---

### Phase 5: Scan Comparison & History
**Priority:** MEDIUM
**Dependencies:** Phase 4
**Estimated Effort:** 3-4 hours

**Tasks:**
1. Create comparison engine: `blueteam/scan_comparison.py`
   - Compare two scans (baseline vs. current)
   - Detect new vulnerabilities
   - Detect fixed vulnerabilities
   - Detect regressions (fixed → vulnerable)
   - Detect improvements (vulnerable → defended)
   - Calculate trend scores

2. Create comparison API endpoints
   - `/api/scans/compare` - Generate comparison
   - `/api/scans/{id}/history` - Get historical comparisons
   - `/api/scans/trends` - Aggregate trends over time

3. Add dashboard comparison view
   - Side-by-side scan comparison
   - Highlight new/fixed/regression findings
   - Trend graphs (vulnerability count over time)
   - Severity distribution changes

4. Create automated regression detection
   - Run comparison after each scan
   - Alert on regressions
   - Track improvement metrics

**Deliverables:**
- [ ] blueteam/scan_comparison.py
- [ ] Comparison API endpoints
- [ ] Dashboard comparison view
- [ ] Automated regression alerts
- [ ] Trend visualization

---

### Phase 6: Testing & Validation
**Priority:** HIGH
**Dependencies:** All previous phases
**Estimated Effort:** 2-3 hours

**Tasks:**
1. Unit tests
   - Test hierarchical_json reporter
   - Test scan importer
   - Test comparison engine
   - Test API endpoints

2. Integration tests
   - Run full scan with new structure
   - Import to database
   - Query via API
   - Verify dashboard display

3. Migration testing
   - Test migration script on copy of production data
   - Verify no data loss
   - Validate foreign key integrity
   - Test rollback procedure

4. Performance testing
   - Benchmark database queries
   - Test with large scan datasets
   - Optimize slow queries
   - Add necessary indexes

**Deliverables:**
- [ ] Unit test suite
- [ ] Integration tests passing
- [ ] Migration validated
- [ ] Performance benchmarks
- [ ] Optimization complete

---

### Phase 7: Documentation & Deployment
**Priority:** HIGH
**Dependencies:** All previous phases
**Estimated Effort:** 1-2 hours

**Tasks:**
1. Update README.md
   - Document new report structure
   - Update scan configuration guide
   - Add migration instructions
   - Document new API endpoints

2. Create operator guide
   - How to run scans with new structure
   - How to compare scans
   - How to interpret trends
   - Troubleshooting guide

3. Deploy to Alfred
   - Apply database migration
   - Deploy updated code
   - Run test scan
   - Verify dashboard

4. Deploy to cp.quigs.com (webhost)
   - Apply database migration
   - Deploy updated code
   - Import historical scans
   - Verify integration

**Deliverables:**
- [ ] Updated README.md
- [ ] Operator guide created
- [ ] Deployed to Alfred
- [ ] Deployed to webhost
- [ ] Historical data migrated

---

## Risk Mitigation

### Database Migration Risks
**Risk:** Data loss during migration
**Mitigation:**
- Full database backup before migration
- Test migration on copy first
- Rollback script prepared
- Validation queries to verify data integrity

### Backward Compatibility Risks
**Risk:** Breaking existing workflows
**Mitigation:**
- Maintain old report format in parallel
- Create compatibility views in database
- Gradual deprecation timeline
- Clear migration documentation

### Performance Risks
**Risk:** New structure slower than old
**Mitigation:**
- Benchmark before/after
- Optimize indexes
- Use materialized views for aggregations
- Cache frequently-accessed data

---

## Success Criteria

1. **All scans generate hierarchical reports** with complete metadata
2. **Database contains full scan history** with no data loss
3. **Dashboard displays scans** with filtering and comparison
4. **API returns scan data** in <200ms for typical queries
5. **Comparison engine detects** regressions and improvements
6. **Documentation is complete** and tested by another operator
7. **All tests pass** with >80% code coverage
8. **Production deployment successful** with zero downtime

---

## Timeline

**Total Estimated Effort:** 15-20 hours

**Proposed Schedule:**
- **Day 1:** Phase 1 (Database Schema) + Phase 2 (Attack Catalog)
- **Day 2:** Phase 3 (Report Generation) + Phase 4 (Database Integration)
- **Day 3:** Phase 5 (Comparison) + Phase 6 (Testing) + Phase 7 (Deployment)

**Checkpoints:**
- End of Day 1: Database schema complete, catalog populated
- End of Day 2: Reports generating, data importing to DB
- End of Day 3: Full deployment with historical data migrated

---

## Rollback Plan

If critical issues arise:

1. **Revert database migration**
   ```sql
   -- Run rollback script
   psql -U alfred_admin -d alfred_admin -f sql/rollback-scan-registry.sql
   ```

2. **Revert code changes**
   ```bash
   git checkout main
   git branch -D feature/ideal-report-structure
   ```

3. **Restore backup**
   ```bash
   pg_restore -U alfred_admin -d alfred_admin backup-YYYYMMDD.dump
   ```

4. **Verify old workflow**
   - Run scan with old format
   - Check existing mitigation dashboard
   - Validate reports directory

---

## Artemis Server Migration Instructions

**Artemis** is Brandon's production server running WordPress and other services. The cyber-guardian scanner will be deployed to Artemis for production security monitoring.

### Prerequisites

1. **PostgreSQL Database Setup**
   ```bash
   # Create database and user (if not exists)
   sudo -u postgres createdb artemis_security
   sudo -u postgres createuser artemis_admin
   sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE artemis_security TO artemis_admin;"
   ```

2. **Create blueteam schema**
   ```bash
   sudo -u postgres psql artemis_security -c "CREATE SCHEMA IF NOT EXISTS blueteam;"
   sudo -u postgres psql artemis_security -c "GRANT ALL ON SCHEMA blueteam TO artemis_admin;"
   ```

### Migration Steps

**Step 1: Deploy Code**
```bash
# Clone or pull cyber-guardian repo
cd /opt/claude-workspace/projects
git clone https://github.com/Quig-Enterprises/cyber-guardian.git
cd cyber-guardian
git checkout feature/ideal-report-structure

# Install dependencies
pip install -r requirements.txt
```

**Step 2: Apply Database Schema**
```bash
# Apply scan registry schema
sudo -u postgres psql artemis_security -f sql/05-scan-registry-schema.sql

# Populate attack catalog
python3 scripts/build-attack-catalog.py | sudo -u postgres psql artemis_security
```

**Step 3: Configure Scanner**
```bash
# Create Artemis-specific config
cp config.yaml config_artemis.yaml

# Edit config_artemis.yaml:
# - Set target.base_url to Artemis WordPress URL
# - Set target.name to "Artemis Production"
# - Set target.environment to "production"
# - Set target.type to "wordpress"
# - Set database connection to artemis_security
```

**Step 4: Run Initial Scan**
```bash
# Test scan (dry-run)
python3 redteam/cli.py --config config_artemis.yaml --dry-run

# Full production scan
python3 redteam/cli.py --config config_artemis.yaml

# Import results to database
python3 scripts/import-scan-to-db.py \
  --latest \
  --database artemis_security \
  --user artemis_admin
```

**Step 5: Set Up Automated Scanning**
```bash
# Create cron job for daily scans
sudo crontab -e

# Add line:
0 2 * * * cd /opt/claude-workspace/projects/cyber-guardian && python3 redteam/cli.py --config config_artemis.yaml && python3 scripts/import-scan-to-db.py --latest --database artemis_security --user artemis_admin
```

**Step 6: Deploy Dashboard (Optional)**
```bash
# If deploying security dashboard on Artemis:
# 1. Copy dashboard/ to web-accessible directory
# 2. Update dashboard/api/*.php with artemis_security database credentials
# 3. Configure nginx/apache to serve dashboard
# 4. Test at https://artemis.quigs.com/security-dashboard/
```

### Artemis-Specific Notes

- **WordPress Integration**: Artemis scanner will use WordPress-specific attacks from `redteam/attacks/wordpress/`
- **Target Type**: Set `target.type: "wordpress"` in config_artemis.yaml
- **Database Name**: Use `artemis_security` (not `alfred_admin`)
- **Firewall**: Ensure scanner can reach WordPress site (localhost or internal IP)
- **Credentials**: Store scan credentials in environment variables or secure vault
- **Reports**: Reports stored in `redteam/reports/` on Artemis filesystem
- **Retention**: Configure log rotation for report files (recommend 90 days)

### Validation Checklist

- [ ] PostgreSQL database created and accessible
- [ ] Schema applied (all tables exist)
- [ ] Attack catalog populated (116 attacks)
- [ ] Config file created for Artemis
- [ ] Test scan completes successfully
- [ ] Findings imported to database
- [ ] Dashboard accessible (if deployed)
- [ ] Cron job scheduled
- [ ] Alerting configured
- [ ] Documentation updated

---

## Notes

- All changes tracked in git on `feature/ideal-report-structure` branch
- Merge to main only after all success criteria met
- Create GitHub PR for code review before merge
- Tag release as v2.0.0 after successful deployment
- Artemis deployment can happen independently from Alfred
- Each server (Alfred, cp.quigs.com, Artemis) maintains its own scan database
