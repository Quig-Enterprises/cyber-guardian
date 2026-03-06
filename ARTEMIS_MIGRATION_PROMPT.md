# Artemis Migration Prompt

**Purpose:** Migrate existing Artemis users from security-red-team and security-blue-team to the unified Cyber-Guardian framework.

**Context:** The security-red-team and security-blue-team repositories have been archived and merged into Cyber-Guardian. This prompt guides Artemis through the migration process.

---

## Prompt for Artemis

```
I need to migrate my existing security testing setup from the archived
security-red-team and security-blue-team repositories to the new unified
Cyber-Guardian framework.

Current Setup:
- Using security-red-team for offensive security testing
- Using security-blue-team for CMMC compliance monitoring
- Both repos are now archived (as of 2026-03-06)

Task:
Migrate to Cyber-Guardian following these requirements:

1. Clone the new unified repository:
   https://github.com/Quig-Enterprises/cyber-guardian

2. Install the package with all dependencies

3. Migrate my existing config files from both red team and blue team

4. Verify the CLI works:
   - cyber-guardian --version
   - cyber-guardian redteam --help
   - cyber-guardian blueteam --help

5. Test that I can run the same attacks and compliance checks as before

Migration Documentation:
- Migration guide: /opt/claude-workspace/projects/cyber-guardian/MIGRATION_COMPLETE.md
- Red team README: https://github.com/Quig-Enterprises/security-red-team
- Blue team README: https://github.com/Quig-Enterprises/security-blue-team

Please guide me through the migration step by step, ensuring:
- My existing configuration is preserved
- All attack modules still work
- All compliance tracking is maintained
- The new CLI commands are equivalent to my old workflow
```

---

## Expected Artemis Actions

When given this prompt, Artemis should:

1. **Clone Repository**
   ```bash
   git clone https://github.com/Quig-Enterprises/cyber-guardian.git
   cd cyber-guardian
   ```

2. **Setup Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -e .
   ```

3. **Migrate Configuration**
   ```bash
   # If user has old configs
   cp /path/to/security-red-team/config.yaml config.yaml

   # Merge blue team config sections if needed
   # (configs are compatible, minimal changes needed)
   ```

4. **Verify Installation**
   ```bash
   cyber-guardian --version
   cyber-guardian redteam --help
   cyber-guardian blueteam --help
   cyber-guardian dashboard --help
   ```

5. **Test Red Team**
   ```bash
   # List available attacks
   cyber-guardian redteam --help

   # Run a simple test (if config allows)
   # cyber-guardian redteam --attack ai.jailbreak
   ```

6. **Test Blue Team**
   ```bash
   # Check compliance reporting
   cyber-guardian blueteam --help

   # Generate compliance report (if database configured)
   # cyber-guardian blueteam --report compliance
   ```

7. **Update Command References**

   Provide translation table:

   **Old Red Team:**
   ```bash
   python runner.py --all
   python runner.py --category ai
   python runner.py --attack ai.jailbreak
   ```

   **New Cyber-Guardian:**
   ```bash
   cyber-guardian redteam --all
   cyber-guardian redteam --category ai
   cyber-guardian redteam --attack ai.jailbreak
   ```

   **Old Blue Team:**
   ```bash
   python -m blueteam.cli --daemon
   python -m blueteam.cli --report compliance
   ```

   **New Cyber-Guardian:**
   ```bash
   cyber-guardian blueteam --daemon
   cyber-guardian blueteam --report compliance
   cyber-guardian blueteam --ssp
   ```

---

## Alternative: Minimal Migration Prompt

For users who want a quick migration:

```
Migrate me from security-red-team/security-blue-team (now archived) to
the new Cyber-Guardian unified framework at:
https://github.com/Quig-Enterprises/cyber-guardian

I need:
1. Clone and install Cyber-Guardian
2. Preserve my existing config
3. Verify the CLI works
4. Show me the new command syntax
```

---

## Advanced: Automated Migration Script Prompt

For users who want Artemis to create a migration script:

```
Create a migration script that automates the transition from
security-red-team and security-blue-team to Cyber-Guardian.

The script should:
1. Detect if old repos are installed
2. Backup existing configurations
3. Clone Cyber-Guardian
4. Create virtual environment
5. Install dependencies
6. Merge configurations intelligently
7. Test that CLI works
8. Provide command translation cheat sheet
9. Update any cron jobs or systemd services to use new commands

Save as: migrate-to-cyber-guardian.sh
```

---

## Troubleshooting Prompts

**If imports fail:**
```
I'm getting import errors after migrating to Cyber-Guardian. Help me
update my custom attack modules and scripts to use the new shared
infrastructure.

Old imports that are failing:
- from redteam.config import load_config
- from blueteam.db import get_connection

Show me the new import syntax and explain what changed.
```

**If CLI doesn't work:**
```
The cyber-guardian CLI isn't working after installation. Debug the issue:
1. Check if package is installed correctly
2. Verify virtual environment is activated
3. Check for dependency conflicts
4. Test individual components (redteam, blueteam, dashboard)
```

**If config migration fails:**
```
I have custom configurations from both security-red-team and
security-blue-team. Help me merge them into a single config.yaml
for Cyber-Guardian.

Show me:
1. The unified config structure
2. Where my red team settings go
3. Where my blue team settings go
4. Any settings that changed format
```

---

## Success Criteria

Artemis migration is successful when:
- ✅ Cyber-Guardian repository cloned
- ✅ Virtual environment created and activated
- ✅ Package installed with all dependencies
- ✅ Configuration files migrated
- ✅ `cyber-guardian --version` works
- ✅ All three CLI commands work (redteam, blueteam, dashboard)
- ✅ User can run previous workflows with new commands
- ✅ User understands command translation
- ✅ Old repositories removed or clearly marked as deprecated

---

## Notes for Artemis

**Key Points:**
- Both old repos are **archived** (read-only) as of 2026-03-06
- All git history is preserved in Cyber-Guardian
- Configs are mostly compatible (minimal changes needed)
- Main change is command syntax (runner.py → cyber-guardian)
- Import changes only affect custom code (not normal usage)

**Migration Documentation:**
- Full guide: `/opt/claude-workspace/projects/cyber-guardian/MIGRATION_COMPLETE.md`
- Red team notice: `https://github.com/Quig-Enterprises/security-red-team/README.md`
- Blue team notice: `https://github.com/Quig-Enterprises/security-blue-team/README.md`

**Support:**
- Issues: https://github.com/Quig-Enterprises/cyber-guardian/issues
- Tag with `migration` label for migration-specific questions
