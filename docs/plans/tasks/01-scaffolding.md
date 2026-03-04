# Task 01: Project Scaffolding

Set up the complete project structure for the security-red-team Python project at `/opt/security-red-team/`.

---

## Step 1: Create pyproject.toml

Create `/opt/security-red-team/pyproject.toml`:

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "security-red-team"
version = "0.1.0"
description = "Automated security testing framework for EQMON AI chat system"
requires-python = ">=3.11"
dependencies = [
    "aiohttp>=3.9",
    "pyyaml>=6.0",
    "rich>=13.0",
    "jinja2>=3.1",
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pyjwt>=2.8",
    "psycopg2-binary>=2.9",
    "bcrypt>=4.0",
]

[project.scripts]
redteam = "redteam.runner:main"

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

---

## Step 2: Create .gitignore

Create `/opt/security-red-team/.gitignore`:

```gitignore
# Python
__pycache__/
*.py[cod]
*$py.class
*.so
*.egg
*.egg-info/
dist/
build/
.eggs/

# Virtual environment
venv/
.venv/
env/
.env

# Testing
.pytest_cache/
.coverage
htmlcov/
.tox/

# Generated output
reports/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Secrets
*.pem
*.key
secrets.yaml
```

---

## Step 3: Create config.yaml

Create `/opt/security-red-team/config.yaml`:

```yaml
target:
  base_url: "http://localhost:8081/eqmon"
  api_path: "/api"

auth:
  test_users:
    system_admin:
      username: "redteam-sysadmin@test.com"
      password: "RedTeam$ysAdmin2026!"
      role: "system-admin"
    viewer:
      username: "redteam-viewer@test.com"
      password: "RedTeamV!ewer2026!"
      role: "viewer"

test_data:
  session_id_prefix: "redteam-"
  analysis_id: "d381c227-4ae2-442b-bc04-970fecc7ca9e"
  instance_id: "default"

cleanup:
  enabled: true
  delete_messages: true
  delete_notes: true

reporting:
  formats: ["console", "json", "html"]
  output_dir: "reports/"

# Phase 2 (disabled)
ai_attacker:
  enabled: false
  model: "claude-sonnet-4-20250514"
  api_key_env: "ANTHROPIC_API_KEY"

# Database (for cleanup and test user setup)
database:
  host: "localhost"
  name: "eqmon"
  user: "eqmon"
  password: "3eK4NNHxLQakuTQK5KcnB3Vz"
```

---

## Step 4: Create Directory Structure and __init__.py Files

Create the full package layout. Every `__init__.py` contains only a module docstring.

### Directory tree to create:

```
/opt/security-red-team/
├── redteam/
│   ├── __init__.py
│   ├── attacks/
│   │   ├── __init__.py
│   │   ├── ai/
│   │   │   └── __init__.py
│   │   ├── api/
│   │   │   └── __init__.py
│   │   ├── web/
│   │   │   └── __init__.py
│   │   └── ai_powered/
│   │       └── __init__.py
│   ├── evaluators/
│   │   └── __init__.py
│   ├── reporters/
│   │   └── __init__.py
│   └── cleanup/
│       └── __init__.py
├── tests/
│   └── __init__.py
└── reports/
    └── .gitkeep
```

### Commands to create the structure:

```bash
cd /opt/security-red-team

# Create directories
mkdir -p redteam/attacks/ai
mkdir -p redteam/attacks/api
mkdir -p redteam/attacks/web
mkdir -p redteam/attacks/ai_powered
mkdir -p redteam/evaluators
mkdir -p redteam/reporters
mkdir -p redteam/cleanup
mkdir -p tests
mkdir -p reports

# Create __init__.py files
cat > redteam/__init__.py << 'EOF'
"""security-red-team: Automated security testing framework for EQMON AI chat system."""
EOF

cat > redteam/attacks/__init__.py << 'EOF'
"""Attack modules for the security red-team framework."""
EOF

cat > redteam/attacks/ai/__init__.py << 'EOF'
"""AI-based attack strategies."""
EOF

cat > redteam/attacks/api/__init__.py << 'EOF'
"""API-level attack strategies."""
EOF

cat > redteam/attacks/web/__init__.py << 'EOF'
"""Web/HTTP attack strategies."""
EOF

cat > redteam/attacks/ai_powered/__init__.py << 'EOF'
"""AI-powered attack strategies (Phase 2)."""
EOF

cat > redteam/evaluators/__init__.py << 'EOF'
"""Response evaluators for determining attack success or failure."""
EOF

cat > redteam/reporters/__init__.py << 'EOF'
"""Reporters for generating test result output in various formats."""
EOF

cat > redteam/cleanup/__init__.py << 'EOF'
"""Cleanup utilities for removing test data after runs."""
EOF

cat > tests/__init__.py << 'EOF'
"""Test suite for the security-red-team framework."""
EOF

# Create reports placeholder
touch reports/.gitkeep
```

---

## Step 5: Create Python Virtual Environment and Install

```bash
cd /opt/security-red-team
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
```

Verify installation:

```bash
which redteam
redteam --help 2>/dev/null || echo "Note: runner entrypoint not yet implemented"
python -c "import redteam; print('redteam package imports OK')"
```

---

## Step 6: Git Init and Initial Commit

```bash
cd /opt/security-red-team
git init
git add -A
git commit -m "feat: initial project scaffolding for security-red-team"
```

Verify:

```bash
git log --oneline -5
git status
```

Expected output: clean working tree, one commit with the scaffolding message.
