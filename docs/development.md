# Development Guide

## Setup

```bash
# Clone repository
git clone https://github.com/Quig-Enterprises/cyber-guardian.git
cd cyber-guardian

# Install dependencies
pip install -e '.[dev]'

# Copy and configure
cp config.yaml config.local.yaml
# Edit config.local.yaml with your settings

# Set environment variables
export DB_PASSWORD="your-db-password"
export REDTEAM_SYSADMIN_PASS="test-password"
```

## Running Tests

```bash
# All tests
pytest

# Specific category
pytest tests/test_ai_attacks.py
pytest tests/test_api_attacks.py

# With coverage
pytest --cov=cyberguardian --cov-report=html
```

## Project Structure

```
cyber-guardian/
├── cyberguardian/       # CLI package
│   ├── __init__.py
│   └── cli.py           # Main entry point
│
├── redteam/             # Red Team (Offensive)
│   ├── attacks/         # Attack modules
│   ├── evaluators/      # Result evaluators
│   ├── reporters/       # Report generators
│   └── cleanup/         # Artifact cleanup
│
├── blueteam/            # Blue Team (Defensive)
│   ├── collectors/      # Log/event collectors
│   ├── correlator/      # Event correlation
│   ├── alerting/        # Alert engine
│   ├── compliance/      # Compliance tracking
│   ├── incident/        # Incident response
│   └── reports/         # Compliance reports
│
├── shared/              # Common infrastructure
│   ├── auth.py          # Authentication client
│   ├── database.py      # Database utilities
│   └── config.py        # Config loader
│
├── docs/                # Documentation
├── tests/               # Integration tests
└── reports/             # Generated reports
```

## Adding a New Attack Module

1. Create attack file in `redteam/attacks/{category}/`
2. Inherit from `Attack` base class
3. Implement `execute()` and `evaluate()` methods
4. Add to registry by importing in `redteam/attacks/{category}/__init__.py`

Example:

```python
from redteam.base import Attack, AttackResult

class NewAttack(Attack):
    name = "category.new_attack"
    category = "ai"
    severity = "high"
    description = "Description of attack"

    async def execute(self, client):
        # Run attack
        response = await client.post("/api/endpoint", json={...})

        return [AttackResult(
            attack_name=self.name,
            variant="variant1",
            status="vulnerable" if success else "defended",
            severity=self.severity,
            evidence=response.text,
            details="Explanation",
            request={...},
            response={...},
            duration_ms=elapsed
        )]

    def evaluate(self, result):
        # Score the result
        pass
```

## Adding a Blue Team Collector

1. Create collector file in `blueteam/collectors/`
2. Inherit from `Collector` base class
3. Implement `collect()` method
4. Register in `blueteam/collectors/__init__.py`

## Code Style

- **Black** for formatting (line length 100)
- **Ruff** for linting
- **Type hints** for all public functions
- **Docstrings** for all classes and public methods

Run formatters:

```bash
black .
ruff check --fix .
```

## Git Workflow

1. Create feature branch from `main`
2. Make changes
3. Run tests
4. Commit with descriptive message
5. Push and create PR

## Versioning

- **Major (X.0.0):** Breaking changes, new architecture
- **Minor (1.X.0):** New features, attack modules, collectors
- **Patch (1.0.X):** Bug fixes, documentation

Update version in:
- `pyproject.toml`
- `cyberguardian/__init__.py`
- `README.md`

## Release Process

1. Update version numbers
2. Update CHANGELOG.md
3. Tag release: `git tag v1.0.0`
4. Push tags: `git push --tags`
5. GitHub Actions will build and publish
