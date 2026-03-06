# Cyber-Guardian

**Integrated Offensive & Defensive Security for CMMC Compliance**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![CMMC](https://img.shields.io/badge/CMMC-Level%202-green.svg)](https://dodcio.defense.gov/CMMC/)

---

## Overview

Cyber-Guardian is a unified red team (offensive) and blue team (defensive) security framework designed for CMMC Level 2 compliance. It combines automated penetration testing with comprehensive security monitoring, incident response, and compliance tracking.

### Key Features

**Red Team (Offensive Security):**
- ✅ 31 attack modules, 156 test variants
- ✅ AI, API, and web security testing
- ✅ Automated vulnerability scoring
- ✅ HTML/JSON/Console reporting
- ✅ Phase 2 ready: AI-powered attack generation

**Blue Team (Defensive Security):**
- ✅ NIST SP 800-171 Rev 2 compliance (110 controls)
- ✅ CMMC Level 2 ready
- ✅ DFARS 252.204-7012 incident response (72-hour reporting)
- ✅ Real-time security monitoring
- ✅ Automated SSP and POA&M generation
- ✅ Evidence collection for assessors

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Quig-Enterprises/cyber-guardian.git
cd cyber-guardian

# Install dependencies
pip install -e .

# Verify installation
cyber-guardian --version
```

### Red Team Usage

```bash
# Run all attacks
cyber-guardian redteam --all

# Run specific category
cyber-guardian redteam --category ai
cyber-guardian redteam --category api
cyber-guardian redteam --category web

# Run specific attack
cyber-guardian redteam --attack ai.jailbreak

# Generate HTML report
cyber-guardian redteam --all --report html
```

### Blue Team Usage

```bash
# Start monitoring daemon
cyber-guardian blueteam --daemon

# Generate compliance report
cyber-guardian blueteam --report compliance

# Generate SSP (System Security Plan)
cyber-guardian blueteam --ssp

# Launch dashboard
cyber-guardian dashboard
```

---

## Architecture

```
cyber-guardian/
├── redteam/          # Offensive Security Module
│   ├── attacks/      # 31 attack modules
│   ├── evaluators/   # Result evaluation
│   ├── reporters/    # Report generation
│   └── cleanup/      # Artifact cleanup
│
├── blueteam/         # Defensive Security Module
│   ├── collectors/   # Log/event collectors
│   ├── correlator/   # Event correlation
│   ├── alerting/     # Alert engine
│   ├── compliance/   # NIST/CMMC tracking
│   ├── incident/     # Incident response
│   └── reports/      # Compliance reports
│
├── shared/           # Common Infrastructure
│   ├── auth.py       # Authentication client
│   ├── database.py   # PostgreSQL utilities
│   └── config.py     # Configuration loader
│
└── docs/             # Documentation
    ├── redteam/      # Red team guides
    ├── blueteam/     # Blue team guides
    └── integration/  # Integration docs
```

---

## Red Team Attack Catalog

### AI Attacks (15 modules, 75+ variants)
- **Jailbreak:** DAN, role-play, instruction override
- **Prompt Injection:** Direct/indirect injection, delimiter attacks
- **System Prompt Extraction:** Progressive extraction techniques
- **Off-Topic:** Force non-domain responses
- **Data Leakage:** Cross-tenant data probing
- **Hallucination:** Force fabricated responses
- **Multi-Turn Manipulation:** Gradual topic shifting

### API Attacks (15 modules, 60+ variants)
- **Auth Bypass:** JWT manipulation, token forgery
- **IDOR:** Cross-tenant/company/vessel access
- **Authorization Boundaries:** Role escalation, privilege testing
- **SQL Injection:** Parameter injection across all endpoints
- **Input Validation:** Oversized/malformed inputs
- **Rate Limiting:** Flood testing
- **Error Leakage:** Information disclosure

### Web Attacks (5 modules, 20+ variants)
- **XSS:** Stored/reflected cross-site scripting
- **CSRF:** Cross-site request forgery
- **CORS:** CORS misconfiguration exploitation
- **Session:** Cookie security testing

---

## Blue Team Compliance

### NIST SP 800-171 Rev 2 Controls (110 total)

**Access Control (3.1.x):** 22 controls
**Audit & Accountability (3.3.x):** 9 controls
**Configuration Management (3.4.x):** 8 controls
**Identification & Authentication (3.5.x):** 11 controls
**Incident Response (3.6.x):** 3 controls
**Maintenance (3.7.x):** 6 controls
**Media Protection (3.8.x):** 9 controls
**Personnel Security (3.9.x):** 2 controls
**Physical Protection (3.10.x):** 6 controls
**Risk Assessment (3.11.x):** 5 controls
**Security Assessment (3.12.x):** 4 controls
**System & Communications Protection (3.13.x):** 19 controls
**System & Information Integrity (3.14.x):** 7 controls

### Incident Response (DFARS 252.204-7012)
- ✅ 72-hour DoD reporting requirement
- ✅ PICERL workflow (Prepare, Identify, Contain, Eradicate, Recover, Learn)
- ✅ Forensic evidence chain
- ✅ Automated reporting templates

---

## Configuration

**config.yaml:**

```yaml
project:
  name: "Cyber-Guardian"
  version: "1.0.0"

target:
  base_url: "http://localhost:8081/eqmon"
  api_path: "/api"

database:
  host: "localhost"
  database: "eqmon"
  user: "${DB_USER}"
  password: "${DB_PASSWORD}"

redteam:
  enabled: true
  cleanup: true
  reporting:
    formats: ["html", "json", "console"]

blueteam:
  enabled: true
  collectors:
    audit_db:
      enabled: true
      poll_interval: 30
  compliance:
    framework: "NIST-800-171-Rev2"
    tracking_enabled: true
  incident:
    dfars_reporting: true
    reporting_deadline_hours: 72
```

---

## Integration: Red Team → Blue Team

Cyber-Guardian provides seamless integration between offensive testing and defensive monitoring:

1. **Automated Import:** Blue team collectors automatically import red team findings
2. **Incident Creation:** HIGH/CRITICAL vulnerabilities create security incidents
3. **POA&M Generation:** Findings populate Plan of Action & Milestones
4. **Compliance Mapping:** Vulnerabilities mapped to NIST controls
5. **Evidence Collection:** Red team reports become assessor evidence

---

## Documentation

- [Red Team Attack Guide](docs/redteam/attack-catalog.md)
- [Blue Team Compliance Tracking](docs/blueteam/compliance-tracking.md)
- [Integration Guide](docs/integration/redteam-blueteam-sync.md)
- [CMMC Assessment Preparation](docs/blueteam/cmmc-prep.md)
- [Development Guide](docs/development.md)

---

## Requirements

- Python >= 3.11
- PostgreSQL >= 14
- Access to target system for testing

### Python Dependencies

```bash
# Core
aiohttp>=3.9
pyyaml>=6.0
pydantic>=2.0
psycopg2-binary>=2.9

# Red Team
pyjwt>=2.8
jinja2>=3.1
rich>=13.0

# Blue Team
fastapi>=0.110
uvicorn>=0.29
reportlab>=4.0

# Testing
pytest>=8.0
pytest-asyncio>=0.23
```

---

## License

MIT License - see [LICENSE](LICENSE) file for details

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## Support

- **Issues:** [GitHub Issues](https://github.com/Quig-Enterprises/cyber-guardian/issues)
- **Documentation:** [GitHub Wiki](https://github.com/Quig-Enterprises/cyber-guardian/wiki)

---

## Authors

- **Brandon Quig** - [Quig Enterprises](https://github.com/Quig-Enterprises)
- **Claude Sonnet 4.5** - AI Development Assistant

---

## Acknowledgments

- NIST for SP 800-171 Rev 2 guidance
- DoD for CMMC framework
- NAVSEA for maritime security requirements
- Open source security community

---

**Cyber-Guardian** - Protecting Critical Infrastructure Through Integrated Security Testing
