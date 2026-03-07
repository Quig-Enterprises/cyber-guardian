"""CVE lookup engine for cyber-guardian security testing framework.

Public API:
    CVERecord, CVEQuery, ExploitRef, ExploitMaturity -- data models
    CVESyncManager -- local data synchronization
    CVEEngine -- orchestrator (available after engine.py is created)
"""

from redteam.cve.models import CVERecord, CVEQuery, ExploitRef, ExploitMaturity

__all__ = [
    "CVERecord",
    "CVEQuery",
    "ExploitRef",
    "ExploitMaturity",
]

# CVESyncManager is imported when sync.py exists
try:
    from redteam.cve.sync import CVESyncManager
    __all__.append("CVESyncManager")
except ImportError:
    pass

# CVEEngine is imported when engine.py exists
try:
    from redteam.cve.engine import CVEEngine
    __all__.append("CVEEngine")
except ImportError:
    pass
