"""CVE-based attack modules for Cyber-Guardian."""

from redteam.attacks.cve.wp_core_cve import WPCoreCVEAttack
from redteam.attacks.cve.wp_plugin_cve import WPPluginCVEAttack
from redteam.attacks.cve.wp_theme_cve import WPThemeCVEAttack
from redteam.attacks.cve.server_cve import ServerCVEAttack
from redteam.attacks.cve.dependency_cve import DependencyCVEAttack

__all__ = [
    "WPCoreCVEAttack",
    "WPPluginCVEAttack",
    "WPThemeCVEAttack",
    "ServerCVEAttack",
    "DependencyCVEAttack",
]
