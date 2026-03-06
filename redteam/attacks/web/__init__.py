"""Web/HTTP attack strategies."""

from redteam.attacks.web.deception_detection import DeceptionDetectionAttack
from redteam.attacks.web.cors import CORSAttack
from redteam.attacks.web.security_headers import SecurityHeadersAttack
from redteam.attacks.web.directory_traversal import DirectoryTraversalAttack
from redteam.attacks.web.http_methods import HTTPMethodsAttack
from redteam.attacks.web.server_fingerprint import ServerFingerprintAttack
from redteam.attacks.web.open_redirect import OpenRedirectAttack
from redteam.attacks.web.tls_security import TLSSecurityAttack

__all__ = [
    "DeceptionDetectionAttack",
    "CORSAttack",
    "SecurityHeadersAttack",
    "DirectoryTraversalAttack",
    "HTTPMethodsAttack",
    "ServerFingerprintAttack",
    "OpenRedirectAttack",
    "TLSSecurityAttack",
]
