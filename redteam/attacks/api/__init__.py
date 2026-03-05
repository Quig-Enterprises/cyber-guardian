"""API-level attack strategies.

Modules are auto-discovered by the AttackRegistry via pkgutil.
Explicit imports kept for convenience but not required for discovery.
"""

from redteam.attacks.api.auth_bypass import AuthBypassAttack
from redteam.attacks.api.idor import IdorAttack
from redteam.attacks.api.authz_boundaries import AuthzBoundariesAttack
from redteam.attacks.api.injection import InjectionAttack
from redteam.attacks.api.input_validation import InputValidationAttack
from redteam.attacks.api.rate_limiting import RateLimitingAttack
from redteam.attacks.api.error_leakage import ErrorLeakageAttack
from redteam.attacks.api.ssrf import SsrfAttack
from redteam.attacks.api.concurrent_sessions import ConcurrentSessionsAttack
from redteam.attacks.api.file_upload import FileUploadAttack
from redteam.attacks.api.unauth_admin_settings import UnauthAdminSettingsAttack
from redteam.attacks.api.jwt_secret_extraction import JWTSecretExtractionAttack
from redteam.attacks.api.session_timeout import SessionTimeoutAttack
from redteam.attacks.api.privilege_escalation_v2 import PrivilegeEscalationV2Attack
from redteam.attacks.api.password_policy import PasswordPolicyAttack
from redteam.attacks.api.account_lockout_bypass import AccountLockoutBypassAttack

__all__ = [
    "AuthBypassAttack",
    "IdorAttack",
    "AuthzBoundariesAttack",
    "InjectionAttack",
    "InputValidationAttack",
    "RateLimitingAttack",
    "ErrorLeakageAttack",
    "SsrfAttack",
    "ConcurrentSessionsAttack",
    "FileUploadAttack",
    "UnauthAdminSettingsAttack",
    "JWTSecretExtractionAttack",
    "SessionTimeoutAttack",
    "PrivilegeEscalationV2Attack",
    "PasswordPolicyAttack",
    "AccountLockoutBypassAttack",
]
