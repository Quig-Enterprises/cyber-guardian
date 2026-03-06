"""WordPress-specific attack modules for Cyber-Guardian."""

from redteam.attacks.wordpress.admin_exposure import AdminExposureAttack
from redteam.attacks.wordpress.brute_force import BruteForceAttack
from redteam.attacks.wordpress.comment_xss import CommentXSSAttack
from redteam.attacks.wordpress.config_exposure import ConfigExposureAttack
from redteam.attacks.wordpress.cron_abuse import CronAbuseAttack
from redteam.attacks.wordpress.debug_disclosure import DebugDisclosureAttack
from redteam.attacks.wordpress.file_upload import FileUploadAttack
from redteam.attacks.wordpress.info_disclosure import InfoDisclosureAttack
from redteam.attacks.wordpress.plugin_audit import PluginAuditAttack
from redteam.attacks.wordpress.plugin_enumeration import PluginEnumerationAttack
from redteam.attacks.wordpress.rest_api_exposure import RestApiExposureAttack
from redteam.attacks.wordpress.security_headers import SecurityHeadersAttack
from redteam.attacks.wordpress.user_enumeration import UserEnumerationAttack
from redteam.attacks.wordpress.xmlrpc_abuse import XmlrpcAbuseAttack

__all__ = [
    "AdminExposureAttack",
    "BruteForceAttack",
    "CommentXSSAttack",
    "ConfigExposureAttack",
    "CronAbuseAttack",
    "DebugDisclosureAttack",
    "FileUploadAttack",
    "InfoDisclosureAttack",
    "PluginAuditAttack",
    "PluginEnumerationAttack",
    "RestApiExposureAttack",
    "SecurityHeadersAttack",
    "UserEnumerationAttack",
    "XmlrpcAbuseAttack",
]
