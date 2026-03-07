"""Compliance bridge — maps red team attack results to compliance control status.

This module connects red team attack outcomes to the three compliance frameworks
(NIST 800-171, PCI DSS 4.0, HIPAA Security Rule), determining which controls
are met, not met, partially met, or not yet assessed based on actual attack
evidence.

Cross-framework propagation uses the cross_map.py equivalence/overlap data
to flag related controls in other frameworks when a control fails.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional
import json
import logging
import sys
import os
from datetime import datetime
from pathlib import Path

# Add blueteam to path for cross_map import
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'blueteam'))

from redteam.base import Score, Status, AttackResult, Severity
from blueteam.compliance.cross_map import MAPPINGS as CROSS_MAPPINGS
from blueteam.compliance.nist_800_171 import CONTROLS as NIST_CONTROLS
from blueteam.compliance.pci_dss_v4 import CONTROLS as PCI_CONTROLS
from blueteam.compliance.hipaa_security import CONTROLS as HIPAA_CONTROLS

logger = logging.getLogger("redteam.compliance_bridge")

# All supported framework keys
ALL_FRAMEWORKS = ["nist_800_171", "pci_dss_v4", "hipaa"]

# Framework key to control catalog mapping
FRAMEWORK_CATALOGS = {
    "nist_800_171": NIST_CONTROLS,
    "pci_dss_v4": PCI_CONTROLS,
    "hipaa": HIPAA_CONTROLS,
}


class ComplianceStatus(str, Enum):
    """Status of a compliance control based on attack evidence."""
    MET = "met"
    NOT_MET = "not_met"
    PARTIALLY_MET = "partially_met"
    NOT_ASSESSED = "not_assessed"


@dataclass
class ControlAssessment:
    """Assessment of a single compliance control based on attack results.

    Attributes:
        framework: Framework key (e.g. "nist_800_171", "pci_dss_v4", "hipaa").
        control_id: Control identifier within the framework (e.g. "3.13.8").
        status: Determined compliance status based on attack evidence.
        evidence: List of evidence dicts from matching attack results.
        cross_framework_flags: Controls in other frameworks affected by this
            control's status via cross-framework propagation.
        family: Control family name (e.g. "System and Communications Protection").
        requirement: Full requirement text from the control catalog.
    """
    framework: str
    control_id: str
    status: ComplianceStatus
    evidence: list[dict] = field(default_factory=list)
    cross_framework_flags: list[dict] = field(default_factory=list)
    family: str = ""
    requirement: str = ""


# ==============================================================================
# ATTACK-TO-CONTROL MAPPING REGISTRY
# ==============================================================================
# Each entry maps an (attack_name, variant_pattern) to compliance controls.
#   - variant "*" matches all variants of the attack
#   - evidence_level "full" = attack alone proves/disproves the control
#   - evidence_level "partial" = attack informs but doesn't fully satisfy
# ==============================================================================

ATTACK_CONTROL_MAP = [
    # ======================================================================
    # COMPLIANCE CATEGORY (attacks that directly target controls)
    # ======================================================================

    # compliance.pci_tls_crypto -> PCI Req 4 TLS/crypto
    {"attack": "compliance.pci_tls_crypto", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["4.2.1", "4.2.1.1"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_tls_crypto", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.8", "3.13.11"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_tls_crypto", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.e.2.ii"],
     "evidence_level": "full"},

    # compliance.pci_auth_controls -> PCI Req 8 authentication
    {"attack": "compliance.pci_auth_controls", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.3.4", "8.3.5", "8.3.6", "8.2.2", "8.4.2"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_auth_controls", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.8", "3.5.7", "3.5.10", "3.5.3"],
     "evidence_level": "partial"},

    # compliance.pci_access_control -> PCI Req 7 access restriction
    {"attack": "compliance.pci_access_control", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.2.1", "7.2.2", "7.3.1"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_access_control", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.1", "3.1.2", "3.1.5"],
     "evidence_level": "partial"},
    {"attack": "compliance.pci_access_control", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.1", "164.308.a.3.i"],
     "evidence_level": "partial"},

    # compliance.pci_logging -> PCI Req 10 logging
    {"attack": "compliance.pci_logging", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["10.2.1", "10.2.2", "10.6.1", "10.3.3"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_logging", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.3.1", "3.3.4", "3.3.5", "3.3.7"],
     "evidence_level": "partial"},
    {"attack": "compliance.pci_logging", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.b.1", "164.312.b.4"],
     "evidence_level": "partial"},

    # compliance.pci_secure_config -> PCI Req 2 secure config
    {"attack": "compliance.pci_secure_config", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.1", "2.2.2", "2.2.5"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_secure_config", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.2", "3.4.6", "3.4.7"],
     "evidence_level": "partial"},

    # compliance.pci_data_protection -> PCI Req 3 stored data
    {"attack": "compliance.pci_data_protection", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.5.1", "3.3.1", "3.4.1"],
     "evidence_level": "full"},
    {"attack": "compliance.pci_data_protection", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.16"],
     "evidence_level": "partial"},

    # compliance.hipaa_encryption -> HIPAA encryption at rest/transit
    {"attack": "compliance.hipaa_encryption", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iv", "164.312.e.2.ii"],
     "evidence_level": "full"},
    {"attack": "compliance.hipaa_encryption", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.8", "3.13.16"],
     "evidence_level": "full"},
    {"attack": "compliance.hipaa_encryption", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["4.2.1", "3.5.1"],
     "evidence_level": "partial"},

    # compliance.hipaa_access_audit -> HIPAA unique IDs, audit
    {"attack": "compliance.hipaa_access_audit", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.i", "164.312.b.1", "164.312.b.2", "164.312.b.4"],
     "evidence_level": "full"},
    {"attack": "compliance.hipaa_access_audit", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.1", "3.3.1", "3.3.4", "3.3.8"],
     "evidence_level": "partial"},
    {"attack": "compliance.hipaa_access_audit", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.2.1", "10.2.1"],
     "evidence_level": "partial"},

    # compliance.hipaa_session_auth -> HIPAA session/auth
    {"attack": "compliance.hipaa_session_auth", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iii", "164.312.d.2", "164.312.d.1", "164.312.a.2.ii"],
     "evidence_level": "full"},
    {"attack": "compliance.hipaa_session_auth", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.12", "3.5.3", "3.5.1"],
     "evidence_level": "partial"},
    {"attack": "compliance.hipaa_session_auth", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.2.8", "8.4.2"],
     "evidence_level": "partial"},

    # compliance.encryption_at_rest
    {"attack": "compliance.encryption_at_rest", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.16"],
     "evidence_level": "full"},
    {"attack": "compliance.encryption_at_rest", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iv"],
     "evidence_level": "full"},
    {"attack": "compliance.encryption_at_rest", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.5.1"],
     "evidence_level": "partial"},

    # compliance.mfa_absence
    {"attack": "compliance.mfa_absence", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.3"],
     "evidence_level": "full"},
    {"attack": "compliance.mfa_absence", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.4.2"],
     "evidence_level": "full"},
    {"attack": "compliance.mfa_absence", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.d.2"],
     "evidence_level": "full"},

    # compliance.audit_log_tamper
    {"attack": "compliance.audit_log_tamper", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.3.4", "3.3.8"],
     "evidence_level": "full"},
    {"attack": "compliance.audit_log_tamper", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["10.3.3"],
     "evidence_level": "full"},
    {"attack": "compliance.audit_log_tamper", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.b.4"],
     "evidence_level": "full"},

    # compliance.network_segmentation
    {"attack": "compliance.network_segmentation", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.1", "3.13.5", "3.13.6"],
     "evidence_level": "full"},
    {"attack": "compliance.network_segmentation", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["1.3.1", "1.3.2", "1.4.1"],
     "evidence_level": "full"},

    # compliance.cui_data_flow
    {"attack": "compliance.cui_data_flow", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.3"],
     "evidence_level": "full"},

    # compliance.software_integrity
    {"attack": "compliance.software_integrity", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1", "3.14.2"],
     "evidence_level": "full"},
    {"attack": "compliance.software_integrity", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.c.1", "164.312.c.2"],
     "evidence_level": "partial"},

    # compliance.supply_chain_deps
    {"attack": "compliance.supply_chain_deps", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1"],
     "evidence_level": "partial"},
    {"attack": "compliance.supply_chain_deps", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.3.2"],
     "evidence_level": "partial"},

    # compliance.anomaly_detection_evasion
    {"attack": "compliance.anomaly_detection_evasion", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.6", "3.14.7"],
     "evidence_level": "full"},

    # compliance.device_attestation
    {"attack": "compliance.device_attestation", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.2"],
     "evidence_level": "full"},
    {"attack": "compliance.device_attestation", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.d.3"],
     "evidence_level": "partial"},

    # compliance.dual_authorization_bypass
    {"attack": "compliance.dual_authorization_bypass", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.4"],
     "evidence_level": "full"},

    # compliance.cui_retention
    {"attack": "compliance.cui_retention", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.8.9"],
     "evidence_level": "partial"},
    {"attack": "compliance.cui_retention", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.2.1"],
     "evidence_level": "partial"},

    # compliance.system_diversity / system_refresh
    {"attack": "compliance.system_diversity", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.2"],
     "evidence_level": "partial"},
    {"attack": "compliance.system_refresh", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.1"],
     "evidence_level": "partial"},

    # ======================================================================
    # INFRASTRUCTURE CATEGORY
    # ======================================================================

    # infrastructure.ssh_audit -> SSH config security
    {"attack": "infrastructure.ssh_audit", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.13", "3.13.8", "3.5.4"],
     "evidence_level": "full"},
    {"attack": "infrastructure.ssh_audit", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.7", "4.2.1"],
     "evidence_level": "partial"},
    {"attack": "infrastructure.ssh_audit", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.e.2.ii"],
     "evidence_level": "partial"},

    # infrastructure.firewall_audit -> Firewall rules
    {"attack": "infrastructure.firewall_audit", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.1", "3.13.5", "3.13.6"],
     "evidence_level": "full"},
    {"attack": "infrastructure.firewall_audit", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["1.2.1", "1.3.1", "1.3.2", "1.4.1"],
     "evidence_level": "full"},

    # infrastructure.service_enumeration -> Unnecessary services
    {"attack": "infrastructure.service_enumeration", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.6", "3.4.7"],
     "evidence_level": "full"},
    {"attack": "infrastructure.service_enumeration", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.5", "1.2.5"],
     "evidence_level": "full"},

    # infrastructure.file_permissions -> File permission audit
    {"attack": "infrastructure.file_permissions", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.5", "3.4.2"],
     "evidence_level": "partial"},
    {"attack": "infrastructure.file_permissions", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.2.2"],
     "evidence_level": "partial"},

    # infrastructure.kernel_patch -> Kernel/OS patching
    {"attack": "infrastructure.kernel_patch", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1"],
     "evidence_level": "full"},
    {"attack": "infrastructure.kernel_patch", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.3.3"],
     "evidence_level": "full"},
    {"attack": "infrastructure.kernel_patch", "variant": "*",
     "framework": "hipaa", "controls": ["164.308.a.1.ii.B"],
     "evidence_level": "partial"},

    # ======================================================================
    # DNS CATEGORY
    # ======================================================================

    # dns.dnssec -> DNSSEC validation
    {"attack": "dns.dnssec", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.15"],
     "evidence_level": "full"},

    # dns.email_auth -> SPF/DKIM/DMARC
    {"attack": "dns.email_auth", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.8", "3.14.6"],
     "evidence_level": "partial"},
    {"attack": "dns.email_auth", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.e.1"],
     "evidence_level": "partial"},

    # dns.subdomain_takeover -> Subdomain takeover
    {"attack": "dns.subdomain_takeover", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.1"],
     "evidence_level": "partial"},

    # ======================================================================
    # SECRETS CATEGORY
    # ======================================================================

    # secrets.source_code -> Source code secret scanning
    {"attack": "secrets.source_code", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.10", "3.13.16"],
     "evidence_level": "full"},
    {"attack": "secrets.source_code", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.5.1", "6.2.4"],
     "evidence_level": "partial"},
    {"attack": "secrets.source_code", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iv"],
     "evidence_level": "partial"},

    # secrets.env_exposure -> Environment file exposure
    {"attack": "secrets.env_exposure", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.10", "3.4.2"],
     "evidence_level": "full"},
    {"attack": "secrets.env_exposure", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.6"],
     "evidence_level": "partial"},

    # secrets.git_history -> Git history secrets
    {"attack": "secrets.git_history", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.10"],
     "evidence_level": "full"},
    {"attack": "secrets.git_history", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.5.1"],
     "evidence_level": "partial"},

    # ======================================================================
    # EXPOSURE CATEGORY
    # ======================================================================

    # exposure.backup_files -> Backup file discovery
    {"attack": "exposure.backup_files", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.2", "3.8.9"],
     "evidence_level": "partial"},
    {"attack": "exposure.backup_files", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.6"],
     "evidence_level": "partial"},

    # exposure.sensitive_paths -> Sensitive path exposure
    {"attack": "exposure.sensitive_paths", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.2", "3.1.22"],
     "evidence_level": "partial"},
    {"attack": "exposure.sensitive_paths", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4", "2.2.6"],
     "evidence_level": "partial"},

    # ======================================================================
    # CLOUD CATEGORY
    # ======================================================================

    # cloud.s3_buckets -> S3 bucket security
    {"attack": "cloud.s3_buckets", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.1", "3.1.22", "3.13.16"],
     "evidence_level": "partial"},
    {"attack": "cloud.s3_buckets", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.3.1", "3.5.1"],
     "evidence_level": "partial"},

    # cloud.iam_audit -> IAM configuration audit
    {"attack": "cloud.iam_audit", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.1", "3.1.5", "3.5.1", "3.5.3"],
     "evidence_level": "partial"},
    {"attack": "cloud.iam_audit", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.2.1", "7.2.2", "8.4.2"],
     "evidence_level": "partial"},
    {"attack": "cloud.iam_audit", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.1", "164.312.d.2"],
     "evidence_level": "partial"},

    # cloud.security_groups -> Security group audit
    {"attack": "cloud.security_groups", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.1", "3.13.6"],
     "evidence_level": "partial"},
    {"attack": "cloud.security_groups", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["1.3.1", "1.3.2"],
     "evidence_level": "partial"},

    # ======================================================================
    # WEB CATEGORY
    # ======================================================================

    # web.tls_security -> TLS version, ciphers
    {"attack": "web.tls_security", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.8", "3.13.11"],
     "evidence_level": "full"},
    {"attack": "web.tls_security", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["4.2.1", "2.2.7"],
     "evidence_level": "full"},
    {"attack": "web.tls_security", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.e.2.ii"],
     "evidence_level": "full"},

    # web.certificate -> Certificate validation
    {"attack": "web.certificate", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.8"],
     "evidence_level": "partial"},
    {"attack": "web.certificate", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["4.2.1.1"],
     "evidence_level": "full"},

    # web.security_headers -> Security headers (CSP, HSTS, etc)
    {"attack": "web.security_headers", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.2", "3.14.6"],
     "evidence_level": "partial"},
    {"attack": "web.security_headers", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},

    # web.cors -> CORS policy
    {"attack": "web.cors", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.3", "3.13.4"],
     "evidence_level": "partial"},

    # web.csrf -> CSRF protection
    {"attack": "web.csrf", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},

    # web.xss -> XSS protection
    {"attack": "web.xss", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},
    {"attack": "web.xss", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.2"],
     "evidence_level": "partial"},

    # web.session -> Session security
    {"attack": "web.session", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.9", "3.1.10"],
     "evidence_level": "partial"},
    {"attack": "web.session", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.2.8"],
     "evidence_level": "partial"},
    {"attack": "web.session", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iii"],
     "evidence_level": "partial"},

    # web.sri -> Subresource integrity
    {"attack": "web.sri", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1"],
     "evidence_level": "partial"},
    {"attack": "web.sri", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.4.1"],
     "evidence_level": "partial"},

    # web.directory_traversal -> Path traversal
    {"attack": "web.directory_traversal", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.1", "3.1.2"],
     "evidence_level": "partial"},
    {"attack": "web.directory_traversal", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},

    # ======================================================================
    # API CATEGORY
    # ======================================================================

    # api.auth_bypass -> Authentication bypass
    {"attack": "api.auth_bypass", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.2", "3.1.1"],
     "evidence_level": "full"},
    {"attack": "api.auth_bypass", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.3.1"],
     "evidence_level": "full"},
    {"attack": "api.auth_bypass", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.d.1"],
     "evidence_level": "full"},

    # api.idor -> Insecure direct object reference
    {"attack": "api.idor", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.1", "3.1.2"],
     "evidence_level": "full"},
    {"attack": "api.idor", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.3.1"],
     "evidence_level": "full"},
    {"attack": "api.idor", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.1"],
     "evidence_level": "partial"},

    # api.privilege_escalation_v2
    {"attack": "api.privilege_escalation_v2", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.5", "3.1.7"],
     "evidence_level": "full"},
    {"attack": "api.privilege_escalation_v2", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.2.2"],
     "evidence_level": "full"},

    # api.injection -> SQL/command injection
    {"attack": "api.injection", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.2"],
     "evidence_level": "partial"},
    {"attack": "api.injection", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "full"},

    # api.input_validation -> Input validation
    {"attack": "api.input_validation", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},

    # api.session_timeout -> Session timeouts
    {"attack": "api.session_timeout", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.13.9", "3.1.11"],
     "evidence_level": "full"},
    {"attack": "api.session_timeout", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.2.8"],
     "evidence_level": "full"},
    {"attack": "api.session_timeout", "variant": "*",
     "framework": "hipaa", "controls": ["164.312.a.2.iii"],
     "evidence_level": "full"},

    # api.account_lockout_bypass -> Lockout mechanism
    {"attack": "api.account_lockout_bypass", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.8"],
     "evidence_level": "full"},
    {"attack": "api.account_lockout_bypass", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.3.4"],
     "evidence_level": "full"},

    # api.password_policy -> Password strength
    {"attack": "api.password_policy", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.7", "3.5.8"],
     "evidence_level": "full"},
    {"attack": "api.password_policy", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["8.3.5", "8.3.6"],
     "evidence_level": "full"},

    # api.error_leakage -> Error information disclosure
    {"attack": "api.error_leakage", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.2"],
     "evidence_level": "partial"},
    {"attack": "api.error_leakage", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},

    # api.excessive_data -> Excessive data exposure
    {"attack": "api.excessive_data", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.3"],
     "evidence_level": "partial"},
    {"attack": "api.excessive_data", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["3.4.1"],
     "evidence_level": "partial"},

    # api.mass_assignment -> Mass assignment
    {"attack": "api.mass_assignment", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.2.4"],
     "evidence_level": "partial"},
    {"attack": "api.mass_assignment", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.5"],
     "evidence_level": "partial"},

    # api.lateral_movement -> Cross-tenant access
    {"attack": "api.lateral_movement", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.2", "3.13.4"],
     "evidence_level": "full"},

    # api.jwt_secret_extraction -> JWT security
    {"attack": "api.jwt_secret_extraction", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.10", "3.13.10"],
     "evidence_level": "full"},

    # api.replay_attack -> Replay resistance
    {"attack": "api.replay_attack", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.5.4", "3.13.15"],
     "evidence_level": "full"},

    # api.concurrent_sessions -> Session limits
    {"attack": "api.concurrent_sessions", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.11"],
     "evidence_level": "partial"},

    # api.authz_boundaries -> Authorization boundaries
    {"attack": "api.authz_boundaries", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.1.2"],
     "evidence_level": "full"},
    {"attack": "api.authz_boundaries", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["7.2.1"],
     "evidence_level": "partial"},

    # api.file_upload -> File upload security
    {"attack": "api.file_upload", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.5"],
     "evidence_level": "partial"},
    {"attack": "api.file_upload", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["5.2.1"],
     "evidence_level": "partial"},

    # ======================================================================
    # CVE CATEGORY
    # ======================================================================

    # cve.dependency_cve -> Known dependency vulnerabilities
    {"attack": "cve.dependency_cve", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1", "3.11.2"],
     "evidence_level": "full"},
    {"attack": "cve.dependency_cve", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.3.1", "6.3.3"],
     "evidence_level": "full"},

    # cve.server_cve -> Server software CVEs
    {"attack": "cve.server_cve", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1", "3.11.2"],
     "evidence_level": "full"},
    {"attack": "cve.server_cve", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.3.3", "6.3.1"],
     "evidence_level": "full"},

    # cve.dependency_freshness -> Dependency currency
    {"attack": "cve.dependency_freshness", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.1"],
     "evidence_level": "partial"},
    {"attack": "cve.dependency_freshness", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["6.3.2"],
     "evidence_level": "partial"},

    # cve.config_verification -> Configuration verification
    {"attack": "cve.config_verification", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.4.2"],
     "evidence_level": "partial"},
    {"attack": "cve.config_verification", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["2.2.1"],
     "evidence_level": "partial"},

    # ======================================================================
    # MALWARE CATEGORY
    # ======================================================================

    # malware.clamav_scan -> AV scanning
    {"attack": "malware.clamav_scan", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.2", "3.14.5"],
     "evidence_level": "full"},
    {"attack": "malware.clamav_scan", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["5.2.1", "5.3.2"],
     "evidence_level": "full"},
    {"attack": "malware.clamav_scan", "variant": "*",
     "framework": "hipaa", "controls": ["164.308.a.5.ii.B"],
     "evidence_level": "full"},

    # malware.rootkit_check -> Rootkit detection
    {"attack": "malware.rootkit_check", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.2", "3.14.3"],
     "evidence_level": "full"},
    {"attack": "malware.rootkit_check", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["5.2.2", "11.5.2"],
     "evidence_level": "partial"},

    # malware.webshell_detect -> Webshell detection
    {"attack": "malware.webshell_detect", "variant": "*",
     "framework": "nist_800_171", "controls": ["3.14.2"],
     "evidence_level": "full"},
    {"attack": "malware.webshell_detect", "variant": "*",
     "framework": "pci_dss_v4", "controls": ["5.2.2", "11.5.2"],
     "evidence_level": "partial"},
]


# ==============================================================================
# INTERNAL HELPERS
# ==============================================================================

def _build_control_lookup() -> dict[tuple[str, str], dict]:
    """Build a fast lookup from (framework, control_id) to control metadata.

    Returns:
        Dict mapping (framework_key, control_id) to {"family": ..., "requirement": ...}.
    """
    lookup: dict[tuple[str, str], dict] = {}
    for fw_key, catalog in FRAMEWORK_CATALOGS.items():
        for ctrl in catalog:
            lookup[(fw_key, ctrl["control_id"])] = {
                "family": ctrl.get("family", ""),
                "requirement": ctrl.get("requirement", ""),
            }
    return lookup


def _build_mapping_index() -> dict[tuple[str, str], list[tuple[str, str, str]]]:
    """Build an inverted index from controls to the attacks that inform them.

    Returns:
        Dict mapping (framework, control_id) to list of
        (attack_name, variant_pattern, evidence_level) tuples.
    """
    index: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for entry in ATTACK_CONTROL_MAP:
        attack = entry["attack"]
        variant = entry["variant"]
        framework = entry["framework"]
        evidence_level = entry["evidence_level"]
        for control_id in entry["controls"]:
            key = (framework, control_id)
            if key not in index:
                index[key] = []
            index[key].append((attack, variant, evidence_level))
    return index


def _match_variant(pattern: str, actual_variant: str) -> bool:
    """Check if an attack variant matches a mapping pattern.

    Args:
        pattern: The variant pattern from the mapping ("*" matches all).
        actual_variant: The actual variant name from the attack result.

    Returns:
        True if the variant matches.
    """
    if pattern == "*":
        return True
    return pattern == actual_variant


def _determine_control_status(
    result_statuses: list[tuple[Status, str]],
) -> ComplianceStatus:
    """Determine compliance status from a set of attack result statuses.

    Args:
        result_statuses: List of (attack_status, evidence_level) tuples.
            Only VULNERABLE, PARTIAL, and DEFENDED statuses should be passed;
            SKIPPED and ERROR are filtered out by the caller.

    Returns:
        The determined ComplianceStatus.
    """
    if not result_statuses:
        return ComplianceStatus.NOT_ASSESSED

    has_vulnerable = any(s == Status.VULNERABLE for s, _ in result_statuses)
    has_partial = any(s == Status.PARTIAL for s, _ in result_statuses)
    has_defended = any(s == Status.DEFENDED for s, _ in result_statuses)

    if has_vulnerable:
        return ComplianceStatus.NOT_MET
    if has_partial and has_defended:
        return ComplianceStatus.PARTIALLY_MET
    if has_partial:
        return ComplianceStatus.PARTIALLY_MET
    if has_defended:
        return ComplianceStatus.MET

    return ComplianceStatus.NOT_ASSESSED


# ==============================================================================
# CROSS-FRAMEWORK PROPAGATION
# ==============================================================================

# Severity ordering for status comparison (worse = lower index)
_STATUS_SEVERITY = {
    ComplianceStatus.NOT_MET: 0,
    ComplianceStatus.PARTIALLY_MET: 1,
    ComplianceStatus.NOT_ASSESSED: 2,
    ComplianceStatus.MET: 3,
}


def _propagate_cross_framework(
    assessments: dict[tuple[str, str], ControlAssessment],
) -> None:
    """Propagate compliance failures across frameworks using CROSS_MAPPINGS.

    Uses the cross_map.py equivalence/overlap data to flag related controls
    when a control fails. Direct evidence always takes priority over
    cross-framework propagation.

    Rules:
        - "equivalent": source NOT_MET -> target NOT_MET
          (unless target has direct evidence showing MET)
        - "overlapping": source NOT_MET -> target PARTIALLY_MET at most
          (unless target has direct evidence showing MET)
        - "partial": informational flag only, no status change

    Args:
        assessments: Mutable dict of (framework, control_id) -> ControlAssessment.
            Modified in place to add cross_framework_flags and propagate statuses.
    """
    for mapping in CROSS_MAPPINGS:
        src_key = (mapping["source_framework"], mapping["source_control"])
        tgt_key = (mapping["target_framework"], mapping["target_control"])
        relationship = mapping["relationship"]

        src_assessment = assessments.get(src_key)
        tgt_assessment = assessments.get(tgt_key)

        if src_assessment is None or tgt_assessment is None:
            continue

        # Only propagate from failing controls
        if src_assessment.status not in (ComplianceStatus.NOT_MET, ComplianceStatus.PARTIALLY_MET):
            continue

        # Check if target has direct evidence (non-empty evidence list means
        # attack results directly informed this control)
        target_has_direct_evidence = len(tgt_assessment.evidence) > 0

        # Determine what status to propagate
        if relationship == "equivalent" and src_assessment.status == ComplianceStatus.NOT_MET:
            propagated_status = ComplianceStatus.NOT_MET
            if not target_has_direct_evidence:
                # Only override if target has no direct evidence
                if _STATUS_SEVERITY.get(propagated_status, 3) < _STATUS_SEVERITY.get(tgt_assessment.status, 3):
                    tgt_assessment.status = propagated_status
            # Add flag regardless
            tgt_assessment.cross_framework_flags.append({
                "framework": mapping["source_framework"],
                "control_id": mapping["source_control"],
                "relationship": relationship,
                "propagated_status": propagated_status.value,
            })

        elif relationship == "overlapping" and src_assessment.status == ComplianceStatus.NOT_MET:
            propagated_status = ComplianceStatus.PARTIALLY_MET
            if not target_has_direct_evidence:
                if _STATUS_SEVERITY.get(propagated_status, 3) < _STATUS_SEVERITY.get(tgt_assessment.status, 3):
                    tgt_assessment.status = propagated_status
            tgt_assessment.cross_framework_flags.append({
                "framework": mapping["source_framework"],
                "control_id": mapping["source_control"],
                "relationship": relationship,
                "propagated_status": propagated_status.value,
            })

        elif relationship == "partial":
            # Informational only -- no status change
            if src_assessment.status in (ComplianceStatus.NOT_MET, ComplianceStatus.PARTIALLY_MET):
                tgt_assessment.cross_framework_flags.append({
                    "framework": mapping["source_framework"],
                    "control_id": mapping["source_control"],
                    "relationship": relationship,
                    "propagated_status": src_assessment.status.value,
                })

        # Also propagate the flag in the reverse direction (source gets
        # a note about the target it affects)
        if relationship in ("equivalent", "overlapping"):
            src_assessment.cross_framework_flags.append({
                "framework": mapping["target_framework"],
                "control_id": mapping["target_control"],
                "relationship": relationship,
                "propagated_status": src_assessment.status.value,
            })


# ==============================================================================
# PUBLIC API
# ==============================================================================

def assess_compliance(
    scores: list[Score],
    frameworks: Optional[list[str]] = None,
) -> dict[tuple[str, str], ControlAssessment]:
    """Assess compliance status of controls based on attack results.

    This is the core assessment engine. It matches attack results from scores
    to compliance controls via the ATTACK_CONTROL_MAP, determines each
    control's compliance status, and propagates failures across frameworks.

    Args:
        scores: List of Score objects from the red team runner, each containing
            attack results with status information.
        frameworks: List of framework keys to assess. Defaults to all three
            frameworks ("nist_800_171", "pci_dss_v4", "hipaa").

    Returns:
        Dict mapping (framework, control_id) tuples to ControlAssessment objects.
    """
    if frameworks is None:
        frameworks = list(ALL_FRAMEWORKS)

    control_lookup = _build_control_lookup()
    mapping_index = _build_mapping_index()

    # Build a quick lookup: attack_name -> list of AttackResult
    results_by_attack: dict[str, list[AttackResult]] = {}
    for score in scores:
        for result in score.results:
            if result.attack_name not in results_by_attack:
                results_by_attack[result.attack_name] = []
            results_by_attack[result.attack_name].append(result)

    assessments: dict[tuple[str, str], ControlAssessment] = {}

    for fw_key in frameworks:
        catalog = FRAMEWORK_CATALOGS.get(fw_key, [])
        for ctrl in catalog:
            control_id = ctrl["control_id"]
            key = (fw_key, control_id)

            # Get metadata from the lookup
            meta = control_lookup.get(key, {})

            assessment = ControlAssessment(
                framework=fw_key,
                control_id=control_id,
                status=ComplianceStatus.NOT_ASSESSED,
                family=meta.get("family", ""),
                requirement=meta.get("requirement", ""),
            )

            # Find all attack mappings that reference this control
            attack_mappings = mapping_index.get(key, [])

            if not attack_mappings:
                # No attacks map to this control
                assessments[key] = assessment
                continue

            # Collect evidence from matching attack results
            result_statuses: list[tuple[Status, str]] = []

            for attack_name, variant_pattern, evidence_level in attack_mappings:
                attack_results = results_by_attack.get(attack_name, [])

                for result in attack_results:
                    if not _match_variant(variant_pattern, result.variant):
                        continue

                    # Skip non-deterministic statuses
                    if result.status in (Status.SKIPPED, Status.ERROR):
                        continue

                    result_statuses.append((result.status, evidence_level))

                    assessment.evidence.append({
                        "attack": attack_name,
                        "variant": result.variant,
                        "result_status": result.status.value,
                        "evidence_level": evidence_level,
                        "severity": result.severity.value,
                        "details": result.details or result.evidence,
                    })

            assessment.status = _determine_control_status(result_statuses)
            assessments[key] = assessment

    # Run cross-framework propagation
    _propagate_cross_framework(assessments)

    return assessments


def generate_compliance_report(
    scores: list[Score],
    frameworks: Optional[list[str]] = None,
) -> dict:
    """Generate a JSON-serializable compliance assessment report.

    This is the public API that runner.py calls to produce compliance output.
    It runs the full assessment pipeline and formats the results into a
    structured report with per-framework summaries, per-control details,
    and attack coverage statistics.

    Args:
        scores: List of Score objects from the red team runner.
        frameworks: List of framework keys to assess. Defaults to all three.

    Returns:
        Dict with the complete compliance assessment report, ready for
        JSON serialization.
    """
    if frameworks is None:
        frameworks = list(ALL_FRAMEWORKS)

    assessments = assess_compliance(scores, frameworks)

    # Build per-framework summaries
    summary: dict[str, dict[str, int]] = {}
    for fw_key in frameworks:
        catalog = FRAMEWORK_CATALOGS.get(fw_key, [])
        fw_summary = {
            "total": len(catalog),
            "met": 0,
            "not_met": 0,
            "partially_met": 0,
            "not_assessed": 0,
        }
        for ctrl in catalog:
            key = (fw_key, ctrl["control_id"])
            assessment = assessments.get(key)
            if assessment is None:
                fw_summary["not_assessed"] += 1
                continue
            if assessment.status == ComplianceStatus.MET:
                fw_summary["met"] += 1
            elif assessment.status == ComplianceStatus.NOT_MET:
                fw_summary["not_met"] += 1
            elif assessment.status == ComplianceStatus.PARTIALLY_MET:
                fw_summary["partially_met"] += 1
            else:
                fw_summary["not_assessed"] += 1
        summary[fw_key] = fw_summary

    # Build per-control detail list
    controls_list: list[dict] = []
    for fw_key in frameworks:
        catalog = FRAMEWORK_CATALOGS.get(fw_key, [])
        for ctrl in catalog:
            key = (fw_key, ctrl["control_id"])
            assessment = assessments.get(key)
            if assessment is None:
                continue
            controls_list.append({
                "framework": assessment.framework,
                "control_id": assessment.control_id,
                "family": assessment.family,
                "requirement": assessment.requirement,
                "status": assessment.status.value,
                "evidence": assessment.evidence,
                "cross_framework_flags": assessment.cross_framework_flags,
            })

    # Build attack coverage statistics
    all_attack_names = set()
    for score in scores:
        all_attack_names.add(score.attack_name)

    mapped_attacks = set()
    for entry in ATTACK_CONTROL_MAP:
        mapped_attacks.add(entry["attack"])

    attacks_with_mappings = all_attack_names & mapped_attacks
    attacks_without_mappings = sorted(all_attack_names - mapped_attacks)

    # Determine unmapped categories
    unmapped_categories = set()
    for attack_name in attacks_without_mappings:
        parts = attack_name.split(".")
        if parts:
            unmapped_categories.add(parts[0])

    report = {
        "report_type": "compliance_assessment",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "frameworks_assessed": frameworks,
        "summary": summary,
        "controls": controls_list,
        "attack_coverage": {
            "total_attacks_run": len(all_attack_names),
            "attacks_with_mappings": len(attacks_with_mappings),
            "attacks_without_mappings": attacks_without_mappings,
            "unmapped_categories": sorted(unmapped_categories),
        },
    }

    return report


def write_compliance_report(report: dict, output_dir: str) -> str:
    """Write a compliance assessment report to a JSON file.

    Args:
        report: The report dict from generate_compliance_report().
        output_dir: Directory to write the report file into.

    Returns:
        Absolute path to the written report file.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    filename = f"compliance-assessment-{timestamp}.json"
    filepath = output_path / filename

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)

    logger.info("Compliance report written to %s", filepath)
    return str(filepath.resolve())


def get_mapping_stats() -> dict:
    """Return a summary of attack-to-control mappings per framework.

    Returns:
        Dict with mapping counts and unique control/attack tallies:
        {
            "total_mappings": int,
            "by_framework": {
                "nist_800_171": {"mappings": N, "unique_controls": N, "unique_attacks": N},
                ...
            },
            "total_unique_attacks": int,
            "total_unique_controls": int,
        }
    """
    fw_controls: dict[str, set[str]] = {fw: set() for fw in ALL_FRAMEWORKS}
    fw_attacks: dict[str, set[str]] = {fw: set() for fw in ALL_FRAMEWORKS}
    fw_mappings: dict[str, int] = {fw: 0 for fw in ALL_FRAMEWORKS}
    all_controls: set[tuple[str, str]] = set()
    all_attacks: set[str] = set()

    for entry in ATTACK_CONTROL_MAP:
        fw = entry["framework"]
        attack = entry["attack"]
        controls = entry["controls"]

        if fw in fw_mappings:
            fw_mappings[fw] += 1
            fw_attacks[fw].add(attack)
            for ctrl in controls:
                fw_controls[fw].add(ctrl)
                all_controls.add((fw, ctrl))
            all_attacks.add(attack)

    return {
        "total_mappings": len(ATTACK_CONTROL_MAP),
        "by_framework": {
            fw: {
                "mappings": fw_mappings[fw],
                "unique_controls": len(fw_controls[fw]),
                "unique_attacks": len(fw_attacks[fw]),
            }
            for fw in ALL_FRAMEWORKS
        },
        "total_unique_attacks": len(all_attacks),
        "total_unique_controls": len(all_controls),
    }
