"""Compliance-focused attack modules for CMMC gap analysis."""

from redteam.attacks.compliance.dual_authorization_bypass import DualAuthorizationBypassAttack
from redteam.attacks.compliance.network_segmentation import NetworkSegmentationAttack
from redteam.attacks.compliance.anomaly_detection_evasion import AnomalyDetectionEvasionAttack
from redteam.attacks.compliance.cui_retention import CUIRetentionAttack
from redteam.attacks.compliance.device_attestation import DeviceAttestationAttack
from redteam.attacks.compliance.supply_chain_deps import SupplyChainDepsAttack
from redteam.attacks.compliance.system_diversity import SystemDiversityAttack
from redteam.attacks.compliance.software_integrity import SoftwareIntegrityAttack
from redteam.attacks.compliance.system_refresh import SystemRefreshAttack

__all__ = [
    "DualAuthorizationBypassAttack",
    "NetworkSegmentationAttack",
    "AnomalyDetectionEvasionAttack",
    "CUIRetentionAttack",
    "DeviceAttestationAttack",
    "SupplyChainDepsAttack",
    "SystemDiversityAttack",
    "SoftwareIntegrityAttack",
    "SystemRefreshAttack",
]
