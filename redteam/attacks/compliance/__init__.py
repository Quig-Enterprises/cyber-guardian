"""Compliance-focused attack modules for CMMC gap analysis."""

from redteam.attacks.compliance.dual_authorization_bypass import DualAuthorizationBypassAttack
from redteam.attacks.compliance.network_segmentation import NetworkSegmentationAttack

__all__ = [
    "DualAuthorizationBypassAttack",
    "NetworkSegmentationAttack",
]
