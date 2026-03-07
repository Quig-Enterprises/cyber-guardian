"""Cross-framework compliance mapping — pci_dss_v4 ↔ nist_800_171 ↔ hipaa Security Rule."""

# Relationship types:
#   equivalent  — controls address essentially the same requirement
#   overlapping — controls address related but not identical requirements
#   partial     — one control partially satisfies the other

MAPPINGS = [
    # ──────────────────────────────────────────────────────────────────────
    # ACCESS CONTROL
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.1",
        "target_framework": "nist_800_171",
        "target_control": "3.1.1",
        "relationship": "equivalent",
        "notes": "Both require limiting system access to authorized users.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.1",
        "target_framework": "pci_dss_v4",
        "target_control": "7.3.1",
        "relationship": "overlapping",
        "notes": "hipaa access control aligns with PCI default-deny access policy.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "7.3.1",
        "target_framework": "nist_800_171",
        "target_control": "3.1.1",
        "relationship": "overlapping",
        "notes": "Both enforce access control; PCI emphasizes default-deny posture.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "7.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.1.2",
        "relationship": "equivalent",
        "notes": "Both require role-based or job-function-based access control models.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "7.2.2",
        "target_framework": "nist_800_171",
        "target_control": "3.1.5",
        "relationship": "overlapping",
        "notes": "Both enforce least privilege; PCI scopes to cardholder data environments.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.3.i",
        "target_framework": "nist_800_171",
        "target_control": "3.1.1",
        "relationship": "overlapping",
        "notes": "hipaa workforce authorization policies overlap with NIST access enforcement.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.3.ii.C",
        "target_framework": "nist_800_171",
        "target_control": "3.1.1",
        "relationship": "partial",
        "notes": "hipaa access termination procedures partially satisfy NIST access control.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "1.3.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.1",
        "relationship": "overlapping",
        "notes": "PCI inbound traffic restrictions align with NIST boundary protection.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "1.3.2",
        "target_framework": "nist_800_171",
        "target_control": "3.13.2",
        "relationship": "overlapping",
        "notes": "PCI outbound traffic restrictions align with NIST boundary protection.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "1.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.1",
        "relationship": "overlapping",
        "notes": "PCI NSC configuration rules support NIST communications boundary protection.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.2.iii",
        "target_framework": "nist_800_171",
        "target_control": "3.1.12",
        "relationship": "equivalent",
        "notes": "Both require automatic session termination after inactivity period.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "8.3.4",
        "target_framework": "nist_800_171",
        "target_control": "3.1.8",
        "relationship": "overlapping",
        "notes": "PCI lockout after failed login attempts aligns with NIST unsuccessful logon handling.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # AUTHENTICATION & IDENTITY
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.312.d.1",
        "target_framework": "nist_800_171",
        "target_control": "3.5.1",
        "relationship": "equivalent",
        "notes": "Both require identification and authentication of users before granting access.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.d.2",
        "target_framework": "nist_800_171",
        "target_control": "3.5.3",
        "relationship": "equivalent",
        "notes": "Both require multi-factor authentication for privileged and remote access.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.d.2",
        "target_framework": "pci_dss_v4",
        "target_control": "8.4.2",
        "relationship": "equivalent",
        "notes": "Both mandate MFA for access to sensitive systems and data.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "8.4.2",
        "target_framework": "nist_800_171",
        "target_control": "3.5.3",
        "relationship": "equivalent",
        "notes": "Both enforce multi-factor authentication for system access.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "8.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.5.1",
        "relationship": "equivalent",
        "notes": "Both require unique identification for every user account.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.2.i",
        "target_framework": "nist_800_171",
        "target_control": "3.5.1",
        "relationship": "equivalent",
        "notes": "Both require unique user identification for accountability.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.2.i",
        "target_framework": "pci_dss_v4",
        "target_control": "8.2.1",
        "relationship": "equivalent",
        "notes": "Both require assigning unique IDs to each user.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "8.3.5",
        "target_framework": "nist_800_171",
        "target_control": "3.5.7",
        "relationship": "overlapping",
        "notes": "PCI password complexity requirements overlap with NIST authenticator strength.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "8.2.2",
        "target_framework": "nist_800_171",
        "target_control": "3.5.10",
        "relationship": "overlapping",
        "notes": "Both discourage shared or group authentication credentials.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.d.3",
        "target_framework": "nist_800_171",
        "target_control": "3.5.2",
        "relationship": "overlapping",
        "notes": "hipaa entity/device authentication aligns with NIST device identification.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # ENCRYPTION & DATA PROTECTION
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.2.iv",
        "target_framework": "nist_800_171",
        "target_control": "3.13.16",
        "relationship": "equivalent",
        "notes": "Both require encryption of sensitive data at rest (ePHI / CUI).",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.a.2.iv",
        "target_framework": "pci_dss_v4",
        "target_control": "3.5.1",
        "relationship": "overlapping",
        "notes": "hipaa encryption at rest aligns with PCI requirement to render PAN unreadable.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "3.5.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.16",
        "relationship": "overlapping",
        "notes": "Both protect stored sensitive data via encryption; scoped to PAN vs. CUI.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.e.2.ii",
        "target_framework": "nist_800_171",
        "target_control": "3.13.8",
        "relationship": "equivalent",
        "notes": "Both require encryption of data during transmission over networks.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.e.2.ii",
        "target_framework": "pci_dss_v4",
        "target_control": "4.2.1",
        "relationship": "equivalent",
        "notes": "Both mandate strong cryptography for data transmitted over open networks.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "4.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.8",
        "relationship": "equivalent",
        "notes": "Both require strong cryptographic protection for data in transit.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "3.6.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.15",
        "relationship": "overlapping",
        "notes": "PCI key management procedures align with NIST cryptographic key establishment.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.e.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.1",
        "relationship": "partial",
        "notes": "hipaa transmission security guards partially satisfy NIST boundary protection.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # AUDIT & LOGGING
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.312.b.1",
        "target_framework": "nist_800_171",
        "target_control": "3.3.1",
        "relationship": "equivalent",
        "notes": "Both require enabling audit logging for system events.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.b.1",
        "target_framework": "pci_dss_v4",
        "target_control": "10.2.1",
        "relationship": "equivalent",
        "notes": "Both require audit log generation for security-relevant activities.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "10.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.3.1",
        "relationship": "equivalent",
        "notes": "Both require creation of audit records for auditable events.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "10.2.2",
        "target_framework": "nist_800_171",
        "target_control": "3.3.1",
        "relationship": "overlapping",
        "notes": "PCI required log fields (user, event type, timestamp) overlap with NIST audit content.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "10.2.1.2",
        "target_framework": "nist_800_171",
        "target_control": "3.3.2",
        "relationship": "equivalent",
        "notes": "Both require logging of administrative and privileged actions.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.b.4",
        "target_framework": "nist_800_171",
        "target_control": "3.3.4",
        "relationship": "equivalent",
        "notes": "Both require protection of audit logs against unauthorized modification.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "10.3.3",
        "target_framework": "nist_800_171",
        "target_control": "3.3.8",
        "relationship": "overlapping",
        "notes": "PCI centralized log backup aligns with NIST log protection via central storage.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.b.5",
        "target_framework": "nist_800_171",
        "target_control": "3.3.1",
        "relationship": "overlapping",
        "notes": "hipaa audit log completeness supports NIST audit record generation requirements.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "10.6.1",
        "target_framework": "nist_800_171",
        "target_control": "3.3.5",
        "relationship": "overlapping",
        "notes": "PCI time synchronization supports NIST audit timestamp correlation.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.1.ii.D",
        "target_framework": "nist_800_171",
        "target_control": "3.3.3",
        "relationship": "overlapping",
        "notes": "hipaa review of system activity logs aligns with NIST audit review and analysis.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # INTEGRITY & CHANGE DETECTION
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.312.c.1",
        "target_framework": "nist_800_171",
        "target_control": "3.14.1",
        "relationship": "equivalent",
        "notes": "Both require policies and mechanisms to protect information integrity.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.312.c.2",
        "target_framework": "nist_800_171",
        "target_control": "3.14.2",
        "relationship": "equivalent",
        "notes": "Both require mechanisms to authenticate and verify data integrity.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "11.5.2",
        "target_framework": "nist_800_171",
        "target_control": "3.14.3",
        "relationship": "equivalent",
        "notes": "Both require file integrity monitoring to detect unauthorized changes.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "6.3.3",
        "target_framework": "nist_800_171",
        "target_control": "3.14.1",
        "relationship": "overlapping",
        "notes": "PCI security patch management supports NIST system integrity through timely updates.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "6.3.1",
        "target_framework": "nist_800_171",
        "target_control": "3.11.2",
        "relationship": "overlapping",
        "notes": "PCI vulnerability identification and ranking aligns with NIST vulnerability scanning.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # MALWARE & THREAT PROTECTION
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "pci_dss_v4",
        "source_control": "5.2.1",
        "target_framework": "nist_800_171",
        "target_control": "3.14.2",
        "relationship": "overlapping",
        "notes": "PCI anti-malware deployment supports NIST malicious code protection.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "5.3.1",
        "target_framework": "nist_800_171",
        "target_control": "3.14.4",
        "relationship": "overlapping",
        "notes": "PCI signature update requirements align with NIST malware protection updates.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.5.ii.B",
        "target_framework": "nist_800_171",
        "target_control": "3.14.2",
        "relationship": "overlapping",
        "notes": "hipaa malicious software protection procedures overlap with NIST malware defenses.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "11.5.1",
        "target_framework": "nist_800_171",
        "target_control": "3.13.1",
        "relationship": "partial",
        "notes": "PCI intrusion detection partially satisfies NIST boundary protection requirements.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "6.4.1",
        "target_framework": "nist_800_171",
        "target_control": "3.14.6",
        "relationship": "overlapping",
        "notes": "PCI web application firewall aligns with NIST monitoring for unauthorized connections.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # INCIDENT RESPONSE
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.6.i",
        "target_framework": "nist_800_171",
        "target_control": "3.6.1",
        "relationship": "equivalent",
        "notes": "Both require establishing an incident response plan and capability.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.6.ii",
        "target_framework": "nist_800_171",
        "target_control": "3.6.2",
        "relationship": "equivalent",
        "notes": "Both require incident detection, reporting, and response procedures.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "12.10.1",
        "target_framework": "nist_800_171",
        "target_control": "3.6.1",
        "relationship": "equivalent",
        "notes": "Both require a documented and tested incident response plan.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.6.i",
        "target_framework": "pci_dss_v4",
        "target_control": "12.10.1",
        "relationship": "equivalent",
        "notes": "Both mandate organizational readiness for security incident response.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # RISK & VULNERABILITY MANAGEMENT
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.1.ii.A",
        "target_framework": "nist_800_171",
        "target_control": "3.11.1",
        "relationship": "equivalent",
        "notes": "Both require periodic risk assessments of organizational systems.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.1.ii.B",
        "target_framework": "nist_800_171",
        "target_control": "3.11.1",
        "relationship": "partial",
        "notes": "hipaa risk mitigation partially satisfies NIST risk assessment requirements.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "11.3.1",
        "target_framework": "nist_800_171",
        "target_control": "3.11.2",
        "relationship": "overlapping",
        "notes": "PCI vulnerability scanning aligns with NIST vulnerability scanning requirements.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # TRAINING & AWARENESS
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.5.i",
        "target_framework": "nist_800_171",
        "target_control": "3.2.1",
        "relationship": "equivalent",
        "notes": "Both require security awareness and training programs for all personnel.",
    },
    {
        "source_framework": "pci_dss_v4",
        "source_control": "12.6.1",
        "target_framework": "nist_800_171",
        "target_control": "3.2.1",
        "relationship": "equivalent",
        "notes": "Both require formal security awareness programs for the workforce.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.5.ii.C",
        "target_framework": "nist_800_171",
        "target_control": "3.1.7",
        "relationship": "overlapping",
        "notes": "hipaa login monitoring awareness aligns with NIST unsuccessful logon attempts.",
    },

    # ──────────────────────────────────────────────────────────────────────
    # BACKUP & RECOVERY
    # ──────────────────────────────────────────────────────────────────────
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.7.ii.A",
        "target_framework": "nist_800_171",
        "target_control": "3.8.9",
        "relationship": "overlapping",
        "notes": "hipaa data backup plan aligns with NIST media protection and availability.",
    },
    {
        "source_framework": "hipaa",
        "source_control": "164.308.a.7.ii.D",
        "target_framework": "nist_800_171",
        "target_control": "3.12.3",
        "relationship": "overlapping",
        "notes": "hipaa contingency plan testing aligns with NIST security plan monitoring.",
    },
]

assert len(MAPPINGS) == 62
