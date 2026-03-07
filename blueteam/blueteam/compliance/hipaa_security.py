"""HIPAA Security Rule — Technically verifiable control catalog."""

CONTROLS = [
    # §164.312(a) Access Control (5 controls)
    {"control_id": "164.312.a.1", "family": "Access Control", "family_id": "AC",
     "requirement": "Implement technical policies and procedures for information systems maintaining ePHI to allow access only to authorized persons or software."},
    {"control_id": "164.312.a.2.i", "family": "Access Control", "family_id": "AC",
     "requirement": "Assign a unique name and/or number for identifying and tracking user identity."},
    {"control_id": "164.312.a.2.ii", "family": "Access Control", "family_id": "AC",
     "requirement": "Establish procedures for obtaining necessary ePHI during an emergency."},
    {"control_id": "164.312.a.2.iii", "family": "Access Control", "family_id": "AC",
     "requirement": "Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity."},
    {"control_id": "164.312.a.2.iv", "family": "Access Control", "family_id": "AC",
     "requirement": "Implement a mechanism to encrypt and decrypt electronic protected health information."},

    # §164.312(b) Audit Controls (5 controls)
    {"control_id": "164.312.b.1", "family": "Audit Controls", "family_id": "AUD",
     "requirement": "Implement hardware, software, and/or procedural mechanisms to record and examine access and activity in information systems containing ePHI."},
    {"control_id": "164.312.b.2", "family": "Audit Controls", "family_id": "AUD",
     "requirement": "Audit log retention — maintain audit logs for a minimum of six years."},
    {"control_id": "164.312.b.3", "family": "Audit Controls", "family_id": "AUD",
     "requirement": "Audit log review — conduct regular review of information system activity records."},
    {"control_id": "164.312.b.4", "family": "Audit Controls", "family_id": "AUD",
     "requirement": "Audit log integrity — protect audit logs from unauthorized modification or deletion."},
    {"control_id": "164.312.b.5", "family": "Audit Controls", "family_id": "AUD",
     "requirement": "Audit log completeness — ensure all ePHI access events are captured in audit logs."},

    # §164.312(c) Integrity (3 controls)
    {"control_id": "164.312.c.1", "family": "Integrity", "family_id": "INT",
     "requirement": "Implement policies and procedures to protect ePHI from improper alteration or destruction."},
    {"control_id": "164.312.c.2", "family": "Integrity", "family_id": "INT",
     "requirement": "Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed in an unauthorized manner."},
    {"control_id": "164.312.c.3", "family": "Integrity", "family_id": "INT",
     "requirement": "Integrity verification of data in transit — authenticate message integrity."},

    # §164.312(d) Person/Entity Authentication (4 controls)
    {"control_id": "164.312.d.1", "family": "Person/Entity Authentication", "family_id": "PEA",
     "requirement": "Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed."},
    {"control_id": "164.312.d.2", "family": "Person/Entity Authentication", "family_id": "PEA",
     "requirement": "Multi-factor authentication for access to ePHI systems."},
    {"control_id": "164.312.d.3", "family": "Person/Entity Authentication", "family_id": "PEA",
     "requirement": "Entity authentication for service-to-service communication accessing ePHI."},
    {"control_id": "164.312.d.4", "family": "Person/Entity Authentication", "family_id": "PEA",
     "requirement": "Authentication credential management including secure storage and rotation."},

    # §164.312(e) Transmission Security (4 controls)
    {"control_id": "164.312.e.1", "family": "Transmission Security", "family_id": "TXS",
     "requirement": "Implement technical security measures to guard against unauthorized access to ePHI transmitted over an electronic communications network."},
    {"control_id": "164.312.e.2.i", "family": "Transmission Security", "family_id": "TXS",
     "requirement": "Implement security measures to ensure electronically transmitted ePHI integrity."},
    {"control_id": "164.312.e.2.ii", "family": "Transmission Security", "family_id": "TXS",
     "requirement": "Implement a mechanism to encrypt ePHI whenever deemed appropriate during transmission."},
    {"control_id": "164.312.e.3", "family": "Transmission Security", "family_id": "TXS",
     "requirement": "Secure email and messaging for ePHI communication."},

    # §164.308(a)(1) Security Management Process (5 controls)
    {"control_id": "164.308.a.1.i", "family": "Security Management Process", "family_id": "SMP",
     "requirement": "Implement policies and procedures to prevent, detect, contain, and correct security violations."},
    {"control_id": "164.308.a.1.ii.A", "family": "Security Management Process", "family_id": "SMP",
     "requirement": "Conduct an accurate and thorough assessment of potential risks and vulnerabilities to ePHI."},
    {"control_id": "164.308.a.1.ii.B", "family": "Security Management Process", "family_id": "SMP",
     "requirement": "Implement security measures sufficient to reduce risks and vulnerabilities to a reasonable and appropriate level."},
    {"control_id": "164.308.a.1.ii.C", "family": "Security Management Process", "family_id": "SMP",
     "requirement": "Apply appropriate sanctions against workforce members who fail to comply with security policies."},
    {"control_id": "164.308.a.1.ii.D", "family": "Security Management Process", "family_id": "SMP",
     "requirement": "Implement procedures to regularly review records of information system activity."},

    # §164.308(a)(3) Information Access Management (4 controls)
    {"control_id": "164.308.a.3.i", "family": "Information Access Management", "family_id": "IAM",
     "requirement": "Implement policies and procedures for authorizing access to ePHI consistent with applicable requirements."},
    {"control_id": "164.308.a.3.ii.A", "family": "Information Access Management", "family_id": "IAM",
     "requirement": "Implement policies and procedures that establish criteria for granting access to ePHI."},
    {"control_id": "164.308.a.3.ii.B", "family": "Information Access Management", "family_id": "IAM",
     "requirement": "Implement policies and procedures that establish criteria for modifying access to ePHI."},
    {"control_id": "164.308.a.3.ii.C", "family": "Information Access Management", "family_id": "IAM",
     "requirement": "Implement procedures for terminating access to ePHI when employment or access relationship ends."},

    # §164.308(a)(5) Security Awareness & Training (4 controls)
    {"control_id": "164.308.a.5.i", "family": "Security Awareness & Training", "family_id": "SAT",
     "requirement": "Implement a security awareness and training program for all members of the workforce."},
    {"control_id": "164.308.a.5.ii.A", "family": "Security Awareness & Training", "family_id": "SAT",
     "requirement": "Implement periodic security reminders."},
    {"control_id": "164.308.a.5.ii.B", "family": "Security Awareness & Training", "family_id": "SAT",
     "requirement": "Implement procedures for guarding against, detecting, and reporting malicious software."},
    {"control_id": "164.308.a.5.ii.C", "family": "Security Awareness & Training", "family_id": "SAT",
     "requirement": "Implement procedures for monitoring login attempts and reporting discrepancies."},

    # §164.308(a)(6) Security Incident Procedures (3 controls)
    {"control_id": "164.308.a.6.i", "family": "Security Incident Procedures", "family_id": "SIP",
     "requirement": "Implement policies and procedures to address security incidents."},
    {"control_id": "164.308.a.6.ii", "family": "Security Incident Procedures", "family_id": "SIP",
     "requirement": "Identify and respond to suspected or known security incidents and mitigate harmful effects."},
    {"control_id": "164.308.a.6.iii", "family": "Security Incident Procedures", "family_id": "SIP",
     "requirement": "Document security incidents and their outcomes."},

    # §164.308(a)(7) Contingency Plan (5 controls)
    {"control_id": "164.308.a.7.i", "family": "Contingency Plan", "family_id": "CTP",
     "requirement": "Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI."},
    {"control_id": "164.308.a.7.ii.A", "family": "Contingency Plan", "family_id": "CTP",
     "requirement": "Establish and implement procedures to create and maintain retrievable exact copies of ePHI (data backup plan)."},
    {"control_id": "164.308.a.7.ii.B", "family": "Contingency Plan", "family_id": "CTP",
     "requirement": "Establish procedures to restore any loss of data (disaster recovery plan)."},
    {"control_id": "164.308.a.7.ii.C", "family": "Contingency Plan", "family_id": "CTP",
     "requirement": "Establish procedures to enable continuation of critical business processes for protection of ePHI (emergency mode operation plan)."},
    {"control_id": "164.308.a.7.ii.D", "family": "Contingency Plan", "family_id": "CTP",
     "requirement": "Implement procedures for periodic testing and revision of contingency plans."},
]

assert len(CONTROLS) == 42, f"Expected 42 controls, got {len(CONTROLS)}"
