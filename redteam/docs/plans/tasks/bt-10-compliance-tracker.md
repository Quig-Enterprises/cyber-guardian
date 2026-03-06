# BT-10: Compliance Tracker

**Goal:** Implement NIST SP 800-171 compliance tracking with all 110 controls, automated evidence collection, SSP generation, and POA&M management.

**Files:**
- Create: `/opt/security-blue-team/blueteam/compliance/controls.py`
- Create: `/opt/security-blue-team/blueteam/compliance/evidence.py`
- Create: `/opt/security-blue-team/blueteam/compliance/ssp.py`
- Create: `/opt/security-blue-team/blueteam/compliance/poam.py`
- Create: `/opt/security-blue-team/blueteam/compliance/nist_800_171.py` (all 110 controls data)
- Create: `/opt/security-blue-team/templates/ssp_template.md.j2`
- Create: `/opt/security-blue-team/templates/poam_template.md.j2`
- Modify: `/opt/security-blue-team/blueteam/cli.py` — compliance subcommands

**Depends on:** BT-05

---

## Step 1: Create NIST 800-171r2 control definitions

```python
# blueteam/compliance/nist_800_171.py
"""All 110 NIST SP 800-171 Rev 2 controls."""

CONTROLS = [
    # 3.1 Access Control (22 controls)
    {"control_id": "3.1.1", "family": "Access Control", "family_id": "AC",
     "requirement": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices."},
    {"control_id": "3.1.2", "family": "Access Control", "family_id": "AC",
     "requirement": "Limit system access to the types of transactions and functions that authorized users are permitted to execute."},
    # ... (all 110 controls — full data embedded)
    {"control_id": "3.1.3", "family": "Access Control", "family_id": "AC",
     "requirement": "Control the flow of CUI in accordance with approved authorizations."},
    {"control_id": "3.1.4", "family": "Access Control", "family_id": "AC",
     "requirement": "Separate the duties of individuals to reduce the risk of malevolent activity without collusion."},
    {"control_id": "3.1.5", "family": "Access Control", "family_id": "AC",
     "requirement": "Employ the principle of least privilege, including for specific security functions and privileged accounts."},
    {"control_id": "3.1.6", "family": "Access Control", "family_id": "AC",
     "requirement": "Use non-privileged accounts or roles when accessing nonsecurity functions."},
    {"control_id": "3.1.7", "family": "Access Control", "family_id": "AC",
     "requirement": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs."},
    {"control_id": "3.1.8", "family": "Access Control", "family_id": "AC",
     "requirement": "Limit unsuccessful logon attempts."},
    {"control_id": "3.1.9", "family": "Access Control", "family_id": "AC",
     "requirement": "Provide privacy and security notices consistent with applicable CUI rules."},
    {"control_id": "3.1.10", "family": "Access Control", "family_id": "AC",
     "requirement": "Use session lock with pattern-hiding displays to prevent access and viewing of data after a period of inactivity."},
    {"control_id": "3.1.11", "family": "Access Control", "family_id": "AC",
     "requirement": "Terminate (automatically) a user session after a defined condition."},
    {"control_id": "3.1.12", "family": "Access Control", "family_id": "AC",
     "requirement": "Monitor and control remote access sessions."},
    {"control_id": "3.1.13", "family": "Access Control", "family_id": "AC",
     "requirement": "Employ cryptographic mechanisms to protect the confidentiality of remote access sessions."},
    {"control_id": "3.1.14", "family": "Access Control", "family_id": "AC",
     "requirement": "Route remote access via managed access control points."},
    {"control_id": "3.1.15", "family": "Access Control", "family_id": "AC",
     "requirement": "Authorize remote execution of privileged commands and remote access to security-relevant information."},
    {"control_id": "3.1.16", "family": "Access Control", "family_id": "AC",
     "requirement": "Authorize wireless access prior to allowing such connections."},
    {"control_id": "3.1.17", "family": "Access Control", "family_id": "AC",
     "requirement": "Protect wireless access using authentication and encryption."},
    {"control_id": "3.1.18", "family": "Access Control", "family_id": "AC",
     "requirement": "Control connection of mobile devices."},
    {"control_id": "3.1.19", "family": "Access Control", "family_id": "AC",
     "requirement": "Encrypt CUI on mobile devices and mobile computing platforms."},
    {"control_id": "3.1.20", "family": "Access Control", "family_id": "AC",
     "requirement": "Verify and control/limit connections to and use of external systems."},
    {"control_id": "3.1.21", "family": "Access Control", "family_id": "AC",
     "requirement": "Limit use of portable storage devices on external systems."},
    {"control_id": "3.1.22", "family": "Access Control", "family_id": "AC",
     "requirement": "Control CUI posted or processed on publicly accessible systems."},

    # 3.2 Awareness and Training (3 controls)
    {"control_id": "3.2.1", "family": "Awareness and Training", "family_id": "AT",
     "requirement": "Ensure that managers, systems administrators, and users are made aware of the security risks."},
    {"control_id": "3.2.2", "family": "Awareness and Training", "family_id": "AT",
     "requirement": "Ensure that personnel are trained to carry out their assigned information security-related duties."},
    {"control_id": "3.2.3", "family": "Awareness and Training", "family_id": "AT",
     "requirement": "Provide security awareness training on recognizing and reporting potential indicators of insider threat."},

    # 3.3 Audit and Accountability (9 controls)
    {"control_id": "3.3.1", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Create and retain system audit logs and records to the extent needed to enable monitoring, analysis, investigation, and reporting of unlawful or unauthorized system activity."},
    {"control_id": "3.3.2", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Ensure that the actions of individual system users can be uniquely traced to those users."},
    {"control_id": "3.3.3", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Review and update logged events."},
    {"control_id": "3.3.4", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Alert in the event of an audit logging process failure."},
    {"control_id": "3.3.5", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Correlate audit record review, analysis, and reporting processes for investigation and response."},
    {"control_id": "3.3.6", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Provide audit record reduction and report generation to support on-demand analysis and reporting."},
    {"control_id": "3.3.7", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Provide a system capability that compares and synchronizes internal system clocks with an authoritative source."},
    {"control_id": "3.3.8", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Protect audit information and audit logging tools from unauthorized access, modification, and deletion."},
    {"control_id": "3.3.9", "family": "Audit and Accountability", "family_id": "AU",
     "requirement": "Limit management of audit logging functionality to a subset of privileged users."},

    # 3.4 Configuration Management (9 controls)
    {"control_id": "3.4.1", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Establish and maintain baseline configurations and inventories of organizational systems."},
    {"control_id": "3.4.2", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Establish and enforce security configuration settings for IT products."},
    {"control_id": "3.4.3", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Track, review, approve or disapprove, and log changes to organizational systems."},
    {"control_id": "3.4.4", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Analyze the security impact of changes prior to implementation."},
    {"control_id": "3.4.5", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Define, document, approve, and enforce physical and logical access restrictions associated with changes."},
    {"control_id": "3.4.6", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Employ the principle of least functionality by configuring systems to provide only essential capabilities."},
    {"control_id": "3.4.7", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Restrict, disable, or prevent the use of nonessential programs, functions, ports, protocols, and services."},
    {"control_id": "3.4.8", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Apply deny-by-exception policy to prevent the use of unauthorized software."},
    {"control_id": "3.4.9", "family": "Configuration Management", "family_id": "CM",
     "requirement": "Control and monitor user-installed software."},

    # 3.5 Identification and Authentication (11 controls)
    {"control_id": "3.5.1", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Identify system users, processes acting on behalf of users, and devices."},
    {"control_id": "3.5.2", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access."},
    {"control_id": "3.5.3", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Use multifactor authentication for local and network access to privileged accounts and for network access to non-privileged accounts."},
    {"control_id": "3.5.4", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Employ replay-resistant authentication mechanisms for network access."},
    {"control_id": "3.5.5", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Prevent reuse of identifiers for a defined period."},
    {"control_id": "3.5.6", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Disable identifiers after a defined period of inactivity."},
    {"control_id": "3.5.7", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Enforce a minimum password complexity and change of characters when new passwords are created."},
    {"control_id": "3.5.8", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Prohibit password reuse for a specified number of generations."},
    {"control_id": "3.5.9", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Allow temporary password use for system logons with an immediate change to a permanent password."},
    {"control_id": "3.5.10", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Store and transmit only cryptographically-protected passwords."},
    {"control_id": "3.5.11", "family": "Identification and Authentication", "family_id": "IA",
     "requirement": "Obscure feedback of authentication information."},

    # 3.6 Incident Response (3 controls)
    {"control_id": "3.6.1", "family": "Incident Response", "family_id": "IR",
     "requirement": "Establish an operational incident-handling capability for organizational systems that includes preparation, detection, analysis, containment, recovery, and user response activities."},
    {"control_id": "3.6.2", "family": "Incident Response", "family_id": "IR",
     "requirement": "Track, document, and report incidents to designated officials and/or authorities both internal and external to the organization."},
    {"control_id": "3.6.3", "family": "Incident Response", "family_id": "IR",
     "requirement": "Test the organizational incident response capability."},

    # 3.7 Maintenance (6 controls)
    {"control_id": "3.7.1", "family": "Maintenance", "family_id": "MA",
     "requirement": "Perform maintenance on organizational systems."},
    {"control_id": "3.7.2", "family": "Maintenance", "family_id": "MA",
     "requirement": "Provide controls on the tools, techniques, mechanisms, and personnel used to conduct system maintenance."},
    {"control_id": "3.7.3", "family": "Maintenance", "family_id": "MA",
     "requirement": "Ensure equipment removed for off-site maintenance is sanitized of any CUI."},
    {"control_id": "3.7.4", "family": "Maintenance", "family_id": "MA",
     "requirement": "Check media containing diagnostic and test programs for malicious code before the media are used."},
    {"control_id": "3.7.5", "family": "Maintenance", "family_id": "MA",
     "requirement": "Require multifactor authentication to establish nonlocal maintenance sessions via external network connections."},
    {"control_id": "3.7.6", "family": "Maintenance", "family_id": "MA",
     "requirement": "Supervise the maintenance activities of maintenance personnel without required access authorization."},

    # 3.8 Media Protection (9 controls)
    {"control_id": "3.8.1", "family": "Media Protection", "family_id": "MP",
     "requirement": "Protect (physically control and securely store) system media containing CUI, both paper and digital."},
    {"control_id": "3.8.2", "family": "Media Protection", "family_id": "MP",
     "requirement": "Limit access to CUI on system media to authorized users."},
    {"control_id": "3.8.3", "family": "Media Protection", "family_id": "MP",
     "requirement": "Sanitize or destroy system media containing CUI before disposal or release for reuse."},
    {"control_id": "3.8.4", "family": "Media Protection", "family_id": "MP",
     "requirement": "Mark media with necessary CUI markings and distribution limitations."},
    {"control_id": "3.8.5", "family": "Media Protection", "family_id": "MP",
     "requirement": "Control access to media containing CUI and maintain accountability for media during transport."},
    {"control_id": "3.8.6", "family": "Media Protection", "family_id": "MP",
     "requirement": "Implement cryptographic mechanisms to protect the confidentiality of CUI stored on digital media during transport."},
    {"control_id": "3.8.7", "family": "Media Protection", "family_id": "MP",
     "requirement": "Control the use of removable media on system components."},
    {"control_id": "3.8.8", "family": "Media Protection", "family_id": "MP",
     "requirement": "Prohibit the use of portable storage devices when such devices have no identifiable owner."},
    {"control_id": "3.8.9", "family": "Media Protection", "family_id": "MP",
     "requirement": "Protect the confidentiality of backup CUI at storage locations."},

    # 3.9 Personnel Security (2 controls)
    {"control_id": "3.9.1", "family": "Personnel Security", "family_id": "PS",
     "requirement": "Screen individuals prior to authorizing access to organizational systems containing CUI."},
    {"control_id": "3.9.2", "family": "Personnel Security", "family_id": "PS",
     "requirement": "Ensure organizational systems containing CUI are protected during and after personnel actions such as terminations and transfers."},

    # 3.10 Physical Protection (6 controls)
    {"control_id": "3.10.1", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Limit physical access to organizational systems, equipment, and operating environments to authorized individuals."},
    {"control_id": "3.10.2", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Protect and monitor the physical facility and support infrastructure for organizational systems."},
    {"control_id": "3.10.3", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Escort visitors and monitor visitor activity."},
    {"control_id": "3.10.4", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Maintain audit logs of physical access."},
    {"control_id": "3.10.5", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Control and manage physical access devices."},
    {"control_id": "3.10.6", "family": "Physical Protection", "family_id": "PE",
     "requirement": "Enforce safeguarding measures for CUI at alternate work sites."},

    # 3.11 Risk Assessment (3 controls)
    {"control_id": "3.11.1", "family": "Risk Assessment", "family_id": "RA",
     "requirement": "Periodically assess the risk to organizational operations and individuals, resulting from the operation of organizational systems and the associated processing, storage, or transmission of CUI."},
    {"control_id": "3.11.2", "family": "Risk Assessment", "family_id": "RA",
     "requirement": "Scan for vulnerabilities in organizational systems and applications periodically and when new vulnerabilities affecting those systems and applications are identified."},
    {"control_id": "3.11.3", "family": "Risk Assessment", "family_id": "RA",
     "requirement": "Remediate vulnerabilities in accordance with risk assessments."},

    # 3.12 Security Assessment (4 controls)
    {"control_id": "3.12.1", "family": "Security Assessment", "family_id": "CA",
     "requirement": "Periodically assess the security controls in organizational systems to determine if the controls are effective in their application."},
    {"control_id": "3.12.2", "family": "Security Assessment", "family_id": "CA",
     "requirement": "Develop and implement plans of action designed to correct deficiencies and reduce or eliminate vulnerabilities."},
    {"control_id": "3.12.3", "family": "Security Assessment", "family_id": "CA",
     "requirement": "Monitor security controls on an ongoing basis to ensure the continued effectiveness of the controls."},
    {"control_id": "3.12.4", "family": "Security Assessment", "family_id": "CA",
     "requirement": "Develop, document, and periodically update system security plans that describe system boundaries, environments of operation, how security requirements are implemented, and relationships with or connections to other systems."},

    # 3.13 System and Communications Protection (16 controls)
    {"control_id": "3.13.1", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Monitor, control, and protect communications at the external boundaries and key internal boundaries of organizational systems."},
    {"control_id": "3.13.2", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Employ architectural designs, software development techniques, and systems engineering principles that promote effective information security."},
    {"control_id": "3.13.3", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Separate user functionality from system management functionality."},
    {"control_id": "3.13.4", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Prevent unauthorized and unintended information transfer via shared system resources."},
    {"control_id": "3.13.5", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Implement subnetworks for publicly accessible system components that are physically or logically separated from internal networks."},
    {"control_id": "3.13.6", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Deny network communications traffic by default and allow network communications traffic by exception."},
    {"control_id": "3.13.7", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Prevent remote devices from simultaneously establishing non-remote connections with organizational systems and communicating via some other connection to resources in external networks."},
    {"control_id": "3.13.8", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission unless otherwise protected by alternative physical safeguards."},
    {"control_id": "3.13.9", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Terminate network connections associated with communications sessions at the end of the sessions or after a defined period of inactivity."},
    {"control_id": "3.13.10", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Establish and manage cryptographic keys for cryptography employed in organizational systems."},
    {"control_id": "3.13.11", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI."},
    {"control_id": "3.13.12", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Prohibit remote activation of collaborative computing devices and provide indication of devices in use to users present at the device."},
    {"control_id": "3.13.13", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Control and monitor the use of mobile code."},
    {"control_id": "3.13.14", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Control and monitor the use of Voice over Internet Protocol (VoIP) technologies."},
    {"control_id": "3.13.15", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Protect the authenticity of communications sessions."},
    {"control_id": "3.13.16", "family": "System and Communications Protection", "family_id": "SC",
     "requirement": "Protect the confidentiality of CUI at rest."},

    # 3.14 System and Information Integrity (7 controls)
    {"control_id": "3.14.1", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Identify, report, and correct system flaws in a timely manner."},
    {"control_id": "3.14.2", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Provide protection from malicious code at designated locations within organizational systems."},
    {"control_id": "3.14.3", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Monitor system security alerts and advisories and take action in response."},
    {"control_id": "3.14.4", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Update malicious code protection mechanisms when new releases are available."},
    {"control_id": "3.14.5", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Perform periodic scans of organizational systems and real-time scans of files from external sources as files are downloaded, opened, or executed."},
    {"control_id": "3.14.6", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks."},
    {"control_id": "3.14.7", "family": "System and Information Integrity", "family_id": "SI",
     "requirement": "Identify unauthorized use of organizational systems."},
]

assert len(CONTROLS) == 110, f"Expected 110 controls, got {len(CONTROLS)}"
```

The implementer should populate this file with ALL 110 controls. The above is the complete list.

---

## Step 2: Implement compliance management

```python
# blueteam/compliance/controls.py
"""Compliance control management — load, query, update."""
from blueteam.db import get_connection
from blueteam.compliance.nist_800_171 import CONTROLS

def load_controls(config: dict):
    """Load all 110 NIST SP 800-171r2 controls into the database."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        for ctrl in CONTROLS:
            cur.execute("""
                INSERT INTO blueteam.compliance_controls
                    (control_id, family, family_id, requirement)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (control_id) DO NOTHING
            """, (ctrl["control_id"], ctrl["family"],
                  ctrl["family_id"], ctrl["requirement"]))

def get_status_summary(config: dict) -> dict:
    """Get compliance status summary by family."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT family, status, COUNT(*) as count
            FROM blueteam.compliance_controls
            GROUP BY family, status
            ORDER BY family, status
        """)
        rows = cur.fetchall()
    summary = {}
    for row in rows:
        family = row["family"]
        if family not in summary:
            summary[family] = {}
        summary[family][row["status"]] = row["count"]
    return summary

def get_gaps(config: dict) -> list:
    """Get all controls not fully implemented."""
    conn = get_connection(config)
    with conn.cursor() as cur:
        cur.execute("""
            SELECT control_id, family, requirement, status
            FROM blueteam.compliance_controls
            WHERE status NOT IN ('implemented', 'not_applicable')
            ORDER BY control_id
        """)
        return cur.fetchall()

def update_control(config: dict, control_id: str, **kwargs):
    """Update a control's status and notes."""
    conn = get_connection(config)
    sets = []
    values = []
    for key in ("status", "implementation_notes", "evidence_type", "assessor_notes"):
        if key in kwargs:
            sets.append(f"{key} = %s")
            values.append(kwargs[key])
    if not sets:
        return
    sets.append("updated_at = NOW()")
    sets.append("last_assessed = NOW()")
    values.append(control_id)
    with conn.cursor() as cur:
        cur.execute(
            f"UPDATE blueteam.compliance_controls SET {', '.join(sets)} WHERE control_id = %s",
            values
        )
```

---

## Step 3: Add CLI compliance commands

```python
# Add to cli.py
@compliance.command(name="load")
@click.pass_context
def compliance_load(ctx):
    """Load all 110 NIST SP 800-171r2 controls into database."""
    from blueteam.compliance.controls import load_controls
    load_controls(ctx.obj["config"])
    console.print("[green]Loaded 110 NIST SP 800-171r2 controls.[/green]")

@compliance.command(name="status")
@click.pass_context
def compliance_status(ctx):
    """Show compliance status by family."""
    from blueteam.compliance.controls import get_status_summary
    summary = get_status_summary(ctx.obj["config"])
    # Rich table output...

@compliance.command(name="gaps")
@click.pass_context
def compliance_gaps(ctx):
    """Show all unimplemented/partial controls."""
    from blueteam.compliance.controls import get_gaps
    gaps = get_gaps(ctx.obj["config"])
    # Rich table output...
```

---

## Step 4: SSP and POA&M generation

Implement `ssp.py` and `poam.py` using Jinja2 templates to generate markdown documents from compliance data. Templates in `/opt/security-blue-team/templates/`.

---

## Step 5: Run and verify

```bash
blueteam compliance load
blueteam compliance status
blueteam compliance gaps
```

---

## Step 6: Commit

```bash
git add -A
git commit -m "feat: compliance tracker with 110 NIST controls, SSP, POA&M (NIST 3.12.1-3.12.4)"
```
