#!/usr/bin/env python3
"""
Network Security Scanner
Version: 1.0.0
Date: 2026-03-11

Scans for open ports, unexpected services, and network exposure beyond firewall checks.
Identifies services running on non-standard ports and compares against security baseline.

Usage:
    python3 network-security-scanner.py --server peter
    python3 network-security-scanner.py --server willie
    python3 network-security-scanner.py --all-servers
"""

import argparse
import json
import logging
import os
import re
import socket
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import psycopg2
from psycopg2.extras import RealDictCursor

# Database config
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "5432")),
    "database": os.getenv("DB_NAME", "eqmon"),
    "user": os.getenv("DB_USER", "eqmon"),
}

# Get password from .pgpass
PGPASS_FILE = Path.home() / ".pgpass"
if PGPASS_FILE.exists():
    with open(PGPASS_FILE) as f:
        for line in f:
            parts = line.strip().split(":")
            if len(parts) == 5 and parts[0] == DB_CONFIG["host"] and \
               parts[2] == DB_CONFIG["database"] and parts[3] == DB_CONFIG["user"]:
                DB_CONFIG["password"] = parts[4]
                break

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("network-security-scanner")

# Approved port whitelist by server type
APPROVED_PORTS = {
    "peter": {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL (localhost only)",
        5432: "PostgreSQL (localhost only)",
    },
    "willie": {
        22: "SSH",
        25: "SMTP",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "Submission",
        993: "IMAPS",
        995: "POP3S",
        4190: "ManageSieve",
    },
    "alfred": {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        8008: "Matrix",
        9090: "Keystone",
        5432: "PostgreSQL (localhost only)",
    }
}


class NetworkSecurityScanner:
    """Scans network exposure and open ports."""
    
    def __init__(self, ssh_host: str = None, ssh_key: str = None, server_name: str = "unknown"):
        self.ssh_host = ssh_host
        self.ssh_key = ssh_key
        self.server_name = server_name
        self.approved_ports = APPROVED_PORTS.get(server_name, {})
    
    def scan_listening_ports(self) -> List[Dict]:
        """Get list of listening ports using ss command."""
        logger.info(f"Scanning listening ports on {self.server_name}...")
        
        if self.ssh_host:
            cmd = ["ssh", "-i", self.ssh_key, self.ssh_host,
                   "ss -tlnp | grep LISTEN"]
        else:
            cmd = ["ss", "-tlnp"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        ports = []
        for line in result.stdout.strip().split('\n'):
            if 'LISTEN' in line:
                port_info = self._parse_ss_line(line)
                if port_info:
                    ports.append(port_info)
        
        logger.info(f"Found {len(ports)} listening ports")
        return ports
    
    def _parse_ss_line(self, line: str) -> Optional[Dict]:
        """Parse ss output line to extract port and process info."""
        # Example: tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1234,fd=3))
        parts = line.split()
        
        if len(parts) < 4:
            return None
        
        # Extract local address (0.0.0.0:22 or :::22)
        local_addr = parts[3] if len(parts) > 3 else ""
        
        # Extract port
        if ':' in local_addr:
            port_str = local_addr.split(':')[-1]
            try:
                port = int(port_str)
            except ValueError:
                return None
        else:
            return None
        
        # Extract bind address
        bind_addr = local_addr.rsplit(':', 1)[0]
        if bind_addr.startswith('['):
            bind_addr = bind_addr[1:-1]  # Remove [ ] from IPv6
        
        # Extract process info
        process = "unknown"
        pid = None
        if "users:(" in line:
            match = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            if match:
                process = match.group(1)
                pid = int(match.group(2))
        
        return {
            "port": port,
            "bind_address": bind_addr,
            "process": process,
            "pid": pid,
            "protocol": parts[0] if parts else "tcp"
        }
    
    def check_remote_access_mysql(self) -> Dict:
        """Check if MySQL/MariaDB allows remote connections."""
        logger.info("Checking MySQL remote access configuration...")
        
        finding = {
            "check": "mysql-remote-access",
            "status": "PASS",
            "severity": "LOW",
            "details": ""
        }
        
        if self.ssh_host:
            # Check bind-address in my.cnf
            cmd = ["ssh", "-i", self.ssh_key, self.ssh_host,
                   "grep -r '^bind-address' /etc/mysql/ 2>/dev/null || echo 'not found'"]
        else:
            cmd = ["grep", "-r", "^bind-address", "/etc/mysql/"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "127.0.0.1" in result.stdout:
            finding["details"] = "MySQL bound to localhost only (secure)"
        elif "0.0.0.0" in result.stdout:
            finding["status"] = "FAIL"
            finding["severity"] = "HIGH"
            finding["details"] = "MySQL bound to 0.0.0.0 (allows remote connections)"
        elif "not found" in result.stdout:
            finding["status"] = "WARNING"
            finding["severity"] = "MEDIUM"
            finding["details"] = "MySQL bind-address not explicitly set"
        
        return finding
    
    def analyze_port_exposure(self, ports: List[Dict]) -> List[Dict]:
        """Analyze ports against approved whitelist."""
        findings = []
        
        for port_info in ports:
            port = port_info["port"]
            bind_addr = port_info["bind_address"]
            process = port_info["process"]
            
            # Check if port is in whitelist
            if port not in self.approved_ports:
                findings.append({
                    "type": "unexpected-port",
                    "severity": "MEDIUM",
                    "port": port,
                    "bind_address": bind_addr,
                    "process": process,
                    "title": f"Unexpected port {port} open",
                    "description": f"Port {port} ({process}) is listening but not in approved list",
                    "recommendation": f"Verify if {process} on port {port} is required"
                })
            
            # Check if localhost-only service is exposed externally
            if port in [3306, 5432]:  # MySQL, PostgreSQL
                if bind_addr not in ["127.0.0.1", "localhost", "::1"]:
                    findings.append({
                        "type": "database-exposed",
                        "severity": "HIGH",
                        "port": port,
                        "bind_address": bind_addr,
                        "process": process,
                        "title": f"Database exposed on {bind_addr}:{port}",
                        "description": f"{process} should only listen on localhost",
                        "recommendation": f"Configure {process} to bind to 127.0.0.1 only"
                    })
            
            # Check for non-standard SSH port
            if process == "sshd" and port != 22:
                findings.append({
                    "type": "non-standard-port",
                    "severity": "LOW",
                    "port": port,
                    "bind_address": bind_addr,
                    "process": process,
                    "title": f"SSH on non-standard port {port}",
                    "description": "SSH running on non-standard port (security through obscurity)",
                    "recommendation": "This is acceptable if intentional"
                })
        
        return findings
    
    def test_external_connectivity(self, port: int) -> bool:
        """Test if a port is externally accessible (for localhost scans)."""
        if self.ssh_host:
            # Can't test external connectivity from remote scan
            return False
        
        try:
            # Try to connect to localhost on this port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            return result == 0
        except:
            return False
    
    def scan_firewall_rules(self) -> Dict:
        """Check firewall configuration."""
        logger.info("Checking firewall configuration...")
        
        finding = {
            "check": "firewall-status",
            "status": "PASS",
            "severity": "LOW",
            "details": "",
            "rules": []
        }
        
        if self.ssh_host:
            # Check UFW status remotely
            cmd = ["ssh", "-i", self.ssh_key, self.ssh_host,
                   "sudo ufw status verbose 2>/dev/null || iptables -L -n 2>/dev/null | head -20"]
        else:
            cmd = ["sudo", "ufw", "status", "verbose"]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if "Status: active" in result.stdout:
            finding["details"] = "UFW firewall is active"
            # Parse rules
            for line in result.stdout.split('\n'):
                if 'ALLOW' in line or 'DENY' in line:
                    finding["rules"].append(line.strip())
        elif "Status: inactive" in result.stdout:
            finding["status"] = "FAIL"
            finding["severity"] = "MEDIUM"
            finding["details"] = "UFW firewall is inactive"
        else:
            # Check iptables
            if "Chain INPUT" in result.stdout:
                finding["details"] = "Using iptables/nftables (no UFW)"
            else:
                finding["status"] = "WARNING"
                finding["severity"] = "MEDIUM"
                finding["details"] = "Could not determine firewall status"
        
        return finding
    
    def save_to_database(self, ports: List[Dict], findings: List[Dict], 
                        firewall_check: Dict, mysql_check: Dict) -> int:
        """Save scan results to database."""
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()
        
        # Insert scan record
        cur.execute("""
            INSERT INTO blueteam.network_security_scans 
            (scan_date, server_name, ports_scanned, findings_count)
            VALUES (%s, %s, %s, %s)
            RETURNING scan_id
        """, (
            datetime.now(),
            self.server_name,
            len(ports),
            len(findings)
        ))
        
        scan_id = cur.fetchone()[0]
        
        # Insert port information
        for port_info in ports:
            cur.execute("""
                INSERT INTO blueteam.network_ports
                (scan_id, port_number, bind_address, process_name, 
                 process_pid, protocol, is_approved)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                port_info["port"],
                port_info["bind_address"],
                port_info["process"],
                port_info.get("pid"),
                port_info["protocol"],
                port_info["port"] in self.approved_ports
            ))
        
        # Insert findings
        for finding in findings:
            cur.execute("""
                INSERT INTO blueteam.network_security_findings
                (scan_id, finding_type, severity, port_number, 
                 bind_address, process_name, title, description, recommendation)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                finding["type"],
                finding["severity"],
                finding.get("port"),
                finding.get("bind_address"),
                finding.get("process"),
                finding["title"],
                finding["description"],
                finding["recommendation"]
            ))
        
        # Insert firewall check
        cur.execute("""
            INSERT INTO blueteam.network_security_findings
            (scan_id, finding_type, severity, title, description, recommendation)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            scan_id,
            "firewall-check",
            firewall_check["severity"],
            firewall_check["check"],
            firewall_check["details"],
            "Enable and configure firewall" if firewall_check["status"] == "FAIL" else "Firewall configured"
        ))
        
        # Insert MySQL check if applicable
        if self.server_name == "peter":
            cur.execute("""
                INSERT INTO blueteam.network_security_findings
                (scan_id, finding_type, severity, title, description, recommendation)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                scan_id,
                "mysql-remote-access",
                mysql_check["severity"],
                mysql_check["check"],
                mysql_check["details"],
                "Configure MySQL to bind to 127.0.0.1" if mysql_check["status"] == "FAIL" else "MySQL properly configured"
            ))
        
        conn.commit()
        cur.close()
        conn.close()
        
        logger.info(f"Saved scan results to database (scan_id={scan_id})")
        return scan_id


def main():
    parser = argparse.ArgumentParser(description='Network security scanner')
    parser.add_argument('--server', choices=['peter', 'willie', 'alfred'],
                       required=True, help='Server to scan')
    parser.add_argument('--dry-run', action='store_true',
                       help='Scan but do not save to database')
    
    args = parser.parse_args()
    
    # Determine SSH settings
    ssh_host = None
    ssh_key = None
    
    if args.server == 'peter':
        ssh_host = "ubuntu@webhost.tailce791f.ts.net"
        ssh_key = str(Path.home() / ".ssh" / "webhost_key")
    elif args.server == 'willie':
        ssh_host = "ubuntu@mailcow.tailce791f.ts.net"
        ssh_key = str(Path.home() / ".ssh" / "bq_laptop_rsa")
    
    scanner = NetworkSecurityScanner(ssh_host, ssh_key, args.server)
    
    # Scan listening ports
    ports = scanner.scan_listening_ports()
    
    # Analyze port exposure
    findings = scanner.analyze_port_exposure(ports)
    
    # Check firewall
    firewall_check = scanner.scan_firewall_rules()
    
    # Check MySQL remote access (Peter only)
    mysql_check = {"status": "SKIP", "severity": "LOW", "details": "N/A", "check": "mysql-check"}
    if args.server == "peter":
        mysql_check = scanner.check_remote_access_mysql()
    
    # Print summary
    print("\n" + "="*80)
    print(f"NETWORK SECURITY SCAN SUMMARY - {args.server.upper()}")
    print("="*80)
    print(f"Listening ports: {len(ports)}")
    print(f"Security findings: {len(findings)}")
    print("\nPort Summary:")
    
    for port_info in sorted(ports, key=lambda x: x["port"]):
        port = port_info["port"]
        approved = "✓" if port in scanner.approved_ports else "⚠"
        print(f"  {approved} {port:5d} {port_info['bind_address']:15s} {port_info['process']}")
    
    if findings:
        print("\nSecurity Findings:")
        for finding in sorted(findings, key=lambda x: (x["severity"], x["port"])):
            print(f"  [{finding['severity']}] {finding['title']}")
            print(f"      {finding['description']}")
    
    print(f"\nFirewall: {firewall_check['details']}")
    if args.server == "peter":
        print(f"MySQL: {mysql_check['details']}")
    
    # Save to database
    if not args.dry_run:
        scan_id = scanner.save_to_database(ports, findings, firewall_check, mysql_check)
        print(f"\nScan ID: {scan_id}")
        print("View results: SELECT * FROM blueteam.v_network_security_findings;")
    
    print("="*80)
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
