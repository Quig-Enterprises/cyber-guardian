#!/usr/bin/env python3
"""Build Attack Catalog SQL Generator

Scans all Python attack modules in redteam/attacks/*/*.py and generates SQL
INSERT statements to populate the attack_catalog and attack_compliance tables.

This script extracts attack metadata from Attack subclasses and parses docstrings
and comments for compliance framework references (NIST, PCI-DSS, etc.).

Usage:
    # Generate SQL to stdout
    python scripts/build-attack-catalog.py > /tmp/catalog.sql

    # Apply to database
    psql -U alfred_admin -d alfred_admin -f /tmp/catalog.sql

    # Validate catalog vs actual modules
    python scripts/build-attack-catalog.py --validate

    # Verbose mode (show parsing details)
    python scripts/build-attack-catalog.py --verbose

Output:
    SQL INSERT statements using ON CONFLICT DO UPDATE for idempotency.
    Safe to run multiple times - updates existing entries.

Extracted Metadata:
    From Attack class attributes:
        - name: attack_id (e.g., "api.account_lockout_bypass")
        - category: category (e.g., "api", "infrastructure", "secrets")
        - description: description attribute or docstring first line
        - severity: default_severity (Severity.HIGH → "high")
        - target_types: target_types set (default: ["app"])

    From docstrings/comments:
        - Compliance references via pattern matching:
            "NIST SP 800-171" or "NIST 3.1.8" → framework="NIST-800-171-Rev2"
            "NIST CSF" → framework="NIST-CSF"
            "PCI-DSS" → framework="PCI-DSS"
            "CMMC" → framework="CMMC"

Schema:
    attack_catalog:
        attack_id (PK) | name | category | description | default_severity | target_types[]

    attack_compliance:
        attack_id (FK) | framework | control_id | description

Examples:
    Attack class:
        class FilePermissionsAttack(Attack):
            name = "infrastructure.file_permissions"
            category = "infrastructure"
            severity = Severity.HIGH
            description = "Check for insecure file permissions..."
            target_types = {"app", "wordpress", "generic"}

    Compliance reference in docstring:
        '''Implements NIST SP 800-171 3.1.8 - Limit unsuccessful logon attempts'''
        → INSERT INTO attack_compliance VALUES
          ('api.account_lockout_bypass', 'NIST-800-171-Rev2', '3.1.8', ...)

Version: 1.0
Created: 2026-03-08
"""

import argparse
import ast
import logging
import re
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='-- %(levelname)s: %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


class AttackMetadata:
    """Stores extracted metadata for an attack module."""

    def __init__(self):
        self.attack_id: str = ""
        self.name: str = ""
        self.category: str = "unknown"
        self.description: str = ""
        self.severity: str = "medium"
        self.target_types: List[str] = ["app"]
        self.compliance_refs: List[Tuple[str, str, str]] = []  # (framework, control_id, description)
        self.file_path: str = ""

    def is_valid(self) -> bool:
        """Check if minimum required metadata is present."""
        return bool(self.attack_id and self.category)

    def __repr__(self) -> str:
        return f"AttackMetadata({self.attack_id}, category={self.category}, compliance={len(self.compliance_refs)})"


class AttackScanner:
    """Scans Python attack modules and extracts metadata."""

    # Compliance framework patterns
    COMPLIANCE_PATTERNS = [
        # NIST SP 800-171 patterns
        (r'NIST\s+SP\s+800-171\s+(?:Rev\s*2\s+)?(\d+\.\d+\.\d+)', 'NIST-800-171-Rev2'),
        (r'NIST\s+800-171\s+(?:Rev\s*2\s+)?(\d+\.\d+\.\d+)', 'NIST-800-171-Rev2'),
        (r'NIST\s+(\d+\.\d+\.\d+)', 'NIST-800-171-Rev2'),  # Assume 800-171 if just control ID

        # NIST Cybersecurity Framework
        (r'NIST\s+CSF\s+([A-Z]{2}\.[A-Z]{2}-\d+)', 'NIST-CSF'),
        (r'NIST\s+Cybersecurity\s+Framework\s+([A-Z]{2}\.[A-Z]{2}-\d+)', 'NIST-CSF'),

        # PCI-DSS - Match "Requirement X" or "Req X" (avoid version numbers like 4.0)
        (r'PCI\s+DSS\s+(?:v?\s*)?4\.0\s+Req(?:uirement)?\s+(\d+(?:\.\d+)?)', 'PCI-DSS'),
        (r'PCI-DSS\s+(?:v?\s*)?4\.0\s+Req(?:uirement)?\s+(\d+(?:\.\d+)?)', 'PCI-DSS'),
        (r'PCI\s+DSS\s+Req(?:uirement)?\s+(\d+(?:\.\d+)?)', 'PCI-DSS'),
        (r'PCI-DSS\s+Req(?:uirement)?\s+(\d+(?:\.\d+)?)', 'PCI-DSS'),
        # PCI control IDs (X.Y or X.Y.Z, but NOT version numbers like 4.0)
        (r'PCI-DSS\s+(\d{1,2}\.\d+\.\d+)', 'PCI-DSS'),  # Match X.Y.Z format only

        # CMMC
        (r'CMMC\s+(?:Level\s+)?(\d+)\s+([A-Z]{2}\.\d+\.\d+)', 'CMMC'),
        (r'CMMC\s+([A-Z]{2}\.\d+\.\d+)', 'CMMC'),
    ]

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.attacks_dir = base_path / "redteam" / "attacks"
        self.modules: List[AttackMetadata] = []

    def scan_all(self) -> List[AttackMetadata]:
        """Scan all attack modules and return metadata list."""
        if not self.attacks_dir.exists():
            logger.error(f"Attacks directory not found: {self.attacks_dir}")
            return []

        python_files = list(self.attacks_dir.glob("*/*.py"))
        python_files = [f for f in python_files if f.name != "__init__.py"]

        logger.info(f"Scanning {len(python_files)} attack modules...")

        for py_file in sorted(python_files):
            try:
                metadata = self._scan_module(py_file)
                if metadata and metadata.is_valid():
                    self.modules.append(metadata)
                    logger.debug(f"  ✓ {metadata.attack_id}")
                else:
                    logger.warning(f"  ✗ {py_file.name}: incomplete metadata")
            except Exception as e:
                logger.error(f"  ✗ {py_file.name}: {e}")

        logger.info(f"Successfully scanned {len(self.modules)} attack modules")
        return self.modules

    def _scan_module(self, py_file: Path) -> AttackMetadata:
        """Scan a single Python module for Attack class."""
        metadata = AttackMetadata()
        metadata.file_path = str(py_file.relative_to(self.base_path))

        # Read file content
        content = py_file.read_text(encoding='utf-8')

        # Parse AST
        try:
            tree = ast.parse(content, filename=str(py_file))
        except SyntaxError as e:
            logger.warning(f"Syntax error in {py_file.name}: {e}")
            return metadata

        # Find Attack subclass
        attack_class = self._find_attack_class(tree)
        if not attack_class:
            logger.debug(f"No Attack subclass found in {py_file.name}")
            return metadata

        # Extract class attributes
        self._extract_class_attributes(attack_class, metadata)

        # Parse docstrings for compliance references
        class_docstring = ast.get_docstring(attack_class)
        module_docstring = ast.get_docstring(tree)

        for doc in [class_docstring, module_docstring]:
            if doc:
                self._extract_compliance_refs(doc, metadata)

        return metadata

    def _find_attack_class(self, tree: ast.Module) -> ast.ClassDef | None:
        """Find the Attack subclass in the AST."""
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                # Check if it inherits from Attack
                for base in node.bases:
                    if isinstance(base, ast.Name) and base.id == 'Attack':
                        return node
        return None

    def _extract_class_attributes(self, class_node: ast.ClassDef, metadata: AttackMetadata):
        """Extract Attack class attributes from AST."""
        for item in class_node.body:
            if not isinstance(item, ast.Assign):
                continue

            # Get attribute name
            if not item.targets:
                continue
            target = item.targets[0]
            if not isinstance(target, ast.Name):
                continue
            attr_name = target.id

            # Extract value
            if attr_name == 'name':
                metadata.attack_id = self._extract_string_value(item.value)
                metadata.name = metadata.attack_id
            elif attr_name == 'category':
                metadata.category = self._extract_string_value(item.value)
            elif attr_name == 'description':
                metadata.description = self._extract_string_value(item.value)
            elif attr_name == 'severity':
                # Extract Severity enum value (e.g., Severity.HIGH → "high")
                metadata.severity = self._extract_severity_value(item.value)
            elif attr_name == 'target_types':
                metadata.target_types = self._extract_set_value(item.value)

        # Use class docstring as description if not set
        if not metadata.description:
            docstring = ast.get_docstring(class_node)
            if docstring:
                # Use first non-empty line
                for line in docstring.splitlines():
                    line = line.strip()
                    if line and not line.startswith('-'):
                        metadata.description = line[:255]
                        break

    def _extract_string_value(self, node: ast.expr) -> str:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant):
            return str(node.value)
        elif isinstance(node, ast.Str):  # Python 3.7 compatibility
            return node.s
        return ""

    def _extract_severity_value(self, node: ast.expr) -> str:
        """Extract severity enum value (Severity.HIGH → 'high')."""
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == 'Severity':
                return node.attr.lower()
        return "medium"

    def _extract_set_value(self, node: ast.expr) -> List[str]:
        """Extract set/list of strings from AST node."""
        values = []
        if isinstance(node, ast.Set):
            for elt in node.elts:
                val = self._extract_string_value(elt)
                if val:
                    values.append(val)
        elif isinstance(node, ast.List):
            for elt in node.elts:
                val = self._extract_string_value(elt)
                if val:
                    values.append(val)
        return values or ["app"]

    def _extract_compliance_refs(self, text: str, metadata: AttackMetadata):
        """Extract compliance framework references from text."""
        for pattern, framework in self.COMPLIANCE_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                control_id = match.group(1)

                # Extract description (sentence containing the reference)
                desc = self._extract_reference_context(text, match.start(), match.end())

                # Add if not duplicate
                ref = (framework, control_id, desc)
                if ref not in metadata.compliance_refs:
                    metadata.compliance_refs.append(ref)
                    logger.debug(f"    Found: {framework} {control_id}")

    def _extract_reference_context(self, text: str, start: int, end: int) -> str:
        """Extract sentence context around compliance reference."""
        # Find sentence boundaries
        before = text[:start].rfind('.')
        after = text[end:].find('.')

        if before == -1:
            before = 0
        else:
            before += 1

        if after == -1:
            after = len(text)
        else:
            after = end + after

        sentence = text[before:after].strip()

        # Clean up
        sentence = re.sub(r'\s+', ' ', sentence)
        sentence = sentence.replace('\n', ' ')

        return sentence[:500]  # Limit length


class SQLGenerator:
    """Generates SQL INSERT statements for attack catalog."""

    def __init__(self, modules: List[AttackMetadata]):
        self.modules = modules

    def generate_sql(self) -> str:
        """Generate complete SQL script."""
        lines = []

        # Header
        lines.append("-- Attack Catalog SQL")
        lines.append("-- Generated by scripts/build-attack-catalog.py")
        lines.append(f"-- Total modules: {len(self.modules)}")
        lines.append("-- This script is idempotent (safe to run multiple times)")
        lines.append("")
        lines.append("BEGIN;")
        lines.append("")

        # Attack catalog inserts
        lines.append("-- ===========================================================================")
        lines.append("-- ATTACK CATALOG")
        lines.append("-- ===========================================================================")
        lines.append("")

        for module in sorted(self.modules, key=lambda m: m.attack_id):
            lines.extend(self._generate_catalog_insert(module))
            lines.append("")

        # Attack compliance inserts
        lines.append("-- ===========================================================================")
        lines.append("-- ATTACK COMPLIANCE MAPPINGS")
        lines.append("-- ===========================================================================")
        lines.append("")

        compliance_count = 0
        for module in sorted(self.modules, key=lambda m: m.attack_id):
            if module.compliance_refs:
                lines.extend(self._generate_compliance_inserts(module))
                lines.append("")
                compliance_count += len(module.compliance_refs)

        if compliance_count == 0:
            lines.append("-- No compliance mappings found in attack modules")
            lines.append("")

        # Footer
        lines.append("COMMIT;")
        lines.append("")
        lines.append(f"-- Successfully generated SQL for {len(self.modules)} attack modules")
        lines.append(f"-- Compliance mappings: {compliance_count}")

        return "\n".join(lines)

    def _generate_catalog_insert(self, module: AttackMetadata) -> List[str]:
        """Generate INSERT for attack_catalog table."""
        lines = []

        # Escape SQL strings
        attack_id = self._sql_escape(module.attack_id)
        name = self._sql_escape(module.name or module.attack_id)
        category = self._sql_escape(module.category)
        description = self._sql_escape(module.description)
        severity = self._sql_escape(module.severity)

        # Format target_types array
        target_types_array = self._format_array(module.target_types)

        lines.append(f"INSERT INTO blueteam.attack_catalog (")
        lines.append(f"    attack_id, name, category, description, default_severity, target_types")
        lines.append(f") VALUES (")
        lines.append(f"    '{attack_id}',")
        lines.append(f"    '{name}',")
        lines.append(f"    '{category}',")
        lines.append(f"    '{description}',")
        lines.append(f"    '{severity}',")
        lines.append(f"    {target_types_array}")
        lines.append(f")")
        lines.append(f"ON CONFLICT (attack_id) DO UPDATE SET")
        lines.append(f"    name = EXCLUDED.name,")
        lines.append(f"    category = EXCLUDED.category,")
        lines.append(f"    description = EXCLUDED.description,")
        lines.append(f"    default_severity = EXCLUDED.default_severity,")
        lines.append(f"    target_types = EXCLUDED.target_types,")
        lines.append(f"    updated_at = CURRENT_TIMESTAMP;")

        return lines

    def _generate_compliance_inserts(self, module: AttackMetadata) -> List[str]:
        """Generate INSERTs for attack_compliance table."""
        lines = []

        attack_id = self._sql_escape(module.attack_id)

        for framework, control_id, description in module.compliance_refs:
            framework_esc = self._sql_escape(framework)
            control_id_esc = self._sql_escape(control_id)
            desc_esc = self._sql_escape(description)

            lines.append(f"INSERT INTO blueteam.attack_compliance (")
            lines.append(f"    attack_id, framework, control_id, description")
            lines.append(f") VALUES (")
            lines.append(f"    '{attack_id}',")
            lines.append(f"    '{framework_esc}',")
            lines.append(f"    '{control_id_esc}',")
            lines.append(f"    '{desc_esc}'")
            lines.append(f")")
            lines.append(f"ON CONFLICT (attack_id, framework, control_id) DO UPDATE SET")
            lines.append(f"    description = EXCLUDED.description;")
            lines.append("")

        return lines

    def _sql_escape(self, value: str) -> str:
        """Escape single quotes for SQL."""
        if not value:
            return ""
        return value.replace("'", "''")

    def _format_array(self, values: List[str]) -> str:
        """Format Python list as PostgreSQL array."""
        if not values:
            return "ARRAY[]::VARCHAR[]"
        escaped = [f"'{self._sql_escape(v)}'" for v in values]
        return f"ARRAY[{', '.join(escaped)}]::VARCHAR[]"


class CatalogValidator:
    """Validates attack catalog against actual modules."""

    def __init__(self, modules: List[AttackMetadata]):
        self.modules = modules

    def validate(self) -> bool:
        """Run all validation checks."""
        logger.info("Running validation checks...")

        all_valid = True
        all_valid &= self._check_required_fields()
        all_valid &= self._check_unique_ids()
        all_valid &= self._check_categories()
        all_valid &= self._check_severities()
        all_valid &= self._check_target_types()

        if all_valid:
            logger.info("✓ All validation checks passed")
        else:
            logger.error("✗ Validation failed")

        return all_valid

    def _check_required_fields(self) -> bool:
        """Check all modules have required fields."""
        missing = []
        for module in self.modules:
            if not module.attack_id:
                missing.append(f"{module.file_path}: missing attack_id")
            if not module.category:
                missing.append(f"{module.attack_id}: missing category")
            if not module.description:
                missing.append(f"{module.attack_id}: missing description")

        if missing:
            logger.error("Missing required fields:")
            for msg in missing[:10]:
                logger.error(f"  - {msg}")
            if len(missing) > 10:
                logger.error(f"  ... and {len(missing) - 10} more")
            return False

        logger.info(f"  ✓ Required fields: {len(self.modules)} modules OK")
        return True

    def _check_unique_ids(self) -> bool:
        """Check attack_id uniqueness."""
        seen = {}
        duplicates = []

        for module in self.modules:
            if module.attack_id in seen:
                duplicates.append(
                    f"{module.attack_id}: {seen[module.attack_id]} vs {module.file_path}"
                )
            else:
                seen[module.attack_id] = module.file_path

        if duplicates:
            logger.error("Duplicate attack_id values:")
            for dup in duplicates:
                logger.error(f"  - {dup}")
            return False

        logger.info(f"  ✓ Unique IDs: {len(self.modules)} unique attack_id values")
        return True

    def _check_categories(self) -> bool:
        """Check category values."""
        valid_categories = {
            'api', 'compliance', 'web', 'ai', 'aws', 'cloud',
            'infrastructure', 'secrets', 'static', 'malware'
        }

        invalid = []
        for module in self.modules:
            if module.category not in valid_categories:
                invalid.append(f"{module.attack_id}: unknown category '{module.category}'")

        if invalid:
            logger.warning("Unknown categories (may be intentional):")
            for msg in invalid[:5]:
                logger.warning(f"  - {msg}")
            if len(invalid) > 5:
                logger.warning(f"  ... and {len(invalid) - 5} more")

        category_counts = {}
        for module in self.modules:
            category_counts[module.category] = category_counts.get(module.category, 0) + 1

        logger.info(f"  ✓ Categories: {', '.join(f'{k}={v}' for k, v in sorted(category_counts.items()))}")
        return True

    def _check_severities(self) -> bool:
        """Check severity values."""
        valid_severities = {'critical', 'high', 'medium', 'low', 'info'}

        invalid = []
        for module in self.modules:
            if module.severity not in valid_severities:
                invalid.append(f"{module.attack_id}: invalid severity '{module.severity}'")

        if invalid:
            logger.error("Invalid severity values:")
            for msg in invalid:
                logger.error(f"  - {msg}")
            return False

        severity_counts = {}
        for module in self.modules:
            severity_counts[module.severity] = severity_counts.get(module.severity, 0) + 1

        logger.info(f"  ✓ Severities: {', '.join(f'{k}={v}' for k, v in sorted(severity_counts.items()))}")
        return True

    def _check_target_types(self) -> bool:
        """Check target_types values."""
        valid_types = {'app', 'wordpress', 'static', 'cloud', 'generic'}

        all_target_types = set()
        for module in self.modules:
            all_target_types.update(module.target_types)

        invalid = all_target_types - valid_types
        if invalid:
            logger.warning(f"Unknown target_types (may be intentional): {invalid}")

        logger.info(f"  ✓ Target types found: {', '.join(sorted(all_target_types))}")
        return True


def main():
    parser = argparse.ArgumentParser(
        description='Build attack catalog SQL from Python attack modules',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Validate catalog without generating SQL'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose logging (show all parsed modules)'
    )
    parser.add_argument(
        '--base-path',
        type=Path,
        default=Path(__file__).parent.parent,
        help='Base path of cyber-guardian project (default: script parent dir)'
    )

    args = parser.parse_args()

    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    # Scan attack modules
    scanner = AttackScanner(args.base_path)
    modules = scanner.scan_all()

    if not modules:
        logger.error("No attack modules found")
        return 1

    # Validate
    validator = CatalogValidator(modules)
    if args.validate:
        return 0 if validator.validate() else 1
    else:
        # Always validate before generating SQL
        if not validator.validate():
            logger.error("Validation failed - not generating SQL")
            return 1

    # Generate SQL
    generator = SQLGenerator(modules)
    sql = generator.generate_sql()

    # Output to stdout
    print(sql)

    return 0


if __name__ == '__main__':
    sys.exit(main())
