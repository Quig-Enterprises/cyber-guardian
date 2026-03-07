"""Nginx configuration parser for CVE verification."""

import re
from typing import Any


class NginxConfigParser:
    """Simple nginx config parser focused on security-relevant patterns."""

    def __init__(self, config_text: str):
        """Initialize parser with nginx config text.

        Args:
            config_text: Raw nginx configuration content
        """
        self.config_text = config_text
        self.lines = config_text.split('\n')

    def parse(self) -> dict[str, Any]:
        """Parse nginx config into structured data.

        Returns:
            Dictionary with parsed config sections
        """
        return {
            "php_locations": self.find_php_locations(),
            "has_fastcgi": self.has_fastcgi_config(),
        }

    def find_php_locations(self) -> list[dict[str, Any]]:
        """Find all location blocks that handle PHP files.

        Returns:
            List of location block dictionaries with directives
        """
        locations = []
        in_location = False
        current_location = None
        brace_depth = 0

        for line_num, line in enumerate(self.lines, 1):
            stripped = line.strip()

            # Detect PHP location block start
            if re.match(r'location\s+~\s+.*\.php', stripped):
                in_location = True
                current_location = {
                    "line": line_num,
                    "pattern": stripped,
                    "directives": [],
                }

            if in_location:
                # Track brace depth
                brace_depth += stripped.count('{')
                brace_depth -= stripped.count('}')

                # Extract directives within this location
                if 'fastcgi_' in stripped or 'include' in stripped:
                    current_location["directives"].append({
                        "line": line_num,
                        "text": stripped,
                    })

                # End of location block
                if brace_depth == 0 and '}' in stripped and current_location:
                    locations.append(current_location)
                    in_location = False
                    current_location = None
                    brace_depth = 0

        return locations

    def has_fastcgi_config(self) -> bool:
        """Check if config contains any fastcgi directives.

        Returns:
            True if fastcgi directives are present
        """
        return any('fastcgi_' in line for line in self.lines)

    def has_directive(self, location_block: dict, directive_name: str) -> bool:
        """Check if directive exists in location block.

        Args:
            location_block: Location block dictionary from find_php_locations()
            directive_name: Directive to search for (e.g., "fastcgi_split_path_info")

        Returns:
            True if directive exists in the block
        """
        for directive in location_block.get("directives", []):
            if directive_name in directive["text"]:
                return True
        return False

    def get_directive_value(self, location_block: dict, directive_name: str) -> str | None:
        """Extract value of a directive from location block.

        Args:
            location_block: Location block dictionary
            directive_name: Directive name to extract

        Returns:
            Directive value or None if not found
        """
        for directive in location_block.get("directives", []):
            text = directive["text"]
            if directive_name in text:
                # Extract value after directive name
                match = re.search(rf'{directive_name}\s+(.+?);', text)
                if match:
                    return match.group(1).strip()
        return None

    def has_vulnerable_fastcgi_split_path_info(self) -> bool:
        r"""Check for CVE-2019-11043 vulnerable pattern.

        The vulnerable pattern is:
            location ~ \.php$ {
                fastcgi_split_path_info ^(.+\.php)(/.+)$;
                ...
            }

        Returns:
            True if vulnerable pattern is present
        """
        php_locations = self.find_php_locations()

        for location in php_locations:
            split_path_value = self.get_directive_value(location, "fastcgi_split_path_info")
            if split_path_value:
                # Vulnerable patterns typically use (.+\.php)(/.+)
                # This allows path manipulation
                if re.search(r'\^\(.+\\.php\)\(/\.?\+\)', split_path_value):
                    return True
        return False
