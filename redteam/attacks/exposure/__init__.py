"""Data exposure and sensitive path detection attack modules."""

from redteam.attacks.exposure.backup_files import BackupFileAttack
from redteam.attacks.exposure.sensitive_paths import SensitivePathAttack

__all__ = [
    "BackupFileAttack",
    "SensitivePathAttack",
]
