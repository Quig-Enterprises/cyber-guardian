"""Encryption at rest verification — NIST SP 800-171 Control 3.13.16.

Checks whether CUI stored in the database is encrypted at the column
level, whether chat history is encrypted, and whether database backups
are encrypted.
"""

import os

from redteam.base import Attack, AttackResult, Severity, Status


class EncryptionAtRestAttack(Attack):
    name = "compliance.encryption_at_rest"
    category = "compliance"
    severity = Severity.HIGH
    description = (
        "NIST 3.13.16 — Verify confidentiality of CUI at rest via "
        "database column encryption, chat encryption, and backup encryption"
    )

    DB_CONFIG = {
        "host": "localhost",
        "dbname": "eqmon",
        "user": "eqmon",
    }

    def _get_db_password(self) -> str:
        """Get DB password from environment or fallback."""
        return os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        try:
            import psycopg2
        except ImportError:
            results.append(self._make_result(
                variant="db_column_encryption",
                status=Status.ERROR,
                evidence="psycopg2 not installed — cannot test database encryption.",
                details="Install psycopg2-binary to enable database encryption tests.",
            ))
            return results

        conn = None
        try:
            conn = psycopg2.connect(
                host=self.DB_CONFIG["host"],
                dbname=self.DB_CONFIG["dbname"],
                user=self.DB_CONFIG["user"],
                password=self._get_db_password(),
            )
            cur = conn.cursor()

            # ----------------------------------------------------------------
            # 1. Check if pgcrypto extension is installed and bearing data
            #    columns use encryption (e.g., pgp_sym_encrypt)
            # ----------------------------------------------------------------
            cur.execute(
                "SELECT EXISTS(SELECT 1 FROM pg_extension WHERE extname = 'pgcrypto');"
            )
            pgcrypto_installed = cur.fetchone()[0]

            # Check for encrypted columns by looking for bytea types or
            # known encryption patterns in column defaults/check constraints
            cur.execute("""
                SELECT table_name, column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name IN ('bearing_data', 'bearing_measurements',
                                     'devices', 'vessels', 'analysis_results')
                  AND data_type = 'bytea'
                ORDER BY table_name, column_name;
            """)
            encrypted_columns = cur.fetchall()

            if not pgcrypto_installed and not encrypted_columns:
                db_status = Status.VULNERABLE
                detail = (
                    "pgcrypto extension is NOT installed and no bytea (encrypted) "
                    "columns found in bearing data tables. CUI is stored in plaintext."
                )
            elif pgcrypto_installed and encrypted_columns:
                db_status = Status.DEFENDED
                detail = (
                    f"pgcrypto is installed. Found {len(encrypted_columns)} bytea column(s): "
                    f"{[f'{t}.{c}' for t, c, _ in encrypted_columns]}."
                )
            elif pgcrypto_installed:
                db_status = Status.PARTIAL
                detail = (
                    "pgcrypto extension is installed but no bytea columns found in "
                    "bearing data tables. Extension may not be actively used for encryption."
                )
            else:
                db_status = Status.PARTIAL
                detail = (
                    f"Found {len(encrypted_columns)} bytea column(s) but pgcrypto "
                    "is not installed. Columns may use application-level encryption."
                )

            results.append(self._make_result(
                variant="db_column_encryption",
                status=db_status,
                severity=Severity.HIGH,
                evidence=(
                    f"pgcrypto installed: {pgcrypto_installed}, "
                    f"Encrypted columns: {encrypted_columns}"
                ),
                details=detail,
            ))

            # ----------------------------------------------------------------
            # 2. Check if ai_chat_messages content is encrypted
            # ----------------------------------------------------------------
            cur.execute("""
                SELECT column_name, data_type
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name = 'ai_chat_messages'
                  AND column_name IN ('content', 'message', 'response')
                ORDER BY column_name;
            """)
            chat_columns = cur.fetchall()

            plaintext_columns = [
                (col, dtype) for col, dtype in chat_columns
                if dtype in ('text', 'character varying', 'json', 'jsonb')
            ]

            if plaintext_columns:
                # Verify by sampling — check if actual data is readable plaintext
                sample_query = f"SELECT {plaintext_columns[0][0]} FROM ai_chat_messages LIMIT 1;"
                try:
                    cur.execute(sample_query)
                    row = cur.fetchone()
                    if row and row[0] and len(str(row[0])) > 0:
                        # Data is readable plaintext
                        chat_status = Status.VULNERABLE
                        sample_preview = str(row[0])[:100]
                        detail = (
                            f"Chat message column '{plaintext_columns[0][0]}' stores "
                            f"plaintext ({plaintext_columns[0][1]}). "
                            f"Sample: '{sample_preview}...'. CUI in chat is not encrypted at rest."
                        )
                    else:
                        chat_status = Status.PARTIAL
                        detail = "Chat columns exist as plaintext types but no data to verify."
                except Exception:
                    chat_status = Status.VULNERABLE
                    detail = (
                        f"Chat columns use plaintext types: "
                        f"{[(c, d) for c, d in plaintext_columns]}. "
                        "Unable to sample data but column types indicate no encryption."
                    )
            elif chat_columns:
                chat_status = Status.DEFENDED
                detail = f"Chat columns use non-plaintext types: {chat_columns}."
            else:
                chat_status = Status.PARTIAL
                detail = "ai_chat_messages table or expected columns not found."

            results.append(self._make_result(
                variant="chat_history_encryption",
                status=chat_status,
                severity=Severity.HIGH,
                evidence=f"Chat columns: {chat_columns}, Plaintext: {plaintext_columns}",
                details=detail,
            ))

            # ----------------------------------------------------------------
            # 3. Check if database backups are encrypted
            # ----------------------------------------------------------------
            # Look for pg_dump cron jobs or backup scripts
            backup_evidence = []
            backup_encrypted = False

            # Check common backup locations
            for backup_dir in ["/var/backups", "/opt/backups", "/opt/eqmon/backups"]:
                try:
                    if os.path.isdir(backup_dir):
                        for f in os.listdir(backup_dir):
                            if "eqmon" in f.lower() or "pg_dump" in f.lower() or f.endswith(".sql"):
                                full_path = os.path.join(backup_dir, f)
                                backup_evidence.append(full_path)
                                # .gpg or .enc extension indicates encryption
                                if f.endswith((".gpg", ".enc", ".aes")):
                                    backup_encrypted = True
                except PermissionError:
                    backup_evidence.append(f"{backup_dir}: permission denied")

            # Check cron for encrypted backup commands
            try:
                import subprocess
                cron_result = subprocess.run(
                    ["crontab", "-l"], capture_output=True, text=True, timeout=5
                )
                cron_text = cron_result.stdout
                if "pg_dump" in cron_text:
                    backup_evidence.append(f"cron: {[l for l in cron_text.splitlines() if 'pg_dump' in l]}")
                    if "gpg" in cron_text or "openssl" in cron_text or "encrypt" in cron_text:
                        backup_encrypted = True
            except Exception:
                pass

            if backup_encrypted:
                backup_status = Status.DEFENDED
                detail = "Database backups appear to be encrypted."
            elif backup_evidence:
                backup_status = Status.VULNERABLE
                detail = (
                    f"Found backup artifacts but no encryption detected: {backup_evidence}. "
                    "NIST 3.13.16 requires encryption of CUI at rest including backups."
                )
            else:
                backup_status = Status.VULNERABLE
                detail = (
                    "No backup infrastructure detected. Backups either don't exist "
                    "(separate compliance issue) or are stored without encryption."
                )

            results.append(self._make_result(
                variant="backup_encryption",
                status=backup_status,
                severity=Severity.HIGH,
                evidence=f"Backup files: {backup_evidence}, Encrypted: {backup_encrypted}",
                details=detail,
            ))

        except psycopg2.Error as e:
            results.append(self._make_result(
                variant="db_column_encryption",
                status=Status.ERROR,
                evidence=f"Database connection failed: {e}",
                details="Could not connect to database to verify encryption at rest.",
            ))
        finally:
            if conn:
                conn.close()

        return results
