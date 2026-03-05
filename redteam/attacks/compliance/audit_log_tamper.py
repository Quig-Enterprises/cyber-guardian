"""Audit log tamper resistance — NIST SP 800-171 Control 3.3.8.

Verifies that the application user cannot delete, update, or truncate
audit log records in the database. After BT-02 fix, the eqmon database
user should have restricted permissions on audit tables.
"""

import os

from redteam.base import Attack, AttackResult, Severity, Status


class AuditLogTamperAttack(Attack):
    name = "compliance.audit_log_tamper"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 3.3.8 — Verify audit logs are protected from unauthorized "
        "modification or deletion by application-level database users"
    )

    DB_CONFIG = {
        "host": "localhost",
        "dbname": "eqmon",
        "user": "eqmon",
    }

    TAMPER_OPERATIONS = [
        (
            "delete_audit_events",
            "DELETE FROM audit_events WHERE id = -999;",
            "DELETE",
            "Attempted to delete audit records",
        ),
        (
            "update_audit_events",
            "UPDATE audit_events SET event_type = 'tampered' WHERE id = -999;",
            "UPDATE",
            "Attempted to modify audit records",
        ),
        (
            "truncate_audit_events",
            "TRUNCATE audit_events;",
            "TRUNCATE",
            "Attempted to truncate entire audit log",
        ),
    ]

    def _get_db_password(self) -> str:
        """Get DB password from environment or fallback."""
        return os.environ.get("EQMON_AUTH_DB_PASS", "3eK4NNHxLQakuTQK5KcnB3Vz")

    async def execute(self, client) -> list[AttackResult]:
        results = []

        try:
            import psycopg2
        except ImportError:
            for variant, _, _, _ in self.TAMPER_OPERATIONS:
                results.append(self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    evidence="psycopg2 not installed — cannot test audit log protection.",
                    details="Install psycopg2-binary to enable audit tamper tests.",
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

            for variant_name, sql, operation, description in self.TAMPER_OPERATIONS:
                cur = conn.cursor()
                try:
                    # Each operation runs in its own transaction so failures
                    # don't poison subsequent tests.
                    cur.execute(sql)
                    conn.commit()

                    # If we get here, the operation succeeded — vulnerable
                    rows_affected = cur.rowcount
                    results.append(self._make_result(
                        variant=variant_name,
                        status=Status.VULNERABLE,
                        severity=Severity.HIGH if operation == "TRUNCATE" else Severity.MEDIUM,
                        evidence=(
                            f"{operation} executed successfully as '{self.DB_CONFIG['user']}' user. "
                            f"Rows affected: {rows_affected}."
                        ),
                        details=(
                            f"{description}. The eqmon database user has {operation} "
                            "permission on audit_events. NIST 3.3.8 requires that "
                            "audit logs be protected from unauthorized modification."
                        ),
                        request={"sql": sql, "user": self.DB_CONFIG["user"]},
                        response={"rows_affected": rows_affected},
                    ))

                except psycopg2.errors.InsufficientPrivilege as e:
                    conn.rollback()
                    results.append(self._make_result(
                        variant=variant_name,
                        status=Status.DEFENDED,
                        evidence=f"{operation} denied: {str(e).strip()}",
                        details=(
                            f"{description}. Permission correctly denied — "
                            f"the eqmon user cannot {operation} audit records."
                        ),
                        request={"sql": sql, "user": self.DB_CONFIG["user"]},
                        response={"error": str(e).strip()},
                    ))

                except psycopg2.errors.UndefinedTable:
                    conn.rollback()
                    results.append(self._make_result(
                        variant=variant_name,
                        status=Status.VULNERABLE,
                        severity=Severity.MEDIUM,
                        evidence="audit_events table does not exist.",
                        details=(
                            "The audit_events table was not found. "
                            "NIST 3.3.8 requires an audit logging system. "
                            "Without the table, there are no audit logs to protect."
                        ),
                        request={"sql": sql},
                        response={"error": "UndefinedTable"},
                    ))

                except psycopg2.Error as e:
                    conn.rollback()
                    # Other DB errors — could be permission-related
                    error_msg = str(e).strip()
                    if "permission denied" in error_msg.lower():
                        tamper_status = Status.DEFENDED
                    else:
                        tamper_status = Status.PARTIAL

                    results.append(self._make_result(
                        variant=variant_name,
                        status=tamper_status,
                        evidence=f"{operation} error: {error_msg}",
                        details=f"{description}. Database returned: {error_msg}",
                        request={"sql": sql, "user": self.DB_CONFIG["user"]},
                        response={"error": error_msg},
                    ))
                finally:
                    cur.close()

        except psycopg2.Error as e:
            for variant, _, _, _ in self.TAMPER_OPERATIONS:
                results.append(self._make_result(
                    variant=variant,
                    status=Status.ERROR,
                    evidence=f"Database connection failed: {e}",
                    details="Could not connect to database to test audit log protection.",
                ))
        finally:
            if conn:
                conn.close()

        return results
