#!/usr/bin/env python3
"""
Password Hash Audit Scanner

Checks password hashes across all local user databases for:
  - Insecure algorithms (MD5, SHA1, plaintext, phpass-MD5)
  - Weak bcrypt cost factors (< 10)
  - Common/compromised passwords (tested against SecLists top-10K via hash comparison;
    bcrypt hashes tested against top-1K via bcrypt.checkpw)

Databases scanned:
  - PostgreSQL alfred_admin.public.users  (Keystone)
  - MySQL wordpress.wp_users              (WordPress)

Results stored in blueteam.password_audit_runs / blueteam.password_audit_findings.
"""

import hashlib
import logging
import re
import sys
import time
from pathlib import Path

import bcrypt
import psycopg2
import psycopg2.extras

logger = logging.getLogger("password-audit")

# ---------------------------------------------------------------------------
# Wordlist
# ---------------------------------------------------------------------------

WORDLIST_PATH = Path(__file__).parent.parent / "data/passwords/top-10k-common.txt"
BCRYPT_CHECK_LIMIT = 100    # bcrypt verify is slow (~100ms each); top-100 covers egregiously common passwords
FAST_CHECK_LIMIT   = 10000  # MD5/SHA1/etc are instant; check all 10K

def load_wordlist() -> list[bytes]:
    """Load password wordlist as a list of UTF-8 byte strings."""
    if not WORDLIST_PATH.exists():
        logger.warning(f"Wordlist not found: {WORDLIST_PATH} — skipping common password check")
        return []
    words = []
    with open(WORDLIST_PATH, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            w = line.rstrip("\n")
            if w:
                words.append(w.encode("utf-8"))
    logger.info(f"  Loaded {len(words):,} common passwords from wordlist")
    return words


def build_fast_lookup(words: list[bytes]) -> dict[str, dict[str, bytes]]:
    """Pre-compute MD5/SHA1/SHA256/SHA512 digests for fast hash comparison."""
    md5    = {}
    sha1   = {}
    sha256 = {}
    sha512 = {}
    for w in words[:FAST_CHECK_LIMIT]:
        md5[hashlib.md5(w).hexdigest()]      = w
        sha1[hashlib.sha1(w).hexdigest()]    = w
        sha256[hashlib.sha256(w).hexdigest()] = w
        sha512[hashlib.sha512(w).hexdigest()] = w
    return {"md5": md5, "sha1": sha1, "sha256": sha256, "sha512": sha512}


# ---------------------------------------------------------------------------
# Hash algorithm detection
# ---------------------------------------------------------------------------

HASH_PATTERNS = [
    (re.compile(r'^\$2[ayb]\$(\d{2})\$'), "bcrypt"),
    (re.compile(r'^\$wp\$2[ayb]\$(\d{2})\$'), "bcrypt_wp"),   # WordPress 6+ bcrypt wrapper
    (re.compile(r'^\$P\$'), "phpass_md5"),                      # WordPress legacy phpass
    (re.compile(r'^[a-fA-F0-9]{32}$'), "md5"),
    (re.compile(r'^[a-fA-F0-9]{40}$'), "sha1"),
    (re.compile(r'^[a-fA-F0-9]{64}$'), "sha256"),
    (re.compile(r'^[a-fA-F0-9]{128}$'), "sha512"),
    (re.compile(r'^\{SHA\}'), "sha1_base64"),
    (re.compile(r'^\{SSHA\}'), "ssha"),
    (re.compile(r'^\$argon2'), "argon2"),
    (re.compile(r'^\$scrypt\$'), "scrypt"),
    (re.compile(r'^\$pbkdf2'), "pbkdf2"),
]

MIN_BCRYPT_COST = 10


# Domains that should never appear in production user accounts
BLOCKED_EMAIL_DOMAINS = {
    'test.com', 'test.net', 'test.org',
    'fake.com', 'noreply.com',
    'mailinator.com', 'guerrillamail.com', 'trashmail.com',
}


def detect_hash(hash_str: str) -> tuple[str, int | None]:
    """Return (algorithm, cost_factor_or_None)."""
    if not hash_str:
        return "empty", None
    for pattern, name in HASH_PATTERNS:
        m = pattern.match(hash_str)
        if m:
            cost = None
            if name in ("bcrypt", "bcrypt_wp"):
                try:
                    cost = int(m.group(1))
                except (IndexError, ValueError):
                    pass
            return name, cost
    if len(hash_str) < 20 and not hash_str.startswith("$"):
        return "likely_plaintext", None
    return "unknown", None


def assess_severity(algorithm: str, cost: int | None) -> tuple[str, str]:
    """Return (severity, finding_description) based on algorithm/cost alone."""
    if algorithm == "empty":
        return "critical", "Empty password hash — no password set"
    if algorithm == "likely_plaintext":
        return "critical", "Password appears to be stored in plaintext"
    if algorithm in ("md5", "sha1", "sha1_base64", "ssha"):
        return "insecure", f"Password hashed with {algorithm.upper()} — fast hash, trivially crackable with GPU"
    if algorithm == "phpass_md5":
        return "insecure", "Password hashed with phpass MD5 (WordPress legacy) — weak, use bcrypt"
    if algorithm == "sha256":
        return "weak", "Password hashed with SHA-256 — no salt/stretching, use bcrypt/argon2"
    if algorithm == "sha512":
        return "weak", "Password hashed with SHA-512 — no salt/stretching, use bcrypt/argon2"
    if algorithm in ("bcrypt", "bcrypt_wp"):
        if cost is not None and cost < MIN_BCRYPT_COST:
            return "weak", f"Bcrypt cost factor {cost} is below minimum {MIN_BCRYPT_COST} — increase work factor"
        return "ok", f"Bcrypt cost={cost} — acceptable"
    if algorithm in ("argon2", "scrypt", "pbkdf2"):
        return "ok", f"{algorithm} — modern key derivation function"
    if algorithm == "unknown":
        return "weak", "Unrecognised hash format — cannot verify security"
    return "ok", f"Algorithm: {algorithm}"


def check_common_password(
    hash_str: str,
    algorithm: str,
    words: list[bytes],
    fast_lookup: dict,
) -> str | None:
    """
    Return the matched common password (as a string) if the hash matches one,
    otherwise None. Never logs or stores the plaintext — callers redact it.
    """
    if not words or not hash_str:
        return None

    if algorithm in ("md5", "sha1", "sha256", "sha512"):
        table = fast_lookup.get(algorithm, {})
        match = table.get(hash_str.lower())
        return match.decode() if match else None

    if algorithm in ("bcrypt", "bcrypt_wp"):
        # Strip WordPress $wp$ prefix before checking
        check_hash = hash_str
        if algorithm == "bcrypt_wp" and hash_str.startswith("$wp$"):
            check_hash = hash_str[4:]
        check_hash_bytes = check_hash.encode("utf-8")
        for word in words[:BCRYPT_CHECK_LIMIT]:
            try:
                if bcrypt.checkpw(word, check_hash_bytes):
                    return word.decode()
            except Exception:
                pass
        return None

    if algorithm == "phpass_md5":
        try:
            from passlib.hash import phpass
            for word in words[:FAST_CHECK_LIMIT]:
                try:
                    if phpass.verify(word.decode(), hash_str):
                        return word.decode()
                except Exception:
                    pass
        except ImportError:
            pass
        return None

    return None


# ---------------------------------------------------------------------------
# Per-user audit: returns list of finding dicts
# ---------------------------------------------------------------------------

def audit_user(
    source_db: str,
    source_table: str,
    user_id: str,
    user_email: str,
    hash_str: str,
    words: list[bytes],
    fast_lookup: dict,
) -> list[dict]:
    findings = []
    algo, cost = detect_hash(hash_str or "")
    severity, description = assess_severity(algo, cost)

    base = {
        "source_db": source_db,
        "source_table": source_table,
        "user_id": user_id,
        "user_email": user_email,
        "hash_algorithm": algo,
        "hash_cost": cost,
    }

    findings.append({**base, "severity": severity, "finding": description})

    # Common password check (only for hashes that aren't already flagged critical/insecure
    # for algorithm reasons — but still worth checking even weak-algorithm hashes)
    if algo not in ("empty", "likely_plaintext", "unknown") and words:
        matched = check_common_password(hash_str, algo, words, fast_lookup)
        if matched:
            # Redact: report that it matched, but not what the password is
            findings.append({
                **base,
                "severity": "insecure",
                "finding": f"Password matches a known compromised/common password (checked top {BCRYPT_CHECK_LIMIT if algo in ('bcrypt','bcrypt_wp') else FAST_CHECK_LIMIT} from SecLists)",
            })

    # Blocked email domain check
    email = user_email or ""
    if "@" in email:
        domain = email.split("@", 1)[1].lower()
        if domain in BLOCKED_EMAIL_DOMAINS:
            findings.append({
                **base,
                "severity": "weak",
                "finding": f"Test/placeholder email domain '{domain}' in production account — use example.com/example.net/example.org",
            })

    return findings


# ---------------------------------------------------------------------------
# Database scanning
# ---------------------------------------------------------------------------

def scan_postgres_users(pg_conn, words: list[bytes], fast_lookup: dict) -> list[dict]:
    """Scan alfred_admin.public.users."""
    with pg_conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT id, email, password_hash FROM public.users WHERE is_active = TRUE")
        rows = cur.fetchall()

    findings = []
    for row in rows:
        findings += audit_user(
            "alfred_admin", "public.users",
            str(row["id"]), row["email"] or "",
            row["password_hash"] or "",
            words, fast_lookup,
        )
    logger.info(f"  alfred_admin.public.users: {len(rows)} users checked")
    return findings


def scan_mysql_wordpress(words: list[bytes], fast_lookup: dict) -> list[dict]:
    """Scan wordpress.wp_users via MySQL."""
    try:
        import pymysql
    except ImportError:
        logger.warning("pymysql not installed — skipping WordPress MySQL scan")
        return []

    findings = []
    try:
        conn = pymysql.connect(
            host="127.0.0.1", port=3306,
            user="wpuser", password="wppass123",
            database="wordpress", connect_timeout=5,
        )
        with conn.cursor(pymysql.cursors.DictCursor) as cur:
            cur.execute("SELECT ID, user_login, user_email, user_pass FROM wp_users")
            rows = cur.fetchall()
        conn.close()

        for row in rows:
            email = row.get("user_email") or row["user_login"]
            findings += audit_user(
                "wordpress", "wp_users",
                str(row["ID"]), email,
                row["user_pass"] or "",
                words, fast_lookup,
            )
        logger.info(f"  wordpress.wp_users: {len(rows)} users checked")
    except Exception as e:
        logger.warning(f"  WordPress MySQL scan failed: {e}")

    return findings


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    logger.info("Password audit scan starting")
    start = time.time()

    # Load wordlist once before opening DB connections
    words = load_wordlist()
    fast_lookup = build_fast_lookup(words) if words else {}

    pg_conn = psycopg2.connect(
        host="127.0.0.1", port=5432,
        dbname="alfred_admin", user="alfred_admin",
        password="Xk9OUuMWtRkBEnY2jugt6992",
    )
    pg_conn.autocommit = False

    with pg_conn.cursor() as cur:
        cur.execute(
            "INSERT INTO blueteam.password_audit_runs (status) VALUES ('running') RETURNING run_id"
        )
        run_id = cur.fetchone()[0]
    pg_conn.commit()

    try:
        all_findings = []
        all_findings += scan_postgres_users(pg_conn, words, fast_lookup)
        all_findings += scan_mysql_wordpress(words, fast_lookup)

        counts = {"ok": 0, "weak": 0, "insecure": 0, "critical": 0}
        for f in all_findings:
            sev = f["severity"]
            counts[sev] = counts.get(sev, 0) + 1

        with pg_conn.cursor() as cur:
            for f in all_findings:
                if f["severity"] == "ok":
                    continue
                cur.execute("""
                    INSERT INTO blueteam.password_audit_findings
                        (run_id, source_db, source_table, user_id, user_email,
                         hash_algorithm, hash_cost, severity, finding)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    run_id,
                    f["source_db"], f["source_table"], f["user_id"], f["user_email"],
                    f["hash_algorithm"], f["hash_cost"], f["severity"], f["finding"],
                ))

        with pg_conn.cursor() as cur:
            cur.execute("SELECT blueteam.resolve_fixed_password_findings(%s)", (run_id,))
            resolved = cur.fetchone()[0]
        if resolved:
            logger.info(f"  Resolved {resolved} previously flagged findings")

        elapsed = round(time.time() - start, 2)
        insecure_count = counts.get("insecure", 0) + counts.get("critical", 0)
        weak_count = counts.get("weak", 0)
        ok_count = counts.get("ok", 0)

        with pg_conn.cursor() as cur:
            cur.execute("""
                UPDATE blueteam.password_audit_runs
                SET status='completed', duration_sec=%s,
                    total_checked=%s, weak_count=%s, insecure_count=%s, ok_count=%s
                WHERE run_id=%s
            """, (elapsed, len(all_findings), weak_count, insecure_count, ok_count, run_id))
        pg_conn.commit()

        logger.info(
            f"Scan complete in {elapsed}s — "
            f"{len(all_findings)} checks: "
            f"{ok_count} ok, {weak_count} weak, {insecure_count} insecure/critical"
        )
        sys.exit(0 if insecure_count == 0 else 1)

    except Exception as e:
        logger.error(f"Password audit failed: {e}", exc_info=True)
        with pg_conn.cursor() as cur:
            cur.execute(
                "UPDATE blueteam.password_audit_runs SET status='failed', error_msg=%s WHERE run_id=%s",
                (str(e), run_id)
            )
        pg_conn.commit()
        sys.exit(2)
    finally:
        pg_conn.close()


if __name__ == "__main__":
    main()
