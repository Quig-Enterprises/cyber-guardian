"""Device attestation / comply-to-connect — NIST SP 800-172 Control 3.5.3e.

Verifies that the system rejects connections from unknown, unattested, or
improperly configured devices (comply-to-connect enforcement).
"""

import json
import time
import uuid

from redteam.base import Attack, AttackResult, Severity, Status


class DeviceAttestationAttack(Attack):
    name = "compliance.device_attestation"
    category = "compliance"
    severity = Severity.MEDIUM
    description = (
        "NIST 800-172 3.5.3e — Verify comply-to-connect rejects unknown/unattested devices"
    )

    async def execute(self, client) -> list[AttackResult]:
        results = []

        # Ensure we have an authenticated session for protected-endpoint probes.
        await client.login()

        # ----------------------------------------------------------------
        # 1. unknown_user_agent_access
        # ----------------------------------------------------------------
        # Send requests with non-standard User-Agent strings that indicate
        # non-org-issued devices.  If all return normal 200 responses the
        # system performs no device fingerprinting.
        unknown_uas = [
            "curl/7.0",
            "wget/1.0",
            "python-urllib/3.11",
            "PostmanRuntime/7.0",
            "",
        ]

        ua_successes = 0
        ua_evidence_parts = []

        for ua in unknown_uas:
            sc, body, hdrs = await client.get(
                "/api/equipment.php",
                headers={"User-Agent": ua},
                cookies=client._cookies,
            )
            if sc == 200:
                ua_successes += 1
            ua_evidence_parts.append(f"UA={repr(ua)} → {sc}")

        ua_evidence = "; ".join(ua_evidence_parts)

        if ua_successes == len(unknown_uas):
            ua_status = Status.VULNERABLE
            ua_detail = (
                f"All {len(unknown_uas)} non-standard / empty User-Agent strings received "
                "HTTP 200 from a protected endpoint. The system performs no device "
                "fingerprinting or User-Agent filtering. NIST 800-172 3.5.3e requires "
                "comply-to-connect controls that reject unrecognised device profiles."
            )
        elif ua_successes > 0:
            ua_status = Status.PARTIAL
            ua_detail = (
                f"{ua_successes}/{len(unknown_uas)} non-standard User-Agent strings were "
                "accepted. Partial User-Agent filtering detected; policy is inconsistently "
                "applied."
            )
        else:
            ua_status = Status.DEFENDED
            ua_detail = (
                "All non-standard User-Agent strings were rejected. "
                "Device fingerprinting / User-Agent enforcement appears active."
            )

        results.append(self._make_result(
            variant="unknown_user_agent_access",
            status=ua_status,
            evidence=ua_evidence,
            details=ua_detail,
            request={"endpoint": "/api/equipment.php", "user_agents_tested": unknown_uas},
            response={"successes": ua_successes, "total": len(unknown_uas)},
        ))

        # ----------------------------------------------------------------
        # 2. spoofed_device_headers
        # ----------------------------------------------------------------
        # Send device-identifying headers that suggest an unauthorized device.
        # If the server accepts the request without challenge, it is not
        # validating device-attestation headers.
        spoofed_headers = {
            "X-Device-Id": "unknown-device",
            "X-Client-Cert": "none",
            "X-Platform": "unauthorized",
        }

        sc, body, hdrs = await client.get(
            "/api/equipment.php",
            headers=spoofed_headers,
            cookies=client._cookies,
        )

        attested_required = any(
            k.lower() in str(hdrs).lower()
            for k in ("x-device-attestation", "www-authenticate", "x-client-cert-required")
        )

        if sc == 200 and not attested_required:
            spoof_status = Status.PARTIAL
            spoof_detail = (
                f"Request with explicit 'unauthorized' device headers was accepted "
                f"(status {sc}). The server does not validate device-attestation headers "
                "such as X-Device-Id or X-Platform. NIST 800-172 3.5.3e compliance "
                "requires device identity verification at the network boundary."
            )
        elif attested_required:
            spoof_status = Status.DEFENDED
            spoof_detail = (
                f"Server responded with a certificate / attestation challenge (status {sc}). "
                "Device header validation appears enforced."
            )
        else:
            spoof_status = Status.PARTIAL
            spoof_detail = (
                f"Server returned {sc} for spoofed device headers. "
                "Unable to confirm whether attestation headers are validated."
            )

        results.append(self._make_result(
            variant="spoofed_device_headers",
            status=spoof_status,
            evidence=f"Status: {sc}, Response headers: {json.dumps(dict(hdrs))[:400]}",
            details=spoof_detail,
            request={"endpoint": "/api/equipment.php", "headers": spoofed_headers},
            response={"status": sc, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 3. missing_client_certificate
        # ----------------------------------------------------------------
        # Access a protected endpoint without any client-certificate headers.
        # A comply-to-connect system implementing mTLS would return a 401/403
        # or include a certificate challenge in the response.
        sc, body, hdrs = await client.get(
            "/api/admin/",
            cookies=client._cookies,
        )

        cert_challenge = any(
            indicator in str(hdrs).lower() or indicator in body.lower()
            for indicator in ("client-cert", "ssl_client", "mutual-tls", "x-ssl-client")
        )
        tls_error = sc in (400, 401, 403, 495, 496)

        if cert_challenge or tls_error:
            cert_status = Status.DEFENDED
            cert_detail = (
                f"Server returned {sc} and/or issued a certificate-related challenge. "
                "Mutual TLS / client certificate enforcement appears active."
            )
        else:
            cert_status = Status.PARTIAL
            cert_detail = (
                f"Protected endpoint returned {sc} without requiring a client certificate "
                "or issuing a certificate challenge. No mutual TLS enforcement detected. "
                "NIST 800-172 3.5.3e recommends mTLS or equivalent device attestation "
                "for high-value CUI environments."
            )

        results.append(self._make_result(
            variant="missing_client_certificate",
            status=cert_status,
            evidence=(
                f"Status: {sc}, Cert challenge detected: {cert_challenge}, "
                f"Headers: {json.dumps(dict(hdrs))[:400]}"
            ),
            details=cert_detail,
            request={"endpoint": "/api/admin/", "client_cert": "none"},
            response={"status": sc, "body": body[:300]},
        ))

        # ----------------------------------------------------------------
        # 4. multiple_device_simulation
        # ----------------------------------------------------------------
        # Login once then make requests varying the User-Agent rapidly to
        # simulate different physical devices on the same session.  A
        # comply-to-connect system should detect device inconsistency and
        # revoke / challenge the session.
        device_uas = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
        ]

        multi_successes = 0
        multi_evidence_parts = []

        for ua in device_uas:
            sc, body, hdrs = await client.get(
                "/api/equipment.php",
                headers={"User-Agent": ua},
                cookies=client._cookies,
            )
            if sc == 200:
                multi_successes += 1
            multi_evidence_parts.append(
                f"UA={ua[:60]}… → {sc}"
            )

        multi_evidence = "; ".join(multi_evidence_parts)

        if multi_successes == len(device_uas):
            multi_status = Status.VULNERABLE
            multi_detail = (
                f"All {len(device_uas)} simulated 'different devices' (Windows Chrome, "
                "Mac Safari, Linux Firefox, iPhone) accessed the same authenticated session "
                "without any re-challenge or revocation. NIST 800-172 3.5.3e comply-to-connect "
                "should detect device-profile inconsistency within a session and require "
                "re-attestation."
            )
        elif multi_successes > 0:
            multi_status = Status.PARTIAL
            multi_detail = (
                f"{multi_successes}/{len(device_uas)} device simulations succeeded. "
                "Inconsistent device-consistency enforcement detected."
            )
        else:
            multi_status = Status.DEFENDED
            multi_detail = (
                "Device-switching within the same session was rejected. "
                "Session device-consistency enforcement appears active."
            )

        results.append(self._make_result(
            variant="multiple_device_simulation",
            status=multi_status,
            evidence=multi_evidence,
            details=multi_detail,
            request={
                "endpoint": "/api/equipment.php",
                "session_id": str(uuid.uuid4()),
                "device_user_agents": [ua[:80] for ua in device_uas],
            },
            response={"successes": multi_successes, "total": len(device_uas)},
        ))

        # ----------------------------------------------------------------
        # 5. outdated_client_simulation
        # ----------------------------------------------------------------
        # Send requests with User-Agent strings indicating very old / end-of-life
        # software.  NIST 800-172 trust profiles imply minimum client-version
        # enforcement; accepting EOL clients is a PARTIAL compliance gap.
        outdated_uas = [
            "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
            "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/30.0.0.0 Safari/537.36",
        ]

        outdated_successes = 0
        outdated_evidence_parts = []

        for ua in outdated_uas:
            sc, body, hdrs = await client.get(
                "/api/equipment.php",
                headers={"User-Agent": ua},
                cookies=client._cookies,
            )
            if sc == 200:
                outdated_successes += 1
            outdated_evidence_parts.append(f"UA={ua[:60]}… → {sc}")

        outdated_evidence = "; ".join(outdated_evidence_parts)
        _probe_time = time.time()  # record probe timestamp for audit trail

        if outdated_successes == len(outdated_uas):
            outdated_status = Status.PARTIAL
            outdated_detail = (
                f"Both end-of-life User-Agent strings (MSIE 6.0, Chrome/30) received "
                f"HTTP 200 responses. The system imposes no minimum client-version "
                "requirement. NIST 800-172 3.5.3e trust profiles should reject clients "
                "running EOL / unpatched software that cannot be considered 'compliant' "
                "devices."
            )
        elif outdated_successes > 0:
            outdated_status = Status.PARTIAL
            outdated_detail = (
                f"{outdated_successes}/{len(outdated_uas)} outdated User-Agent strings "
                "were accepted. Minimum version enforcement is inconsistent."
            )
        else:
            outdated_status = Status.DEFENDED
            outdated_detail = (
                "All outdated / EOL User-Agent strings were rejected. "
                "Minimum client-version enforcement appears active."
            )

        results.append(self._make_result(
            variant="outdated_client_simulation",
            status=outdated_status,
            evidence=outdated_evidence,
            details=outdated_detail,
            request={"endpoint": "/api/equipment.php", "outdated_user_agents": outdated_uas},
            response={"successes": outdated_successes, "total": len(outdated_uas)},
        ))

        return results
