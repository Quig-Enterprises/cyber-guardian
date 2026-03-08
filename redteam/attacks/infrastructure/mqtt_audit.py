"""MQTT broker security audit — authentication, authorization, and transport checks.

Variants:
- anonymous_connect:       Connects without credentials. MQTT 3.1.1 servers should
                           reject unauthenticated connections unless intentionally open.
- default_credentials:     Tries well-known default username/password pairs. A hit
                           means the broker was never re-keyed after install.
- credential_brute:        Rapid-fire login attempts to detect missing rate-limiting
                           or account lockout on the broker.
- acl_wildcard_subscribe:  After authenticating, subscribes to '#' and '$SYS/#'.
                           A broker with no ACL will let any authenticated user read
                           all topics including device credentials in $SYS.
- plaintext_transport:     Checks that port 1883 (plaintext) is not reachable while
                           confirming port 8883 (TLS) is available. Plaintext MQTT
                           on a network interface exposes credentials and payloads.
- websocket_exposure:      Checks whether the MQTT WebSocket endpoint (8083/8083) is
                           accessible without auth. Many brokers expose WS for browser
                           clients but forget to lock it down.
"""

import asyncio
import logging
import socket
from urllib.parse import urlparse

from redteam.base import Attack, AttackResult, Severity, Status

logger = logging.getLogger(__name__)

# Well-known MQTT default / factory credentials
DEFAULT_CREDS = [
    ("", ""),                       # anonymous (empty user + pass)
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("mqtt", "mqtt"),
    ("mosquitto", "mosquitto"),
    ("test", "test"),
    ("guest", "guest"),
    ("user", "user"),
    ("root", "root"),
    ("pi", "raspberry"),
]

MQTT_CONNECT   = 0x10
MQTT_CONNACK   = 0x20
MQTT_SUBSCRIBE = 0x82
MQTT_SUBACK    = 0x90
MQTT_DISCONNECT = 0xE0

CONNACK_CODES = {
    0x00: "accepted",
    0x01: "refused: unacceptable protocol",
    0x02: "refused: identifier rejected",
    0x03: "refused: server unavailable",
    0x04: "refused: bad credentials",
    0x05: "refused: not authorized",
}


def _encode_utf8(s: str) -> bytes:
    enc = s.encode("utf-8")
    return len(enc).to_bytes(2, "big") + enc


def _build_connect_packet(client_id: str = "cg-probe", username: str = "", password: str = "") -> bytes:
    """Build a minimal MQTT 3.1.1 CONNECT packet."""
    # Variable header: protocol name + level + connect flags + keep-alive
    protocol_name = _encode_utf8("MQTT")
    protocol_level = bytes([0x04])  # MQTT 3.1.1

    connect_flags = 0x02  # Clean session
    if username:
        connect_flags |= 0x80
    if password:
        connect_flags |= 0x40

    keep_alive = (0).to_bytes(2, "big")  # 0 = disable

    payload = _encode_utf8(client_id)
    if username:
        payload += _encode_utf8(username)
    if password:
        payload += _encode_utf8(password)

    variable_header = protocol_name + protocol_level + bytes([connect_flags]) + keep_alive
    remaining = variable_header + payload
    remaining_length = _encode_remaining_length(len(remaining))

    return bytes([MQTT_CONNECT]) + remaining_length + remaining


def _encode_remaining_length(length: int) -> bytes:
    encoded = []
    while True:
        byte = length % 128
        length //= 128
        if length > 0:
            byte |= 0x80
        encoded.append(byte)
        if length == 0:
            break
    return bytes(encoded)


def _build_subscribe_packet(topic: str, packet_id: int = 1) -> bytes:
    """Build a minimal MQTT 3.1.1 SUBSCRIBE packet."""
    pid = packet_id.to_bytes(2, "big")
    topic_filter = _encode_utf8(topic) + bytes([0x00])  # QoS 0
    payload = pid + topic_filter
    remaining_length = _encode_remaining_length(len(payload))
    return bytes([MQTT_SUBSCRIBE]) + remaining_length + payload


def _build_disconnect_packet() -> bytes:
    return bytes([MQTT_DISCONNECT, 0x00])


async def _mqtt_try_connect(
    host: str, port: int, username: str, password: str,
    timeout: float = 4.0, client_id: str = "cg-probe"
) -> tuple[bool, int, str]:
    """
    Attempt an MQTT CONNECT to host:port with the given credentials.

    Returns (connected: bool, return_code: int, message: str).
    return_code == 0 means broker accepted the connection.
    """
    packet = _build_connect_packet(client_id=client_id, username=username, password=password)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.write(packet)
        await writer.drain()

        # Read at least 4 bytes for the CONNACK
        data = await asyncio.wait_for(reader.read(4), timeout=timeout)
        writer.write(_build_disconnect_packet())
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if len(data) >= 4 and data[0] == MQTT_CONNACK:
            return_code = data[3]
            return (return_code == 0, return_code, CONNACK_CODES.get(return_code, f"unknown code {return_code}"))

        return (False, -1, f"unexpected response: {data.hex()}")

    except asyncio.TimeoutError:
        return (False, -2, "connection timed out")
    except ConnectionRefusedError:
        return (False, -3, "connection refused")
    except OSError as exc:
        return (False, -4, str(exc))


async def _mqtt_try_subscribe(
    host: str, port: int, username: str, password: str,
    topic: str, timeout: float = 5.0
) -> tuple[bool, str]:
    """
    Connect, subscribe to *topic*, and return (subscribed: bool, message: str).
    A SUBACK with return code != 0x80 means the subscription was granted.
    """
    packet = _build_connect_packet(username=username, password=password, client_id="cg-acl")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.write(packet)
        await writer.drain()

        connack = await asyncio.wait_for(reader.read(4), timeout=timeout)
        if len(connack) < 4 or connack[0] != MQTT_CONNACK or connack[3] != 0x00:
            writer.close()
            return (False, "could not authenticate for subscription test")

        sub_packet = _build_subscribe_packet(topic)
        writer.write(sub_packet)
        await writer.drain()

        suback = await asyncio.wait_for(reader.read(5), timeout=timeout)
        writer.write(_build_disconnect_packet())
        await writer.drain()
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if len(suback) >= 5 and suback[0] == MQTT_SUBACK:
            granted_qos = suback[4]
            if granted_qos == 0x80:
                return (False, f"subscription to '{topic}' denied (0x80 — not authorized)")
            return (True, f"subscription to '{topic}' granted at QoS {granted_qos}")

        return (False, f"unexpected SUBACK response: {suback.hex()}")

    except asyncio.TimeoutError:
        return (False, "timed out waiting for SUBACK")
    except ConnectionRefusedError:
        return (False, "connection refused")
    except OSError as exc:
        return (False, str(exc))


def _tcp_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except OSError:
        return False


class MQTTAuditAttack(Attack):
    """Probe MQTT broker for authentication, ACL, and transport security weaknesses."""

    name = "infrastructure.mqtt_audit"
    category = "infrastructure"
    severity = Severity.HIGH
    description = (
        "Audit MQTT broker security: anonymous access, default credentials, "
        "ACL wildcard subscription, plaintext port exposure, and WebSocket access"
    )
    target_types = {"app", "generic"}

    # Ports
    PLAINTEXT_PORT = 1883
    TLS_PORT       = 8883
    WS_PORT        = 8083   # common Mosquitto WS port
    WS_PORT_ALT    = 8084   # alternative

    def _get_broker_host(self, client) -> str:
        """Derive broker host from the scan target base URL."""
        try:
            if client is not None:
                parsed = urlparse(client.base_url)
                return parsed.hostname or "localhost"
        except Exception:
            pass
        return self._config.get("target", {}).get("origin_ip") or "localhost"

    async def execute(self, client) -> list[AttackResult]:
        results = []
        host = self._get_broker_host(client)

        # ----------------------------------------------------------------
        # 1. anonymous_connect
        # ----------------------------------------------------------------
        anon_connected, anon_code, anon_msg = await _mqtt_try_connect(
            host, self.PLAINTEXT_PORT, username="", password=""
        )

        if anon_connected:
            results.append(self._make_result(
                variant="anonymous_connect",
                status=Status.VULNERABLE,
                severity=Severity.HIGH,
                evidence=f"MQTT CONNACK 0x00 (accepted) on {host}:{self.PLAINTEXT_PORT} with no credentials",
                details=(
                    "The MQTT broker accepts anonymous connections. Any device or "
                    "attacker on the network can connect, subscribe to all topics, "
                    "and publish arbitrary messages without authentication. "
                    "Configure 'allow_anonymous false' (Mosquitto) or equivalent."
                ),
                request={"host": host, "port": self.PLAINTEXT_PORT, "username": "", "password": ""},
                response={"return_code": anon_code, "message": anon_msg},
            ))
        elif anon_code in (-2, -3, -4):
            results.append(self._make_result(
                variant="anonymous_connect",
                status=Status.ERROR,
                evidence=f"Could not reach {host}:{self.PLAINTEXT_PORT} — {anon_msg}",
                details="Broker port unreachable. Verify host/port and network path.",
                request={"host": host, "port": self.PLAINTEXT_PORT},
                response={"error": anon_msg},
            ))
        else:
            results.append(self._make_result(
                variant="anonymous_connect",
                status=Status.DEFENDED,
                evidence=f"Anonymous connection refused: CONNACK {hex(anon_code)} — {anon_msg}",
                details="Broker rejects unauthenticated connections. Anonymous access is disabled.",
                request={"host": host, "port": self.PLAINTEXT_PORT, "username": "", "password": ""},
                response={"return_code": anon_code, "message": anon_msg},
            ))

        # If broker is unreachable skip remaining network variants
        if anon_code in (-2, -3, -4):
            for variant in ("default_credentials", "credential_brute",
                            "acl_wildcard_subscribe", "plaintext_transport", "websocket_exposure"):
                results.append(self._make_result(
                    variant=variant,
                    status=Status.SKIPPED,
                    evidence=f"Broker {host}:{self.PLAINTEXT_PORT} unreachable — skipped",
                    details="Broker port could not be reached. Remaining MQTT checks skipped.",
                ))
            return results

        # ----------------------------------------------------------------
        # 2. default_credentials
        # ----------------------------------------------------------------
        default_hits = []
        for user, passwd in DEFAULT_CREDS:
            if not user and not passwd:
                continue  # anonymous already checked
            ok, code, msg = await _mqtt_try_connect(
                host, self.PLAINTEXT_PORT, username=user, password=passwd,
                client_id=f"cg-default-{user or 'empty'}"
            )
            if ok:
                default_hits.append(f"username='{user}' password='{passwd}'")

        if default_hits:
            results.append(self._make_result(
                variant="default_credentials",
                status=Status.VULNERABLE,
                severity=Severity.CRITICAL,
                evidence="Broker accepts one or more default credential pairs:\n" + "\n".join(default_hits),
                details=(
                    "Default or well-known credentials were accepted by the broker. "
                    "An attacker can use these to authenticate without targeting "
                    "specific users. Change all broker credentials immediately and "
                    "disable any accounts that are no longer needed."
                ),
                request={"host": host, "port": self.PLAINTEXT_PORT, "pairs_tested": len(DEFAULT_CREDS) - 1},
                response={"accepted": default_hits},
            ))
        else:
            results.append(self._make_result(
                variant="default_credentials",
                status=Status.DEFENDED,
                evidence=f"None of {len(DEFAULT_CREDS) - 1} default credential pairs were accepted",
                details="Broker rejected all tested default/factory credentials.",
                request={"host": host, "port": self.PLAINTEXT_PORT, "pairs_tested": len(DEFAULT_CREDS) - 1},
                response={"accepted": []},
            ))

        # ----------------------------------------------------------------
        # 3. credential_brute — rapid sequential attempts, detect no lockout
        # ----------------------------------------------------------------
        BRUTE_ATTEMPTS = 12
        BRUTE_USER = "admin"
        accepted_count = 0
        refused_count  = 0
        error_count    = 0

        for i in range(BRUTE_ATTEMPTS):
            ok, code, _ = await _mqtt_try_connect(
                host, self.PLAINTEXT_PORT,
                username=BRUTE_USER, password=f"wrongpass{i}",
                client_id=f"cg-brute-{i}"
            )
            if ok:
                accepted_count += 1
            elif code == 0x04:   # bad credentials — expected
                refused_count += 1
            elif code in (-2, -3, -4):
                error_count += 1

        if error_count > BRUTE_ATTEMPTS // 2:
            results.append(self._make_result(
                variant="credential_brute",
                status=Status.ERROR,
                evidence=f"{error_count}/{BRUTE_ATTEMPTS} attempts failed with network errors",
                details="Too many connection errors to assess brute-force protection.",
                request={"host": host, "port": self.PLAINTEXT_PORT, "attempts": BRUTE_ATTEMPTS},
                response={"refused": refused_count, "errors": error_count},
            ))
        elif refused_count == BRUTE_ATTEMPTS:
            results.append(self._make_result(
                variant="credential_brute",
                status=Status.DEFENDED,
                evidence=(
                    f"All {BRUTE_ATTEMPTS} rapid login attempts with bad passwords "
                    f"returned CONNACK 0x04 (bad credentials) — no lockout triggered but broker correctly rejects"
                ),
                details=(
                    "Broker consistently rejects bad credentials. Note: MQTT brokers "
                    "typically do not lock accounts — ensure network-level rate limiting "
                    "(firewall rules, fail2ban) is in place to mitigate brute-force."
                ),
                request={"host": host, "port": self.PLAINTEXT_PORT, "attempts": BRUTE_ATTEMPTS, "user": BRUTE_USER},
                response={"refused": refused_count},
            ))
        else:
            # Broker accepted some wrong passwords or behaved inconsistently
            results.append(self._make_result(
                variant="credential_brute",
                status=Status.PARTIAL,
                severity=Severity.MEDIUM,
                evidence=(
                    f"Unexpected results during {BRUTE_ATTEMPTS} rapid attempts: "
                    f"accepted={accepted_count}, refused={refused_count}, errors={error_count}"
                ),
                details=(
                    "Broker behavior was inconsistent during rapid credential testing. "
                    "Manual review recommended — broker may have weak password validation."
                ),
                request={"host": host, "port": self.PLAINTEXT_PORT, "attempts": BRUTE_ATTEMPTS},
                response={"accepted": accepted_count, "refused": refused_count, "errors": error_count},
            ))

        # ----------------------------------------------------------------
        # 4. acl_wildcard_subscribe — requires a valid credential
        #    Use anonymous if it worked, otherwise skip
        # ----------------------------------------------------------------
        acl_user = ""
        acl_pass = ""
        acl_source = "anonymous"

        if not anon_connected:
            # Try to find a working credential from default hits
            for pair_str in default_hits:
                # parse "username='u' password='p'"
                try:
                    parts = dict(p.split("=", 1) for p in pair_str.split(" "))
                    acl_user = parts.get("username", "").strip("'")
                    acl_pass = parts.get("password", "").strip("'")
                    acl_source = f"default credential ({acl_user})"
                    break
                except Exception:
                    continue

        if not anon_connected and not default_hits:
            results.append(self._make_result(
                variant="acl_wildcard_subscribe",
                status=Status.SKIPPED,
                evidence="No valid credential available — cannot test ACL enforcement",
                details=(
                    "ACL wildcard subscription test requires at least one valid credential. "
                    "Anonymous access is disabled and no default credentials matched. "
                    "Run again with a known-good broker credential via config."
                ),
            ))
        else:
            wildcard_granted, wildcard_msg = await _mqtt_try_subscribe(
                host, self.PLAINTEXT_PORT, acl_user, acl_pass, "#"
            )
            sys_granted, sys_msg = await _mqtt_try_subscribe(
                host, self.PLAINTEXT_PORT, acl_user, acl_pass, "$SYS/#"
            )

            acl_hits = []
            if wildcard_granted:
                acl_hits.append(f"'#' (all topics): {wildcard_msg}")
            if sys_granted:
                acl_hits.append(f"'$SYS/#' (broker internals): {sys_msg}")

            if acl_hits:
                results.append(self._make_result(
                    variant="acl_wildcard_subscribe",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence=(
                        f"Using {acl_source}, wildcard subscriptions were granted:\n"
                        + "\n".join(acl_hits)
                    ),
                    details=(
                        "The broker grants wildcard '#' or '$SYS/#' subscriptions to "
                        "authenticated clients without topic-level ACLs. An authenticated "
                        "attacker (or any valid device) can silently receive all messages "
                        "on every topic, including credentials, commands, and sensor data. "
                        "Configure topic ACLs to restrict clients to only the topics they need."
                    ),
                    request={"host": host, "port": self.PLAINTEXT_PORT, "credential_source": acl_source},
                    response={"wildcard_granted": wildcard_granted, "sys_granted": sys_granted},
                ))
            else:
                results.append(self._make_result(
                    variant="acl_wildcard_subscribe",
                    status=Status.DEFENDED,
                    evidence=(
                        f"Wildcard subscriptions denied using {acl_source}. "
                        f"'#': {wildcard_msg} | '$SYS/#': {sys_msg}"
                    ),
                    details="ACL enforcement prevents wildcard topic subscriptions.",
                    request={"host": host, "port": self.PLAINTEXT_PORT, "credential_source": acl_source},
                    response={"wildcard_granted": wildcard_granted, "sys_granted": sys_granted},
                ))

        # ----------------------------------------------------------------
        # 5. plaintext_transport
        # ----------------------------------------------------------------
        plaintext_open = _tcp_port_open(host, self.PLAINTEXT_PORT)
        tls_open       = _tcp_port_open(host, self.TLS_PORT)

        if plaintext_open and not tls_open:
            pt_status = Status.VULNERABLE
            pt_severity = Severity.HIGH
            pt_evidence = (
                f"Port {self.PLAINTEXT_PORT} (MQTT plaintext) is open; "
                f"port {self.TLS_PORT} (MQTT/TLS) is closed."
            )
            pt_detail = (
                "The broker only offers plaintext MQTT. Credentials and all message "
                "payloads are transmitted in the clear. Any attacker on the same "
                "network segment can capture session tokens, subscribe credentials, "
                "and message content. Enable TLS on port 8883 and migrate clients."
            )
        elif plaintext_open and tls_open:
            pt_status = Status.PARTIAL
            pt_severity = Severity.MEDIUM
            pt_evidence = (
                f"Both port {self.PLAINTEXT_PORT} (plaintext) and "
                f"port {self.TLS_PORT} (TLS) are open."
            )
            pt_detail = (
                "TLS is available but the plaintext port is still open. Clients that "
                "connect to 1883 transmit credentials in clear text. Disable port 1883 "
                "and require all clients to use 8883 with TLS."
            )
        elif tls_open:
            pt_status = Status.DEFENDED
            pt_severity = Severity.INFO
            pt_evidence = (
                f"Port {self.PLAINTEXT_PORT} is closed; "
                f"port {self.TLS_PORT} (TLS) is open."
            )
            pt_detail = "Plaintext MQTT is disabled; TLS-only transport enforced."
        else:
            pt_status = Status.ERROR
            pt_severity = Severity.INFO
            pt_evidence = f"Neither port {self.PLAINTEXT_PORT} nor {self.TLS_PORT} is reachable."
            pt_detail = "Could not assess transport security — no MQTT ports responding."

        results.append(self._make_result(
            variant="plaintext_transport",
            status=pt_status,
            severity=pt_severity,
            evidence=pt_evidence,
            details=pt_detail,
            request={"host": host, "ports_checked": [self.PLAINTEXT_PORT, self.TLS_PORT]},
            response={"plaintext_open": plaintext_open, "tls_open": tls_open},
        ))

        # ----------------------------------------------------------------
        # 6. websocket_exposure
        # ----------------------------------------------------------------
        ws_open     = _tcp_port_open(host, self.WS_PORT)
        ws_alt_open = _tcp_port_open(host, self.WS_PORT_ALT)
        open_ws_ports = [p for p, o in [(self.WS_PORT, ws_open), (self.WS_PORT_ALT, ws_alt_open)] if o]

        if open_ws_ports:
            # Try anonymous MQTT-over-WebSocket using the raw TCP port
            # (We don't speak HTTP upgrade here; just check port reachability + anon CONNACK)
            ws_anon_hits = []
            for ws_port in open_ws_ports:
                ws_ok, ws_code, ws_msg = await _mqtt_try_connect(
                    host, ws_port, username="", password="", client_id="cg-ws-anon"
                )
                if ws_ok:
                    ws_anon_hits.append(f"port {ws_port}: anonymous accepted")
                else:
                    ws_anon_hits.append(f"port {ws_port}: {ws_msg}")

            any_anon_ws = any("anonymous accepted" in h for h in ws_anon_hits)

            if any_anon_ws:
                results.append(self._make_result(
                    variant="websocket_exposure",
                    status=Status.VULNERABLE,
                    severity=Severity.HIGH,
                    evidence="MQTT WebSocket port(s) accept anonymous connections:\n" + "\n".join(ws_anon_hits),
                    details=(
                        "The MQTT WebSocket endpoint allows unauthenticated access. "
                        "Browser-based MQTT clients (or malicious JavaScript from any "
                        "webpage) can connect to this port without credentials and "
                        "read or publish any topic accessible to anonymous users. "
                        "Apply the same authentication and ACL policies to WS as TCP."
                    ),
                    request={"host": host, "ws_ports": open_ws_ports},
                    response={"results": ws_anon_hits},
                ))
            else:
                results.append(self._make_result(
                    variant="websocket_exposure",
                    status=Status.PARTIAL,
                    severity=Severity.MEDIUM,
                    evidence=(
                        f"MQTT WebSocket port(s) {open_ws_ports} are open but "
                        "did not accept anonymous MQTT connections."
                    ),
                    details=(
                        "WebSocket MQTT ports are accessible from the network. "
                        "Anonymous access appears disabled, but the port surface "
                        "is exposed. Verify firewall rules restrict access to "
                        "trusted origins and that authentication is enforced."
                    ),
                    request={"host": host, "ws_ports": open_ws_ports},
                    response={"results": ws_anon_hits},
                ))
        else:
            results.append(self._make_result(
                variant="websocket_exposure",
                status=Status.DEFENDED,
                evidence=(
                    f"MQTT WebSocket ports {self.WS_PORT} and {self.WS_PORT_ALT} "
                    "are not open."
                ),
                details="No MQTT WebSocket endpoints are reachable from this network context.",
                request={"host": host, "ports_checked": [self.WS_PORT, self.WS_PORT_ALT]},
                response={"open_ports": open_ws_ports},
            ))

        return results
