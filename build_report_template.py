"""Moteur de règles IVSA.

Charge le référentiel `config/rules.yaml` dans des modèles Pydantic v2
strictement typés, puis applique chaque règle de conformité et de sécurité
issue de la base de connaissances ILEXIA aux structures normalisées produites
par `core.parser`. Chaque méthode `check_*` retourne un `CheckResult` unique
(PASS/FAIL/WARNING/NOT_APPLICABLE) accompagné, en cas d'écart, d'un ou
plusieurs `Anomaly` documentés (preuve technique, risque cyber, remédiation).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

from ivsa.core.exceptions import ConfigError
from ivsa.core.models import (
    Anomaly,
    AnomalyCategory,
    CheckResult,
    ComplianceStatus,
    NetworkEndpoint,
    NetworkFlow,
    OptionsKeepAlive,
    Severity,
    SipDialog,
    SipMessage,
    RtpTeardownSample,
)

# -----------------------------------------------------------------------------
# Modèles de configuration (miroir strict de config/rules.yaml)
# -----------------------------------------------------------------------------


class RulesetMetadata(BaseModel):
    ruleset_name: str
    ruleset_version: str
    sources: list[str] = Field(default_factory=list)


class SipSignalingSpec(BaseModel):
    protocol: str
    port: int = Field(ge=1, le=65535)


class RtpMediaSpec(BaseModel):
    protocol: str
    port_range: tuple[int, int]
    remote_port_range: tuple[int, int]

    @field_validator("port_range", "remote_port_range")
    @classmethod
    def _validate_range(cls, value: tuple[int, int]) -> tuple[int, int]:
        low, high = value
        if not (0 <= low <= high <= 65535):
            raise ValueError(f"Plage de ports invalide : {value}")
        return value


class NatMatrixRule(BaseModel):
    enabled: bool
    reference: str
    sip_signaling: SipSignalingSpec
    rtp_media: RtpMediaSpec
    isolation_requirement: str
    severity_on_violation: Severity


class IdentityMaskingRule(BaseModel):
    enabled: bool
    reference: str
    trigger_prefixes: list[str]
    required_header_p_asserted_identity: bool
    privacy_header_accepted_values: list[str]
    anonymous_from_pattern: str
    severity_on_missing_pai: Severity
    severity_on_missing_privacy: Severity


class ForbiddenHeaderSpec(BaseModel):
    name: str
    severity: Severity
    check_rfc1918_leak: bool
    description: str


class ForbiddenHeadersRule(BaseModel):
    enabled: bool
    reference: str
    headers: list[ForbiddenHeaderSpec]


class AuthorizedSipMethodsRule(BaseModel):
    enabled: bool
    reference: str
    whitelist: list[str]
    severity_on_violation: Severity


class CodecPriorityRule(BaseModel):
    enabled: bool
    reference: str
    expected_order: list[str]
    codec_aliases: dict[str, list[str]]
    ignored_codecs: list[str]
    applicable_methods: list[str]
    severity_on_violation: Severity

    def canonicalize(self, raw_encoding_name: str) -> str | None:
        """Ramène un nom de codec brut SDP (`PCMA`, `ITU-T G.711 PCMA`, ...)
        vers son identifiant canonique déclaré dans `expected_order`."""

        needle = raw_encoding_name.strip().upper()
        for canonical, aliases in self.codec_aliases.items():
            for alias in aliases:
                if alias.strip().upper() == needle:
                    return canonical
        return None

    def is_ignored(self, raw_encoding_name: str) -> bool:
        needle = raw_encoding_name.strip().upper()
        return any(needle == ignored.upper() for ignored in self.ignored_codecs)


class FaxConformityRule(BaseModel):
    enabled: bool
    reference: str
    forbidden_codec: str
    required_codec: str
    severity_on_violation: Severity


class SipTrunkCleartextSpec(BaseModel):
    severity: Severity
    description: str


class Fax2MailSpec(BaseModel):
    required_transport: str
    severity: Severity


class Mail2FaxSpec(BaseModel):
    required_auth: str
    severity: Severity


class AncillaryFlowsEncryptionRule(BaseModel):
    enabled: bool
    reference: str
    sip_trunk_cleartext: SipTrunkCleartextSpec
    fax2mail_smtp: Fax2MailSpec
    mail2fax_imap: Mail2FaxSpec


class Rfc3261StateMachineRule(BaseModel):
    enabled: bool
    reference: str
    monitored_final_error_codes: list[int]
    severity_on_violation: Severity
    rule_orphan_response: str
    rule_late_response: str


class RtpTeardownRule(BaseModel):
    enabled: bool
    reference: str
    tolerance_ms: int = Field(ge=0)
    severity_on_violation: Severity


class TrunkSupervisionRule(BaseModel):
    enabled: bool
    reference: str
    expected_options_period_seconds: int = Field(gt=0)
    tolerance_seconds: int = Field(ge=0)
    severity_on_violation: Severity


class SiemEcsRule(BaseModel):
    enabled: bool
    ecs_version: str
    dataset: str
    event_category: str
    event_type: str
    network_protocol: str
    observer_vendor: str
    observer_product: str


class RulesConfig(BaseModel):
    metadata: RulesetMetadata
    nat_matrix: NatMatrixRule
    identity_masking: IdentityMaskingRule
    forbidden_headers: ForbiddenHeadersRule
    authorized_sip_methods: AuthorizedSipMethodsRule
    codec_priority: CodecPriorityRule
    fax_conformity: FaxConformityRule
    ancillary_flows_encryption: AncillaryFlowsEncryptionRule
    rfc3261_state_machine: Rfc3261StateMachineRule
    rtp_teardown: RtpTeardownRule
    trunk_supervision: TrunkSupervisionRule
    siem_ecs: SiemEcsRule

    @classmethod
    def from_yaml(cls, path: str | Path) -> "RulesConfig":
        yaml_path = Path(path)
        if not yaml_path.is_file():
            raise ConfigError(f"Fichier de règles introuvable : {yaml_path}")
        try:
            raw_text = yaml_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"Impossible de lire le fichier de règles {yaml_path} : {exc}") from exc
        try:
            data: dict[str, Any] = yaml.safe_load(raw_text) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"YAML invalide dans {yaml_path} : {exc}") from exc
        try:
            return cls.model_validate(data)
        except Exception as exc:  # pydantic.ValidationError et erreurs de structure
            raise ConfigError(f"Référentiel de règles non conforme au schéma attendu : {exc}") from exc


class AncillaryFlowObservations(BaseModel):
    """Constats sur les flux annexes (Fax2Mail SMTP / Mail2Fax IMAP / trunk)
    remontés par le moteur de parsing lorsqu'ils sont présents dans la capture."""

    sip_trunk_observed: bool = False
    sip_trunk_uses_tls: bool = False
    smtp_observed: bool = False
    smtp_uses_tls: bool = False
    imap_observed: bool = False
    imap_uses_oauth2: bool = False


# -----------------------------------------------------------------------------
# Moteur de règles
# -----------------------------------------------------------------------------

_RFC1918_NETWORKS_HINT = ("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                           "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                           "172.30.", "172.31.", "192.168.")


class RuleEngine:
    """Applique le référentiel `RulesConfig` aux données extraites d'une capture."""

    def __init__(self, config: RulesConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------ NAT
    def check_nat_matrix(
        self,
        flows: list[NetworkFlow],
        sbc_sip_endpoints: list[NetworkEndpoint] | None = None,
        sbc_rtp_endpoints: list[NetworkEndpoint] | None = None,
    ) -> CheckResult:
        rule = self.config.nat_matrix
        rule_id = "NAT-001"
        title = "Isolation de la matrice de flux NAT (SIP / RTP) vis-à-vis du SBC opérateur"
        if not rule.enabled or not flows:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        allowed_sip_ips = {str(e.ip) for e in (sbc_sip_endpoints or [])}
        allowed_rtp_ips = {str(e.ip) for e in (sbc_rtp_endpoints or [])}
        lan_low, lan_high = rule.rtp_media.port_range

        for flow in self._merge_bidirectional(flows):
            endpoint_ips = {str(flow.local_endpoint.ip), str(flow.remote_endpoint.ip)}
            if flow.purpose.value == "sip":
                if allowed_sip_ips and not (endpoint_ips & allowed_sip_ips):
                    anomalies.append(self._nat_violation_anomaly(rule, flow, "SIP", allowed_sip_ips))
            elif flow.purpose.value == "rtp":
                if allowed_rtp_ips and not (endpoint_ips & allowed_rtp_ips):
                    anomalies.append(self._nat_violation_anomaly(rule, flow, "RTP", allowed_rtp_ips))
                endpoint_ports = {flow.local_endpoint.port, flow.remote_endpoint.port}
                if not any(lan_low <= port <= lan_high for port in endpoint_ports):
                    anomalies.append(
                        Anomaly(
                            rule_id=rule_id,
                            category=AnomalyCategory.OTT_CONFORMITY,
                            title=title,
                            severity=rule.severity_on_violation,
                            status=ComplianceStatus.FAIL,
                            description=(
                                f"Le flux RTP local {flow.local_endpoint} utilise un port "
                                f"({flow.local_endpoint.port}) hors de la plage LAN déclarée "
                                f"[{lan_low}-{lan_high}]."
                            ),
                            technical_evidence=(
                                f"Flux {flow.protocol.value} {flow.local_endpoint} <-> "
                                f"{flow.remote_endpoint} (trames {flow.frame_numbers})."
                            ),
                            cyber_risk=(
                                "Une plage RTP non maîtrisée élargit la surface d'exposition du "
                                "NAT/PAT et complique le filtrage strict côté FW/Routeur, facilitant "
                                "l'interception ou l'injection de flux média non sollicités."
                            ),
                            remediation=(
                                "Restreindre la configuration RTP de l'IPBX à la plage de ports "
                                f"[{lan_low}-{lan_high}] et aligner les règles NAT/PAT et de filtrage "
                                "du FW/Routeur en conséquence (cf. Tableaux 4 et 5 du Guide OXO)."
                            ),
                            source_reference=rule.reference,
                            frame_numbers=flow.frame_numbers,
                            call_id=flow.call_id,
                        )
                    )

        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    @staticmethod
    def _merge_bidirectional(flows: list[NetworkFlow]) -> list[NetworkFlow]:
        """Fusionne les deux `NetworkFlow` unidirectionnels d'une même
        conversation (aller/retour) en une seule entrée, afin que la
        vérification de la matrice NAT ne considère l'extrémité distante
        attendue (le SBC) qu'une fois, quel que soit le sens observé."""

        merged: dict[tuple, NetworkFlow] = {}
        for flow in flows:
            endpoint_a = (str(flow.local_endpoint.ip), flow.local_endpoint.port)
            endpoint_b = (str(flow.remote_endpoint.ip), flow.remote_endpoint.port)
            key = (flow.purpose.value, frozenset({endpoint_a, endpoint_b}))
            if key not in merged:
                merged[key] = flow.model_copy(deep=True)
            else:
                merged[key].frame_numbers = sorted(
                    set(merged[key].frame_numbers) | set(flow.frame_numbers)
                )
        return list(merged.values())

    def _nat_violation_anomaly(
        self, rule: NatMatrixRule, flow: NetworkFlow, flow_kind: str, allowed_ips: set[str]
    ) -> Anomaly:
        return Anomaly(
            rule_id="NAT-001",
            category=AnomalyCategory.OTT_CONFORMITY,
            title="Isolation de la matrice de flux NAT (SIP / RTP) vis-à-vis du SBC opérateur",
            severity=rule.severity_on_violation,
            status=ComplianceStatus.FAIL,
            description=(
                f"Un flux {flow_kind} a été observé avec une extrémité distante "
                f"({flow.remote_endpoint.ip}) absente de la liste des SBC opérateur déclarés "
                f"({', '.join(sorted(allowed_ips)) or 'aucune'})."
            ),
            technical_evidence=(
                f"Flux {flow.protocol.value} {flow.local_endpoint} <-> {flow.remote_endpoint} "
                f"(trames {flow.frame_numbers})."
            ),
            cyber_risk=(
                "Un flux SIP/RTP établi avec une adresse IP tierce non déclarée par l'opérateur "
                "constitue une rupture de l'isolation attendue du Trunk et peut traduire une usurpation "
                "de SBC, un relais non autorisé ou une exfiltration de flux voix."
            ),
            remediation=(
                "Vérifier la configuration NAT statique (Outbound NAT) et les règles de filtrage du "
                "FW/Routeur afin de n'autoriser que les adresses IP du SBC SIP/RTP fournies par "
                "l'opérateur (cf. Tableaux 4 et 5 du Guide OXO)."
            ),
            source_reference=rule.reference,
            frame_numbers=flow.frame_numbers,
            call_id=flow.call_id,
        )

    # ------------------------------------------------------------ Identité
    def check_identity_masking(self, dialogs: list[SipDialog]) -> CheckResult:
        rule = self.config.identity_masking
        rule_id = "ID-002"
        title = "Masquage d'identité de l'appelant (PAI / Privacy)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        evaluated = False
        accepted_privacy = {v.strip().lower() for v in rule.privacy_header_accepted_values}

        for dialog in dialogs:
            invite = next(
                (m for m in dialog.messages if m.is_request and m.method == "INVITE"), None
            )
            if invite is None:
                continue

            is_masked_call = bool(invite.privacy) or (
                invite.from_uri is not None
                and rule.anonymous_from_pattern.lower() in invite.from_uri.lower()
            )
            if not is_masked_call:
                continue

            evaluated = True
            if rule.required_header_p_asserted_identity and not invite.p_asserted_identity:
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.OTT_CONFORMITY,
                        title=title,
                        severity=rule.severity_on_missing_pai,
                        status=ComplianceStatus.FAIL,
                        description=(
                            "Un appel masqué (Privacy activée) ne comporte pas l'en-tête "
                            "P-Asserted-Identity attendu."
                        ),
                        technical_evidence=(
                            f"INVITE trame {invite.frame_number}, Call-ID {dialog.call_id}, "
                            f"From: {invite.from_uri}, Privacy: {invite.privacy}."
                        ),
                        cyber_risk=(
                            "L'absence de P-Asserted-Identity empêche l'opérateur et les correspondants "
                            "de confiance d'établir l'identité réelle de l'appelant, ce qui peut faire "
                            "échouer la levée d'anonymat légale (réquisition judiciaire) et les appels "
                            "d'urgence."
                        ),
                        remediation=(
                            "Activer l'en-tête P-Asserted-Identity sur la passerelle SIP pour tout appel "
                            "masqué (cf. Guide OXO §Activation du header P-Asserted-Identity)."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=[invite.frame_number],
                        call_id=dialog.call_id,
                        sip_method=invite.method,
                    )
                )

            privacy_value = (invite.privacy or "").strip().lower()
            if invite.privacy and privacy_value not in accepted_privacy:
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.OTT_CONFORMITY,
                        title=title,
                        severity=rule.severity_on_missing_privacy,
                        status=ComplianceStatus.FAIL,
                        description=(
                            f"La valeur de l'en-tête Privacy ('{invite.privacy}') ne correspond à "
                            "aucune valeur attendue pour un masquage d'identité conforme."
                        ),
                        technical_evidence=(
                            f"INVITE trame {invite.frame_number}, Call-ID {dialog.call_id}, "
                            f"Privacy: {invite.privacy}."
                        ),
                        cyber_risk=(
                            "Une valeur Privacy non standard peut ne pas être interprétée par le SBC "
                            "opérateur, exposant involontairement l'identité de l'appelant."
                        ),
                        remediation=(
                            "Configurer la valeur Privacy conformément aux spécifications STAS "
                            "(valeurs attendues : id / user / header)."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=[invite.frame_number],
                        call_id=dialog.call_id,
                        sip_method=invite.method,
                    )
                )

        if not evaluated:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)
        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # --------------------------------------------------------- En-têtes
    def check_forbidden_headers(self, messages: list[SipMessage]) -> CheckResult:
        rule = self.config.forbidden_headers
        rule_id = "HDR-003"
        title = "En-têtes SIP interdits et fuite d'adressage LAN privé"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        header_map = {
            "Referred-By": lambda m: m.referred_by,
        }
        for spec in rule.headers:
            extractor = header_map.get(spec.name)
            for message in messages:
                value = extractor(message) if extractor else self._search_raw_header(message, spec.name)
                if not value:
                    continue
                leaked_ip = self._extract_rfc1918_ip(value) if spec.check_rfc1918_leak else None
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.STAS_VULNERABILITY,
                        title=title,
                        severity=spec.severity,
                        status=ComplianceStatus.FAIL,
                        description=(
                            f"L'en-tête interdit '{spec.name}' est présent dans un message SIP "
                            f"({message.label})."
                            + (
                                f" Il expose l'adresse LAN privée {leaked_ip} (RFC 1918)."
                                if leaked_ip
                                else ""
                            )
                        ),
                        technical_evidence=f"{spec.name}: {value} (trame {message.frame_number}).",
                        cyber_risk=(
                            spec.description
                            if not leaked_ip
                            else spec.description
                            + " Un attaquant en écoute sur le réseau opérateur peut ainsi cartographier "
                            "le plan d'adressage interne du client (reconnaissance réseau)."
                        ),
                        remediation=(
                            f"Désactiver l'émission de l'en-tête '{spec.name}' vers le Trunk SIP "
                            "opérateur (règle de manipulation d'en-têtes sortants sur l'IPBX ou le SBC)."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=[message.frame_number],
                        call_id=message.call_id,
                        sip_method=message.method,
                        sip_status_code=message.status_code,
                    )
                )

        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    @staticmethod
    def _search_raw_header(message: SipMessage, header_name: str) -> str | None:
        for line in message.raw_header_block.splitlines():
            if line.lower().startswith(f"{header_name.lower()}:"):
                return line.split(":", 1)[1].strip()
        return None

    @staticmethod
    def _extract_rfc1918_ip(value: str) -> str | None:
        import re

        for match in re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", value):
            if match.startswith(_RFC1918_NETWORKS_HINT):
                return match
        return None

    # -------------------------------------------------------- Méthodes
    def check_authorized_methods(self, messages: list[SipMessage]) -> CheckResult:
        rule = self.config.authorized_sip_methods
        rule_id = "MET-004"
        title = "Méthodes SIP autorisées sur le Trunk (whitelist STAS)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        whitelist = {m.upper() for m in rule.whitelist}
        anomalies: list[Anomaly] = []
        reported: set[tuple[str, int]] = set()

        for message in messages:
            if not message.allow_methods:
                continue
            unauthorized = sorted({m.upper() for m in message.allow_methods} - whitelist)
            for method in unauthorized:
                key = (method, message.frame_number)
                if key in reported:
                    continue
                reported.add(key)
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.RFC_DEVIATION,
                        title=title,
                        severity=rule.severity_on_violation,
                        status=ComplianceStatus.FAIL,
                        description=(
                            f"La méthode SIP '{method}' est annoncée dans l'en-tête Allow alors "
                            "qu'elle n'est pas autorisée par la STAS opérateur."
                        ),
                        technical_evidence=(
                            f"Allow: {', '.join(message.allow_methods)} (trame {message.frame_number})."
                        ),
                        cyber_risk=(
                            "Une méthode SIP non autorisée mais acceptée par l'équipement élargit la "
                            "surface d'attaque du Trunk (ex : REFER/SUBSCRIBE/NOTIFY détournés pour du "
                            "rebond d'appel ou de la fuite d'état de présence)."
                        ),
                        remediation=(
                            "Restreindre l'en-tête Allow annoncé par l'IPBX à la liste STAS "
                            f"({', '.join(sorted(whitelist))}) et désactiver les fonctionnalités "
                            "correspondantes côté PABX si elles ne sont pas requises sur ce Trunk."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=[message.frame_number],
                        call_id=message.call_id,
                        sip_method=message.method,
                        sip_status_code=message.status_code,
                    )
                )

        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # -------------------------------------------------------------- Codecs
    def check_codec_priority(self, messages: list[SipMessage]) -> CheckResult:
        rule = self.config.codec_priority
        rule_id = "COD-005"
        title = "Ordre de priorité des codecs (conformité STAS)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        evaluated = False

        for message in messages:
            applicable = (message.is_request and message.method in rule.applicable_methods) or (
                not message.is_request and str(message.status_code) in rule.applicable_methods
            )
            if not applicable or not message.sdp_media:
                continue

            for media in message.sdp_media:
                canonical_order = [
                    rule.canonicalize(codec.encoding_name)
                    for codec in media.codecs
                    if not rule.is_ignored(codec.encoding_name)
                ]
                canonical_order = [c for c in canonical_order if c is not None]
                if len(canonical_order) < 2:
                    continue

                evaluated = True
                expected_positions = {
                    codec: index for index, codec in enumerate(rule.expected_order)
                }
                observed_relevant = [c for c in canonical_order if c in expected_positions]
                sorted_relevant = sorted(observed_relevant, key=lambda c: expected_positions[c])
                if observed_relevant != sorted_relevant:
                    anomalies.append(
                        Anomaly(
                            rule_id=rule_id,
                            category=AnomalyCategory.STAS_VULNERABILITY,
                            title=title,
                            severity=rule.severity_on_violation,
                            status=ComplianceStatus.FAIL,
                            description=(
                                "L'ordre de négociation des codecs ne respecte pas la priorité STAS "
                                f"attendue ({' > '.join(rule.expected_order)})."
                            ),
                            technical_evidence=(
                                f"Ordre observé : {' > '.join(canonical_order)} "
                                f"(trame {message.frame_number}, {message.label})."
                            ),
                            cyber_risk=(
                                "Un ordre de codec non conforme à la STAS peut forcer l'usage d'un codec "
                                "à plus faible compression (bande passante WAN accrue) et traduit une "
                                "divergence de configuration entre l'IPBX et la plateforme opérateur, "
                                "symptomatique d'un défaut plus large de gouvernance de configuration."
                            ),
                            remediation=(
                                "Aligner l'ordre des codecs déclarés sur la passerelle SIP avec la "
                                f"priorité STAS ({' puis '.join(rule.expected_order)}), cf. Guide OXO "
                                "§Paramétrage des codecs / §Configuration avancée (PrefCodec)."
                            ),
                            source_reference=rule.reference,
                            frame_numbers=[message.frame_number],
                            call_id=message.call_id,
                            sip_method=message.method,
                            sip_status_code=message.status_code,
                        )
                    )

        if not evaluated:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)
        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # ------------------------------------------------------------------ Fax
    def check_fax_conformity(self, messages: list[SipMessage]) -> CheckResult:
        rule = self.config.fax_conformity
        rule_id = "FAX-006"
        title = "Conformité de la négociation Fax (T.38 vs G.711A)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        evaluated = False
        forbidden = rule.forbidden_codec.upper()

        for message in messages:
            for media in message.sdp_media:
                if media.media_type.lower() not in ("image", "audio"):
                    continue
                encodings = [c.encoding_name.upper() for c in media.codecs]
                if not any(forbidden in encoding.replace(".", "") for encoding in encodings):
                    continue
                evaluated = True
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.OTT_CONFORMITY,
                        title=title,
                        severity=rule.severity_on_violation,
                        status=ComplianceStatus.FAIL,
                        description=(
                            "Le codec T.38 est négocié dans la SDP alors qu'il n'est pas supporté par "
                            "le Trunk SIP OTT et doit être remplacé par un repli G.711A."
                        ),
                        technical_evidence=(
                            f"Codecs négociés : {', '.join(encodings)} (trame {message.frame_number}, "
                            f"{message.label})."
                        ),
                        cyber_risk=(
                            "Une négociation T.38 non aboutie sur ce Trunk provoque un échec silencieux "
                            "des transmissions de télécopie, avec un risque de perte de preuves "
                            "documentaires (accusés de réception, contrats) sans alerte opérateur."
                        ),
                        remediation=(
                            "Désactiver T.38 sur la passerelle SIP dédiée au Trunk OTT et forcer le "
                            f"codec {rule.required_codec} pour les flux fax (cf. Guide OXO "
                            "§Paramétrage des fax)."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=[message.frame_number],
                        call_id=message.call_id,
                        sip_method=message.method,
                        sip_status_code=message.status_code,
                    )
                )

        if not evaluated:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)
        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # ------------------------------------------------------- Chiffrement
    def check_ancillary_encryption(self, observations: AncillaryFlowObservations) -> CheckResult:
        rule = self.config.ancillary_flows_encryption
        rule_id = "ENC-007"
        title = "Chiffrement des flux annexes (Trunk SIP, Fax2Mail, Mail2Fax)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []

        if observations.sip_trunk_observed and not observations.sip_trunk_uses_tls:
            anomalies.append(
                Anomaly(
                    rule_id=rule_id,
                    category=AnomalyCategory.OTT_CONFORMITY,
                    title=title,
                    severity=rule.sip_trunk_cleartext.severity,
                    status=ComplianceStatus.WARNING,
                    description="Le Trunk SIP OTT est établi en clair (UDP sans TLS/SRTP).",
                    technical_evidence="Signalisation SIP observée en clair sur le Trunk opérateur.",
                    cyber_risk=(
                        "En l'absence de TLS/SRTP, la signalisation et les flux voix sont interceptables "
                        "en clair par tout tiers en position d'écoute sur le chemin opérateur."
                    ),
                    remediation=(
                        rule.sip_trunk_cleartext.description
                        + " Si une exigence contractuelle de chiffrement existe, migrer vers une offre "
                        "Trunk SIP-TLS/SRTP."
                    ),
                    source_reference=rule.reference,
                )
            )

        if observations.smtp_observed and not observations.smtp_uses_tls:
            anomalies.append(
                Anomaly(
                    rule_id=rule_id,
                    category=AnomalyCategory.OTT_CONFORMITY,
                    title=title,
                    severity=rule.fax2mail_smtp.severity,
                    status=ComplianceStatus.FAIL,
                    description="Le flux Fax2Mail (SMTP) est observé sans chiffrement TLS.",
                    technical_evidence="Session SMTP observée sans négociation STARTTLS/TLS.",
                    cyber_risk=(
                        "Les fax convertis en pièces jointes e-mail transitent en clair, exposant des "
                        "documents potentiellement sensibles à une interception réseau."
                    ),
                    remediation="Activer le chiffrement TLS obligatoire sur le relais SMTP Fax2Mail.",
                    source_reference=rule.reference,
                )
            )

        if observations.imap_observed and not observations.imap_uses_oauth2:
            anomalies.append(
                Anomaly(
                    rule_id=rule_id,
                    category=AnomalyCategory.OTT_CONFORMITY,
                    title=title,
                    severity=rule.mail2fax_imap.severity,
                    status=ComplianceStatus.FAIL,
                    description="Le flux Mail2Fax (IMAP) n'utilise pas d'authentification OAuth2.",
                    technical_evidence="Authentification IMAP observée sans mécanisme OAuth2 (XOAUTH2).",
                    cyber_risk=(
                        "Une authentification IMAP par mot de passe statique expose les identifiants de "
                        "la boîte Mail2Fax à un risque de compromission par rejeu ou fuite d'identifiants."
                    ),
                    remediation="Migrer l'authentification IMAP du service Mail2Fax vers OAuth2.",
                    source_reference=rule.reference,
                )
            )

        if not anomalies:
            status = ComplianceStatus.PASS
        elif any(a.status == ComplianceStatus.FAIL for a in anomalies):
            status = ComplianceStatus.FAIL
        else:
            status = ComplianceStatus.WARNING
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # -------------------------------------------------------------- RFC3261
    def check_rfc3261_state_machine(self, dialogs: list[SipDialog]) -> CheckResult:
        rule = self.config.rfc3261_state_machine
        rule_id = "RFC-008"
        title = "Écarts à la machine d'état SIP (RFC 3261 §17)"
        if not rule.enabled:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        evaluated = False
        monitored = set(rule.monitored_final_error_codes)

        for dialog in dialogs:
            bye_ts = dialog.bye_timestamp()
            invite_cseqs = dialog.invite_cseq_numbers()
            for message in dialog.messages:
                if message.is_request or message.status_code not in monitored:
                    continue
                evaluated = True

                orphan = message.cseq_number is None or message.cseq_number not in invite_cseqs
                late = bye_ts is not None and message.timestamp > bye_ts

                if orphan or late:
                    reason = rule.rule_orphan_response if orphan else rule.rule_late_response
                    anomalies.append(
                        Anomaly(
                            rule_id=rule_id,
                            category=AnomalyCategory.RFC_DEVIATION,
                            title=title,
                            severity=rule.severity_on_violation,
                            status=ComplianceStatus.FAIL,
                            description=(
                                f"Réponse {message.status_code} {message.reason_phrase or ''} émise en "
                                "dehors d'une transaction INVITE valide."
                            ).strip(),
                            technical_evidence=(
                                f"Call-ID {dialog.call_id}, CSeq {message.cseq_number}, "
                                f"trame {message.frame_number}. Motif : {reason.strip()}"
                            ),
                            cyber_risk=(
                                "Un rejet SIP émis hors machine d'état RFC 3261 peut traduire une "
                                "implémentation propriétaire non conforme, susceptible de désynchroniser "
                                "les dialogues SIP et d'être exploitée pour des attaques de rejeu ou de "
                                "déni de service applicatif ciblé sur le trunk."
                            ),
                            remediation=(
                                "Vérifier l'implémentation de la machine d'état des transactions INVITE "
                                "côté IPBX/SBC et corriger l'émission de réponses finales hors contexte "
                                "transactionnel valide."
                            ),
                            source_reference=rule.reference,
                            frame_numbers=[message.frame_number],
                            call_id=dialog.call_id,
                            sip_method=message.cseq_method,
                            sip_status_code=message.status_code,
                        )
                    )

        if not evaluated:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)
        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # --------------------------------------------------------- RTP teardown
    def check_rtp_teardown(self, samples: list[RtpTeardownSample]) -> CheckResult:
        rule = self.config.rtp_teardown
        rule_id = "RTP-009"
        title = "Persistance de flux RTP après clôture de session (BYE)"
        if not rule.enabled or not samples:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        for sample in samples:
            if sample.delay_after_bye_ms <= rule.tolerance_ms or not sample.frames_after_bye:
                continue
            anomalies.append(
                Anomaly(
                    rule_id=rule_id,
                    category=AnomalyCategory.RFC_DEVIATION,
                    title=title,
                    severity=rule.severity_on_violation,
                    status=ComplianceStatus.FAIL,
                    description=(
                        "Des paquets RTP ont été observés après l'échange BYE/200 OK clôturant le "
                        f"dialogue, au-delà de la tolérance de {rule.tolerance_ms} ms."
                    ),
                    technical_evidence=(
                        f"Call-ID {sample.call_id}, délai observé {sample.delay_after_bye_ms:.1f} ms, "
                        f"trames RTP résiduelles {sample.frames_after_bye}."
                    ),
                    cyber_risk=(
                        "Un flux RTP non correctement clôturé maintient un canal média ouvert au-delà de "
                        "la session légitime, ce qui peut être exploité pour prolonger une écoute ou "
                        "saturer les ressources de transcodage du PABX."
                    ),
                    remediation=(
                        "Vérifier la gestion de la fermeture de session RTP côté IPBX (relâchement du "
                        "flux dès réception du BYE) ; cf. Rapport Asterisk §6."
                    ),
                    source_reference=rule.reference,
                    frame_numbers=sample.frames_after_bye,
                    call_id=sample.call_id,
                )
            )

        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # ---------------------------------------------------- Supervision Trunk
    def check_trunk_supervision(self, keepalives: list[OptionsKeepAlive]) -> CheckResult:
        rule = self.config.trunk_supervision
        rule_id = "SUP-010"
        title = "Supervision du Trunk par messages SIP OPTIONS (Keep-Alive)"
        if not rule.enabled or not keepalives:
            return CheckResult(rule_id=rule_id, title=title, status=ComplianceStatus.NOT_APPLICABLE)

        anomalies: list[Anomaly] = []
        expected = rule.expected_options_period_seconds
        tolerance = rule.tolerance_seconds

        for keepalive in keepalives:
            intervals = keepalive.intervals_seconds()
            if not intervals:
                continue
            deviant = [i for i in intervals if abs(i - expected) > tolerance]
            if deviant:
                anomalies.append(
                    Anomaly(
                        rule_id=rule_id,
                        category=AnomalyCategory.OTT_CONFORMITY,
                        title=title,
                        severity=rule.severity_on_violation,
                        status=ComplianceStatus.FAIL,
                        description=(
                            f"La périodicité des messages SIP OPTIONS entre {keepalive.source} et "
                            f"{keepalive.destination} dévie de la période attendue de {expected}s "
                            f"(± {tolerance}s)."
                        ),
                        technical_evidence=f"Intervalles observés (s) : {[round(i, 1) for i in intervals]}.",
                        cyber_risk=(
                            "Une supervision de trunk irrégulière retarde la détection d'une rupture du "
                            "lien opérateur et peut masquer une dégradation de service ou une attaque en "
                            "cours sur le lien SIP."
                        ),
                        remediation=(
                            f"Régler le temporisateur d'émission des messages OPTIONS à {expected} "
                            "secondes côté IPBX (cf. Rapport OXO §5.5 / Rapport Asterisk §5.5)."
                        ),
                        source_reference=rule.reference,
                        frame_numbers=keepalive.frame_numbers,
                        sip_method="OPTIONS",
                    )
                )

        status = ComplianceStatus.FAIL if anomalies else ComplianceStatus.PASS
        return CheckResult(rule_id=rule_id, title=title, status=status, anomalies=anomalies)

    # ------------------------------------------------------------- Global
    def run_all(
        self,
        *,
        dialogs: list[SipDialog],
        messages: list[SipMessage],
        flows: list[NetworkFlow],
        sbc_sip_endpoints: list[NetworkEndpoint] | None = None,
        sbc_rtp_endpoints: list[NetworkEndpoint] | None = None,
        rtp_teardown_samples: list[RtpTeardownSample] | None = None,
        keepalives: list[OptionsKeepAlive] | None = None,
        ancillary_observations: AncillaryFlowObservations | None = None,
    ) -> list[CheckResult]:
        """Exécute l'intégralité du référentiel et retourne un `CheckResult` par règle."""

        return [
            self.check_nat_matrix(flows, sbc_sip_endpoints, sbc_rtp_endpoints),
            self.check_identity_masking(dialogs),
            self.check_forbidden_headers(messages),
            self.check_authorized_methods(messages),
            self.check_codec_priority(messages),
            self.check_fax_conformity(messages),
            self.check_ancillary_encryption(ancillary_observations or AncillaryFlowObservations()),
            self.check_rfc3261_state_machine(dialogs),
            self.check_rtp_teardown(rtp_teardown_samples or []),
            self.check_trunk_supervision(keepalives or []),
        ]
