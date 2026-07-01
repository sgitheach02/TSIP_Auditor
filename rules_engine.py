"""Modèles Pydantic v2 - structures de données de l'analyseur IVSA.

Ces modèles constituent le contrat de données strict entre le moteur de
parsing réseau (`core.parser`), le moteur de règles (`core.rules_engine`) et
le moteur de rapport (`core.reporter`). Toute valeur non conforme (adresse IP
invalide, port hors plage, sévérité inconnue, etc.) est rejetée dès la
construction de l'objet, garantissant qu'aucune donnée corrompue ne puisse
se propager jusqu'au rapport Word final.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from typing import Union

from pydantic import BaseModel, ConfigDict, Field, field_validator

IpAddress = Union[IPv4Address, IPv6Address]


class Severity(str, Enum):
    """Échelle de sévérité cyber associée à une non-conformité."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]


class ComplianceStatus(str, Enum):
    """Statut de conformité d'un point de contrôle du rapport d'audit."""

    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class AnomalyCategory(str, Enum):
    """Grande famille de règle, reflétant la structure de la base de connaissances."""

    OTT_CONFORMITY = "Conformité OTT"
    RFC_DEVIATION = "Écart RFC 3261 / Systèmes propriétaires"
    STAS_VULNERABILITY = "Vulnérabilité & non-conformité STAS"
    SIEM_NORMALIZATION = "Normalisation SIEM"


class Transport(str, Enum):
    UDP = "UDP"
    TCP = "TCP"
    TLS = "TLS"


class NetworkEndpoint(BaseModel):
    """Couple adresse IP / port validé, utilisé pour toute extrémité de flux."""

    model_config = ConfigDict(frozen=True)

    ip: IpAddress
    port: int = Field(ge=0, le=65535)

    def is_private(self) -> bool:
        return self.ip.is_private

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.ip}:{self.port}"


class SdpCodec(BaseModel):
    """Un codec négocié dans une ligne média SDP, dans son ordre d'apparition."""

    payload_type: int | None = Field(default=None, ge=0, le=127)
    encoding_name: str
    clock_rate: int | None = None

    @field_validator("encoding_name")
    @classmethod
    def _normalize_encoding_name(cls, value: str) -> str:
        return value.strip()


class SdpMediaDescription(BaseModel):
    """Une ligne `m=` SDP et ses attributs `a=` associés."""

    media_type: str
    port: int = Field(ge=0, le=65535)
    protocol: str
    codecs: list[SdpCodec] = Field(default_factory=list)
    ptime_ms: int | None = None
    maxptime_ms: int | None = None
    connection_address: str | None = None

    def codec_order(self) -> list[str]:
        """Ordre de préférence des codecs tel que négocié (hors DTMF/CN)."""

        return [codec.encoding_name for codec in self.codecs]


class SipMessage(BaseModel):
    """Une requête ou une réponse SIP extraite d'une trame réseau."""

    model_config = ConfigDict(frozen=True)

    frame_number: int = Field(ge=1)
    timestamp: datetime
    transport: Transport
    source: NetworkEndpoint
    destination: NetworkEndpoint

    is_request: bool
    method: str | None = None
    status_code: int | None = Field(default=None, ge=100, le=699)
    reason_phrase: str | None = None

    call_id: str
    cseq_number: int | None = None
    cseq_method: str | None = None

    from_uri: str | None = None
    from_tag: str | None = None
    to_uri: str | None = None
    to_tag: str | None = None

    allow_methods: list[str] = Field(default_factory=list)
    privacy: str | None = None
    p_asserted_identity: str | None = None
    referred_by: str | None = None
    contact_uri: str | None = None

    raw_header_block: str = ""
    sdp_media: list[SdpMediaDescription] = Field(default_factory=list)

    @field_validator("method")
    @classmethod
    def _upper_method(cls, value: str | None) -> str | None:
        return value.upper() if value else value

    @property
    def label(self) -> str:
        if self.is_request:
            return self.method or "UNKNOWN"
        return f"{self.status_code} {self.reason_phrase or ''}".strip()


class SipDialog(BaseModel):
    """Regroupement des messages d'un même dialogue SIP (même Call-ID)."""

    call_id: str
    messages: list[SipMessage] = Field(default_factory=list)

    @property
    def has_invite(self) -> bool:
        return any(m.is_request and m.method == "INVITE" for m in self.messages)

    @property
    def has_bye(self) -> bool:
        return any(m.is_request and m.method == "BYE" for m in self.messages)

    def bye_timestamp(self) -> datetime | None:
        for message in self.messages:
            if message.is_request and message.method == "BYE":
                return message.timestamp
        return None

    def invite_cseq_numbers(self) -> set[int]:
        return {
            m.cseq_number
            for m in self.messages
            if m.is_request and m.method == "INVITE" and m.cseq_number is not None
        }


class FlowPurpose(str, Enum):
    SIP_SIGNALING = "sip"
    RTP_MEDIA = "rtp"
    OTHER = "other"


class NetworkFlow(BaseModel):
    """Un flux réseau (paire d'extrémités) observé au niveau trame (couche IP/UDP).

    Construit par le moteur Scapy à partir des trames brutes, indépendamment
    du dissecteur SIP applicatif, pour la vérification de la matrice de flux
    NAT (isolation SIP/RTP vis-à-vis du SBC opérateur).
    """

    protocol: Transport
    purpose: FlowPurpose
    local_endpoint: NetworkEndpoint
    remote_endpoint: NetworkEndpoint
    frame_numbers: list[int] = Field(default_factory=list)
    call_id: str | None = None


class RtpTeardownSample(BaseModel):
    """Observation, pour un dialogue donné, des flux RTP autour de sa clôture BYE."""

    call_id: str
    bye_timestamp: datetime
    last_rtp_timestamp: datetime | None = None
    frames_after_bye: list[int] = Field(default_factory=list)
    delay_after_bye_ms: float = 0.0


class OptionsKeepAlive(BaseModel):
    """Séquence d'observations des messages SIP OPTIONS de supervision de trunk."""

    source: NetworkEndpoint
    destination: NetworkEndpoint
    timestamps: list[datetime] = Field(default_factory=list)
    frame_numbers: list[int] = Field(default_factory=list)

    def intervals_seconds(self) -> list[float]:
        if len(self.timestamps) < 2:
            return []
        ordered = sorted(self.timestamps)
        return [
            (later - earlier).total_seconds()
            for earlier, later in zip(ordered[:-1], ordered[1:])
        ]


class Anomaly(BaseModel):
    """Un écart de conformité ou une vulnérabilité détectée par le moteur de règles."""

    rule_id: str
    category: AnomalyCategory
    title: str
    severity: Severity
    status: ComplianceStatus
    description: str
    technical_evidence: str
    cyber_risk: str
    remediation: str
    source_reference: str
    frame_numbers: list[int] = Field(default_factory=list)
    call_id: str | None = None
    sip_method: str | None = None
    sip_status_code: int | None = None

    @field_validator("frame_numbers")
    @classmethod
    def _sorted_unique_frames(cls, value: list[int]) -> list[int]:
        return sorted(set(value))


class CheckResult(BaseModel):
    """Résultat synthétique d'un point de contrôle, conforme ou non."""

    rule_id: str
    title: str
    status: ComplianceStatus
    anomalies: list[Anomaly] = Field(default_factory=list)


class AnalysisMetadata(BaseModel):
    """Métadonnées d'exécution d'une analyse, reportées en en-tête du rapport."""

    pcap_filename: str
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)
    analyst: str = "IVSA"
    client_name: str | None = None
    site_name: str | None = None
    ipbx_vendor: str | None = None
    ipbx_version: str | None = None
    operator: str | None = None
    trunk_type: str | None = None
    sbc_sip_endpoint: str | None = None
    sbc_rtp_endpoint: str | None = None
    total_packets_captured: int = 0
    total_sip_messages: int = 0
    total_sip_dialogs: int = 0
    ruleset_name: str = ""
    ruleset_version: str = ""


class AnalysisResult(BaseModel):
    """Résultat complet d'une analyse : métadonnées + ensemble des points de contrôle."""

    metadata: AnalysisMetadata
    checks: list[CheckResult] = Field(default_factory=list)

    @property
    def anomalies(self) -> list[Anomaly]:
        return [a for check in self.checks for a in check.anomalies]

    @property
    def pass_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.PASS)

    @property
    def fail_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.FAIL)

    @property
    def warning_count(self) -> int:
        return sum(1 for c in self.checks if c.status == ComplianceStatus.WARNING)

    def severity_breakdown(self) -> dict[str, int]:
        breakdown = {severity.value: 0 for severity in Severity}
        for anomaly in self.anomalies:
            breakdown[anomaly.severity.value] += 1
        return breakdown
