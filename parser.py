"""Normalisation SIEM (Elastic Common Schema) des anomalies IVSA.

Chaque `Anomaly` détectée par le moteur de règles est convertie en un
événement conforme à l'Elastic Common Schema (ECS) v8.x, prêt à être ingéré
par un pipeline Logstash/PFELK, conformément aux spécifications de la
présentation ELK v2 de la base de connaissances ILEXIA : `event.category`,
`network.protocol`, `sip.method`, `sip.status_code` et `error.message` sont
systématiquement renseignés.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from ivsa.core.exceptions import EcsExportError
from ivsa.core.models import AnalysisResult, Anomaly, ComplianceStatus, Severity
from ivsa.core.rules_engine import SiemEcsRule

_SEVERITY_TO_ECS_SCORE: dict[Severity, int] = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 70,
    Severity.MEDIUM: 50,
    Severity.LOW: 30,
    Severity.INFO: 10,
}


class EcsEventMeta(BaseModel):
    category: list[str]
    kind: str
    type: list[str]
    action: str
    dataset: str
    severity: int
    outcome: str


class EcsNetwork(BaseModel):
    protocol: str
    transport: str = "udp"


class EcsSip(BaseModel):
    method: str | None = None
    status_code: int | None = None
    call_id: str | None = None
    rule_id: str
    category: str


class EcsError(BaseModel):
    message: str
    code: str


class EcsObserver(BaseModel):
    vendor: str
    product: str
    version: str = "1.0.0"


class EcsRelated(BaseModel):
    frame_numbers: list[int] = Field(default_factory=list)


class EcsIvsaEvent(BaseModel):
    """Un événement ECS unique représentant une anomalie ou un contrôle conforme."""

    model_config = ConfigDict(populate_by_name=True)

    timestamp: datetime = Field(alias="@timestamp")
    event: EcsEventMeta
    network: EcsNetwork
    sip: EcsSip
    error: EcsError
    observer: EcsObserver
    related: EcsRelated
    message: str
    labels: dict[str, str] = Field(default_factory=dict)

    def to_json_line(self) -> str:
        payload = self.model_dump(by_alias=True, mode="json", exclude_none=True)
        return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _build_event(
    anomaly: Anomaly, analysis_timestamp: datetime, siem_config: SiemEcsRule
) -> EcsIvsaEvent:
    outcome = "failure" if anomaly.status == ComplianceStatus.FAIL else "success"
    return EcsIvsaEvent(
        **{"@timestamp": analysis_timestamp},
        event=EcsEventMeta(
            category=[siem_config.event_category],
            kind="alert" if anomaly.status == ComplianceStatus.FAIL else "event",
            type=[siem_config.event_type],
            action=anomaly.rule_id,
            dataset=siem_config.dataset,
            severity=_SEVERITY_TO_ECS_SCORE[anomaly.severity],
            outcome=outcome,
        ),
        network=EcsNetwork(protocol=siem_config.network_protocol),
        sip=EcsSip(
            method=anomaly.sip_method,
            status_code=anomaly.sip_status_code,
            call_id=anomaly.call_id,
            rule_id=anomaly.rule_id,
            category=anomaly.category.value,
        ),
        error=EcsError(message=anomaly.description, code=anomaly.rule_id),
        observer=EcsObserver(vendor=siem_config.observer_vendor, product=siem_config.observer_product),
        related=EcsRelated(frame_numbers=anomaly.frame_numbers),
        message=anomaly.description,
        labels={
            "severity": anomaly.severity.value,
            "status": anomaly.status.value,
            "source_reference": anomaly.source_reference,
        },
    )


def build_ecs_events(result: AnalysisResult, siem_config: SiemEcsRule) -> list[EcsIvsaEvent]:
    """Construit la liste des événements ECS pour toutes les anomalies d'une analyse."""

    return [
        _build_event(anomaly, result.metadata.analysis_timestamp, siem_config)
        for anomaly in result.anomalies
    ]


def export_ndjson(result: AnalysisResult, siem_config: SiemEcsRule, output_path: str | Path) -> int:
    """Exporte les événements ECS au format NDJSON (une ligne JSON par événement),
    directement consommable par un pipeline Logstash/PFELK via un input `file`
    ou `http`. Retourne le nombre d'événements écrits.
    """

    events = build_ecs_events(result, siem_config)
    destination = Path(output_path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("w", encoding="utf-8") as handle:
            for event in events:
                handle.write(event.to_json_line())
                handle.write("\n")
    except OSError as exc:
        raise EcsExportError(f"Impossible d'écrire l'export ECS vers {destination} : {exc}") from exc
    return len(events)
