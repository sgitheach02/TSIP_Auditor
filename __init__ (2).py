"""Moteur de génération du rapport d'audit Word.

Charge le gabarit `templates/audit_report_template.docx` (charte graphique
et structure Ilexia) et y injecte, via `docxtpl` (moteur de template Jinja2
appliqué à des documents Word), les résultats structurés d'une analyse
(`AnalysisResult`) : statut PASS/FAIL par point de contrôle, description
technique de chaque écart, risque cyber associé et préconisation de
remédiation.
"""

from __future__ import annotations

from pathlib import Path

from docxtpl import DocxTemplate
from jinja2 import TemplateSyntaxError

from ivsa.core.exceptions import ReportGenerationError
from ivsa.core.models import AnalysisResult, Severity

DEFAULT_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "templates" / "audit_report_template.docx"


def _build_render_context(result: AnalysisResult, ruleset_sources: list[str]) -> dict:
    dumped = result.model_dump(mode="json")

    severity_summary = [
        {"label": severity.value, "count": result.severity_breakdown()[severity.value]}
        for severity in Severity
        if result.severity_breakdown()[severity.value] > 0
    ]

    return {
        "metadata": dumped["metadata"],
        "checks": dumped["checks"],
        "pass_count": result.pass_count,
        "fail_count": result.fail_count,
        "warning_count": result.warning_count,
        "severity_summary": severity_summary,
        "ruleset_sources": ruleset_sources,
    }


class ReportBuilder:
    """Génère un rapport d'audit Word à partir d'un `AnalysisResult`."""

    def __init__(self, template_path: str | Path = DEFAULT_TEMPLATE_PATH) -> None:
        self.template_path = Path(template_path)
        if not self.template_path.is_file():
            raise ReportGenerationError(f"Gabarit de rapport introuvable : {self.template_path}")

    def render(
        self,
        result: AnalysisResult,
        output_path: str | Path,
        ruleset_sources: list[str] | None = None,
    ) -> Path:
        """Rend le rapport Word final et l'écrit sur disque, retourne son chemin."""

        destination = Path(output_path)
        try:
            template = DocxTemplate(str(self.template_path))
            context = _build_render_context(result, ruleset_sources or [])
            template.render(context, autoescape=True)
        except TemplateSyntaxError as exc:
            raise ReportGenerationError(
                f"Le gabarit {self.template_path} contient une erreur de syntaxe Jinja2 : {exc}"
            ) from exc
        except Exception as exc:  # frontière avec docxtpl / python-docx / lxml
            raise ReportGenerationError(
                f"Échec de la génération du rapport Word à partir de {self.template_path} : {exc}"
            ) from exc

        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            template.save(str(destination))
        except OSError as exc:
            raise ReportGenerationError(f"Impossible d'écrire le rapport vers {destination} : {exc}") from exc

        return destination
