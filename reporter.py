"""Exceptions applicatives IVSA.

Toute erreur prévisible (configuration invalide, capture illisible, gabarit
de rapport corrompu, ...) est levée sous une sous-classe de `IvsaError` afin
de permettre à la CLI de distinguer une erreur applicative maîtrisée d'un
bogue interne, et de restituer un message d'erreur exploitable à l'auditeur
réseau qui exécute l'outil.
"""

from __future__ import annotations


class IvsaError(Exception):
    """Racine de la hiérarchie d'exceptions applicatives IVSA."""


class ConfigError(IvsaError):
    """Le référentiel de règles (`rules.yaml`) est absent, illisible ou invalide."""


class PcapParsingError(IvsaError):
    """La capture réseau fournie est illisible, absente ou corrompue."""


class ReportGenerationError(IvsaError):
    """Le rapport Word n'a pas pu être généré à partir du gabarit fourni."""


class EcsExportError(IvsaError):
    """Les événements ECS n'ont pas pu être sérialisés ou écrits sur disque."""
