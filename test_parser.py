from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from ivsa.core.rules_engine import RulesConfig
from tests.fixtures.pcap_builder import build_full_scenario, write_pcap

_RULES_PATH = Path(__file__).resolve().parent.parent / "ivsa" / "config" / "rules.yaml"

requires_tshark = pytest.mark.skipif(
    shutil.which("tshark") is None, reason="TShark n'est pas installé dans cet environnement."
)


@pytest.fixture()
def rules_config() -> RulesConfig:
    return RulesConfig.from_yaml(_RULES_PATH)


@pytest.fixture()
def full_scenario_pcap(tmp_path) -> Path:
    pcap_path = tmp_path / "full_scenario.pcapng"
    write_pcap(pcap_path, build_full_scenario())
    return pcap_path
