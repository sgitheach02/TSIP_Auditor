# IVSA — Interop Validation & Security Automator

Automatisation de bout en bout de l'audit de conformité et de sécurité des
Trunks SIP ToIP : ingestion d'une capture réseau `.pcapng`, application d'un
référentiel de règles métier compilé depuis une base de connaissances
documentaire, et génération d'un rapport d'audit Microsoft Word (`.docx`).

## Base de connaissances exploitée

Le référentiel de règles (`ivsa/config/rules.yaml`) est directement compilé à
partir de guides de configuration et de rapports de tests d'interopérabilité
de Trunks SIP opérateur :

- Guide de configuration Trunk SIP OTT (IPBX Alcatel OmniPCX Office / OXO) —
  matrice de flux NAT, paramétrage codecs/fax, P-Asserted-Identity.
- Rapport de tests d'interopérabilité Trunk SIP OTT (IPBX Alcatel OXO) —
  méthodes SIP non autorisées, non-conformité STAS des codecs, masquage
  d'identité, appels d'urgence.
- Guide de configuration Trunk SIP (IPBX Alcatel OmniPCX Enterprise / OXE) —
  codecs, RFC 3325 (PAI), supervision de trunk.
- Rapport de tests d'interopérabilité Trunk SIP (IPBX Asterisk) — en-tête
  `Referred-By` exposant une IP LAN privée, ordre de priorité codec non
  conforme à la STAS, persistance RTP après `BYE`.

## Stack technique

| Besoin | Outil |
| --- | --- |
| Parsing SIP/SDP applicatif profond | `Pyshark` (moteur TShark) |
| Analyse de trames bas niveau (NAT, timing RTP) | `Scapy` |
| Validation stricte des schémas de données | `Pydantic v2` |
| Normalisation SIEM | JSON structuré → Elastic Common Schema (ECS) v8.x |
| Génération du rapport Word | `python-docx` + `docxtpl` (Jinja2 sur `.docx`) |

`Pyshark` nécessite le binaire `tshark` (Wireshark CLI) installé et présent
dans le `PATH` (`apt-get install tshark` / `brew install wireshark`).

## Architecture du projet

```
ivsa/
├── __init__.py
├── cli.py                       # Point d'entrée CLI (orchestration complète)
├── config/
│   └── rules.yaml               # Référentiel de règles de conformité et de sécurité
├── core/
│   ├── models.py                # Schémas Pydantic v2 (SIP, SDP, Anomalie, ECS...)
│   ├── sdp.py                   # Parseur SDP (RFC 4566) autonome
│   ├── parser.py                # Moteur Pyshark + Scapy (extraction réseau)
│   ├── rules_engine.py          # Chargement rules.yaml + application des règles
│   ├── ecs_formatter.py         # Normalisation SIEM (ECS v8.x, export NDJSON)
│   ├── reporter.py              # Génération du rapport Word (docxtpl)
│   └── exceptions.py            # Hiérarchie d'exceptions applicatives
├── scripts/
│   └── build_report_template.py # Génère templates/audit_report_template.docx
└── templates/
    └── audit_report_template.docx  # Gabarit Word (charte + balises Jinja2)

tests/
├── conftest.py                  # Fixtures pytest (RulesConfig, captures synthétiques)
├── fixtures/pcap_builder.py     # Générateurs de captures .pcapng reproduisant
│                                 # les écarts documentés (Scapy)
├── test_sdp.py / test_models.py / test_rules_engine.py
├── test_parser.py / test_ecs_formatter.py / test_reporter.py / test_cli.py
```

## Référentiel de règles (`ivsa/config/rules.yaml`)

| Règle | Source documentaire | Contrôle |
| --- | --- | --- |
| `NAT-001` | Guide OXO — matrice de flux NAT | Isolation des flux SIP/RTP vis-à-vis du SBC opérateur déclaré |
| `ID-002` | Rapport OXO / Asterisk §Interaction Features | Présence de `P-Asserted-Identity` + `Privacy` conforme sur appel masqué |
| `HDR-003` | Rapport Asterisk §Renvoi et transfert | En-têtes interdits (`Referred-By`) et fuite d'IP LAN (RFC 1918) |
| `MET-004` | Rapport OXO / Asterisk §Appel de base | Méthodes SIP hors whitelist STAS dans `Allow` |
| `COD-005` | Rapport OXO / Asterisk §Appel de base | Ordre de priorité codec STAS (G.729 avant G.711A) |
| `FAX-006` | Guide OXO §Paramétrage des fax | Négociation T.38 non supportée sur le Trunk OTT |
| `ENC-007` | Guide OXO (avertissement Trunk non chiffré) | Chiffrement TLS/OAuth2 des flux annexes (Fax2Mail/Mail2Fax) |
| `RFC-008` | RFC 3261 §17 / Rapport OXO §Appel de base | Réponses 480/486 hors machine d'état SIP |
| `RTP-009` | Rapport Asterisk §Comportement anormal des flux RTP | Persistance de flux RTP après clôture `BYE` |
| `SUP-010` | Rapport OXO / Asterisk §SIP OPTIONS | Périodicité de supervision `SIP OPTIONS` (60s) |

## Installation

```bash
python3 -m pip install -r requirements.txt
# Développement / tests :
python3 -m pip install -r requirements-dev.txt
```

## Utilisation

```bash
python3 -m ivsa.cli \
    --pcap capture_trunk_operateur.pcapng \
    --client "Client Démo SA" --site "Siège Paris" \
    --ipbx-vendor Asterisk --ipbx-version 22.1.0 \
    --operator "Opérateur X" --trunk-type "OTT SIP" \
    --sbc-sip-ip 203.0.113.10 --sbc-rtp-ip 203.0.113.10 \
    --output rapport_audit.docx \
    --ecs-output anomalies.ndjson \
    --strict
```

Options principales :

- `--pcap` (obligatoire) : capture réseau `.pcapng` à analyser.
- `--rules` : référentiel YAML alternatif (défaut : `ivsa/config/rules.yaml`).
- `--template` : gabarit Word alternatif.
- `--output` : chemin du rapport Word généré.
- `--ecs-output` : export NDJSON des anomalies au format ECS (ingestion
  Logstash/ELK).
- `--sbc-sip-ip` / `--sbc-rtp-ip` : adresses IP du SBC opérateur (répétables),
  utilisées pour la vérification de la matrice de flux NAT.
- `--strict` : code de sortie `2` si au moins une non-conformité (`FAIL`) est
  détectée (utile en intégration continue).

Le code de sortie est `0` en cas de succès, `1` en cas d'erreur applicative
(capture illisible, référentiel invalide, gabarit corrompu, ...), `2` en mode
`--strict` si des non-conformités ont été détectées.

## Régénérer le gabarit de rapport

Le gabarit Word (`ivsa/templates/audit_report_template.docx`) est un artefact
binaire versionné, généré par :

```bash
python3 -m ivsa.scripts.build_report_template
```

## Tests

```bash
python3 -m pytest
```

La suite de tests génère ses propres captures `.pcapng` synthétiques (via
Scapy) reproduisant fidèlement les écarts documentés dans les rapports de
tests d'interopérabilité de référence, sans dépendre de traces réseau
externes ni d'adresses IP réelles (toutes les adresses utilisées dans les
fixtures de test appartiennent aux plages documentaires RFC 1918/RFC 5737).
Les tests d'intégration nécessitant `tshark` sont automatiquement ignorés si
le binaire n'est pas disponible sur la machine d'exécution.
