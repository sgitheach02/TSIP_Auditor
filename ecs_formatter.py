# =============================================================================
# IVSA - Ilexia Validation & Security Automator
# Référentiel de règles de conformité et de sécurité pour les Trunks SIP ToIP
#
# Ce fichier compile les cas d'usage extraits de la base de connaissances
# documentaire ILEXIA :
#   - Guide_de_Configuration_OTT_UDP_Alcatel_OXO_R6.3_v1.1
#   - Rapport_de_tests_OTT_Alcatel_OXO_R6.3_SFR_ILEXIA_Tests_Interoperabilite_v1.0
#   - Guide_de_Configuration_OXE_R101.1_LEVELSYS_Trunk_SIP_ILEXIA_v1.1
#   - Rapport_de_tests_Asterisk_SFR_ILEXIA_Tests_Interoperabilite_2025_v1
#
# Toute évolution de ce référentiel (nouveau trunk, nouvel opérateur, nouvelle
# STAS) doit se traduire par une mise à jour de ce fichier et non par une
# modification du code applicatif.
# =============================================================================

metadata:
  ruleset_name: "IVSA Trunk SIP Compliance & Security Ruleset"
  ruleset_version: "1.0.0"
  sources:
    - "Guide_de_Configuration_OTT_UDP_Alcatel_OXO_R6.3_v1.1"
    - "Rapport_de_tests_OTT_Alcatel_OXO_R6.3_SFR_ILEXIA_Tests_Interoperabilite_v1.0"
    - "Guide_de_Configuration_OXE_R101.1_LEVELSYS_Trunk_SIP_ILEXIA_v1.1"
    - "Rapport_de_tests_Asterisk_SFR_ILEXIA_Tests_Interoperabilite_2025_v1"

# -----------------------------------------------------------------------------
# 1. Matrice de flux NAT (Port Forwarding / Outbound NAT) de référence.
#    Source : Guide OXO R6.3, §"Caractéristiques du FW/Routeur" (Tableaux 4 et 5).
#    Les adresses de SBC réelles sont fournies par l'opérateur au moment de
#    l'audit (paramètres --sbc-sip-ip et --sbc-rtp-ip de la CLI) ; ce référentiel
#    ne fixe que la structure et les plages attendues.
# -----------------------------------------------------------------------------
nat_matrix:
  enabled: true
  reference: "Guide OXO R6.3 - Tableau 4 (NAT Port Forward / Outbound) et Tableau 5 (Règles de filtrage FW/Routeur)"
  sip_signaling:
    protocol: "UDP"
    port: 5060
  rtp_media:
    protocol: "UDP"
    port_range: [32000, 32255]
    remote_port_range: [50000, 64999]
  isolation_requirement: >
    Les flux SIP (port 5060/UDP) et RTP (plage LAN 32000-32255/UDP) échangés avec le
    SBC opérateur doivent être strictement limités, en émission comme en réception, aux
    adresses IP déclarées du SBC SIP et du SBC RTP. Toute IP source ou destination des
    flux SIP/RTP en dehors de ces adresses déclarées constitue une rupture de l'isolation
    NAT attendue (Outbound NAT statique requis, cf. Tableau 9 - Configuration du NAT statique).
  severity_on_violation: "HIGH"

# -----------------------------------------------------------------------------
# 2. Masquage d'identité de l'appelant (CLIR / *31 / *32 / *55) et appels
#    d'urgence.
#    Source : Rapport OXO §5.3 "Interaction Features" et Rapport Asterisk §5.3.
#    Preuve : From: Anonymous ; P-Asserted-Identity: <sip:SDA@IP> ; Privacy: id
# -----------------------------------------------------------------------------
identity_masking:
  enabled: true
  reference: "Rapport OXO R6.3 §5.3 Interaction Features / Rapport Asterisk §5.3"
  trigger_prefixes: ["*31", "*32", "*55"]
  required_header_p_asserted_identity: true
  privacy_header_accepted_values:
    - "id"
    - "user"
    - "header"
    - "user;id"
    - "id;user"
  anonymous_from_pattern: "anonymous"
  severity_on_missing_pai: "HIGH"
  severity_on_missing_privacy: "MEDIUM"

# -----------------------------------------------------------------------------
# 3. En-têtes SIP formellement interdits sur le Trunk SIP OTT SFR.
#    Source : Rapport Asterisk §5.2 "Renvoi et transfert" - preuve capturée :
#    "Referred-By: <sip:2601@172.30.107.1>" dans un RE-INVITE de transfert
#    aveugle, exposant l'adressage LAN interne (RFC 1918) au réseau opérateur.
# -----------------------------------------------------------------------------
forbidden_headers:
  enabled: true
  reference: "Rapport Asterisk 22.1.0 §5.2 - Referred-By non autorisé sur le Trunk SFR"
  headers:
    - name: "Referred-By"
      severity: "CRITICAL"
      check_rfc1918_leak: true
      description: >
        En-tête SIP interdit par la STAS SFR sur le Trunk OTT. Sa présence expose
        fréquemment l'adressage LAN privé du PABX (RFC 1918) au réseau opérateur,
        constituant une fuite d'information (Information Leakage) exploitable en
        reconnaissance réseau.
    - name: "X-Real-IP"
      severity: "HIGH"
      check_rfc1918_leak: true
      description: >
        En-tête non standard susceptible d'exposer l'adressage interne réel du poste
        appelant derrière le NAT.

# -----------------------------------------------------------------------------
# 4. Méthodes SIP autorisées sur le Trunk (whitelist STAS opérateur).
#    Source : Rapport OXO §5.1 "Appel de base" (Tableau "Méthodes non
#    autorisées") et Rapport Asterisk §5.1 - comparaison des en-têtes Allow
#    IPBX / Plateforme SFR par rapport à la STAS :
#    "Allow: ACK, BYE, INVITE, CANCEL, UPDATE, OPTIONS, PRACK"
# -----------------------------------------------------------------------------
authorized_sip_methods:
  enabled: true
  reference: "STAS SFR - Rapport OXO §5.1 / Rapport Asterisk §5.1, tableau Allow Header"
  whitelist:
    - "INVITE"
    - "ACK"
    - "CANCEL"
    - "BYE"
    - "OPTIONS"
    - "UPDATE"
    - "PRACK"
  severity_on_violation: "MEDIUM"

# -----------------------------------------------------------------------------
# 5. Ordre de priorité des codecs (conformité STAS opérateur).
#    Source : Guide OXO §"Paramétrage des codecs" / §"Configuration avancée"
#    (PrefCodec = G.729 forcé en priorité) et Rapport OXO §5.1 : la STAS SFR
#    impose le G.729 en priorité n°1 et le G.711A en priorité n°2. L'écart
#    constaté et documenté est la plateforme opérateur qui propose le G.711A
#    avant le G.729 (Rapport Asterisk §5.1 : "la plateforme SFR propose le
#    codec G711.A en priorité 1 et G729 en priorité 2 [...] non conforme").
# -----------------------------------------------------------------------------
codec_priority:
  enabled: true
  reference: "STAS SFR - Rapport OXO §5.1 / Rapport Asterisk §5.1"
  expected_order: ["G729", "PCMA"]
  codec_aliases:
    G729: ["G729", "G.729", "ITU-T G.729"]
    PCMA: ["PCMA", "G711A", "G.711A", "G711", "ITU-T G.711 PCMA"]
    PCMU: ["PCMU", "G711U", "G.711U", "ITU-T G.711 PCMU"]
    T38: ["T38", "T.38"]
  ignored_codecs: ["telephone-event", "DynamicRTP-Type-101", "CN"]
  applicable_methods: ["INVITE", "200"]
  severity_on_violation: "MEDIUM"

# -----------------------------------------------------------------------------
# 6. Conformité de la négociation Fax.
#    Source : Guide OXO §"Paramétrage des fax" : "Le T.38 n'étant pas
#    supporté par la solution de téléphonie SIP OTT [...] utiliser le mode
#    G711A" ; confirmé par Rapport Asterisk §Conclusion : "seule cette
#    méthode [G711A] est autorisée sur ce trunk d'après la STAS de SFR".
# -----------------------------------------------------------------------------
fax_conformity:
  enabled: true
  reference: "Guide OXO R6.3 §Paramétrage des fax / Rapport Asterisk §Conclusion"
  forbidden_codec: "T38"
  required_codec: "PCMA"
  severity_on_violation: "HIGH"

# -----------------------------------------------------------------------------
# 7. Chiffrement des flux annexes et du Trunk SIP.
#    Le Trunk OTT documenté est explicitement non chiffré (Guide OXO,
#    avertissement liminaire : "interconnexion SIP non chiffrée entre
#    l'opérateur et le client"). Ce comportement est donc classé INFO
#    (conforme au mode opératoire documenté) tandis que l'absence de TLS/OAuth2
#    sur les flux annexes Fax2Mail / Mail2Fax reste évaluée en sévérité HIGH
#    dès qu'un flux de cette nature est observé en clair dans la capture.
# -----------------------------------------------------------------------------
ancillary_flows_encryption:
  enabled: true
  reference: "Guide OXO R6.3 - avertissement Trunk SIP non chiffré / exigences Fax2Mail/Mail2Fax"
  sip_trunk_cleartext:
    severity: "INFO"
    description: >
      Le Trunk SIP OTT est nominalement non chiffré (UDP en clair) selon la
      documentation de référence. Ce constat est informatif et ne doit pas être
      élevé en non-conformité sauf exigence contractuelle explicite de chiffrement.
  fax2mail_smtp:
    required_transport: "TLS"
    severity: "HIGH"
  mail2fax_imap:
    required_auth: "OAUTH2"
    severity: "HIGH"

# -----------------------------------------------------------------------------
# 8. Écarts à la machine d'état SIP RFC 3261 (§17).
#    Source : Rapport OXO §5.1 "Méthodes non autorisées" / "Non-conformité de
#    la STAS" — rejets SIP non conformes observés sur les codes 480/486 hors
#    contexte transactionnel valide.
# -----------------------------------------------------------------------------
rfc3261_state_machine:
  enabled: true
  reference: "RFC 3261 §17 (Transactions) - Rapport OXO §5.1 / Rapport Asterisk §5.1"
  monitored_final_error_codes: [480, 486]
  severity_on_violation: "HIGH"
  rule_orphan_response: >
    Un code de réponse finale 480 ou 486 est considéré hors machine d'état si aucune
    requête INVITE portant le même Call-ID et le même numéro de CSeq n'a été observée
    au préalable dans la capture (absence de transaction ouverte correspondante).
  rule_late_response: >
    Un code de réponse finale 480 ou 486 est considéré hors machine d'état s'il est émis
    après qu'un BYE a déjà clos le dialogue identifié par le même Call-ID.

# -----------------------------------------------------------------------------
# 9. Persistance anormale des flux RTP après clôture de session.
#    Source : Rapport Asterisk §6 "Comportement anormal des flux RTP après
#    méthode BYE".
# -----------------------------------------------------------------------------
rtp_teardown:
  enabled: true
  reference: "Rapport Asterisk 22.1.0 §6"
  tolerance_ms: 50
  severity_on_violation: "LOW"

# -----------------------------------------------------------------------------
# 10. Supervision du Trunk (Keep-Alive SIP OPTIONS).
#     Source : Rapport OXO §5.5 / Rapport Asterisk §5.5 - "messages OPTIONS
#     toutes les 60 secondes".
# -----------------------------------------------------------------------------
trunk_supervision:
  enabled: true
  reference: "Rapport OXO §5.5 / Rapport Asterisk §5.5"
  expected_options_period_seconds: 60
  tolerance_seconds: 5
  severity_on_violation: "LOW"

# -----------------------------------------------------------------------------
# 11. Normalisation SIEM (Elastic Common Schema).
#     Source : Présentation ELK v2 - pipeline Logstash/PFELK.
# -----------------------------------------------------------------------------
siem_ecs:
  enabled: true
  ecs_version: "8.11"
  dataset: "ivsa.sip_audit"
  event_category: "network"
  event_type: "info"
  network_protocol: "sip"
  observer_vendor: "ILEXIA"
  observer_product: "IVSA"
