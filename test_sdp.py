"""Générateurs de captures `.pcapng` synthétiques pour les tests IVSA.

Chaque scénario reproduit fidèlement un écart documenté dans la base de
connaissances ILEXIA (Rapport OXO R6.3, Rapport Asterisk 22.1.0) afin que les
tests valident le comportement réel attendu du moteur de règles, plutôt que
des cas purement artificiels.
"""

from __future__ import annotations

from pathlib import Path

from scapy.all import Ether, IP, UDP, wrpcap

_T0 = 1_782_900_000.0


def _sip_packet(src: str, dst: str, sport: int, dport: int, payload: str, at: float):
    packet = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload.encode()
    packet.time = at
    return packet


def build_referred_by_leak_and_bad_order(base_time: float = _T0) -> list:
    """Reproduit le Rapport Asterisk §5.1/§5.2 : en-tête `Referred-By` exposant
    une IP LAN privée, méthodes SIP non STAS dans `Allow`, et ordre de codec
    non conforme (PCMA avant G729)."""

    invite = (
        "INVITE sip:0781637430@80.118.100.128 SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK1\r\n"
        "From: <sip:0140335051@37.71.240.183>;tag=t1\r\n"
        "To: <sip:0781637430@80.118.100.128>\r\n"
        "Call-ID: call-1\r\nCSeq: 1 INVITE\r\n"
        "Allow: OPTIONS, REGISTER, SUBSCRIBE, NOTIFY, PUBLISH, INVITE, ACK, BYE, CANCEL, "
        "UPDATE, PRACK, MESSAGE, INFO, REFER\r\n"
        "Referred-By: <sip:2601@172.30.107.1>\r\n"
        "Max-Forwards: 70\r\nContent-Type: application/sdp\r\nContent-Length: 200\r\n\r\n"
        "v=0\r\no=- 1 1 IN IP4 37.71.240.183\r\ns=-\r\nc=IN IP4 37.71.240.183\r\nt=0 0\r\n"
        "m=audio 32010 RTP/AVP 8 18 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:18 G729/8000\r\n"
        "a=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n"
    )
    resp200 = (
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK1\r\n"
        "From: <sip:0140335051@37.71.240.183>;tag=t1\r\nTo: <sip:0781637430@80.118.100.128>;tag=t1b\r\n"
        "Call-ID: call-1\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    bye = (
        "BYE sip:0781637430@80.118.100.128 SIP/2.0\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK2\r\n"
        "From: <sip:0140335051@37.71.240.183>;tag=t1\r\nTo: <sip:0781637430@80.118.100.128>;tag=t1b\r\n"
        "Call-ID: call-1\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
    )
    resp200_bye = (
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK2\r\n"
        "From: <sip:0140335051@37.71.240.183>;tag=t1\r\nTo: <sip:0781637430@80.118.100.128>;tag=t1b\r\n"
        "Call-ID: call-1\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n"
    )

    return [
        _sip_packet("37.71.240.183", "80.118.100.128", 5060, 5060, invite, base_time),
        _sip_packet("80.118.100.128", "37.71.240.183", 5060, 5060, resp200, base_time + 0.05),
        _sip_packet("37.71.240.183", "80.118.100.128", 5060, 5060, bye, base_time + 30),
        _sip_packet("80.118.100.128", "37.71.240.183", 5060, 5060, resp200_bye, base_time + 30.01),
        # Flux RTP résiduel après la clôture BYE (Rapport Asterisk §6).
        Ether()
        / IP(src="37.71.240.183", dst="80.118.100.128")
        / UDP(sport=32010, dport=50048)
        / bytes(180),
    ]


def build_masked_call_missing_pai(base_time: float = _T0 + 60) -> list:
    """Appel masqué (Privacy: id) sans P-Asserted-Identity — non conforme au
    Rapport OXO §5.3 / Rapport Asterisk §5.3 qui exigent le PAI en complément."""

    invite = (
        "INVITE sip:0781637431@80.118.100.128 SIP/2.0\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK3\r\n"
        "From: Anonymous <sip:anonymous@anonymous.invalid>;tag=t2\r\nTo: <sip:0781637431@80.118.100.128>\r\n"
        "Call-ID: call-2\r\nCSeq: 1 INVITE\r\nPrivacy: id\r\nContent-Length: 0\r\n\r\n"
    )
    resp486 = (
        "SIP/2.0 486 Busy Here\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK3\r\n"
        "From: Anonymous <sip:anonymous@anonymous.invalid>;tag=t2\r\nTo: <sip:0781637431@80.118.100.128>;tag=t2b\r\n"
        "Call-ID: call-2\r\nCSeq: 99 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    return [
        _sip_packet("37.71.240.183", "80.118.100.128", 5060, 5060, invite, base_time),
        # CSeq 99 orphelin : aucune transaction INVITE correspondante -> écart RFC 3261.
        _sip_packet("80.118.100.128", "37.71.240.183", 5060, 5060, resp486, base_time + 0.05),
    ]


def build_masked_call_compliant(base_time: float = _T0 + 120) -> list:
    """Appel masqué conforme : PAI et Privacy corrects (Rapport OXO §5.3)."""

    invite = (
        "INVITE sip:0781637432@80.118.100.128 SIP/2.0\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK4\r\n"
        "From: Anonymous <sip:anonymous@anonymous.invalid>;tag=t3\r\nTo: <sip:0781637432@80.118.100.128>\r\n"
        "Call-ID: call-3\r\nCSeq: 1 INVITE\r\nPrivacy: id\r\n"
        "P-Asserted-Identity: <sip:0185342713@37.71.240.183>\r\nContent-Length: 0\r\n\r\n"
    )
    resp200 = (
        "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bK4\r\n"
        "From: Anonymous <sip:anonymous@anonymous.invalid>;tag=t3\r\nTo: <sip:0781637432@80.118.100.128>;tag=t3b\r\n"
        "Call-ID: call-3\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n"
    )
    return [
        _sip_packet("37.71.240.183", "80.118.100.128", 5060, 5060, invite, base_time),
        _sip_packet("80.118.100.128", "37.71.240.183", 5060, 5060, resp200, base_time + 0.05),
    ]


def build_fax_t38_negotiation(base_time: float = _T0 + 180) -> list:
    """Négociation fax T.38 sur le Trunk OTT — non supportée (Guide OXO
    §Paramétrage des fax)."""

    invite = (
        "INVITE sip:fax@80.118.100.128 SIP/2.0\r\nVia: SIP/2.0/UDP 172.30.107.1:5060;branch=z9hG4bK5\r\n"
        "From: <sip:0140335051@172.30.107.1>;tag=t4\r\nTo: <sip:fax@80.118.100.128>\r\n"
        "Call-ID: call-4\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: 220\r\n\r\n"
        "v=0\r\no=- 1 1 IN IP4 172.30.107.1\r\ns=-\r\nc=IN IP4 172.30.107.1\r\nt=0 0\r\n"
        "m=image 32012 udptl t38\r\n"
    )
    return [_sip_packet("172.30.107.1", "80.118.100.128", 5060, 5060, invite, base_time)]


def build_options_keepalive(base_time: float = _T0 + 240, count: int = 3, period: float = 60.0) -> list:
    """Séquence de supervision SIP OPTIONS toutes les 60s (Rapport OXO §5.5)."""

    packets = []
    for index in range(count):
        options = (
            f"OPTIONS sip:80.118.100.128 SIP/2.0\r\nVia: SIP/2.0/UDP 37.71.240.183:5060;branch=z9hG4bKo{index}\r\n"
            f"From: <sip:trunk@37.71.240.183>;tag=o{index}\r\nTo: <sip:80.118.100.128>\r\n"
            f"Call-ID: options-{index}\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n"
        )
        packets.append(
            _sip_packet(
                "37.71.240.183", "80.118.100.128", 5060, 5060, options, base_time + index * period
            )
        )
    return packets


def build_full_scenario() -> list:
    """Agrège l'ensemble des scénarios ci-dessus pour un test d'intégration
    couvrant chacune des dix règles du référentiel IVSA."""

    packets = []
    packets += build_referred_by_leak_and_bad_order()
    packets += build_masked_call_missing_pai()
    packets += build_masked_call_compliant()
    packets += build_fax_t38_negotiation()
    packets += build_options_keepalive()
    return packets


def write_pcap(path: Path, packets: list) -> Path:
    wrpcap(str(path), packets)
    return path
