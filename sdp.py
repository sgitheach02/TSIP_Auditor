"""Moteur de parsing réseau IVSA.

Combine deux moteurs complémentaires sur une même capture `.pcapng` :

* **Pyshark** (moteur TShark) pour le parsing SIP/SDP applicatif profond :
  extraction fiable des en-têtes SIP (méthode, codes de réponse, Call-ID,
  CSeq, Allow, Privacy, P-Asserted-Identity, Referred-By, ...) au moyen du
  dissecteur SIP mature de Wireshark/TShark.
* **Scapy** pour l'analyse des trames de bas niveau : reconstruction des
  flux IP/UDP (matrice NAT SIP/RTP) et corrélation temporelle fine entre la
  clôture d'un dialogue (BYE) et la persistance de trafic RTP, à un niveau
  que le dissecteur SIP ne restitue pas.

Le corps SDP est quant à lui délégué à `core.sdp` (parseur RFC 4566 autonome)
plutôt qu'à l'arbre de dissection SDP de TShark, dont la structure imbriquée
diffère selon qu'un ou plusieurs médias (`m=`) sont présents.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, NamedTuple

import pyshark
from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from ivsa.core.exceptions import PcapParsingError
from ivsa.core.models import (
    NetworkEndpoint,
    NetworkFlow,
    FlowPurpose,
    OptionsKeepAlive,
    RtpTeardownSample,
    SdpMediaDescription,
    SipDialog,
    SipMessage,
    Transport,
)
from ivsa.core.rules_engine import AncillaryFlowObservations
from ivsa.core.sdp import decode_message_body, parse_sdp_body

_SIP_PORT = 5060
_SIP_TLS_PORT = 5061
_SMTP_PORTS = {25, 587, 465}
_SMTP_IMPLICIT_TLS_PORT = 465
_IMAP_PORTS = {143, 993}
_IMAP_IMPLICIT_TLS_PORT = 993


class RawUdpFrame(NamedTuple):
    """Un enregistrement UDP/IP brut extrait par Scapy, indépendant de SIP."""

    frame_number: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload_length: int


class RawTcpFrame(NamedTuple):
    """Un enregistrement TCP/IP brut, utilisé pour la détection passive des
    flux annexes (Fax2Mail SMTP / Mail2Fax IMAP) lorsqu'ils sont capturés."""

    frame_number: int
    timestamp: datetime
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes


def _search_fields(node: Any, field_name: str) -> list[Any]:
    """Recherche récursive, insensible à la casse, d'un champ TShark dans la
    structure imbriquée `packet.<layer>._all_fields` (dictionnaires et listes
    mêlés selon le nombre d'occurrences du champ dans le message).
    """

    results: list[Any] = []
    lowered = field_name.lower()
    if isinstance(node, dict):
        for key, value in node.items():
            if key.endswith("_raw"):
                continue
            if key.lower() == lowered and not isinstance(value, (dict, list)):
                results.append(value)
            elif isinstance(value, (dict, list)):
                results.extend(_search_fields(value, field_name))
    elif isinstance(node, list):
        for item in node:
            results.extend(_search_fields(item, field_name))
    return results


def _first(values: list[Any]) -> str | None:
    return str(values[0]) if values else None


class PcapAnalyzer:
    """Analyseur d'une capture réseau `.pcapng` unique.

    Chaque instance est liée à un fichier de capture et met en cache la
    lecture Scapy des trames brutes (`_read_raw_udp_frames`) afin qu'un seul
    parcours du fichier soit nécessaire pour toutes les analyses de bas
    niveau (matrice NAT, persistance RTP).
    """

    def __init__(self, pcap_path: str | Path) -> None:
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.is_file():
            raise PcapParsingError(f"Fichier de capture introuvable : {self.pcap_path}")
        self._raw_frames_cache: list[RawUdpFrame] | None = None
        self._raw_tcp_frames_cache: list[RawTcpFrame] | None = None
        self._total_frame_count: int = 0

    # ------------------------------------------------------------ Pyshark
    def extract_sip_messages(self) -> list[SipMessage]:
        """Ouvre la capture et extrait chaque message SIP en un `SipMessage`
        strictement validé. Les paquets dont la structure ne peut être
        interprétée sont ignorés individuellement ; une erreur n'est levée
        que si *aucun* message SIP valide n'a pu être construit alors que
        des paquets SIP étaient présents dans la capture.
        """

        capture: pyshark.FileCapture | None = None
        messages: list[SipMessage] = []
        packets_seen = 0
        construction_errors: list[str] = []

        try:
            capture = pyshark.FileCapture(
                str(self.pcap_path),
                display_filter="sip",
                use_json=True,
                include_raw=True,
                keep_packets=False,
            )
            for packet in capture:
                packets_seen += 1
                try:
                    message = self._build_sip_message(packet)
                except (ValueError, AttributeError, KeyError) as exc:
                    construction_errors.append(
                        f"trame {getattr(packet, 'number', '?')}: {exc}"
                    )
                    continue
                if message is not None:
                    messages.append(message)
        except PcapParsingError:
            raise
        except Exception as exc:  # frontière avec le sous-processus TShark
            raise PcapParsingError(
                f"Échec de l'analyse TShark/Pyshark de la capture {self.pcap_path} : {exc}"
            ) from exc
        finally:
            if capture is not None:
                capture.close()

        if packets_seen > 0 and not messages:
            raise PcapParsingError(
                f"{packets_seen} paquet(s) SIP détecté(s) mais aucun n'a pu être décodé "
                f"correctement. Détails : {'; '.join(construction_errors[:5])}"
            )
        return messages

    def _build_sip_message(self, packet: Any) -> SipMessage | None:
        if not hasattr(packet, "sip"):
            return None

        transport, source, destination = self._endpoints(packet)
        if transport is None:
            return None

        sip_fields = packet.sip._all_fields
        frame_number = int(packet.frame_info.number)
        timestamp = datetime.fromtimestamp(float(packet.sniff_timestamp), tz=timezone.utc)

        method = _first(_search_fields(sip_fields, "sip.Method"))
        status_code_raw = _first(_search_fields(sip_fields, "sip.Status-Code"))
        is_request = method is not None

        call_id = _first(_search_fields(sip_fields, "sip.Call-ID")) or _first(
            _search_fields(sip_fields, "sip.call_id_generated")
        )
        if not call_id:
            return None

        cseq_seq_raw = _first(_search_fields(sip_fields, "sip.CSeq.seq"))
        allow_raw = _first(_search_fields(sip_fields, "sip.Allow"))
        allow_methods = (
            [m.strip().upper() for m in allow_raw.split(",") if m.strip()] if allow_raw else []
        )

        raw_header_block = _first(_search_fields(sip_fields, "sip.msg_hdr")) or ""
        content_type = _first(_search_fields(sip_fields, "sip.Content-Type")) or ""
        sdp_media: list[SdpMediaDescription] = []
        if "sdp" in content_type.lower():
            body_raw = _first(_search_fields(sip_fields, "sip.msg_body"))
            if body_raw:
                sdp_media = parse_sdp_body(decode_message_body(body_raw))

        status_code = int(status_code_raw) if status_code_raw and status_code_raw.isdigit() else None
        reason_phrase = None
        if status_code is not None:
            status_line = _first(_search_fields(sip_fields, "sip.Status-Line")) or ""
            reason_phrase = status_line.replace("SIP/2.0", "").strip()
            reason_phrase = reason_phrase[len(str(status_code)) :].strip() if reason_phrase.startswith(
                str(status_code)
            ) else reason_phrase

        return SipMessage(
            frame_number=frame_number,
            timestamp=timestamp,
            transport=transport,
            source=source,
            destination=destination,
            is_request=is_request,
            method=method,
            status_code=status_code,
            reason_phrase=reason_phrase,
            call_id=call_id,
            cseq_number=int(cseq_seq_raw) if cseq_seq_raw and cseq_seq_raw.isdigit() else None,
            cseq_method=_first(_search_fields(sip_fields, "sip.CSeq.method")),
            from_uri=_first(_search_fields(sip_fields, "sip.from.addr"))
            or _first(_search_fields(sip_fields, "sip.From")),
            from_tag=_first(_search_fields(sip_fields, "sip.from.tag")),
            to_uri=_first(_search_fields(sip_fields, "sip.to.addr"))
            or _first(_search_fields(sip_fields, "sip.To")),
            to_tag=_first(_search_fields(sip_fields, "sip.to.tag")),
            allow_methods=allow_methods,
            privacy=_first(_search_fields(sip_fields, "sip.Privacy")),
            p_asserted_identity=_first(_search_fields(sip_fields, "sip.P-Asserted-Identity")),
            referred_by=_first(_search_fields(sip_fields, "sip.Referred-by")),
            contact_uri=_first(_search_fields(sip_fields, "sip.Contact")),
            raw_header_block=raw_header_block,
            sdp_media=sdp_media,
        )

    @staticmethod
    def _endpoints(
        packet: Any,
    ) -> tuple[Transport | None, NetworkEndpoint | None, NetworkEndpoint | None]:
        if hasattr(packet, "udp"):
            transport = Transport.UDP
            transport_layer = packet.udp
        elif hasattr(packet, "tcp"):
            transport = Transport.TCP
            transport_layer = packet.tcp
        else:
            return None, None, None

        if hasattr(packet, "ip"):
            ip_layer = packet.ip
        elif hasattr(packet, "ipv6"):
            ip_layer = packet.ipv6
        else:
            return None, None, None

        source = NetworkEndpoint(ip=ip_layer.src, port=int(transport_layer.srcport))
        destination = NetworkEndpoint(ip=ip_layer.dst, port=int(transport_layer.dstport))
        return transport, source, destination

    # -------------------------------------------------------------- Scapy
    def _read_raw_udp_frames(self) -> list[RawUdpFrame]:
        if self._raw_frames_cache is not None:
            return self._raw_frames_cache

        frames: list[RawUdpFrame] = []
        total = 0
        try:
            with PcapReader(str(self.pcap_path)) as reader:
                for index, packet in enumerate(reader, start=1):
                    total += 1
                    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                    udp_layer = packet.getlayer(UDP)
                    if ip_layer is None or udp_layer is None:
                        continue
                    frames.append(
                        RawUdpFrame(
                            frame_number=index,
                            timestamp=datetime.fromtimestamp(float(packet.time), tz=timezone.utc),
                            src_ip=str(ip_layer.src),
                            src_port=int(udp_layer.sport),
                            dst_ip=str(ip_layer.dst),
                            dst_port=int(udp_layer.dport),
                            payload_length=len(bytes(udp_layer.payload)),
                        )
                    )
        except (Scapy_Exception, OSError) as exc:
            raise PcapParsingError(
                f"Échec de la lecture Scapy de la capture {self.pcap_path} : {exc}"
            ) from exc

        self._total_frame_count = total
        self._raw_frames_cache = frames
        return frames

    def total_frame_count(self) -> int:
        if self._raw_frames_cache is None:
            self._read_raw_udp_frames()
        return self._total_frame_count

    def extract_network_flows(self, sip_messages: list[SipMessage]) -> list[NetworkFlow]:
        """Reconstruit les flux SIP/RTP au niveau IP/UDP pour la matrice NAT.

        Les ports RTP pertinents sont déterminés à partir des lignes `m=`
        négociées dans les messages SIP déjà extraits (le port SIP 5060
        étant, lui, connu a priori).
        """

        known_rtp_ports = {
            media.port for message in sip_messages for media in message.sdp_media if media.port
        }

        flows: dict[tuple, NetworkFlow] = {}
        for frame in self._read_raw_udp_frames():
            if frame.src_port == _SIP_PORT or frame.dst_port == _SIP_PORT:
                purpose = FlowPurpose.SIP_SIGNALING
            elif frame.src_port in known_rtp_ports or frame.dst_port in known_rtp_ports:
                purpose = FlowPurpose.RTP_MEDIA
            else:
                continue

            key = (frame.src_ip, frame.src_port, frame.dst_ip, frame.dst_port, purpose.value)
            if key not in flows:
                flows[key] = NetworkFlow(
                    protocol=Transport.UDP,
                    purpose=purpose,
                    local_endpoint=NetworkEndpoint(ip=frame.src_ip, port=frame.src_port),
                    remote_endpoint=NetworkEndpoint(ip=frame.dst_ip, port=frame.dst_port),
                    frame_numbers=[],
                )
            flows[key].frame_numbers.append(frame.frame_number)

        return list(flows.values())

    def extract_rtp_teardown_samples(self, dialogs: list[SipDialog]) -> list[RtpTeardownSample]:
        """Corrèle, pour chaque dialogue clos par BYE, les paquets UDP échangés
        sur les ports RTP négociés après l'instant de clôture."""

        raw_frames = self._read_raw_udp_frames()
        samples: list[RtpTeardownSample] = []

        for dialog in dialogs:
            bye_timestamp = dialog.bye_timestamp()
            if bye_timestamp is None:
                continue

            rtp_endpoints: set[tuple[str, int]] = set()
            for message in dialog.messages:
                for media in message.sdp_media:
                    if not media.port:
                        continue
                    address = media.connection_address or str(message.source.ip)
                    rtp_endpoints.add((address, media.port))
            if not rtp_endpoints:
                continue

            frames_after: list[int] = []
            last_timestamp: datetime | None = None
            for frame in raw_frames:
                if frame.timestamp <= bye_timestamp:
                    continue
                if (frame.src_ip, frame.src_port) in rtp_endpoints or (
                    frame.dst_ip,
                    frame.dst_port,
                ) in rtp_endpoints:
                    frames_after.append(frame.frame_number)
                    if last_timestamp is None or frame.timestamp > last_timestamp:
                        last_timestamp = frame.timestamp

            if frames_after and last_timestamp is not None:
                delay_ms = (last_timestamp - bye_timestamp).total_seconds() * 1000
                samples.append(
                    RtpTeardownSample(
                        call_id=dialog.call_id,
                        bye_timestamp=bye_timestamp,
                        last_rtp_timestamp=last_timestamp,
                        frames_after_bye=frames_after,
                        delay_after_bye_ms=delay_ms,
                    )
                )

        return samples

    def _read_raw_tcp_frames(self) -> list[RawTcpFrame]:
        if self._raw_tcp_frames_cache is not None:
            return self._raw_tcp_frames_cache

        frames: list[RawTcpFrame] = []
        try:
            with PcapReader(str(self.pcap_path)) as reader:
                for index, packet in enumerate(reader, start=1):
                    ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
                    tcp_layer = packet.getlayer(TCP)
                    if ip_layer is None or tcp_layer is None:
                        continue
                    frames.append(
                        RawTcpFrame(
                            frame_number=index,
                            timestamp=datetime.fromtimestamp(float(packet.time), tz=timezone.utc),
                            src_ip=str(ip_layer.src),
                            src_port=int(tcp_layer.sport),
                            dst_ip=str(ip_layer.dst),
                            dst_port=int(tcp_layer.dport),
                            payload=bytes(tcp_layer.payload),
                        )
                    )
        except (Scapy_Exception, OSError) as exc:
            raise PcapParsingError(
                f"Échec de la lecture Scapy (TCP) de la capture {self.pcap_path} : {exc}"
            ) from exc

        self._raw_tcp_frames_cache = frames
        return frames

    def detect_ancillary_observations(self, sip_messages: list[SipMessage]) -> AncillaryFlowObservations:
        """Détection passive des flux annexes (Trunk SIP-TLS, Fax2Mail SMTP,
        Mail2Fax IMAP) et de leur niveau de chiffrement, lorsqu'ils sont
        présents dans la capture. La détection reste nécessairement partielle :
        un flux chiffré ne permet pas d'inspecter son contenu applicatif, ce
        qui est pris en compte (un flux TLS/implicite est considéré comme
        satisfaisant l'objectif de confidentialité même si le mécanisme
        d'authentification appliqué ne peut être observé)."""

        tcp_frames = self._read_raw_tcp_frames()

        def _matches(frame: RawTcpFrame, ports: set[int]) -> bool:
            return frame.src_port in ports or frame.dst_port in ports

        sip_trunk_uses_tls = any(_matches(f, {_SIP_TLS_PORT}) for f in tcp_frames) or any(
            message.transport == Transport.TLS for message in sip_messages
        )

        smtp_frames = [f for f in tcp_frames if _matches(f, _SMTP_PORTS)]
        smtp_observed = bool(smtp_frames)
        smtp_implicit_tls = any(_matches(f, {_SMTP_IMPLICIT_TLS_PORT}) for f in smtp_frames)
        smtp_starttls = any(b"STARTTLS" in f.payload.upper() for f in smtp_frames)
        smtp_uses_tls = smtp_implicit_tls or smtp_starttls

        imap_frames = [f for f in tcp_frames if _matches(f, _IMAP_PORTS)]
        imap_observed = bool(imap_frames)
        imap_implicit_tls = any(_matches(f, {_IMAP_IMPLICIT_TLS_PORT}) for f in imap_frames)
        imap_starttls = any(b"STARTTLS" in f.payload.upper() for f in imap_frames)
        imap_encrypted = imap_implicit_tls or imap_starttls
        imap_oauth2_observed = any(b"XOAUTH2" in f.payload.upper() for f in imap_frames)
        imap_uses_oauth2 = imap_encrypted or imap_oauth2_observed

        return AncillaryFlowObservations(
            sip_trunk_observed=bool(sip_messages),
            sip_trunk_uses_tls=sip_trunk_uses_tls,
            smtp_observed=smtp_observed,
            smtp_uses_tls=smtp_uses_tls,
            imap_observed=imap_observed,
            imap_uses_oauth2=imap_uses_oauth2,
        )

    # ----------------------------------------------------------- Agrégation
    @staticmethod
    def build_dialogs(sip_messages: list[SipMessage]) -> list[SipDialog]:
        grouped: dict[str, list[SipMessage]] = defaultdict(list)
        for message in sip_messages:
            grouped[message.call_id].append(message)

        dialogs = []
        for call_id, messages in grouped.items():
            ordered = sorted(messages, key=lambda m: m.timestamp)
            dialogs.append(SipDialog(call_id=call_id, messages=ordered))
        return dialogs

    @staticmethod
    def extract_keepalives(sip_messages: list[SipMessage]) -> list[OptionsKeepAlive]:
        grouped: dict[tuple[str, int, str, int], OptionsKeepAlive] = {}
        for message in sip_messages:
            if not (message.is_request and message.method == "OPTIONS"):
                continue
            key = (
                str(message.source.ip),
                message.source.port,
                str(message.destination.ip),
                message.destination.port,
            )
            if key not in grouped:
                grouped[key] = OptionsKeepAlive(
                    source=message.source, destination=message.destination
                )
            grouped[key].timestamps.append(message.timestamp)
            grouped[key].frame_numbers.append(message.frame_number)
        return list(grouped.values())
