"""
PCAP Parser for SecureMailScope (Member 2 — PCAP Parsing + Protocol ID).

Reads a .pcap / .pcapng file with PyShark (which drives TShark under
the hood) and turns each packet into a clean, structured PacketRecord.

STOPS at: packet extraction + protocol identification.
Does NOT do: TCP stream reconstruction, SMTP/IMAP/POP3 content
analysis, TLS/STARTTLS/certificate analysis, AI/ML, risk scoring,
storage, or the API layer. Those belong to other team members.
"""

import os
import logging
import shutil
from typing import List, Optional, Tuple


try:
    import pyshark
except ImportError as e:
    raise ImportError(
        "pyshark is not installed. Run: pip install pyshark\n"
        "You also need TShark installed on your system — see README.md."
    ) from e

"""
PCAP Parser for SecureMailScope (Member 2 — PCAP Parsing + Protocol ID).

Reads a .pcap / .pcapng file with PyShark (which drives TShark under
the hood) and turns each packet into a clean, structured PacketRecord.

STOPS at: packet extraction + protocol identification.
Does NOT do: TCP stream reconstruction, SMTP/IMAP/POP3 content
analysis, TLS/STARTTLS/certificate analysis, AI/ML, risk scoring,
storage, or the API layer. Those belong to other team members.
"""

import os
import logging
import shutil
from typing import List, Optional, Tuple

def _find_tshark() -> str:
    """
    Find TShark without depending on one developer's Windows path.

    Priority:
    1. TSHARK_PATH environment variable
    2. TShark available on system PATH
    3. Common Windows installation locations
    """
    env_path = os.environ.get("TSHARK_PATH")
    if env_path and os.path.isfile(env_path):
        return env_path

    path = shutil.which("tshark")
    if path:
        return path

    common_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
    ]

    for path in common_paths:
        if os.path.isfile(path):
            return path

    raise InvalidPcapFileError(
        "TShark was not found. Install Wireshark/TShark or set "
        "the TSHARK_PATH environment variable."
    )

try:
    import pyshark
except ImportError as e:
    raise ImportError(
        "pyshark is not installed. Run: pip install pyshark\n"
        "You also need TShark installed on your system — see README.md."
    ) from e

from .exceptions import (
    PcapFileNotFoundError,
    InvalidPcapFileError,
    EmptyPcapFileError,
)
from .models import PacketRecord, ProtocolSummary
from .protocol_identifier import identify_application_protocol

logger = logging.getLogger("secure_mail_scope.pcap_parser")
logging.basicConfig(level=logging.INFO)

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng")


def _validate_file(file_path: str) -> None:
    """Check the file exists and has a supported extension before we
    even try to open it with TShark."""
    if not os.path.isfile(file_path):
        raise PcapFileNotFoundError(f"PCAP file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise InvalidPcapFileError(
            f"Unsupported file extension '{ext}'. "
            f"Expected one of {SUPPORTED_EXTENSIONS}."
        )


def _safe_int(value) -> Optional[int]:
    """Convert a value to int, returning None instead of raising if it
    can't be converted (e.g. a missing or garbled field)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_packet_record(packet, packet_number: int) -> Optional[PacketRecord]:
    """
    Pull the fields we care about out of a single pyshark packet object.

    Returns None if the packet isn't usable for us (no IP layer at
    all, e.g. an ARP packet — or an unexpected internal error while
    reading a field). Either way we skip it rather than crashing, so
    one malformed packet can never take down the whole analysis.
    """
    try:
        # --- Timestamp (available on every sniffed packet) ---
        timestamp = str(getattr(packet, "sniff_time", "UNKNOWN"))

        # --- Packet length ---
        packet_length = _safe_int(getattr(packet, "length", None))

        # --- IP layer (skip packet entirely if neither IPv4 nor IPv6) ---
        src_ip = dst_ip = None
        if hasattr(packet, "ip"):
            src_ip = getattr(packet.ip, "src", None)
            dst_ip = getattr(packet.ip, "dst", None)
        elif hasattr(packet, "ipv6"):
            src_ip = getattr(packet.ipv6, "src", None)
            dst_ip = getattr(packet.ipv6, "dst", None)
        else:
            # No IP layer at all -> irrelevant to email traffic (e.g. ARP)
            return None

        # --- Transport layer (email protocols run over TCP) ---
        src_port = dst_port = None
        transport_protocol = None

        if hasattr(packet, "tcp"):
            transport_protocol = "TCP"
            src_port = _safe_int(getattr(packet.tcp, "srcport", None))
            dst_port = _safe_int(getattr(packet.tcp, "dstport", None))
        elif hasattr(packet, "udp"):
            transport_protocol = "UDP"
            src_port = _safe_int(getattr(packet.udp, "srcport", None))
            dst_port = _safe_int(getattr(packet.udp, "dstport", None))
        # else: no TCP/UDP layer -> transport_protocol/ports stay None.
        # We still keep the packet (it has an IP layer), it just can
        # never resolve to SMTP/IMAP/POP3 without a transport layer.

        # --- Highest-layer protocol hint from TShark's own dissection ---
        highest_layer = getattr(packet, "highest_layer", None)

        # --- Identify SMTP / IMAP / POP3 / UNKNOWN ---
        application_protocol = identify_application_protocol(
            highest_layer=highest_layer,
            src_port=src_port,
            dst_port=dst_port,
        )

        return PacketRecord(
            packet_number=packet_number,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport_protocol,
            application_protocol=application_protocol,
            packet_length=packet_length,
        )

    except Exception as exc:
        # One bad/unusual packet must never crash the whole analysis.
        logger.warning("Skipping packet #%s due to error: %s", packet_number, exc)
        return None


def parse_pcap(file_path: str) -> Tuple[List[PacketRecord], ProtocolSummary]:
    """
    Main entry point for Member 2's module.

    Parameters
    ----------
    file_path : str
        Path to a .pcap or .pcapng file.

    Returns
    -------
    (packets, summary)
        packets: list[PacketRecord]  -- one entry per successfully parsed packet
        summary: ProtocolSummary     -- aggregate counts for the whole file

    Raises
    ------
    PcapFileNotFoundError   -- file doesn't exist
    InvalidPcapFileError    -- wrong extension, or TShark couldn't open it
    EmptyPcapFileError      -- file has zero packets
    """
    _validate_file(file_path)

    packets_out: List[PacketRecord] = []
    summary = ProtocolSummary()

    try:
        capture = pyshark.FileCapture(
        file_path,
        keep_packets=False,
        tshark_path=r"E:\SY\Wireshark\tshark.exe"
        )
    except Exception as exc:
        raise InvalidPcapFileError(
            f"TShark could not open '{file_path}': {exc}"
        ) from exc

    packet_number = 0
    try:
        for raw_packet in capture:
            packet_number += 1
            record = _extract_packet_record(raw_packet, packet_number)

            if record is None:
                summary.skipped_packets += 1
                continue

            packets_out.append(record)

            if record.application_protocol == "SMTP":
                summary.smtp_packets += 1
            elif record.application_protocol == "IMAP":
                summary.imap_packets += 1
            elif record.application_protocol == "POP3":
                summary.pop3_packets += 1
            else:
                summary.unknown_packets += 1
    finally:
        capture.close()

    if packet_number == 0:
        raise EmptyPcapFileError(f"'{file_path}' contains no packets.")

    summary.total_packets = packet_number

    logger.info(
        "Parsed %s: %s total, %s kept, %s skipped.",
        file_path, summary.total_packets, len(packets_out), summary.skipped_packets,
    )

    return packets_out, summary


from .exceptions import (
    PcapFileNotFoundError,
    InvalidPcapFileError,
    EmptyPcapFileError,
)
from .models import PacketRecord, ProtocolSummary
from .protocol_identifier import identify_application_protocol

logger = logging.getLogger("secure_mail_scope.pcap_parser")
logging.basicConfig(level=logging.INFO)

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng")


def _validate_file(file_path: str) -> None:
    """Check the file exists and has a supported extension before we
    even try to open it with TShark."""
    if not os.path.isfile(file_path):
        raise PcapFileNotFoundError(f"PCAP file not found: {file_path}")

    ext = os.path.splitext(file_path)[1].lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise InvalidPcapFileError(
            f"Unsupported file extension '{ext}'. "
            f"Expected one of {SUPPORTED_EXTENSIONS}."
        )


def _safe_int(value) -> Optional[int]:
    """Convert a value to int, returning None instead of raising if it
    can't be converted (e.g. a missing or garbled field)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _extract_packet_record(packet, packet_number: int) -> Optional[PacketRecord]:
    """
    Pull the fields we care about out of a single pyshark packet object.

    Returns None if the packet isn't usable for us (no IP layer at
    all, e.g. an ARP packet — or an unexpected internal error while
    reading a field). Either way we skip it rather than crashing, so
    one malformed packet can never take down the whole analysis.
    """
    try:
        # --- Timestamp (available on every sniffed packet) ---
        timestamp = str(getattr(packet, "sniff_time", "UNKNOWN"))

        # --- Packet length ---
        packet_length = _safe_int(getattr(packet, "length", None))

        # --- IP layer (skip packet entirely if neither IPv4 nor IPv6) ---
        src_ip = dst_ip = None
        if hasattr(packet, "ip"):
            src_ip = getattr(packet.ip, "src", None)
            dst_ip = getattr(packet.ip, "dst", None)
        elif hasattr(packet, "ipv6"):
            src_ip = getattr(packet.ipv6, "src", None)
            dst_ip = getattr(packet.ipv6, "dst", None)
        else:
            # No IP layer at all -> irrelevant to email traffic (e.g. ARP)
            return None

        # --- Transport layer (email protocols run over TCP) ---
        src_port = dst_port = None
        transport_protocol = None

        if hasattr(packet, "tcp"):
            transport_protocol = "TCP"
            src_port = _safe_int(getattr(packet.tcp, "srcport", None))
            dst_port = _safe_int(getattr(packet.tcp, "dstport", None))
        elif hasattr(packet, "udp"):
            transport_protocol = "UDP"
            src_port = _safe_int(getattr(packet.udp, "srcport", None))
            dst_port = _safe_int(getattr(packet.udp, "dstport", None))
        # else: no TCP/UDP layer -> transport_protocol/ports stay None.
        # We still keep the packet (it has an IP layer), it just can
        # never resolve to SMTP/IMAP/POP3 without a transport layer.

        # --- Highest-layer protocol hint from TShark's own dissection ---
        highest_layer = getattr(packet, "highest_layer", None)

        # --- Identify SMTP / IMAP / POP3 / UNKNOWN ---
        application_protocol = identify_application_protocol(
            highest_layer=highest_layer,
            src_port=src_port,
            dst_port=dst_port,
        )

        return PacketRecord(
            packet_number=packet_number,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            transport_protocol=transport_protocol,
            application_protocol=application_protocol,
            packet_length=packet_length,
        )

    except Exception as exc:
        # One bad/unusual packet must never crash the whole analysis.
        logger.warning("Skipping packet #%s due to error: %s", packet_number, exc)
        return None


def parse_pcap(file_path: str) -> Tuple[List[PacketRecord], ProtocolSummary]:
    """
    Main entry point for Member 2's module.

    Parameters
    ----------
    file_path : str
        Path to a .pcap or .pcapng file.

    Returns
    -------
    (packets, summary)
        packets: list[PacketRecord]  -- one entry per successfully parsed packet
        summary: ProtocolSummary     -- aggregate counts for the whole file

    Raises
    ------
    PcapFileNotFoundError   -- file doesn't exist
    InvalidPcapFileError    -- wrong extension, or TShark couldn't open it
    EmptyPcapFileError      -- file has zero packets
    """
    _validate_file(file_path)

    packets_out: List[PacketRecord] = []
    summary = ProtocolSummary()

    try:
        tshark_path = _find_tshark()

        capture = pyshark.FileCapture(
        file_path,
        keep_packets=False,
        tshark_path=tshark_path
       )
    except Exception as exc:
        raise InvalidPcapFileError(
            f"TShark could not open '{file_path}': {exc}"
        ) from exc

    packet_number = 0
    try:
        for raw_packet in capture:
            packet_number += 1
            record = _extract_packet_record(raw_packet, packet_number)

            if record is None:
                summary.skipped_packets += 1
                continue

            packets_out.append(record)

            if record.application_protocol == "SMTP":
                summary.smtp_packets += 1
            elif record.application_protocol == "IMAP":
                summary.imap_packets += 1
            elif record.application_protocol == "POP3":
                summary.pop3_packets += 1
            else:
                summary.unknown_packets += 1
    finally:
        capture.close()

    if packet_number == 0:
        raise EmptyPcapFileError(f"'{file_path}' contains no packets.")

    summary.total_packets = packet_number

    logger.info(
        "Parsed %s: %s total, %s kept, %s skipped.",
        file_path, summary.total_packets, len(packets_out), summary.skipped_packets,
    )

    return packets_out, summary
