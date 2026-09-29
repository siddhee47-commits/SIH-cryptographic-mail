"""
Data structures used across the PCAP parsing module.

Member 3 (TCP stream reconstruction) and later members consume these
structures, so we keep them simple, predictable, and easy to
serialize (e.g. to JSON) for Member 6's FastAPI layer.
"""

from dataclasses import dataclass, asdict
from typing import Optional


@dataclass
class PacketRecord:
    """
    Represents one parsed packet, with only the fields the rest of the
    pipeline (Member 3 onward) actually needs.

    NOTE: We intentionally do NOT include raw payload bytes, TCP
    sequence/ack numbers, or reassembled stream data here — that is
    Member 3's job (TCP stream reconstruction), not ours.
    """
    packet_number: int
    timestamp: str
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    transport_protocol: Optional[str]   # "TCP", "UDP", or None
    application_protocol: str           # "SMTP" | "IMAP" | "POP3" | "UNKNOWN"
    packet_length: Optional[int]

    def to_dict(self) -> dict:
        """Convert this record to a plain dict (handy for JSON output)."""
        return asdict(self)


@dataclass
class ProtocolSummary:
    """Aggregate counts across an entire PCAP file."""
    total_packets: int = 0        # every packet the file contained
    smtp_packets: int = 0
    imap_packets: int = 0
    pop3_packets: int = 0
    unknown_packets: int = 0      # had an IP layer but no confident protocol match
    skipped_packets: int = 0      # errored out or had no usable IP layer (e.g. ARP)

    def to_dict(self) -> dict:
        return asdict(self)
