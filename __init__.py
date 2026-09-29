"""
SecureMailScope — Member 2 module: PCAP Parsing + Protocol Identification.

Public API:

    from pcap_parser import parse_pcap

    packets, summary = parse_pcap("path/to/file.pcap")
"""

from .parser import parse_pcap
from .models import PacketRecord, ProtocolSummary
from .exceptions import (
    PcapParsingError,
    PcapFileNotFoundError,
    InvalidPcapFileError,
    EmptyPcapFileError,
)

__all__ = [
    "parse_pcap",
    "PacketRecord",
    "ProtocolSummary",
    "PcapParsingError",
    "PcapFileNotFoundError",
    "InvalidPcapFileError",
    "EmptyPcapFileError",
]
