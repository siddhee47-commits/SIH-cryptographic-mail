"""
Simple demo/test script for Member 2's PCAP parsing module.

Run from the folder that CONTAINS pcap_parser/ (i.e. your repo root):

    python -m pcap_parser.test_parser
    python -m pcap_parser.test_parser path/to/other_sample.pcap

If no path is given, it looks for a sample PCAP at:
    pcap_parser/sample_pcaps/sample.pcap
"""

import sys
import os

from .parser import parse_pcap
from .exceptions import PcapParsingError

DEFAULT_SAMPLE = os.path.join(
    os.path.dirname(__file__), "sample_pcaps", "sample.pcap"
)


def run_demo(pcap_path: str) -> None:
    print(f"\nAnalyzing: {pcap_path}\n" + "-" * 50)

    try:
        packets, summary = parse_pcap(pcap_path)
    except PcapParsingError as exc:
        print(f"Failed to parse PCAP: {exc}")
        return

    print(f"Total packets in file:  {summary.total_packets}")
    print(f"Skipped (bad) packets:  {summary.skipped_packets}")
    print(f"SMTP packets:           {summary.smtp_packets}")
    print(f"IMAP packets:           {summary.imap_packets}")
    print(f"POP3 packets:           {summary.pop3_packets}")
    print(f"UNKNOWN packets:        {summary.unknown_packets}")

    print("\nFirst 5 packet records (src/dst IP + port, protocol):")
    for record in packets[:5]:
        print(
            f"  #{record.packet_number} "
            f"{record.src_ip}:{record.src_port} -> "
            f"{record.dst_ip}:{record.dst_port} "
            f"[{record.transport_protocol}] "
            f"app={record.application_protocol} "
            f"len={record.packet_length}"
        )

    print("\nFull protocol summary dict (this is what Member 6 will store):")
    print(summary.to_dict())


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SAMPLE
    run_demo(path)
