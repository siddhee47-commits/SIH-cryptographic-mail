# SIH-cryptographic-mail

# Member 2 Module — PCAP Parsing + Protocol Identification

## SecureMailScope (SIH 26159)

## A. My exact responsibility

> **PCAP → Packet Extraction → Protocol Identification → Structured Output**

Nothing more. This module does **not** touch TCP stream reconstruction, SMTP/IMAP/POP3 content analysis, STARTTLS/TLS/certificate analysis, AI/ML, risk scoring, MongoDB, FastAPI, or the dashboard/reports. Those belong to Members 3–6.

## B. Where these files go

The PCAP parser is maintained as its own package:

```text
<your-repo-root>/
└── pcap_parser/
    ├── __init__.py
    ├── parser.py
    ├── protocol_identifier.py
    ├── models.py
    ├── exceptions.py
    ├── test_parser.py
    ├── requirements.txt
    └── sample_pcaps/
        └── sample.pcap