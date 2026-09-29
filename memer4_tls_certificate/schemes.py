
from dataclasses import dataclass
from typing import Optional


@dataclass
class CertificateInfo:
    subject: str
    issue: str
    valid_from: str
    valid_to: str
    expired: bool
    public_key_algorithm: str
    public_key_bits: int
    signature_algorithm: str
    chain_valid: bool


@dataclass
class TLSAnalysis:
    tls_version: str
    cipher_suite: str
    key_exchange: str
    starttls_detected: bool
    handshake_detected: bool
    forward_secrecy: bool
    certificate: Optional[CertificateInfo]
    findings: list