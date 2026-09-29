"""
Protocol identification logic for SecureMailScope (Member 2).

Identifies whether a packet is most likely SMTP, IMAP, POP3, or UNKNOWN.

Strategy (in order of confidence):
1. If TShark/PyShark already recognized an application-layer protocol
   in its "highest layer" dissection (it actually inspected packet
   content/behavior), trust that first.
2. Otherwise, fall back to well-known port numbers. Port-based
   identification is a *hint*, not proof — a port number alone never
   guarantees what protocol is actually running, so this is only used
   when TShark itself wasn't confident.
3. If neither approach gives a confident answer, classify as UNKNOWN.
"""

from typing import Optional

# Well-known ports for each protocol (plaintext + implicit/explicit TLS ports)
SMTP_PORTS = {25, 465, 587}
IMAP_PORTS = {143, 993}
POP3_PORTS = {110, 995}

# "Highest layer" names TShark commonly reports for these protocols
SMTP_LAYER_HINTS = {"smtp"}
IMAP_LAYER_HINTS = {"imap"}
POP3_LAYER_HINTS = {"pop", "pop3"}


def identify_by_layer(highest_layer: Optional[str]) -> Optional[str]:
    """
    Try to identify the protocol using TShark's own protocol dissection.

    This is more trustworthy than a port number because TShark actually
    inspected packet content/behavior, not just the port used.

    Returns "SMTP" / "IMAP" / "POP3" or None if no confident match.
    """
    if not highest_layer:
        return None

    layer = highest_layer.strip().lower()

    if layer in SMTP_LAYER_HINTS:
        return "SMTP"
    if layer in IMAP_LAYER_HINTS:
        return "IMAP"
    if layer in POP3_LAYER_HINTS:
        return "POP3"
    return None


def identify_by_port(src_port: Optional[int], dst_port: Optional[int]) -> Optional[str]:
    """
    Fall back to well-known port numbers when TShark didn't already
    recognize the application protocol.

    We check BOTH src_port and dst_port because either side of the
    connection could be using the well-known port (e.g. a server
    replying from port 25 back to a random client port).

    This is a heuristic, not proof: a port number can be reused for an
    unrelated protocol. Callers should treat this as "likely", not
    "confirmed" — which is exactly why we never claim more than
    port-based identification actually supports.
    """
    ports = {p for p in (src_port, dst_port) if p is not None}

    if ports & SMTP_PORTS:
        return "SMTP"
    if ports & IMAP_PORTS:
        return "IMAP"
    if ports & POP3_PORTS:
        return "POP3"
    return None


def identify_application_protocol(
    highest_layer: Optional[str],
    src_port: Optional[int],
    dst_port: Optional[int],
) -> str:
    """
    Main entry point used by the parser for each packet.

    Order of trust:
      1. TShark's own dissection (identify_by_layer)
      2. Well-known port fallback (identify_by_port)
      3. UNKNOWN if neither is confident
    """
    by_layer = identify_by_layer(highest_layer)
    if by_layer:
        return by_layer

    by_port = identify_by_port(src_port, dst_port)
    if by_port:
        return by_port

    return "UNKNOWN"
