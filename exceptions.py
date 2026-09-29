"""
Custom exceptions for the PCAP parsing module (Member 2 - SecureMailScope).

Having our own exception types lets other team members (and us) catch
specific failure cases instead of guessing what went wrong from a
generic Exception.
"""


class PcapParsingError(Exception):
    """Base class for all errors raised by this module."""
    pass


class PcapFileNotFoundError(PcapParsingError):
    """Raised when the given .pcap/.pcapng file does not exist on disk."""
    pass


class InvalidPcapFileError(PcapParsingError):
    """Raised when the file exists but cannot be parsed as a valid PCAP
    (wrong extension, or TShark failed to open it)."""
    pass


class EmptyPcapFileError(PcapParsingError):
    """Raised when the PCAP file contains zero packets."""
    pass
