# Member 2 Module — PCAP Parsing + Protocol Identification
### SecureMailScope (SIH 26159)

## A. My exact responsibility

> **PCAP → Packet Extraction → Protocol Identification → Structured Output**

Nothing more. This module does **not** touch TCP stream reconstruction, SMTP/IMAP/POP3
content analysis, STARTTLS/TLS/certificate analysis, AI/ML, risk scoring, MongoDB,
FastAPI, or the dashboard/reports. Those belong to Members 3–6.

## B. Where these files go

Your prompt's placeholder for "existing project structure" was left blank, so I don't
actually know your repo's real layout. Rather than guessing and inventing a `backend/`
folder (which you explicitly said not to do), the minimal, self-contained option is:

```
<your-repo-root>/
└── pcap_parser/          ← everything below goes here, as its own package
    ├── __init__.py
    ├── parser.py
    ├── protocol_identifier.py
    ├── models.py
    ├── exceptions.py
    ├── test_parser.py
    ├── requirements.txt
    └── sample_pcaps/
        └── sample.pcap   ← you add this
```

Agree with your team on where `pcap_parser/` sits relative to their folders (e.g. next
to a future `backend/` folder, not inside it). Nothing here assumes or depends on any
other folder existing.

## C. Files created / D. What each does

| File | Purpose |
|---|---|
| `__init__.py` | Public API: `from pcap_parser import parse_pcap`. |
| `parser.py` | The main engine — opens the PCAP with PyShark/TShark, loops over packets, extracts fields, and calls the protocol identifier. |
| `protocol_identifier.py` | Decides SMTP / IMAP / POP3 / UNKNOWN for each packet — TShark's own dissection first, well-known ports as a fallback. |
| `models.py` | `PacketRecord` (one packet) and `ProtocolSummary` (aggregate counts) dataclasses — the structured output Member 3 consumes. |
| `exceptions.py` | Specific exception types (`PcapFileNotFoundError`, `InvalidPcapFileError`, `EmptyPcapFileError`) so callers can handle failures precisely. |
| `test_parser.py` | Demo script — parses a sample PCAP and prints packet counts, protocol breakdown, and sample records. |
| `requirements.txt` | Python dependency (`pyshark`). |
| `sample_pcaps/` | Where you drop a test capture (`sample.pcap`). |

---

## Setup

### 1. Install TShark (Windows)

PyShark doesn't parse packets itself — it drives the TShark program (part of Wireshark).

1. Download and install **Wireshark** from https://www.wireshark.org/download.html
2. During install, keep **"Install TShark"** checked (it's checked by default).
3. Note the install path — usually `C:\Program Files\Wireshark`.
4. Add that folder to your **PATH** environment variable (Windows Settings → "Edit the
   system environment variables" → Environment Variables → edit `Path` → add the
   Wireshark folder).

### 2. Verify TShark is installed

Open a new Command Prompt / PowerShell and run:

```
tshark --version
```

If it prints a version number, you're set. If it says "not recognized", the PATH step
above didn't take — restart your terminal, or re-check the install path.

### 3. Install Python dependencies

From inside `pcap_parser/`'s parent folder:

```
pip install -r pcap_parser/requirements.txt
```

This installs `pyshark`, which is a thin Python wrapper around TShark.

### Why PyShark (and not plain Scapy) here?

Scapy is great for *building/crafting* packets and does its own protocol dissection,
but its built-in awareness of application-layer protocols like SMTP/IMAP/POP3 is
limited — it mostly just sees "TCP data". TShark has mature, actively-maintained
dissectors for SMTP/IMAP/POP3 that can recognize the protocol from actual packet
behavior, not just the port number. Since accurate protocol identification is the
whole point of this module, PyShark (TShark) is the better fit. Scapy would be the
right tool for Member 3 or 4 if they need to actively construct/replay packets.

---

## Running the demo

1. Put a test capture at `pcap_parser/sample_pcaps/sample.pcap` (any `.pcap`/`.pcapng`
   with some SMTP/IMAP/POP3 traffic — you can generate one with Wireshark while sending
   a test email, or find a sample capture online).
2. From your repo root:

```
python -m pcap_parser.test_parser
```

This prints total packets, the SMTP/IMAP/POP3/UNKNOWN breakdown, the first 5 packet
records (IPs, ports, protocol), and the full summary dict.

---

## D. Team integration — how another member imports this

```python
from pcap_parser import parse_pcap

packets, summary = parse_pcap("some/path/capture.pcap")

for record in packets:
    print(record.to_dict())

print(summary.to_dict())
```

No one needs to touch the internals of `pcap_parser/` — just import `parse_pcap` and
use the returned data.

---

## Member 3 handoff

```python
from pcap_parser import parse_pcap

packets, summary = parse_pcap("sample.pcap")
```

**What `packets` contains:** a list of `PacketRecord` objects, one per packet that had
an IP layer, in original packet order. Each has: `packet_number`, `timestamp`, `src_ip`,
`dst_ip`, `src_port`, `dst_port`, `transport_protocol`, `application_protocol` (SMTP /
IMAP / POP3 / UNKNOWN), `packet_length`.

**Which fields Member 3 should use:**
- `src_ip` + `dst_ip` + `src_port` + `dst_port` (the classic 4-tuple, plus
  `transport_protocol`) to group packets into individual TCP connections.
- `application_protocol` to filter down to only the packets relevant to a given
  connection's mail protocol before reconstructing it.
- `packet_number` / `timestamp` to keep reconstructed streams in correct order.

**How to group packets into the same communication:** packets sharing the same
unordered `{src_ip:src_port, dst_ip:dst_port}` pair (in either direction) belong to
the same TCP connection. That grouping — and actually reassembling TCP segments into
a coherent byte stream/session — is Member 3's job, not implemented here.

**What I'm intentionally NOT providing (Member 3's territory):**
- TCP sequence/ack numbers, flags, or any reassembly logic.
- Reconstructed request/response bodies (SMTP commands, IMAP/POP3 dialogue).
- Any judgment about whether a session is "one conversation" beyond the raw 4-tuple.

---

## Beginner-friendly explanations (for the viva)

**PCAP file** — a recording of network traffic. Every packet that crossed a network
interface while capturing gets saved, in order, with a timestamp.

**Packet** — one unit of data sent over a network — like one envelope in a mail
system, carrying a small chunk of a larger conversation.

**Source/Destination IP** — the network "addresses" of the two computers talking:
who sent the packet (source) and who it's going to (destination).

**Source/Destination port** — a number identifying *which program* on each computer
is involved. A server typically listens on a well-known port (e.g. 25 for SMTP);
the client usually uses a random high-numbered port.

**TCP** — a reliable transport protocol that email protocols run on top of; it makes
sure data arrives in order and nothing is silently lost.

**SMTP / IMAP / POP3** — the three protocols this project cares about:
- **SMTP** (ports 25/465/587): sending email between servers, or from a client to
  its outgoing server.
- **IMAP** (ports 143/993): a client reading/syncing mail with a server (mail stays
  on the server).
- **POP3** (ports 110/995): a client downloading mail from a server (often removing
  it from the server after).

**How the code identifies them** — first it trusts TShark's own protocol dissection
(it actually inspected the packet's behavior). If TShark isn't sure, it falls back to
checking whether either side of the connection used one of the well-known ports above.
If neither gives a confident answer, it's labeled `UNKNOWN` rather than guessed.

**How data moves through this module** — `parse_pcap()` opens the file with PyShark →
loops through every packet → for each one, pulls out IP/port/length info and asks
`protocol_identifier.py` what protocol it thinks this is → builds a `PacketRecord` →
collects all records into a list, plus a running `ProtocolSummary` count → returns both
to whoever called it (Member 3, or a test script).

**What you can explain in the presentation:**
1. Why PCAP parsing has to be the *first* stage of a passive email-security pipeline.
2. Why protocol identification uses layered trust (dissection first, ports as
   fallback) instead of blindly trusting port numbers — a firewall/IDS evasion
   technique is running a protocol on a non-standard port.
3. Why one bad packet (malformed, missing layers, truncated capture) is caught and
   skipped instead of crashing the whole analysis — real-world PCAPs are messy.
4. The clean boundary with Member 3: this module never looks inside TCP payload
   content or reassembles streams, it only classifies individual packets.
