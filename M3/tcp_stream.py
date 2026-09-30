from scapy.all import rdpcap, IP, TCP
import json
import os

pcap_file = "input/email.pcap"
output_file = "output/member3_results.json"

if not os.path.exists(pcap_file):
    print("PCAP file not found")
    print("Put the PCAP file inside the input folder")
    exit()

packets = rdpcap(pcap_file)

streams = {}

for packet in packets:

    if IP in packet and TCP in packet:

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        if src_port in [25, 465, 587]:
            protocol = "SMTP"

        elif dst_port in [25, 465, 587]:
            protocol = "SMTP"

        elif src_port in [143, 993]:
            protocol = "IMAP"

        elif dst_port in [143, 993]:
            protocol = "IMAP"

        elif src_port in [110, 995]:
            protocol = "POP3"

        elif dst_port in [110, 995]:
            protocol = "POP3"

        else:
            protocol = "TCP"

        stream_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"

        if stream_id not in streams:
            streams[stream_id] = {
                "source_ip": src_ip,
                "source_port": src_port,
                "destination_ip": dst_ip,
                "destination_port": dst_port,
                "protocol": protocol,
                "packet_count": 0,
                "data": ""
            }

        streams[stream_id]["packet_count"] += 1

        if packet[TCP].payload:
            data = bytes(packet[TCP].payload)

            text = data.decode("utf-8", errors="ignore")

            streams[stream_id]["data"] += text

results = []

for stream_id, stream in streams.items():

    data = stream["data"].upper()

    starttls = "STARTTLS" in data

    email_commands = []

    commands = [
        "HELO",
        "EHLO",
        "MAIL FROM",
        "RCPT TO",
        "AUTH",
        "LOGIN",
        "STARTTLS",
        "USER",
        "PASS"
    ]

    for command in commands:
        if command in data:
            email_commands.append(command)

    result = {
        "stream_id": stream_id,
        "source_ip": stream["source_ip"],
        "source_port": stream["source_port"],
        "destination_ip": stream["destination_ip"],
        "destination_port": stream["destination_port"],
        "protocol": stream["protocol"],
        "packet_count": stream["packet_count"],
        "starttls_detected": starttls,
        "email_commands": email_commands,
        "data": stream["data"]
    }

    results.append(result)

with open(output_file, "w", encoding="utf-8") as file:
    json.dump(results, file, indent=4)

print("Member 3 analysis completed")
print("Total TCP streams:", len(results))
print("Output saved to:", output_file)