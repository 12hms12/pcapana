import sys
import pyshark
from .protocol_stats import analyze_proto_stats
from .bandwidth_usage import analyze_bw
from .visited_domains import analyze_domains


def main(pcap_path):
    print(f"[*] Loading PCAP file: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)

    # --- Protocol Stats ---
    print("[*] Running protocol analysis...")
    protocol_counts = analyze_proto_stats(cap)

    total_packets = sum(protocol_counts.values())
    print(f"Total Packets: {total_packets}")
    print("Protocols:")
    sorted_protocols = sorted((k for k in protocol_counts if k != 'OTHER'))
    if 'OTHER' in protocol_counts:
        sorted_protocols.append('OTHER')
    for proto in sorted_protocols:
        count = protocol_counts[proto]
        print(f"{proto}: {count} ({(count * 100) / total_packets:.2f}%)")

    # --- Bandwidth Usage ---
    print("\n[*] Running bandwidth analysis...")
    cap.reset()
    bandwidth_stats = analyze_bw(cap)
    print("Bandwidth Usage Per IP:")
    for ip, stats in bandwidth_stats.items():
        total = stats['sent'] + stats['received']
        print(f"{ip}: Sent={stats['sent']} bytes, Received={stats['received']} bytes, Total={total} bytes")

    # --- Visited Domains ---
    print("\n[*] Analyzing visited domains...")
    cap.reset()
    top_domains = analyze_domains(cap)
    print("\nMost Visited Domains (by frequency + traffic):")
    for domain, count, size in top_domains[:50]:
        print(f"{domain}: {count} times, {size} bytes")

    cap.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python pcap_parser.py <path_to_pcap>")
        sys.exit(1)

    main(sys.argv[1])
