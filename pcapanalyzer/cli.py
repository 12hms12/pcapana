import argparse
import pyshark
from pcapanalyzer.services.protocol_stats import analyze_proto_stats
from pcapanalyzer.services.bandwidth_usage import analyze_bw
from pcapanalyzer.services.visited_domains import analyze_domains


def run_protocol_stats(cap):
    print("\n[*] Running Protocol Statistics...")
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


def run_bandwidth_usage(cap):
    print("\n[*] Running Bandwidth Analysis...")
    bandwidth_stats = analyze_bw(cap)

    print("Bandwidth Usage Per IP:")
    for ip, stats in bandwidth_stats.items():
        total = stats['sent'] + stats['received']
        print(f"{ip}: Sent={stats['sent']} bytes, Received={stats['received']} bytes, Total={total} bytes")


def run_visited_domains(cap):
    print("\n[*] Running Visited Domains Analysis...")
    domains = analyze_domains(cap)

    print("\nTop Visited Domains (by frequency + traffic):")
    for domain, count, size in domains[:50]:
        print(f"{domain}: {count} times, {size} bytes")


def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for protocol stats, bandwidth, and visited domains.")
    parser.add_argument("pcap_path", help="Path to the PCAP file")
    args = parser.parse_args()

    print(f"[*] Loading PCAP file: {args.pcap_path}")
    cap = pyshark.FileCapture(args.pcap_path, only_summaries=False)

    try:
        run_protocol_stats(cap)
        cap.reset()

        run_visited_domains(cap)
        cap.reset()

        run_bandwidth_usage(cap)
        
    finally:
        cap.close()
