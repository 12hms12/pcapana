import argparse
import pyshark
from collections import Counter, defaultdict
from pcapanalyzer.services.protocol_stats import analyze_proto_stats
from pcapanalyzer.services.bandwidth_usage import analyze_bw
from pcapanalyzer.services.visited_domains import analyze_domains
from pcapanalyzer.services.osi_analyzer import analyze_osi_layers


def run_protocol_stats(cap):
    print("\n[*] Running Protocol Statistics...")
    
    stats = analyze_proto_stats(cap)
    
    if 'QUIC' in stats:
        quic_count = stats['QUIC']
        del stats['QUIC']
        stats['QUIC (UDP)'] = quic_count

    total_packets = sum(stats.values())
    print(f"Total Packets: {total_packets}")

    print("\nProtocol Counts (Sorted by Usage):")
    for proto, count in sorted(stats.items(), key=lambda item: item[1], reverse=True):
        percentage = (count * 100) / total_packets if total_packets > 0 else 0
        print(f"{proto:<15}: {count:<10} ({percentage:.2f}%)")


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


def run_osi_analysis(cap):
    print("\n[*] Running OSI Layer Analysis...")
    osi_stats, total_packets = analyze_osi_layers(cap)
    
    print("\n" + "="*50)
    print("OSI Layer Statistics")
    print("="*50)
    
    if total_packets == 0:
        print("No packets found in the capture file.")
    else:
        layer_order = ['Layer 7 (Application)', 'Layer 6 (Presentation)', 'Layer 5 (Session)', 
                       'Layer 4 (Transport)', 'Layer 3 (Network)', 'Layer 2 (Data Link)']
        for layer in layer_order:
            if layer in osi_stats:
                stats = osi_stats[layer]
                count = stats['count']
                percentage = (count * 100) / total_packets
                protocol_list = ", ".join(sorted(list(stats['protocols'])))
                
                layer_num_str = layer.split(' ')[1].replace('(', '')
                layer_name_only = layer.split('(')[-1].replace(')','')
                print(f"Layer {layer_num_str:<2} | {layer_name_only:<20} | {count:<8} ({percentage:.2f}%) | Protocols: {protocol_list}")
    
    print("\n" + "="*50)
    print("Protocols that are counted in multiple layers:")
    print("="*50)
    print("- QUIC: Appears in Layer 7 and Layer 4")
    print("- TLS/SSL: Appears in Layer 6 and is a foundation for many Layer 7 protocols")
    print("- IP/IPv6: Found in Layer 3, acts as a foundation for all higher-level protocols")
    print("- TCP/UDP: Found in Layer 4, acts as a foundation for many Layer 7 protocols")
    print("="*50 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for protocol stats, bandwidth, and visited domains.")
    parser.add_argument("pcap_path", help="Path to the PCAP file")
    args = parser.parse_args()

    print(f"[*] Loading PCAP file: {args.pcap_path}")
    cap = pyshark.FileCapture(args.pcap_path, only_summaries=False)

    try:
        run_osi_analysis(cap)
        cap.reset()

        run_protocol_stats(cap)
        cap.reset()

        run_visited_domains(cap)
        cap.reset()

        run_bandwidth_usage(cap)
        
    finally:
        cap.close()


if __name__ == "__main__":
    main()