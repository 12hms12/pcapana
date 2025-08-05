import pyshark
from collections import Counter

def analyze_proto_stats(capture):
    print("Analyzing all protocol usage...\n")

    protocol_counts = Counter()

    for pkt in capture:
        try:
            # Use the highest_layer attribute to get the most specific protocol name
            protocol_name = pkt.highest_layer
            protocol_counts[protocol_name] += 1
        except AttributeError:
            protocol_counts['UNKNOWN'] += 1
        except Exception:
            protocol_counts['ERROR'] += 1

    return protocol_counts

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python protocol_stats.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Loading PCAP file: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path) 
    
    try:
        stats = analyze_proto_stats(cap)
        
        # Rename QUIC for better context
        if 'QUIC' in stats:
            quic_count = stats['QUIC']
            del stats['QUIC']
            stats['QUIC (UDP)'] = quic_count

        total_packets = sum(stats.values())
        print("="*50)
        print(f"Total Packets: {total_packets}")
        print("="*50)
        print("Protocol Usage:")
        for proto, count in sorted(stats.items(), key=lambda item: item[1], reverse=True):
            percentage = (count * 100) / total_packets if total_packets > 0 else 0
            print(f"{proto:<15}: {count:<10} ({percentage:.2f}%)")
    finally:
        cap.close()