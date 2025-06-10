import pyshark
from collections import Counter

def analyze_proto_stats(capture):
    print("Analyzing protocol usage...")

    protocol_counts = Counter()

    for pkt in capture:
        try:
            if 'TCP' in pkt:
                if 'HTTP' in pkt:
                    protocol_counts['HTTP'] += 1
                elif 'HTTPS' in pkt:
                    protocol_counts['HTTPS'] += 1
                else:
                    protocol_counts['TCP'] += 1
            elif 'UDP' in pkt:
                if 'DNS' in pkt:
                    protocol_counts['DNS'] += 1
                else:
                    protocol_counts['UDP'] += 1
            elif 'ICMP' in pkt:
                protocol_counts['ICMP'] += 1
            elif 'ARP' in pkt:
                protocol_counts['ARP'] += 1
            else:
                high_layer = pkt.highest_layer
                if high_layer not in ['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'HTTPS', 'ARP']:
                    protocol_counts['OTHER'] += 1
        except Exception:
            protocol_counts['ERROR'] += 1

    return protocol_counts

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python protocol_stats.py <pcap_file>")
        sys.exit(1)

    cap = pyshark.FileCapture(sys.argv[1])
    stats = analyze_proto_stats(cap)
    for proto, count in stats.items():
        print(f"{proto}: {count}")
    cap.close()
