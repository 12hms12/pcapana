from collections import defaultdict

def analyze_bw(capture):
    bandwidth = defaultdict(lambda: {'sent': 0, 'received': 0})

    for pkt in capture:
        try:
            if 'IP' in pkt:
                src = pkt.ip.src
                dst = pkt.ip.dst
                size = int(pkt.length)

                bandwidth[src]['sent'] += size
                bandwidth[dst]['received'] += size
        except AttributeError:
            continue  

    return bandwidth

if __name__ == "__main__":
    import sys
    import pyshark

    if len(sys.argv) != 2:
        print("Usage: python bandwidth_usage.py <pcap_file>")
        sys.exit(1)

    cap = pyshark.FileCapture(sys.argv[1])
    stats = analyze_bw(cap)
    for proto, count in stats.items():
        print(f"{proto}: {count}")
    cap.close()
