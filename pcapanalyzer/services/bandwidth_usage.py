from collections import defaultdict

def analyze_bw(capture):
    """
    Analyzes bandwidth usage per IP address in a pcap file.

    Args:
        capture (pyshark.FileCapture): A pyshark capture object.

    Returns:
        defaultdict: A dictionary-like object with IP addresses as keys,
                     and a dictionary of 'sent' and 'received' bytes as values.
    """
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
            # Skip packets that don't have IP layers or other required attributes
            continue  

    return bandwidth

if __name__ == "__main__":
    import sys
    import pyshark

    if len(sys.argv) != 2:
        print("Usage: python bandwidth_usage.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Analyzing bandwidth usage in: {pcap_path}")
    
    # Use a try...finally block to ensure the capture file is always closed
    cap = pyshark.FileCapture(pcap_path)
    try:
        stats = analyze_bw(cap)
        print("\nBandwidth Usage Per IP:")
        
        # Sort the output by total bandwidth (sent + received) for better visibility
        sorted_stats = sorted(stats.items(), key=lambda item: item[1]['sent'] + item[1]['received'], reverse=True)
        
        for ip, stats in sorted_stats:
            total = stats['sent'] + stats['received']
            # Use f-string formatting to align the output nicely
            print(f"  {ip:<15}: Sent={stats['sent']:<10} bytes | Received={stats['received']:<10} bytes | Total={total:<10} bytes")
    finally:
        cap.close()