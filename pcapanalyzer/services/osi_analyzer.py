import pyshark
from collections import defaultdict

# This mapping organizes protocols by their respective OSI layers.
OSI_LAYER_PROTOCOLS = {
    'Layer 7 (Application)': {'DNS', 'HTTP', 'FTP', 'SSH', 'SMTP', 'RDP', 'QUIC'},
    'Layer 6 (Presentation)': {'TLS', 'SSL'},
    'Layer 5 (Session)': {'RPC'},
    'Layer 4 (Transport)': {'TCP', 'UDP', 'QUIC'},
    'Layer 3 (Network)': {'IP', 'IPv6', 'ICMP', 'ICMPv6'},
    'Layer 2 (Data Link)': {'ARP', 'LLC', 'STP', 'EAPOL'},
}

def analyze_osi_layers(capture):
    """
    Analyzes packet distribution across OSI layers by counting packets that contain protocols
    from each layer. A single packet can be counted in multiple layers.

    Args:
        capture (pyshark.FileCapture): The pyshark capture object.

    Returns:
        tuple: A tuple containing a dictionary of layer stats and the total packet count.
    """
    print("Analyzing packets by OSI Layer (Multi-Layer Count)...")
    
    layer_stats = defaultdict(lambda: {'count': 0, 'protocols': set()})
    total_packets = 0

    for pkt in capture:
        total_packets += 1
        
        # Check for protocols in each layer and count them
        # Layer 7
        for proto in OSI_LAYER_PROTOCOLS['Layer 7 (Application)']:
            if proto in pkt:
                layer_stats['Layer 7 (Application)']['count'] += 1
                if proto == 'QUIC':
                    layer_stats['Layer 7 (Application)']['protocols'].add('QUIC (UDP)')
                else:
                    layer_stats['Layer 7 (Application)']['protocols'].add(proto)
                break 

        # Layer 6
        for proto in OSI_LAYER_PROTOCOLS['Layer 6 (Presentation)']:
            if proto in pkt:
                layer_stats['Layer 6 (Presentation)']['count'] += 1
                layer_stats['Layer 6 (Presentation)']['protocols'].add(proto)
                break

        # Layer 5
        for proto in OSI_LAYER_PROTOCOLS['Layer 5 (Session)']:
            if proto in pkt:
                layer_stats['Layer 5 (Session)']['count'] += 1
                layer_stats['Layer 5 (Session)']['protocols'].add(proto)
                break

        # Layer 4
        for proto in OSI_LAYER_PROTOCOLS['Layer 4 (Transport)']:
            if proto in pkt:
                layer_stats['Layer 4 (Transport)']['count'] += 1
                if proto == 'QUIC':
                    layer_stats['Layer 4 (Transport)']['protocols'].add('QUIC (UDP)')
                else:
                    layer_stats['Layer 4 (Transport)']['protocols'].add(proto)
                break

        # Layer 3
        for proto in OSI_LAYER_PROTOCOLS['Layer 3 (Network)']:
            if proto in pkt:
                layer_stats['Layer 3 (Network)']['count'] += 1
                layer_stats['Layer 3 (Network)']['protocols'].add(proto)
                break

        # Layer 2
        for proto in OSI_LAYER_PROTOCOLS['Layer 2 (Data Link)']:
            if proto in pkt:
                layer_stats['Layer 2 (Data Link)']['count'] += 1
                layer_stats['Layer 2 (Data Link)']['protocols'].add(proto)
                break
            
    return layer_stats, total_packets

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python osi_analyzer.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Loading PCAP file: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    
    try:
        osi_stats, total_packets = analyze_osi_layers(cap)
        
        print("\n" + "="*50)
        print("OSI Layer Statistics")
        print("="*50)
        
        if total_packets == 0:
            print("No packets found in the capture file.")
        else:
            # Sort layers by their number (L7 down to L2)
            layer_order = ['Layer 7 (Application)', 'Layer 6 (Presentation)', 'Layer 5 (Session)', 
                           'Layer 4 (Transport)', 'Layer 3 (Network)', 'Layer 2 (Data Link)']
            for layer in layer_order:
                if layer in osi_stats:
                    stats = osi_stats[layer]
                    count = stats['count']
                    percentage = (count * 100) / total_packets
                    protocol_list = ", ".join(sorted(list(stats['protocols'])))
                    
                    layer_num_str = layer.split(' ')[1].replace('(', '')
                    # Extract just the name from within the parentheses for cleaner output
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

    finally:
        cap.close()