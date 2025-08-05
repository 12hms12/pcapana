import argparse
import pyshark
from collections import Counter, defaultdict
from pcapanalyzer.services.protocol_stats import analyze_proto_stats
from pcapanalyzer.services.bandwidth_usage import analyze_bw
from pcapanalyzer.services.visited_domains import analyze_domains, extract_top_level_domain
from pcapanalyzer.services.osi_analyzer import analyze_osi_layers
from pcapanalyzer.services.port_analyzer import analyze_ports, WELL_KNOWN_PORTS


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


def run_port_analysis(cap):
    print("\n[*] Running Port Analysis...")
    connections = analyze_ports(cap)

    print("\n==============================================")
    print("Port Analysis by IP Address")
    print("==============================================")
    
    if not connections:
        print("No IP connections found.")
    else:
        # Sort local IPs for consistent output
        for local_ip in sorted(connections.keys()):
            print(f"Local IP: {local_ip}")
            
            # Sort ports for consistent output
            for local_port in sorted(connections[local_ip].keys(), key=int):
                service_name = WELL_KNOWN_PORTS.get(int(local_port), "Dynamic Port")
                
                # Format remote connections to include IP, Port, and Protocol
                remote_connections = sorted(
                    list(connections[local_ip][local_port]), 
                    key=lambda x: (x[0], x[1], x[2])
                )
                
                remote_conn_strings = []
                for ip, port, protocol in remote_connections:
                    # Check if the remote port is well-known and add the service name
                    remote_service = WELL_KNOWN_PORTS.get(int(port), protocol)
                    remote_conn_strings.append(f"{ip}:{port} ({remote_service})")
                
                print(f"  -> {service_name} (Port {local_port})")
                print(f"     Communicated with: {', '.join(remote_conn_strings)}")
            print()


def run_visited_domains(cap):
    print("\n[*] Running Visited Domains Analysis...")
    domains = analyze_domains(cap)

    print("\nMost Visited Domains (by frequency + traffic):")
    print("--------------------------------------------------")
    
    if not domains:
        print("No domains found in the capture file.")
    else:
        for domain, count, size in domains[:50]:
            print(f"  {domain:<30}: {count:<5} times, {size:<10} bytes")


def run_bandwidth_usage(cap):
    print("\n[*] Running Bandwidth Analysis...")
    bandwidth_stats = analyze_bw(cap)

    print("Bandwidth Usage Per IP:")
    # Sort the output by total bandwidth (sent + received) for better visibility
    sorted_stats = sorted(bandwidth_stats.items(), key=lambda item: item[1]['sent'] + item[1]['received'], reverse=True)
    
    for ip, stats in sorted_stats:
        total = stats['sent'] + stats['received']
        # Use f-string formatting to align the output nicely
        print(f"  {ip:<15}: Sent={stats['sent']:<10} bytes | Received={stats['received']:<10} bytes | Total={total:<10} bytes")


def main():
    parser = argparse.ArgumentParser(description="Analyze a PCAP file for protocol stats, bandwidth, and visited domains.")
    parser.add_argument("pcap_path", help="Path to the PCAP file")
    args = parser.parse_args()

    print(f"[*] Loading PCAP file: {args.pcap_path}")
    cap = pyshark.FileCapture(args.pcap_path, only_summaries=False)

    try:
        # New order of execution
        run_protocol_stats(cap)
        cap.reset()

        run_osi_analysis(cap)
        cap.reset()

        run_port_analysis(cap)
        cap.reset()

        run_visited_domains(cap)
        cap.reset()

        run_bandwidth_usage(cap)
        
    finally:
        cap.close()


if __name__ == "__main__":
    main()