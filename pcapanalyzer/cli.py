import argparse
import pyshark
import sys
import os
from collections import Counter, defaultdict
from io import StringIO
from pcapanalyzer.services.protocol_stats import analyze_proto_stats
from pcapanalyzer.services.bandwidth_usage import analyze_bw
from pcapanalyzer.services.visited_domains import analyze_domains, extract_top_level_domain
from pcapanalyzer.services.osi_analyzer import analyze_osi_layers
from pcapanalyzer.services.port_analyzer import analyze_ports, WELL_KNOWN_PORTS
from pcapanalyzer.services.report_generator import generate_html_report


def run_protocol_stats(cap):
    stats = analyze_proto_stats(cap)
    
    if 'QUIC' in stats:
        quic_count = stats['QUIC']
        del stats['QUIC']
        stats['QUIC (UDP)'] = quic_count

    total_packets = sum(stats.values())
    
    headers = ["Protocol", "Count", "Percentage (%)"]
    data_rows = []
    
    for proto, count in sorted(stats.items(), key=lambda item: item[1], reverse=True):
        percentage = (count * 100) / total_packets if total_packets > 0 else 0
        data_rows.append({
            "Protocol": proto,
            "Count": count,
            "Percentage (%)": f"{percentage:.2f}%"
        })
    
    return {"headers": headers, "data": data_rows}


def run_osi_analysis(cap):
    osi_stats, total_packets = analyze_osi_layers(cap)
    
    headers = ["Layer", "Name", "Count", "Percentage (%)", "Protocols"]
    data_rows = []
    
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
            
            data_rows.append({
                "Layer": layer_num_str,
                "Name": layer_name_only,
                "Count": count,
                "Percentage (%)": f"{percentage:.2f}%",
                "Protocols": protocol_list
            })
    
    return {"headers": headers, "data": data_rows}


def run_port_analysis(cap):
    connections = analyze_ports(cap)

    headers = ["Local IP", "Local Port (Service)", "Remote Connections"]
    data_rows = []
    
    if connections:
        for local_ip in sorted(connections.keys()):
            for local_port in sorted(connections[local_ip].keys(), key=int):
                service_name = WELL_KNOWN_PORTS.get(int(local_port), "Dynamic Port")
                
                remote_connections = sorted(
                    list(connections[local_ip][local_port]), 
                    key=lambda x: (x[0], x[1], x[2])
                )
                
                remote_conn_strings = []
                for ip, port, protocol in remote_connections:
                    remote_service = WELL_KNOWN_PORTS.get(int(port), protocol)
                    remote_conn_strings.append(f"{ip}:{port} ({remote_service})")
                
                data_rows.append({
                    "Local IP": local_ip,
                    "Local Port (Service)": f"{service_name} ({local_port})",
                    "Remote Connections": ", ".join(remote_conn_strings)
                })

    return {"headers": headers, "data": data_rows}


def run_visited_domains(cap):
    domains = analyze_domains(cap)

    headers = ["Domain", "Count", "Size (bytes)"]
    data_rows = []

    if domains:
        for domain, count, size in domains[:50]:
            data_rows.append({
                "Domain": domain,
                "Count": count,
                "Size (bytes)": size
            })
    
    return {"headers": headers, "data": data_rows}


def run_bandwidth_usage(cap):
    bandwidth_stats = analyze_bw(cap)

    headers = ["IP Address", "Sent (bytes)", "Received (bytes)", "Total (bytes)"]
    data_rows = []

    sorted_stats = sorted(bandwidth_stats.items(), key=lambda item: item[1]['sent'] + item[1]['received'], reverse=True)
    
    for ip, stats in sorted_stats:
        total = stats['sent'] + stats['received']
        data_rows.append({
            "IP Address": ip,
            "Sent (bytes)": stats['sent'],
            "Received (bytes)": stats['received'],
            "Total (bytes)": total
        })

    return {"headers": headers, "data": data_rows}


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file for various network statistics. If no flags are provided, all analyses will be run.",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("pcap_path", help="Path to the PCAP file")
    
    parser.add_argument("-b", "--bandwidth", action="store_true", help="Run bandwidth analysis.")
    parser.add_argument("-d", "--domains", action="store_true", help="Run visited domains analysis.")
    parser.add_argument("-p", "--protocol", action="store_true", help="Run protocol statistics.")
    parser.add_argument("-o", "--osi", action="store_true", help="Run OSI layer analysis.")
    parser.add_argument("-po", "--ports", action="store_true", help="Run port analysis.")
    parser.add_argument("-r", "--report", action="store_true", help="Generate an HTML report instead of printing to the terminal.")
    
    args = parser.parse_args()

    print(f"[*] Loading PCAP file: {args.pcap_path}")
    cap = pyshark.FileCapture(args.pcap_path, only_summaries=False)
    
    analyses_to_run = []
    
    if args.protocol:
        analyses_to_run.append(("Protocol Statistics", run_protocol_stats))
    if args.domains:
        analyses_to_run.append(("Visited Domains", run_visited_domains))
    if args.osi:
        analyses_to_run.append(("OSI Layer Analysis", run_osi_analysis))
    if args.bandwidth:
        analyses_to_run.append(("Bandwidth Analysis", run_bandwidth_usage))
    if args.ports:
        analyses_to_run.append(("Port Analysis", run_port_analysis))
        
    if not analyses_to_run:
        analyses_to_run = [
            ("Protocol Statistics", run_protocol_stats),
            ("Visited Domains", run_visited_domains),
            ("OSI Layer Analysis", run_osi_analysis),
            ("Bandwidth Analysis", run_bandwidth_usage),
            ("Port Analysis", run_port_analysis)
        ]

    try:
        if args.report:
            report_data = {}
            for title, analysis_func in analyses_to_run:
                report_data[title] = analysis_func(cap)
                cap.reset()
            
            generate_html_report(args.pcap_path, report_data)
        else:
            for title, analysis_func in analyses_to_run:
                print(f"\n[*] {title}...")
                data = analysis_func(cap)
                # Print as a simple ASCII table for terminal output
                headers = data['headers']
                print(" | ".join([f"{h:<{20}}" for h in headers]))
                print("-" * (len(" | ".join([f"{h:<{20}}" for h in headers]))))
                for row in data['data']:
                    print(" | ".join([f"{str(row[h]):<{20}}" for h in headers]))
                print("\n")
                cap.reset()
        
    finally:
        cap.close()


if __name__ == "__main__":
    main()