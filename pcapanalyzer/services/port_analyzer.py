import pyshark
import ipaddress
from collections import defaultdict

# A dictionary of common well-known ports for easier readability.
WELL_KNOWN_PORTS = {
    7: 'ECHO', 20: 'FTP (Data)', 21: 'FTP (Control)', 22: 'SSH', 23: 'Telnet',
    25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 123: 'NTP', 137: 'NetBIOS',
    138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP Trap',
    179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
    514: 'Syslog', 587: 'SMTPS', 636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MS SQL Server', 1434: 'MS SQL Monitor', 1701: 'L2TP', 1723: 'PPTP',
    3306: 'MySQL', 3389: 'RDP', 5060: 'SIP', 5061: 'SIP (TLS)', 5432: 'PostgreSQL',
    5632: 'pcAnywhere', 5900: 'VNC', 5901: 'VNC', 5985: 'WinRM', 5986: 'WinRM (HTTPS)',
    6379: 'Redis', 8000: 'HTTP Alt', 8080: 'HTTP Proxy', 8443: 'HTTPS Alt',
    8500: 'Adobe ColdFusion', 8888: 'HTTP Alt', 9090: 'HTTP Alt', 9200: 'Elasticsearch',
    27017: 'MongoDB', 27018: 'MongoDB', 27019: 'MongoDB',
}

def is_private_ip(ip_str):
    """Checks if an IP address is within a private network range."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return ip_obj.is_private
    except ValueError:
        return False

def analyze_ports(capture):
    """
    Analyzes port communication with IP address context and protocol type.

    Returns:
        A dictionary with a key for each local IP, containing a sub-dictionary
        for each port, and a set of (remote_ip, remote_port, protocol) tuples.
    """
    connections = defaultdict(lambda: defaultdict(set))
    local_ips = set()

    for pkt in capture:
        try:
            protocol = None
            if 'TCP' in pkt:
                protocol = 'TCP'
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            elif 'UDP' in pkt:
                protocol = 'UDP'
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
            else:
                continue

            is_src_private = is_private_ip(src_ip)
            is_dst_private = is_private_ip(dst_ip)
            
            # Case 1: Connection from local machine to remote server
            if is_src_private and not is_dst_private:
                connections[src_ip][src_port].add((dst_ip, dst_port, protocol))
            
            # Case 2: Connection from remote server to local machine
            elif is_dst_private and not is_src_private:
                connections[dst_ip][dst_port].add((src_ip, src_port, protocol))

            # Case 3: Both IPs are local (e.g., local network traffic)
            elif is_src_private and is_dst_private:
                connections[src_ip][src_port].add((dst_ip, dst_port, protocol))
                connections[dst_ip][dst_port].add((src_ip, src_port, protocol))

        except (AttributeError, ValueError):
            continue
            
    return connections


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python port_analyzer.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Analyzing port communications in: {pcap_path}")
    
    cap = pyshark.FileCapture(pcap_path)
    try:
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

    finally:
        cap.close()