import pyshark
from collections import Counter, defaultdict
import sys

def extract_top_level_domain(domain):
    """
    Extracts the top-level domain (TLD) and the second-level domain from a given domain name.
    e.g., "www.google.com" -> "google.com"
    """
    parts = domain.strip('.').split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return domain


def analyze_domains(capture):
    """
    Analyzes visited domains from DNS queries, HTTP Host headers, and TLS SNI.
    Scores domains by frequency and total traffic.

    Args:
        capture (pyshark.FileCapture): A pyshark capture object.

    Returns:
        list: A sorted list of tuples, where each tuple contains
              (domain, frequency_count, total_traffic_bytes).
    """
    domain_counter = Counter()
    domain_traffic = defaultdict(int)

    for pkt in capture:
        domain = None

        # DNS queries (unencrypted)
        if 'dns' in pkt:
            try:
                if hasattr(pkt.dns, 'qry_name'):
                    domain = pkt.dns.qry_name
            except AttributeError:
                # Handle cases where dns layer exists but qry_name is missing
                continue

        # HTTP Host header (unencrypted HTTP)
        elif 'http' in pkt:
            try:
                if hasattr(pkt.http, 'host'):
                    domain = pkt.http.host
            except AttributeError:
                # Handle cases where http layer exists but host is missing
                continue

        # TLS SNI (for HTTPS sites)
        elif 'tls' in pkt:
            try:
                if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                    domain = pkt.tls.handshake_extensions_server_name
            except AttributeError:
                # Handle cases where tls layer exists but SNI is missing
                continue

        if domain:
            # Convert domain to lowercase and extract top-level domain for consistency
            tld = extract_top_level_domain(domain.lower())
            domain_counter[tld] += 1
            try:
                # Add packet length to the domain's total traffic
                domain_traffic[tld] += int(pkt.length)
            except (AttributeError, ValueError):
                # Handle cases where pkt.length might be missing or not an int
                continue

    # Combine frequency + traffic score for sorting
    scored_domains = [(domain, domain_counter[domain], domain_traffic[domain]) for domain in domain_counter]
    
    # Sort by descending DNS frequency, then by descending packet volume
    scored_domains.sort(key=lambda x: (x[1], x[2]), reverse=True)

    return scored_domains


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visited_domains.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Analyzing visited domains in: {pcap_path}")
    
    # Use a try...finally block to ensure the capture file is always closed
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    try:
        domains = analyze_domains(cap)

        print("\nMost Visited Domains (by frequency + traffic):")
        print("--------------------------------------------------")
        
        # Print only the top 50 domains or fewer if less are found
        if not domains:
            print("No domains found in the capture file.")
        else:
            for domain, count, size in domains[:50]:
                print(f"  {domain:<30}: {count:<5} times, {size:<10} bytes")
    finally:
        cap.close()