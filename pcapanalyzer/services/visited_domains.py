import pyshark
from collections import Counter, defaultdict
import sys

def extract_top_level_domain(domain):
    parts = domain.strip('.').split('.')
    if len(parts) >= 2:
        return parts[-2] + '.' + parts[-1]
    return domain


def analyze_domains(capture):
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
                continue

        # HTTP Host header (unencrypted HTTP)
        elif 'http' in pkt:
            try:
                if hasattr(pkt.http, 'host'):
                    domain = pkt.http.host
            except AttributeError:
                continue

        # TLS SNI (for HTTPS sites)
        elif 'tls' in pkt:
            try:
                if hasattr(pkt.tls, 'handshake_extensions_server_name'):
                    domain = pkt.tls.handshake_extensions_server_name
            except AttributeError:
                continue

        if domain:
            tld = extract_top_level_domain(domain.lower())
            domain_counter[tld] += 1
            try:
                domain_traffic[tld] += int(pkt.length)
            except:
                continue

    # Combine frequency + traffic score
    scored_domains = [(domain, domain_counter[domain], domain_traffic[domain]) for domain in domain_counter]
    # Sort by descending DNS frequency + packet volume
    scored_domains.sort(key=lambda x: (x[1], x[2]), reverse=True)

    return scored_domains


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python visited_domains.py <pcap_file>")
        sys.exit(1)

    pcap_path = sys.argv[1]
    print(f"[*] Analyzing visited domains in: {pcap_path}")
    cap = pyshark.FileCapture(pcap_path, only_summaries=False)
    domains = analyze_domains(cap)
    cap.close()

    print("\nMost Visited Domains (by frequency + traffic):")
    for domain, count, size in domains[:50]:
        print(f"{domain}: {count} times, {size} bytes")

