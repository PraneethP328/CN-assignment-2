"""
Batch DNS Domain Extractor for CS331 Assignment 2
Uses PcapReader approach from CN_A1 for memory-efficient processing
Automatically handles all PCAPs in 'folpcaps' folder
"""
import os
import glob
from scapy.all import PcapReader, DNS, DNSQR

# ---- Helper Functions ----
def is_valid_domain(domain):
    """Filter out invalid/local domains (from CN_A1)"""
    d = domain.lower().strip()
    
    # Skip local/mDNS/service discovery
    if d.endswith('.local'):
        return False
    if d.startswith('_'):
        return False
    
    # Must have at least one dot (avoid single labels like "localhost")
    if '.' not in d:
        return False
    
    return True

def extract_domains_from_pcap(pcap_file):
    """
    Extract DNS queries using PcapReader (from CN_A1)
    Memory-efficient streaming approach
    """
    domains = set()
    packet_count = 0
    dns_count = 0
    
    try:
        with PcapReader(pcap_file) as pcap:
            for pkt in pcap:
                packet_count += 1
                
                # Show progress every 50000 packets
                if packet_count % 50000 == 0:
                    print(f"    Processed {packet_count} packets, found {len(domains)} domains...")
                
                # Check if packet has DNS layer and is a query (qr == 0)
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and pkt.haslayer(DNSQR):
                    dns_count += 1
                    try:
                        domain = pkt[DNSQR].qname.decode().strip().rstrip('.')
                        if is_valid_domain(domain):
                            domains.add(domain)
                    except:
                        # Skip malformed domains
                        pass
        
        print(f"    Total packets: {packet_count}, DNS queries: {dns_count}, Valid domains: {len(domains)}")
        return sorted(domains)
        
    except Exception as e:
        print(f"    Error processing {pcap_file}: {e}")
        return []

# ---- Main Processing ----
def process_all_pcaps():
    """Process all PCAP files in folpcaps directory"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_dir = os.path.join(script_dir, 'folpcaps')
    output_dir = os.path.join(script_dir, 'domains')
    
    if not os.path.exists(pcap_dir):
        print(f"Error: Directory '{pcap_dir}' not found")
        return
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Automatically detect all .pcap files
    pcap_files = sorted(glob.glob(os.path.join(pcap_dir, '*.pcap')))
    
    if not pcap_files:
        print(f"No PCAP files found in {pcap_dir}")
        return
    
    print("=" * 70)
    print("DNS Domain Extraction Tool - CS331 Assignment 2")
    print("Using PcapReader approach from CN_A1")
    print("=" * 70)
    print()
    
    results = []
    
    for pcap_file in pcap_files:
        base_name = os.path.basename(pcap_file).replace('.pcap', '')
        output_file = os.path.join(output_dir, f"domains_{base_name}.txt")
        
        print(f"Processing: {os.path.basename(pcap_file)}")
        
        domains = extract_domains_from_pcap(pcap_file)
        
        if not domains:
            print(f"  No domains found!")
            print()
            continue
        
        # Save to file
        with open(output_file, 'w') as f:
            for domain in domains:
                f.write(domain + '\n')
        
        print(f"  ✓ Found {len(domains)} unique valid domains")
        print(f"  ✓ Saved to: {output_file}")
        print()
        
        results.append((base_name, len(domains), output_file))
    
    # Summary
    print("=" * 70)
    print("Extraction Complete!")
    print("=" * 70)
    print()
    print("Summary:")
    for name, count, file in results:
        print(f"  {file:40s} : {count:5d} domains")
    print()
    print(f"Total: {len(results)} PCAP files processed successfully")

# ---- Entry Point ----
if __name__ == "__main__":
    process_all_pcaps()
