#!/usr/bin/env python3
"""
Part D (rephrased) - DNS Resolution with Custom Resolver + Comparison with Part B
This script:
 - builds the Mininet topology used in the assignment
 - sets up isolated resolv.conf for Mininet hosts
 - starts the custom DNS server (custom_dns_server.py) on the dns host
 - extracts domains from PCAPs and resolves them using 'dig' through the custom resolver
 - collects per-host metrics (success, latency, throughput)
 - writes human-readable `.txt` result files under results/
 - compares Part D results with Part B (attempts JSON first, falls back to text)
 - attempts to produce a latency plot if matplotlib is available
Edited / rephrased by: Bbxh
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSController
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

import os
import time
import subprocess
import re
import json
import csv
from datetime import datetime
from scapy.all import DNS, PcapReader

# Optional plotting; skip gracefully if not installed
try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except Exception:
    MATPLOTLIB_AVAILABLE = False


# ---------------------------
# Topology (4 hosts + dns + nat)
# ---------------------------
class NetTopoWithNAT(Topo):
    """Simple topology: four hosts, one resolver host, one NAT, chain of switches"""
    def build(self):
        # switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # hosts (h1..h4) and resolver
        self.addHost('h1', ip='10.0.0.1/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        self.addHost('h2', ip='10.0.0.2/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        self.addHost('h3', ip='10.0.0.3/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        self.addHost('h4', ip='10.0.0.4/24', defaultRoute='via 10.0.0.254', inNamespace=True)
        self.addHost('dns', ip='10.0.0.5/24', defaultRoute='via 10.0.0.254', inNamespace=True)

        # NAT node (outside namespace)
        self.addNode('nat0', cls=NAT, ip='10.0.0.254/24', subnet='10.0.0.0/24', inNamespace=False)

        # links host->switch
        self.addLink('h1', s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink('h2', s2, cls=TCLink, bw=100, delay='2ms')
        self.addLink('h3', s3, cls=TCLink, bw=100, delay='2ms')
        self.addLink('h4', s4, cls=TCLink, bw=100, delay='2ms')

        # link resolver to s2 (close to h2)
        self.addLink('dns', s2, cls=TCLink, bw=100, delay='1ms')

        # NAT and backbone links
        self.addLink('nat0', s2)
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')


# ---------------------------
# Helper - isolated resolv.conf for hosts
# ---------------------------
def isolate_resolv_conf(net, host_names=None):
    """
    Create a private resolv.conf for each Mininet host to avoid modifying the VM's /etc/resolv.conf.
    The 'dns' host uses an external upstream (8.8.8.8); other hosts use the local resolver (10.0.0.5).
    """
    if host_names is None:
        host_names = ['h1', 'h2', 'h3', 'h4', 'dns']

    print("\n" + "=" * 70)
    print("Creating isolated resolv.conf files for Mininet hosts (VM unaffected)")
    print("=" * 70)
    for name in host_names:
        h = net.get(name)
        priv_dir = f'/tmp/mininet_{name}_etc'
        h.cmd(f'mkdir -p {priv_dir}')
        h.cmd(f'echo "# isolated resolv.conf for {name}" > {priv_dir}/resolv.conf')

        # resolver host uses upstream 8.8.8.8, others use the custom resolver 10.0.0.5
        if name == 'dns':
            h.cmd(f'echo "nameserver 8.8.8.8" >> {priv_dir}/resolv.conf')
        else:
            h.cmd(f'echo "nameserver 10.0.0.5" >> {priv_dir}/resolv.conf')

        # mount over /etc/resolv.conf inside namespace (best-effort)
        h.cmd(f'mount --bind {priv_dir}/resolv.conf /etc/resolv.conf 2>/dev/null || true')

        # quick verification print
        res = h.cmd('cat /etc/resolv.conf').strip()
        if name == 'dns':
            if '8.8.8.8' in res:
                print(f"  [OK] {name}: upstream=8.8.8.8")
            else:
                print(f"  [WARN] {name}: resolv.conf may not be set")
        else:
            if '10.0.0.5' in res:
                print(f"  [OK] {name}: resolver=10.0.0.5")
            else:
                print(f"  [WARN] {name}: resolv.conf may not be set")
    print("=" * 70)


def cleanup_isolated_resolv(net, host_names=None):
    """Undo the private mounts and remove temporary directories."""
    if host_names is None:
        host_names = ['h1', 'h2', 'h3', 'h4', 'dns']
    print("\nCleaning up isolated resolv.conf mounts...")
    for name in host_names:
        try:
            h = net.get(name)
            if h:
                h.cmd('umount /etc/resolv.conf 2>/dev/null || true')
                h.cmd(f'rm -rf /tmp/mininet_{name}_etc 2>/dev/null || true')
        except Exception:
            pass


# ---------------------------
# PCAP parser - collect unique query domains
# ---------------------------
def extract_domains_from_pcap(pcap_path, max_domains=None):
    """
    Read a pcap and return a sorted list of unique queried domain names.
    This mirrors the Part B behavior in the assignment.
    """
    domains = set()
    if not os.path.exists(pcap_path):
        print(f"Warning: pcap not found: {pcap_path}")
        return []

    try:
        print(f"  Reading PCAP: {pcap_path} ...", end=' ', flush=True)
        start = time.time()
        pkt_count = 0
        with PcapReader(pcap_path) as r:
            for pkt in r:
                pkt_count += 1
                # periodically print progress for very large pcaps
                if pkt_count % 100000 == 0:
                    print(f"\n    [{pkt_count//1000}k pkts, {len(domains)} domains]", end=' ', flush=True)
                try:
                    if DNS in pkt and pkt.haslayer(DNS):
                        dns_layer = pkt[DNS]
                        # only queries (qr==0)
                        if dns_layer.qr == 0 and dns_layer.qd:
                            qd = dns_layer.qd
                            if hasattr(qd, 'qname'):
                                qn = qd.qname
                                if isinstance(qn, bytes):
                                    dom = qn.decode('utf-8', errors='ignore').strip('.')
                                else:
                                    dom = str(qn).strip('.')
                                if dom and '.' in dom:
                                    domains.add(dom.lower())
                except Exception:
                    # be tolerant to malformed packets
                    continue
        elapsed = time.time() - start
        print(f"\n    ✅ Processed {pkt_count:,} packets in {elapsed:.2f}s")
        print(f"    ✅ Found {len(domains)} unique domains")
        domain_list = sorted(domains)
        if max_domains:
            return domain_list[:max_domains]
        return domain_list
    except Exception as e:
        print(f"\n    ❌ Error while reading PCAP: {e}")
        return []


# ---------------------------
# Run resolution for a single domain on a Mininet host using dig
# ---------------------------
def run_dig_on_host(host, domain, dns_server, timeout=5):
    """
    Execute 'dig +short <domain> @<dns_server>' on the provided host
    and return a result dict with latency, ip and status.
    """
    result = {
        'domain': domain,
        'success': False,
        'latency_ms': None,
        'ip_address': None,
        'error': None,
        'bytes': 0
    }
    cmd = f"timeout {timeout} dig +short {domain} @{dns_server}"
    st = time.time()
    try:
        out = host.cmd(cmd)
        elapsed = (time.time() - st) * 1000.0
        result['latency_ms'] = elapsed
        result['bytes'] = len(out)
        if not out.strip():
            result['error'] = "Timeout/No response"
            return result
        lines = [l.strip() for l in out.strip().splitlines() if l.strip()]
        # try to find a valid IPv4 or IPv6
        for ln in lines:
            # IPv4 regex
            if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', ln):
                try:
                    parts = [int(x) for x in ln.split('.')]
                    if all(0 <= p <= 255 for p in parts):
                        result['ip_address'] = ln
                        result['success'] = True
                        return result
                except Exception:
                    continue
            # IPv6 fallback (simple check)
            if ':' in ln and ln != '::1':
                result['ip_address'] = ln
                result['success'] = True
                return result
        # if we reached here, dig returned something but we couldn't parse an IP
        if 'NXDOMAIN' in out or 'SERVFAIL' in out:
            result['error'] = 'NXDOMAIN/SERVFAIL'
        else:
            result['error'] = 'Could not parse IP'
    except Exception as e:
        result['error'] = str(e)
    return result


# ---------------------------
# Resolve all domains from a PCAP on a given host using a specified DNS
# ---------------------------
def resolve_domains_for_host(host, host_label, pcap_file, dns_server):
    """
    Extracts domains from pcap_file, resolves them using dig @dns_server from 'host',
    and returns a stats dictionary. Also writes a human-readable text report.
    """
    print("\n" + "=" * 70)
    print(f"Resolving domains from {os.path.basename(pcap_file)} on {host_label.upper()}")
    print(f"DNS server: {dns_server}")
    print("=" * 70)

    domains = extract_domains_from_pcap(pcap_file)
    if not domains:
        print("  ❌ No domains found — skipping")
        return None

    print(f"\n  Resolving {len(domains)} domains using dig...\n")
    results = []
    succ = 0
    fail = 0
    total_latency = 0.0
    total_bytes = 0
    total_time_s = 0.0

    for i, dom in enumerate(domains, 1):
        if i % 10 == 1:
            print(f"\n  Progress: {i}/{len(domains)}")
        res = run_dig_on_host(host, dom, dns_server)
        results.append(res)
        status_icon = "✅" if res['success'] else "❌"
        info_msg = f"IP: {res['ip_address']}" if res['success'] else res.get('error', 'Unknown')
        print(f"    [{i:3d}] {dom:50s} {status_icon} {info_msg}")

        if res['success']:
            succ += 1
            total_latency += res['latency_ms'] or 0.0
            total_bytes += res['bytes']
            total_time_s += (res['latency_ms'] or 0.0) / 1000.0
        else:
            fail += 1

    avg_latency = (total_latency / succ) if succ > 0 else 0.0
    avg_throughput_bps = (total_bytes * 8 / total_time_s) if total_time_s > 0 else 0.0

    stats = {
        'host': host_label,
        'pcap_file': os.path.basename(pcap_file),
        'dns_server': dns_server,
        'total_queries': len(domains),
        'successful_queries': succ,
        'failed_queries': fail,
        'success_rate_percent': round((succ / len(domains) * 100.0), 2) if domains else 0.0,
        'average_latency_ms': round(avg_latency, 2),
        'average_throughput_bps': round(avg_throughput_bps, 2),
        'domains_tested': domains,
        'results': results
    }

    # Write human-readable .txt report (primary)
    os.makedirs('results', exist_ok=True)
    txt_file = os.path.join('results', f'part_d_{host_label}_results.txt')
    with open(txt_file, 'w') as tf:
        tf.write(f"DNS Resolution Report for {host_label}\n")
        tf.write("=" * 80 + "\n")
        tf.write(f"PCAP: {stats['pcap_file']}\n")
        tf.write(f"DNS server: {dns_server}\n")
        tf.write(f"Total queries: {stats['total_queries']}\n")
        tf.write(f"Successful: {stats['successful_queries']}  Failed: {stats['failed_queries']}\n")
        tf.write(f"Success rate: {stats['success_rate_percent']}%\n")
        tf.write(f"Average latency: {stats['average_latency_ms']} ms\n")
        tf.write(f"Average throughput: {stats['average_throughput_bps']} bps\n")
        tf.write("\n" + "-" * 80 + "\n\n")
        for r in results:
            tf.write(f"{r['domain']}\n")
            if r['success']:
                tf.write(f"  IP: {r['ip_address']}\n")
                tf.write(f"  Latency: {r['latency_ms']:.2f} ms\n")
                tf.write(f"  Bytes returned: {r['bytes']}\n\n")
            else:
                tf.write(f"  ❌ {r.get('error', 'Resolution failed')}\n\n")

    # Save a JSON copy too for compatibility with other scripts (optional)
    json_file = os.path.join('results', f'part_d_{host_label}_results.json')
    with open(json_file, 'w') as jf:
        json.dump({'timestamp': datetime.now().isoformat(), **stats}, jf, indent=2)

    print(f"\n  ✅ Saved TXT: {txt_file}")
    print(f"  ✅ Saved JSON (compat): {json_file}")

    # Return the stats dict (without full results to keep it concise)
    small_stats = {k: stats[k] for k in ('host', 'pcap_file', 'dns_server', 'total_queries',
                                        'successful_queries', 'failed_queries', 'success_rate_percent',
                                        'average_latency_ms', 'average_throughput_bps')}
    small_stats['results_file_txt'] = txt_file
    small_stats['results_file_json'] = json_file
    return small_stats


# ---------------------------
# Comparison: Part B vs Part D
# ---------------------------
def load_part_b_results(maybe_json='part_b_results.json', maybe_txt='part_b_results.txt'):
    """
    Attempt to load Part B results. Prefer JSON; if not available, try to parse a simple TXT.
    Returns list of host result dicts like [{'host': 'h1', 'total_queries':..., ...}, ...]
    """
    if os.path.exists(maybe_json):
        try:
            with open(maybe_json, 'r') as f:
                data = json.load(f)
            return data.get('results', []) if isinstance(data, dict) else data
        except Exception:
            pass

    # Try simple TXT parsing (very tolerant): expect lines like 'Host: H1' or tabular summary
    if os.path.exists(maybe_txt):
        parsed = []
        try:
            with open(maybe_txt, 'r') as f:
                # naive parse: look for lines containing host + total + successful etc separated by whitespace or tabs
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # look for known header-like content
                    parts = line.split()
                    # heuristic: a host line may start with H1 or h1 or Host:
                    if parts and (parts[0].lower().startswith('h') and len(parts[0]) <= 3):
                        # can't guarantee format; just skip
                        continue
                # If no structured parse possible return []
                return []
        except Exception:
            return []
    return []


def compare_and_save(part_b_file, part_d_stats, out_dir='results'):
    """
    Compare the Part D run (part_d_stats list) with Part B results (if available).
    Writes a CSV and TXT comparison.
    """
    os.makedirs(out_dir, exist_ok=True)
    part_b_list = load_part_b_results(part_b_file, maybe_txt='part_b_results.txt')
    if not part_b_list:
        print("  ⚠️  Part B results not found or not parseable. Skipping detailed comparison.")
        # Save Part D summary to TXT alone
        comp_txt = os.path.join(out_dir, 'part_d_summary_only.txt')
        with open(comp_txt, 'w') as f:
            f.write("Part D summary (no Part B data available)\n")
            f.write("=" * 60 + "\n")
            for s in part_d_stats:
                f.write(f"{s['host']}: total={s['total_queries']}, success={s['successful_queries']}, avg_lat={s['average_latency_ms']} ms\n")
        print(f"  ✅ Saved summary-only file: {comp_txt}")
        return

    # If we do have Part B data, form comparisons
    # best-effort: try to match by host name (case-insensitive)
    comparison_records = []
    for d in part_d_stats:
        host_name = d['host']
        match_b = next((b for b in part_b_list if str(b.get('host', '')).lower() == host_name.lower()), None)
        if not match_b:
            # try alternative key names
            match_b = next((b for b in part_b_list if str(b.get('host', '')).lower() in host_name.lower()), None)
        if not match_b:
            print(f"  ⚠️  No Part B entry matched for {host_name}")
            continue
        rec = {
            'host': host_name,
            'part_b_total': match_b.get('total_queries', match_b.get('total', 0)),
            'part_b_success': match_b.get('successful_queries', match_b.get('successful', 0)),
            'part_b_avg_latency': match_b.get('average_latency_ms', match_b.get('avg_latency', 0)),
            'part_d_total': d.get('total_queries', 0),
            'part_d_success': d.get('successful_queries', 0),
            'part_d_avg_latency': d.get('average_latency_ms', 0),
        }
        rec['latency_diff_ms'] = rec['part_d_avg_latency'] - rec['part_b_avg_latency']
        rec['latency_diff_percent'] = (rec['latency_diff_ms'] / rec['part_b_avg_latency'] * 100.0) if rec['part_b_avg_latency'] else 0.0
        comparison_records.append(rec)

    # Save CSV and TXT
    csv_path = os.path.join(out_dir, 'part_b_d_comparison.csv')
    txt_path = os.path.join(out_dir, 'part_b_d_comparison.txt')
    with open(csv_path, 'w', newline='') as cf:
        writer = csv.writer(cf)
        writer.writerow(['Host', 'PartB_Total', 'PartB_Success', 'PartB_AvgLat_ms', 'PartD_Total', 'PartD_Success', 'PartD_AvgLat_ms', 'Diff_ms', 'Diff_percent'])
        for r in comparison_records:
            writer.writerow([r['host'], r['part_b_total'], r['part_b_success'], f"{r['part_b_avg_latency']:.2f}",
                             r['part_d_total'], r['part_d_success'], f"{r['part_d_avg_latency']:.2f}",
                             f"{r['latency_diff_ms']:.2f}", f"{r['latency_diff_percent']:.1f}"])
    with open(txt_path, 'w') as tf:
        tf.write("Part B vs Part D Comparison\n")
        tf.write("=" * 80 + "\n")
        for r in comparison_records:
            tf.write(f"{r['host']}:\n")
            tf.write(f"  Part B - success {r['part_b_success']}/{r['part_b_total']}, avg_lat={r['part_b_avg_latency']:.2f} ms\n")
            tf.write(f"  Part D - success {r['part_d_success']}/{r['part_d_total']}, avg_lat={r['part_d_avg_latency']:.2f} ms\n")
            tf.write(f"  Diff: {r['latency_diff_ms']:+.2f} ms ({r['latency_diff_percent']:+.1f}%)\n\n")
    print(f"  ✅ Saved comparison CSV: {csv_path}")
    print(f"  ✅ Saved comparison TXT: {txt_path}")


# ---------------------------
# Simple plotting (bar chart)
# ---------------------------
def plot_latency_bar(stats_list, out_file='results/dns_latency_comparison.png'):
    if not MATPLOTLIB_AVAILABLE:
        print("  ⚠️  matplotlib not available — skipping latency plot.")
        return
    hosts = [s['host'] for s in stats_list]
    avg_lat = [s['average_latency_ms'] for s in stats_list]
    plt.figure(figsize=(8, 4.5))
    plt.bar(hosts, avg_lat)
    plt.xlabel('Host')
    plt.ylabel('Average latency (ms)')
    plt.title('Avg DNS Resolution Latency (Part D)')
    plt.tight_layout()
    plt.savefig(out_file)
    plt.close()
    print(f"  📊 Saved plot: {out_file}")


# ---------------------------
# Main sequence (orchestrator)
# ---------------------------
def main():
    print("\n" + "=" * 70)
    print("PART D: Custom Resolver DNS Testing (rephrased & txt outputs)")
    print("=" * 70)
    input("\nPress Enter to start Part D (Mininet will be launched)...\n")

    # start the topology and mininet
    setLogLevel('info')
    topo = NetTopoWithNAT()
    net = Mininet(
        topo=topo,
        link=TCLink,
        controller=OVSController,   # Use Mininet's built-in controller directly
        build=True
    )

    try:
        net.start()
        info("\n*** Configuring NAT\n")
        nat = net.get('nat0')
        nat.configDefault()

        # brief stabilization time
        print("\nNetwork stabilizing...")
        time.sleep(2)

        # isolate resolv.conf inside hosts
        isolate_resolv_conf(net)

        # start custom DNS server on the 'dns' host
        print("\n" + "=" * 60)
        print("STEP 1: Starting custom DNS server on dns host (10.0.0.5:53)")
        print("=" * 60)
        dns_host = net.get('dns')

        # ensure dependencies are installed on that host (best-effort, quiet)
        print("  Installing dnspython on dns host (best-effort)...")
        dns_host.cmd('pip3 install -q dnspython 2>&1 | grep -v "already satisfied" || true')

        script_dir = os.path.dirname(os.path.abspath(__file__))
        dns_script = os.path.join(script_dir, 'custom_dns_server.py')
        if not os.path.exists(dns_script):
            print(f"  ❌ custom_dns_server.py not found at {dns_script} - stop here.")
            return

        print("  Launching custom DNS server (background)...")
        dns_host.cmd(f'python3 {dns_script} > /tmp/dns_server.log 2>&1 &')
        time.sleep(3)  # allow server to start

        # verify DNS is listening on port 53 inside dns host
        netstat_out = dns_host.cmd('netstat -uln 2>/dev/null | grep :53 || ss -uln 2>/dev/null | grep :53')
        if ':53' in netstat_out:
            print("  ✅ DNS server appears to be running on port 53 (dns host).")
        else:
            print("  ⚠️  DNS server may not be running (check /tmp/dns_server.log on dns host).")

        # verify VM's /etc/resolv.conf didn't change
        try:
            with open('/etc/resolv.conf', 'r') as vf:
                vm_resolv = vf.read()
            if '10.0.0.5' not in vm_resolv:
                print("  ✅ Host VM resolv.conf is unchanged.")
            else:
                print("  ⚠️  Host VM resolv.conf contains 10.0.0.5 — be careful.")
        except Exception:
            print("  ⚠️  Could not read VM /etc/resolv.conf for verification.")

        # Step 2: resolve domains from PCAPs for each host
        print("\n" + "=" * 60)
        print("STEP 2: Resolve domains from PCAP files using custom resolver (10.0.0.5)")
        print("=" * 60)
        pcap_map = {
            'h1': '/home/student/Downloads/cn_assign_2/folpcaps/PCAP_1_H1.pcap',
            'h2': '/home/student/Downloads/cn_assign_2/folpcaps/PCAP_2_H2.pcap',
            'h3': '/home/student/Downloads/cn_assign_2/folpcaps/PCAP_3_H3.pcap',
            'h4': '/home/student/Downloads/cn_assign_2/folpcaps/PCAP_4_H4.pcap',
        }

        part_d_summary = []
        for host_label in ['h1', 'h2', 'h3', 'h4']:
            h = net.get(host_label)
            pcap_file = pcap_map.get(host_label)
            if not pcap_file or not os.path.exists(pcap_file):
                print(f"  ⚠️  Skipping {host_label}: pcap missing ({pcap_file})")
                continue
            # perform resolution tests
            stats = resolve_domains_for_host(h, host_label, pcap_file, '10.0.0.5')
            if stats:
                part_d_summary.append(stats)
            time.sleep(1)

        # Save combined Part D summary (TXT primary)
        os.makedirs('results', exist_ok=True)
        combined_txt = os.path.join('results', 'part_d_results.txt')
        with open(combined_txt, 'w') as cf:
            cf.write("Part D Combined Summary\n")
            cf.write("=" * 80 + "\n")
            cf.write(f"timestamp: {datetime.now().isoformat()}\n")
            for s in part_d_summary:
                cf.write(f"{s['host']}: total={s['total_queries']}, success={s['successful_queries']}, avg_lat={s['average_latency_ms']} ms\n")
        # Save a JSON copy for compatibility
        combined_json = os.path.join('results', 'part_d_results.json')
        with open(combined_json, 'w') as jf:
            json.dump({'timestamp': datetime.now().isoformat(), 'results': part_d_summary}, jf, indent=2)

        print(f"\n  ✅ Combined textual results saved: {combined_txt}")
        print(f"  ✅ Combined JSON (compat) saved: {combined_json}")

        # Step 3: compare with Part B
        print("\n" + "=" * 60)
        print("STEP 3: Comparison with Part B")
        print("=" * 60)
        compare_and_save('part_b_results.json', part_d_summary, out_dir='results')

        # Step 4: generate plots for H1 or combined
        print("\n" + "=" * 60)
        print("STEP 4: Plot generation (if available)")
        print("=" * 60)
        if part_d_summary:
            plot_latency_bar(part_d_summary, out_file='results/part_d_latency.png')
        else:
            print("  ⚠️  No Part D stats to plot.")

        # Summary and CLI
        print("\nAll steps completed (or attempted). Launching Mininet CLI for manual checks.")
        print("Useful quick checks inside CLI:")
        print("  mininet> h1 cat /etc/resolv.conf")
        print("  mininet> h1 dig google.com")
        print("  mininet> dns cat /tmp/dns_queries.json  # if your custom server logs queries")
        print("Type 'exit' to stop Mininet and continue cleanup.\n")
        CLI(net)

    except Exception as exc:
        print(f"\n❌ ERROR: {exc}")
        import traceback
        traceback.print_exc()
    finally:
        print("\nCleaning up: stopping DNS, unmounting, stopping Mininet...")
        try:
            dns_host = net.get('dns')
            if dns_host:
                dns_host.cmd('pkill -f custom_dns_server.py 2>/dev/null || true')
                time.sleep(1)
        except Exception:
            pass

        # cleanup private mounts
        cleanup_isolated_resolv(net)

        # stop mininet
        try:
            net.stop()
        except Exception:
            pass

        # final verification of VM resolv.conf
        try:
            with open('/etc/resolv.conf', 'r') as vf:
                vm_resolv = vf.read()
            if '10.0.0.5' not in vm_resolv:
                print("Final check: VM resolv.conf unchanged.")
            else:
                print("Final check: VM resolv.conf contains 10.0.0.5. Restore with:")
                print("  echo 'nameserver 8.8.8.8' | sudo tee /etc/resolv.conf")
        except Exception:
            print("Could not read VM /etc/resolv.conf at end.")

        print("\nDone. Part D flow finished.\n")


if __name__ == '__main__':
    main()
