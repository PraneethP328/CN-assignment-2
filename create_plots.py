#!/usr/bin/env python3
import subprocess
import matplotlib.pyplot as plt
import io
import csv

# --- CONFIG ---
# Make sure these file paths are correct for your system
LOG_FILE = "dns_resolver.log"
H1_DOMAINS_FILE = "domains/domains_PCAP_1_H1.txt"
# --- END CONFIG ---

def get_plot_data():
    """
    Parses the log file for the first 10 domains from the H1 file.
    """
    domains_to_find = []
    try:
        # Read the first 10 domains from the H1 domains file
        with open(H1_DOMAINS_FILE, 'r') as f:
            for line in f:
                domain = line.strip()
                if domain:
                    domains_to_find.append(domain)
                if len(domains_to_find) == 10:
                    break
    except FileNotFoundError:
        print(f"Error: Domain file not found at {H1_DOMAINS_FILE}")
        print("Please make sure your domains file is in the same directory.")
        return None

    results = {} # Use a dict to store results by domain
    
    try:
        # Open the log file to find the data
        with open(LOG_FILE, 'r') as f:
            for line in f:
                # This logic finds the *first* log entry for each domain
                for domain in domains_to_find:
                    if domain not in results and f"'{domain}.'" in line:
                        # Found a log for this domain
                        try:
                            # This is a simple parser. It's not robust, but works for the log format.
                            latency = float(line.split("'total_time_ms': '")[1].split("'")[0])
                            servers = line.count("'server_ip_contacted'")
                            results[domain] = (latency, servers)
                            break # Stop checking this line
                        except Exception as e:
                            print(f"Warning: Could not parse log line for {domain}: {e}")
                            
                # If we've found all 10, stop reading the log
                if len(results) == len(domains_to_find):
                    break

    except FileNotFoundError:
        print(f"Error: Log file not found at {LOG_FILE}")
        print("Please make sure you have run the Task D tests to generate the log.")
        return None
    
    # Return the data in the correct order
    final_data = {'domains': [], 'latencies': [], 'servers': []}
    for domain in domains_to_find:
        if domain in results:
            final_data['domains'].append(domain)
            final_data['latencies'].append(results[domain][0])
            final_data['servers'].append(results[domain][1])
        else:
            print(f"Warning: No log entry found for {domain}")

    return final_data


def create_plots():
    print("Getting data for plots...")
    data = get_plot_data()
    
    if not data or not data['domains']:
        print("No data found. Exiting.")
        return

    print("Data parsed. Creating plots...")

    # --- Plot 1: Latency ---
    plt.figure(figsize=(12, 7))
    plt.bar(data['domains'], data['latencies'], color='skyblue')
    plt.xlabel('Domain Name')
    plt.ylabel('Total Latency (ms)')
    plt.title('Total Resolution Latency for First 10 URLs (H1)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout() # Adjust layout to prevent labels overlapping
    plt.savefig('plot_latency.png')
    print("Saved plot_latency.png")

    # --- Plot 2: Servers Visited ---
    plt.figure(figsize=(12, 7))
    plt.bar(data['domains'], data['servers'], color='lightgreen')
    plt.xlabel('Domain Name')
    plt.ylabel('Number of DNS Servers Visited')
    plt.title('Total DNS Servers Visited for First 10 URLs (H1)')
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    plt.savefig('plot_servers_visited.png')
    print("Saved plot_servers_visited.png")

    print("\nDone! Check for 'plot_latency.png' and 'plot_servers_visited.png'.")

if __name__ == "__main__":
    create_plots()