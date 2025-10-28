#!/bin/bash
#
# This script runs DNS queries from a file and calculates ALL
# required metrics: latency, success, fail, and throughput.
#

# --- CHECK ARGUMENTS ---
if [ "$#" -ne 2 ]; then
    echo "Usage:   ./run_all_metrics.sh <domain_file> <resolver_ip>"
    echo "Example (Task B): ./run_all_metrics.sh domains/domains_PCAP_1_H1.txt @8.8.8.8"
    echo "Example (Task D): ./run_all_metrics.sh domains/domains_PCAP_1_H1.txt @10.0.0.5"
    exit 1
fi

DOMAIN_FILE=$1
RESOLVER_IP=$2

echo "--- Running Test ---"
echo "Domain File: $DOMAIN_FILE"
echo "Resolver:    $RESOLVER_IP"
echo "Processing..."

# --- INITIALIZE METRICS ---
total_queries=0
success_count=0
fail_count=0
total_latency=0

# --- START TIMER ---
# Get start time in nanoseconds for precision
total_start_time=$(date +%s.%N)

# --- RUN QUERIES ---
while read -r domain; do
    if [ -z "$domain" ]; then
        continue # Skip empty lines
    fi

    total_queries=$((total_queries + 1))

    # Run dig: +time=5 (5s timeout), +tries=1 (1 attempt)
    dig_output=$(dig +time=5 +tries=1 $RESOLVER_IP $domain)

    # Check for success (NOERROR)
    if echo "$dig_output" | grep -q "status: NOERROR"; then
        success_count=$((success_count + 1))
        
        # Extract query time (latency)
        query_time=$(echo "$dig_output" | grep "Query time:" | awk '{print $4}')
        
        if [ ! -z "$query_time" ] && [ "$query_time" -ge 0 ]; then
            total_latency=$((total_latency + query_time))
        fi
    else
        # Failed (NXDOMAIN, SERVFAIL, Timeout, etc.)
        fail_count=$((fail_count + 1))
    fi

done < "$DOMAIN_FILE"

# --- STOP TIMER ---
total_end_time=$(date +%s.%N)

# --- PRINT FINAL REPORT ---
echo ""
echo "--- Final Report ---"
echo "Total Queries Run:      $total_queries"
echo "Successful Resolutions: $success_count"
echo "Failed Resolutions:     $fail_count"

# Calculate Average Latency
if [ $success_count -gt 0 ]; then
    avg_latency=$(echo "scale=2; $total_latency / $success_count" | bc)
    echo "Average Lookup Latency: $avg_latency ms"
else
    echo "Average Lookup Latency: N/A (0 successes)"
fi

# Calculate Total Duration and Average Throughput
total_duration=$(echo "$total_end_time - $total_start_time" | bc)
if (( $(echo "$total_duration > 0" | bc -l) )); then
    # Throughput = (Total Successes) / (Total Time in Seconds)
    avg_throughput=$(echo "scale=2; $success_count / $total_duration" | bc)
    echo "Average Throughput:       $avg_throughput queries/sec"
else
    echo "Average Throughput:       N/A"
fi
echo "Total Time Taken:       $total_duration seconds"
echo "--------------------------------"
