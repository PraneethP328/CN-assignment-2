#!/usr/bin/env python3
import socket
import datetime
import time
from dnslib import DNSRecord, DNSHeader, RR, A, QTYPE, RCODE
from dnslib.server import DNSServer, BaseResolver

# --- CONFIG ---
# List of root server IPs
ROOT_SERVERS = [
    '198.41.0.4',    # a.root-servers.net
    '199.9.14.201',  # b.root-servers.net
    '192.33.4.12',   # c.root-servers.net
    '199.7.83.42',   # d.root-servers.net
    '192.203.230.10', # e.root-servers.net
    '192.5.5.241',   # f.root-servers.net
    '192.112.36.4',  # g.root-servers.net
    '198.97.190.53', # h.root-servers.net
    '192.36.148.17', # i.root-servers.net
    '192.58.128.30', # j.root-servers.net
    '193.0.14.129',  # k.root-servers.net
    '199.7.91.13',   # l.root-servers.net
    '202.12.27.33',  # m.root-servers.net
]
LOG_FILE = 'dns_resolver.log'

# --- Custom Logger ---
# This logs all the details required by Task D
def write_log(line):
    # This ensures the log is in a parsable format
    log_line_str = ", ".join(f"'{k}': '{v}'" for k, v in line.items())
    with open(LOG_FILE, 'a') as f:
        f.write(f"{{{log_line_str}}}\n")
    # Print a simpler log to the console
    print(f"LOG: {line.get('domain_name')} -> {line.get('total_time_ms')} ms")

# --- Custom Resolver Class ---
class IterativeResolver(BaseResolver):

    def __init__(self):
        # Caching for Bonus Task F would be implemented here
        pass

    def resolve(self, request, handler):
        qname = request.q.qname
        qtype = request.q.qtype

        # --- Logging (Task D) ---
        start_total_time = time.time()
        timestamp = datetime.datetime.now().isoformat()
        log_entry = {
            'timestamp': timestamp,
            'domain_name': str(qname),
            'resolution_mode': 'Iterative',
            'cache_status': 'MISS',
            'steps': [] # This will store a list of dicts
        }
        
        # Start iterative resolution
        nameservers = ROOT_SERVERS[:] # Use a copy of the list
        
        try:
            while True:
                # Pick one nameserver to query
                server_ip = nameservers[0]
                
                step_log = {
                    'server_ip_contacted': server_ip,
                    'step_type': 'Root' if nameservers == ROOT_SERVERS else 'TLD/Authoritative'
                }

                try:
                    # Send the query to the external server
                    proxy_req = DNSRecord(DNSHeader(id=request.header.id, qr=0, opcode=0, ra=0), q=request.q)
                    
                    start_rtt = time.time()
                    # The NAT node in your topo.py gives this host internet access
                    response_packet = proxy_req.send(server_ip, 53, timeout=2)
                    end_rtt = time.time()

                    rtt = (end_rtt - start_rtt) * 1000 # RTT in ms
                    step_log['rtt_ms'] = f"{rtt:.2f}"
                    
                    response = DNSRecord.parse(response_packet)
                    step_log['response_received'] = str(RCODE[response.header.rcode])

                except socket.timeout:
                    step_log['response_received'] = 'TIMEOUT'
                    log_entry['steps'].append(step_log)
                    nameservers.pop(0) # Try next nameserver
                    if not nameservers:
                        raise Exception("All nameservers failed")
                    continue

                log_entry['steps'].append(step_log)

                # --- Process Response ---
                if response.header.rcode == RCODE.NOERROR:
                    if response.rr: # Case 1: We have an answer (A record)
                        step_log['step_type'] = 'Authoritative'
                        reply = request.reply()
                        for rr in response.rr:
                            if rr.rtype == QTYPE.A:
                                reply.add_answer(rr)
                        break # Exit loop
                    
                    elif response.ar: # Case 2: No answer, but we got referrals (glue records)
                        new_nameservers = []
                        for rr in response.ar:
                            if rr.rtype == QTYPE.A:
                                new_nameservers.append(str(rr.rdata))
                        
                        if new_nameservers:
                            nameservers = new_nameservers # These are our new targets
                            step_log['step_type'] = 'TLD' if 'Root' in str(log_entry['steps']) else 'Authoritative'
                        else:
                            reply = request.reply()
                            reply.header.rcode = RCODE.SERVFAIL
                            break
                    
                    else: # Case 3: No answer, no glue records (e.g., CNAME)
                        reply = request.reply()
                        reply.header.rcode = RCODE.SERVFAIL
                        break
                else: # The external server returned an error (e.g., NXDOMAIN)
                    reply = request.reply()
                    reply.header.rcode = response.header.rcode
                    break
            
            # --- Final Logging ---
            end_total_time = time.time()
            total_time_ms = (end_total_time - start_total_time) * 1000
            log_entry['total_time_ms'] = f"{total_time_ms:.2f}"
            write_log(log_entry)
            return reply

        except Exception as e:
            # --- Error Logging ---
            end_total_time = time.time()
            total_time_ms = (end_total_time - start_total_time) * 1000
            log_entry['total_time_ms'] = f"{total_time_ms:.2f}"
            log_entry['error'] = str(e)
            write_log(log_entry)
            
            reply = request.reply()
            reply.header.rcode = RCODE.SERVFAIL
            return reply

# --- Start the Server ---
if __name__ == '__main__':
    print("Starting custom DNS resolver (partc.py) on 10.0.0.5:53...")
    try:
        # Listen on '0.0.0.0' to accept connections
        server = DNSServer(IterativeResolver(), port=53, address="0.0.0.0")
        server.start()
    except Exception as e:
        print(f"Error: {e}")
        print("You might need to use 'sudo python3 partc.py' to run on port 53.")