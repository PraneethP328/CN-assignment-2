#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import OVSBridge # Use OVSBridge for L2 switching
from mininet.nodelib import NAT
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.clean import cleanup # Import the cleanup utility

def create_topology():
    "Create the network topology from the assignment diagram."

    info('*** Creating network\n')
    # Use OVSBridge and no controller for simple L2 learning
    net = Mininet(controller=None, switch=OVSBridge, link=TCLink)

    info('*** Adding hosts\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', defaultRoute=None)
    h2 = net.addHost('h2', ip='10.0.0.2/24', defaultRoute=None)
    h3 = net.addHost('h3', ip='10.0.0.3/24', defaultRoute=None)
    h4 = net.addHost('h4', ip='10.0.0.4/24', defaultRoute=None)
    dns = net.addHost('dns', ip='10.0.0.5/24', defaultRoute=None) # The DNS Resolver

    info('*** Adding switches\n')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4') # This line is now correct

    info('*** Creating links\n')
    # Host-to-Switch links
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s2, bw=100, delay='2ms')
    net.addLink(h3, s3, bw=100, delay='2ms')
    net.addLink(h4, s4, bw=100, delay='2ms')
    net.addLink(dns, s2, bw=100, delay='1ms')
    # Switch-to-Switch links
    net.addLink(s1, s2, bw=100, delay='5ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='10ms')

    # --- NAT PART FOR TASK B ---
    info('*** Adding NAT for internet connectivity\n')
    nat = net.addHost('nat', cls=NAT, ip='10.0.0.254/24', inNamespace=False)
    net.addLink(nat, s1)
    # --- END OF NAT PART ---

    info('*** Starting network\n')
    net.start() # Starts switches in standalone mode

    # --- ROUTING PART FOR TASK B ---
    info('*** Setting default routes for hosts\n')
    h1.cmd('ip route add default via 10.0.0.254')
    h2.cmd('ip route add default via 10.0.0.254')
    h3.cmd('ip route add default via 10.0.0.254')
    h4.cmd('ip route add default via 10.0.0.254')
    dns.cmd('ip route add default via 10.0.0.254')
    nat.cmd('ip route add 10.0.0.0/24 dev %s' % (nat.intfNames()[0]))
    # --- END OF ROUTING PART ---

    info('*** Running CLI\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    
    info('*** Cleaning up any old Mininet state\n')
    cleanup() 
    
    create_topology()