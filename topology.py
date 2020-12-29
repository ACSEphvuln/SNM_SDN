#!/usr/bin/env python3
# File for topology logic

# Base network range: 192.168.210.0/24

from mininet.topo import Topo
class MyTopo( Topo ):  
    "Simple topology example."
    def __init__( self ):
        "Create custom topo."

        # Initialize topology
        Topo.__init__( self )

        # Add routers and firewalls 
        r1 = self.addSwitch('r1')
        r2 = self.addSwitch('r2')
	r3 = self.addSwitch('r3')
	r4 = self.addSwitch('r4')
	f1 = self.addSwitch('f1')
	f2 = self.addSwitch('f2')

        # Add links between routers & firewalls
	self.addLink(r1,r2);
	self.addLink(r2,f2);
	self.addLink(r1,f2);
	self.addLink(f2,r3);
	self.addLink(r3,r4);
	self.addLink(f2,r4);
	self.addLink(r4,f1);

	# Add hosts
	attacker = self.addHost('attacker',);
	httpServer = self.addHost('httpServer');

	# Add links between hosts
	self.addLink(attacker,r1);
	self.addLink(httpServer,f1);


topos = { 'mytopo': ( lambda: MyTopo() ) }
