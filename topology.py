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
	self.addLink(r1,r2,params1={'ip': '192.168.210.225/29'},params2={'ip': '192.168.210.226/29'})
	self.addLink(r2,f2,params1={'ip': '192.168.210.233/29'},params2={'ip': '192.168.210.234/29'})
	self.addLink(r1,f2,params1={'ip': '192.168.210.193/28'},params2={'ip': '192.168.210.194/28'})
	self.addLink(f2,r3,params1={'ip': '192.168.210.65/27'},params2={'ip': '192.168.210.66/27'})
	self.addLink(r3,r4,params1={'ip': '192.168.210.97/27'},params2={'ip': '192.168.210.98/27'})
	self.addLink(f2,r4,params1={'ip': '192.168.210.209/28'},params2={'ip': '192.168.210.210/27'})
	self.addLink(r4,f1,params1={'ip': '192.168.210.129/27'},params2={'ip': '192.168.210.130/27'})

	# Add hosts
	attacker = self.addHost('attacker', ip='192.168.210.42/26');
	httpServer = self.addHost('httpServer', ip='192.168.210.162/27');

	# Add links between hosts
	self.addLink(attacker,r1,params2={'ip': '192.168.210.1/26'});
	self.addLink(httpServer,f1,params2={'ip': '192.168.210.161/27'});


topos = { 'mytopo': ( lambda: MyTopo() ) }
