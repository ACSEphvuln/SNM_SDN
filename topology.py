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
        self.addLink(r1, r2, port1=1, port2=1, intfName1='r1-eth1', intfName2='r2-eth1',
        	params1={'ip': '192.168.210.225/29'}, params2={'ip': '192.168.210.226/29'})
        self.addLink(r2, f2, port1=2, port2=1, intfName1='r2-eth2', intfName2='f2-eth1',
        	params1={'ip': '192.168.210.233/29'}, params2={'ip': '192.168.210.234/29'})
        self.addLink(r1, f2, port1=2, port2=2, intfName1='r1-eth2', intfName2='f2-eth2',
        	params1={'ip': '192.168.210.193/28'}, params2={'ip': '192.168.210.194/28'})
        self.addLink(f2, r3, port1=3, port2=1, intfName1='f2-eth3', intfName2='r3-eth1',
        	params1={'ip': '192.168.210.65/27'}, params2={'ip': '192.168.210.66/27'})
        self.addLink(r3, r4, port1=2, port2=1, intfName1='r3-eth2', intfName2='r4-eth1',
        	params1={'ip': '192.168.210.97/27'}, params2={'ip': '192.168.210.98/27'})
        self.addLink(f2, r4, port1=4, port2=2, intfName1='f2-eth4', intfName2='r4-eth2',
        	params1={'ip': '192.168.210.209/28'}, params2={'ip': '192.168.210.210/28'})
        self.addLink(r4, f1, port1=3, port2=1, intfName1='r4-eth3', intfName2='f1-eth1',
        	params1={'ip': '192.168.210.129/27'}, params2={'ip': '192.168.210.130/27'})

        # Add hosts
        attacker = self.addHost('attacker', ip='192.168.210.42/26', defaultRoute = "via 192.168.210.1")
        httpServer = self.addHost('httpServer', ip='192.168.210.162/27', defaultRoute = "via 192.168.210.161")

        # Add links between hosts
        self.addLink(attacker, r1, port1=0, port2=3, intfName1='attacker-eth0', intfName2='r1-eth3',
        	params1={'ip': '192.168.210.42/26'}, params2={'ip': '192.168.210.1/26'})
        self.addLink(httpServer, f1, port1=1, port2=2, intfName1='httpServer-eth0', intfName2='f1-eth2',
        	params1={'ip': '192.168.210.162/27'}, params2={'ip': '192.168.210.161/27'})

topos = { 'mytopo': ( lambda: MyTopo() ) }
