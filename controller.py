from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
log = core.getLogger()


class Controller(object):
	NUMBER_OF_ROUTERS = 6

	def __init__(self,connection):
		self.connection = connection
		connection.addListeners(self)

		# {ip:[port:mac]}
		self.arpTable=[{
		"192.168.210.42":[3,"aa:aa:aa:aa:aa:aa"], #attacker
		},{

		},{

		},{

		},{
		"192.168.210.162":[2,"fa:fa:fa:fa:fa:fa"], #httpServer
		},{

		}]

		self.externalRouteTable=[
		{	# Router 1 
			"192.168.210.232/29":"192.168.210.226",
			"192.168.210.64/27":"192.168.210.194",
			"192.168.210.208/28":"192.168.210.194",
			"192.168.210.96/27":"192.168.210.194",
			"192.168.210.128/27":"192.168.210.194",
			"192.168.210.160/27":"192.168.210.194",
		},{	# Router 2
			"192.168.210.0/26":"192.168.210.225",
			"192.168.210.192/28":"192.168.210.225",
			"192.168.210.64/27":"192.168.210.234",
			"192.168.210.208/28":"192.168.210.234",
			"192.168.210.96/27":"192.168.210.234",
			"192.168.210.128/27":"192.168.210.234",
			"192.168.210.160/27":"192.168.210.234",
		},{	# Router 3
			"192.168.210.0/26":"192.168.210.65",
			"192.168.210.224/29":"192.168.210.65",
			"192.168.210.192/28":"192.168.210.65",
			"192.168.210.232/29":"192.168.210.65",
			"192.168.210.208/28":"192.168.210.65",
			"192.168.210.128/27":"192.168.210.98",
			"192.168.210.160/27":"192.168.210.98"
		},{ # Router 4
			"192.168.210.0/26":"192.168.210.209",
			"192.168.210.224/29":"192.168.210.209",
			"192.168.210.192/28":"192.168.210.209",
			"192.168.210.232/29":"192.168.210.209",
			"192.168.210.64/27":"192.168.210.97",
			"192.168.210.160/27":"192.168.210.130"
		},{ # Firewall 1
			"192.168.210.0/26":"192.168.210.129",
			"192.168.210.224/29":"192.168.210.129",
			"192.168.210.192/28":"192.168.210.129",
			"192.168.210.232/29":"192.168.210.129",
			"192.168.210.64/27":"192.168.210.129",
			"192.168.210.208/28":"192.168.210.129",
			"192.168.210.96/27":"192.168.210.129",
		},{ # Firewall 2
			"192.168.210.0/26":"192.168.210.193",
			"192.168.210.224/29":"192.168.210.193",
			"192.168.210.96/27":"192.168.210.210",
			"192.168.210.128/27":"192.168.210.210",
			"192.168.210.160/27":"192.168.210.210"
		}]

		self.routingPorts=[
		{   # Router1:
			"mac":"00:00:00:00:01:00",
			"subnets":{
				"192.168.210.224/29":{
					"port":1,
					"ip":"192.168.210.225"
				},
				"192.168.210.192/28":{
					"port":2,
					"ip":"192.168.210.193"
				},
				"192.168.210.0/26":{
					"port":3,
					"ip":"192.168.210.1"
				}
			}
		},{ # Router 2:
			"mac":"00:00:00:00:02:00",
			"subnets":{
				"192.168.210.224/29":{
					"port":1,
					"ip":"192.168.210.226"
				},
				"192.168.210.232/29":{
					"port":2,
					"ip":"192.168.210.233"
				}
			}
		},{ # Router 3:
			"mac":"00:00:00:00:03:00",
			"subnets":{
				"192.168.210.64/27":{
					"port":1,
					"ip":"192.168.210.66"
				},
				"192.168.210.96/27":{
					"port":2,
					"ip":"192.168.210.97"
				}
			}
		},{ # Router 4:
			"mac":"00:00:00:00:04:00",
			"subnets":{
				"192.168.210.96/27":{
					"port":1,
					"ip":"192.168.210.98"
				},
				"192.168.210.208/28":{
					"port":2,
					"ip":"192.168.210.210"
				},
				"192.168.210.128/27":{
					"port":3,
					"ip":"192.168.210.129"
				}
			}
		},{ # Firewall 1:
			"mac":"00:00:00:00:f1:00",
			"subnets":{
				"192.168.210.128/27":{
					"port":1,
					"ip":"192.168.210.130"
				},
				"192.168.210.160/27":{
					"port":2,
					"ip":"192.168.210.161"
				}
			}
		},{ # Firewall 2:
			"mac":"00:00:00:00:f2:00",
			"subnets":{
				"192.168.210.232/29":{
					"port":1,
					"ip":"192.168.210.234"
				},
				"192.168.210.192/28":{
					"port":2,
					"ip":"192.168.210.194"
				},
				"192.168.210.64/27":{
					"port":3,
					"ip":"192.168.210.65"
				},
				"192.168.210.208/28":{
					"port":4,
					"ip":"192.168.210.209"
				}
			}
		}]


		# Assign DPID to each router
		self.switchDPID={
		"00-00-00-00-00-01":0,
		"00-00-00-00-00-02":1,
		"00-00-00-00-00-03":2,
		"00-00-00-00-00-04":3,
		"00-00-00-00-00-05":4,
		"00-00-00-00-00-06":5
		}

	# ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
	def arp(self, packet, data, r):
		arp_packet = packet.payload
		if arp_packet.opcode == pkt.arp.REQUEST:
			# For each subnet in the router 'r'
			for k in self.routingPorts[r]["subnets"]:
				subIP = self.routingPorts[r]["subnets"][k]['ip']
				# Directed to router for the specific subnet
				if str(arp_packet.protodst) == subIP:
					# Forge ARP Reply
					# ARP
					arp_reply = pkt.arp()
					arp_reply.hwsrc = adr.EthAddr(self.routingPorts[r]['mac'])
					arp_reply.hwdst = arp_packet.hwsrc
					arp_reply.opcode = pkt.arp.REPLY
					arp_reply.protosrc = arp_packet.protodst
					arp_reply.protodst = arp_packet.protosrc
					# Ethernet
					eth_packet = pkt.ethernet()
					eth_packet.type = pkt.ethernet.ARP_TYPE
					eth_packet.dst = packet.src
					eth_packet.src = adr.EthAddr(self.routingPorts[r]['mac'])
					eth_packet.payload = arp_reply

					msg = of.ofp_packet_out()
					msg.data = eth_packet.pack()

					action = of.ofp_action_output(port = data.in_port)
					msg.actions.append(action)
					self.connection.send(msg)

					self.LAN_mac_port[r][packet.src] = data.in_port

				else:
					# Ignore. In our topology each port coresponds to a subnet
					pass

		elif arp_packet.opcode == pkt.arp.REPLY:
			log.debug("Received ARP REPLY. Adding to ARP table")
			self.LAN_mac_port[r][packet.src] = data.in_port
			# ! Can pe poisoned if handeled this way


	def forwardIPPacket(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		log.debug("Forwarding packet src:%s dst:%s"%(ipSrc,ipDst))

		# Packet is reffered to router
		if packet.type == pkt.ethernet.ARP_TYPE:
			arp(packet,data,r)
		elif packet.type == pkt.ethernet.IP_TYPE:
			ip_packet = packet.payload

			# Check if the packet is a ping to router
			pingToRouter = False
			if ip_packet.protocol == pkt.ipv4.ICMP_PROTOCOL:
				for k in self.routingPorts[r]["subnets"]:
					if self.routingPorts[r]["subnets"][k]["ip"] == ipDst:
						pingToRouter = True

			# Ping to the router
			if pingToRouter:
		 		icmp_packet = ip_packet.payload
			 	if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
			 		log.debug("Recived icmp request to router %d"%r)
			 		log.debug("Sending a reachable")
		 			echo = pkt.echo()
					echo.seq = icmp_packet.payload.seq + 1
					echo.id = icmp_packet.payload.id

					icmp_reply = pkt.icmp()
					icmp_reply.type = pkt.TYPE_ECHO_REPLY
					icmp_reply.payload = echo

					ip_p = pkt.ipv4()
					ip_p.srcip = ipDst
					ip_p.dstip = ipSrc
					ip_p.protocol = pkt.ipv4.ICMP_PROTOCOL
					ip_p.payload = icmp_reply

					eth_p = pkt.ethernet()
					eth_p.type = pkt.ethernet.IP_TYPE
					# Resend to previous route
					eth_p.dst = packet.src
					eth_p.src = packet.dst
					eth_p.payload = ip_p

					msg = of.ofp_packet_out()
					msg.data = eth_p.pack()
					action = of.ofp_action_output(port = data.in_port)
					msg.actions.append(action)

					self.connection.send(msg)

			# Any other packet
			else:
				# Packet is reffered to a subnetwork from the router
				thisHop = False
				for i in range(0,len(self.routingPorts[r]['subnets'])):
					if ipDst in self.arpTable[r]:
						thisHop = True
						subnetDest = self.routingPorts[r]['subnets'][i]
						if ipDst.inNetwork(subnet):
							# Source and destination are not in the same subnet
							if not ipSrc.inNetwork(self.routingPorts[r]['subnets'][i]):
								log.debug("Forwarding packet from %r to subnetwork %r directly."%(str(ipSrc,subnetDest)))
								msg = of.ofp_flow_mod()
								msg.match.dl_type = pkt.ethernet.IP_TYPE
								msg.match.dl_src = packet.src
								msg.match.dl_dst = packet.dst
								msg.match.nw_src = packet.payload.srcip
								msg.match.nw_dst = packet.payload.dstip # change with subnetDest
								msg.match.in_port = data.in_port
								msg.data = data
								msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(self.arpTable[r][str(ipDst)][1])))
								msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
								msg.actions.append(of.ofp_action_output(port = self.arpTable[r][str(ipDst)][0]))
								self.connection.send(msg)
							else:
								# Ignore. Hosts connected directly in the same port
								pass
					else:
						log.debug("Unknown host")

				# Packed should be forwarded
				if not thisHop:
					for i in self.externalRouteTable[r]:
						if ipDst.inNetwork(self.externalRouteTable[r][i]):
							routerDst = self.externalRouteTable[r][i]

							log.debug("Forwarding from %r to router %r"%(packet.src, routerDst))
							msg = of.ofp_flow_mod()
							msg.match.dl_type = pkt.ethernet.IP_TYPE
							msg.match.dl_src = packet.src
							msg.match.dl_dst = packet.dst    
							msg.match.nw_src = packet.payload.srcip
							msg.match.nw_dst = packet.payload.dstip
							msg.match.in_port = packet_in.in_port
							msg.data = packet_in

							# Find the mac to the next-hop router
							dstMac = ""
							for j in range(0,Controller.NUMBER_OF_ROUTERS):
								if j != r:
									for k in self.routingPorts[j]["subnets"]:
										if self.routingPorts[j]["subnets"][k]["ip"] ==  routerDst:
											dstMac = self.routingPorts[j]["mac"]

							msg.actions.append(of.ofp_action_dl_addr.set_dst(EthAddr(dstMac)))
							msg.actions.append(of.ofp_action_dl_addr.set_src(routingPorts[r]["mac"]))
							msg.actions.append(of.ofp_action_output(port = routingPorts[r]["subnets"][i]["port"]))
							self.connection.send(msg)



	def route(self, packet, data, r):
		log.debug("Event from: %d"%r)
		# ARP packet
		if packet.type == pkt.ethernet.ARP_TYPE:
			self.arp(packet, data, r)
		# IPv4 Packet
		elif packet.type == pkt.ethernet.IP_TYPE:
			self.forwardIPPacket(packet, data, r)	



	def _handle_PacketIn(self,event):
		packet = event.parsed
		if not packet.parsed:
			log.warning("Incomplete packet. Ignored.")
			return
		data = event.ofp
		if dpid_to_str(event.dpid) not in self.switchDPID.keys():
			log.debug("ERROR: Unexpected event DPID:"+ dpid_to_str(event.dpid))
			return
		r = self.switchDPID[dpid_to_str(event.dpid)]
		self.route(packet,data,r)

def launch ():
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
