from pox.core import core
import time
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import pox.lib.addresses as adr
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import dpid_to_str
log = core.getLogger()

ATTACKER = "192.168.210.42"
HTTP_SERVER = "192.168.210.162"

class Controller(object):
	NUMBER_OF_ROUTERS = 6

	def __init__(self,connection):
		self.connection = connection
		connection.addListeners(self)

		# {ip:[port:mac]}
		self.arpTable=[{
		ATTACKER:[3,"aa:aa:aa:aa:aa:aa"], #attacker
		},{

		},{

		},{

		},{
		HTTP_SERVER:[2,"fa:fa:fa:fa:fa:fa"], #httpServer
		},{

		}]

		# For firewall only
		# ip:[last_seen,packet_count]
		self.icmpFlood={}
		self.updFlood={}
		self.synFlood={}

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
		"00-00-00-00-01-00":0,
		"00-00-00-00-02-00":1,
		"00-00-00-00-03-00":2,
		"00-00-00-00-04-00":3,
		"00-00-00-00-f1-00":4,
		"00-00-00-00-f2-00":5
		}

	# ref: https://openflow.stanford.edu/display/ONL/POX+Wiki.html#POXWiki-Example%3AARPmessages
	def arp(self, packet, data, r):
		log.debug("Arp request detected to %r"%str(packet.payload.protodst))
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

					self.arpTable[r][arp_packet.protodst] = [data.in_port, packet.src]
					log.debug("Sending ARP reply: %r -> %r"%(str(arp_reply.hwsrc),subIP))

				else:
					# Ignore. In our topology each port coresponds to a subnet
					pass

		elif arp_packet.opcode == pkt.arp.REPLY:
			log.debug("Received ARP REPLY. Adding to ARP table")
			self.arpTable[r][packet.src] = [data.in_port, packet.src]
			# ! Can pe poisoned if handeled this way


	def findRoute(self,ipSrc,ipDst, inPort , r):
		macNext = None
		portNext = None

		# Check for masquarade attack from local subnetworks
		for subnet in self.routingPorts[r]["subnets"]:
			if ipSrc.inNetwork(subnet):
				if inPort != self.routingPorts[r]["subnets"][subnet]["port"]:
					log.debug("Packet in_port not coresponding with the known port of the subnet. Possible masquerade or misconfiguration,blocking further similar requests.")
					return (None,inPort)


		# Packet is reffered to a subnetwork from the router
		if str(ipDst) in self.arpTable[r]:
			for subnet in self.routingPorts[r]['subnets']:
				# Source and destination are not in the same subnet
				if ipDst.inNetwork(subnet):
					if not ipSrc.inNetwork(subnet):
						log.debug("Found direct route for to %r trough subnetwork %r."%(str(ipDst),subnet))

						macNext = EthAddr(self.arpTable[r][str(ipDst)][1])
						portNext = self.arpTable[r][str(ipDst)][0]

					else:
						log.debug("Packet came from the same subnet. Ignoring.")
		else:
			log.debug("Host is not in router %d subnets. Trying to find next hop."%r)

			# Packed should be forwarded
			existsInNetwork = False

			for i in self.externalRouteTable[r]:
				if ipDst.inNetwork(i):
					existsInNetwork = True
					routerDst = self.externalRouteTable[r][i]

					log.debug("Destination not in this hop. Forwarding to router with the ip %r"%(routerDst))

					# Find the mac to the next-hop router
					dstMac = ""
					for j in range(0,Controller.NUMBER_OF_ROUTERS):
						if j != r:
							for k in self.routingPorts[j]["subnets"]:
								if self.routingPorts[j]["subnets"][k]["ip"] ==  routerDst:
									macNext = EthAddr(self.routingPorts[j]["mac"])
									portNext = self.routingPorts[r]["subnets"][k]["port"]


			if not existsInNetwork:
				log.debug("Next hop not found. No where forward packet.")

		return (macNext,portNext)


	def routeMsgFlow(self, packet, data, macNext, portNext):
		log.debug("Added flow from %r to %r."%(str(packet.src),str(packet.dst)))

		msg = of.ofp_flow_mod()

		msg.match.dl_type = pkt.ethernet.IP_TYPE
		msg.match.dl_dst = packet.dst
		msg.match.nw_src = packet.payload.srcip
		msg.match.nw_dst = packet.payload.dstip
		msg.match.in_port = data.in_port
		msg.data = data
		# Change the mac destination to the next device's address
		msg.actions.append(of.ofp_action_dl_addr.set_dst(macNext))
		# Change the mac of the source with the router's mac
		msg.actions.append(of.ofp_action_dl_addr.set_src(packet.dst))
		# Forward to the specified port
		msg.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(msg)

	def routeMsg(self, packet, data, macNext, portNext):
		log.debug("Routing message without flow from %r to %r."%(str(packet.src),str(packet.dst)))
		# Change the mac destination to the next device's address
		packet.dst = macNext
		# Change the mac of the source with the router's mac
		packet.src = packet.dst
		msg = of.ofp_packet_out()
		msg.data = packet.pack()
		msg.actions.append(of.ofp_action_output(port = portNext))
		self.connection.send(msg)


	def blockMsgFlow(self, packet, data, inPort=None):
		log.debug("Added deny flow.")

		msg = of.ofp_flow_mod()
		msg.match.dl_type = pkt.ethernet.IP_TYPE
		# Any more requests from the source ip will be ignored
		msg.match.nw_src = packet.payload.srcip
		if inPort:
			msg.match.in_port = inPort
		msg.data = data
		msg.actions.append(of.ofp_action_output(port = of.OFPP_NONE))
		self.connection.send(msg)
		


	def router(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		# Packet is reffered to a subnetwork from the router
		(macNext,portNext) = self.findRoute(ipSrc,ipDst,data.in_port, r)

		# If there is a route
		if macNext and portNext:
			self.routeMsgFlow(packet, data, macNext, portNext)
		elif portNext:
			self.blockMsgFlow(packet, data, inPort=portNext)


	def badFlags(self, tcp):
		if tcp:
			# Could be optimised. Used this way for logging purpuses

			# tcp.URG and tcp.FIN and tcp.URG
			if tcp.flags == 0x29:
				log.debug("Detected XMAS recon attack. Packet dropped.")
				return True

			# tcp.SYN and tcp.FIN
			if tcp.flags == 0x3:
				log.debug("Detected SYN-FIN recon attack. Packet dropped.")
				return True

			# no flag
			if tcp.flags == 0x0:
				log.debug("Detected no-flag recon attack. Packet dropped.")
				return True

			# any with urg
			if tcp.URG:
				log.debug("Detected URG. Not used in this network. Possible recon. Packet dropped.")
				return True

		return False

	# Stateful
	def checkFlood(self, floodTable, ipSrc, maxPakets, interval):
		if ipSrc not in floodTable.keys():
			# Add host to watcher
			floodTable[ipSrc] = [time.time()*1000,1]
		else:
			if time.time()*1000 - floodTable[ipSrc][0] > interval:
				# Reset counted packets
				floodTable[ipSrc][1] = 0;

			# Increment observed packets
			floodTable[ipSrc][1] = floodTable[ipSrc][1] + 1
			floodTable[ipSrc][0] = time.time()*1000

			if floodTable[ipSrc][1] > maxPakets:
				# Attack detected
				return True


		return False


	def firewall(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		# Packet is reffered to a subnetwork from the router
		(macNext,portNext) = self.findRoute(ipSrc,ipDst,data.in_port, r)

		# If there is a route
		if macNext and portNext:
			# port 1 -> the traffic that comes out of the protected network
			if portNext == 1:
				# Normal routing
				self.routeMsgFlow(packet, data, macNext, portNext)
			else:

				flood = False
				flagsOK = True;
				ipPacket = packet.payload

				if ipPacket.protocol == pkt.ipv4.ICMP_PROTOCOL:
					flood = self.checkFlood(self.icmpFlood, ipSrc, 1000, 50)
				elif ipPacket.protocol == pkt.ipv4.UDP_PROTOCOL:
					flood = self.checkFlood(self.updFlood, ipSrc, 500, 100)
				elif ipPacket.protocol == pkt.ipv4.TCP_PROTOCOL:
					# SYN
					tcp = ipPacket.payload
					if not self.badFlags(tcp):
						# If flags are not in the list of attacks
						if tcp.flags == 0x2:
							flood = self.checkFlood(self.synFlood, ipSrc, 100, 100)
					else:
						flagsOK = False


				if flood:
					# Block ip
					log.debug("!!! Flood attack detected. Blocking %r."%ipSrc)
					self.blockMsgFlow(packet, data)
				else:
					if flagsOK:
						# Will not block the attacker.
						self.routeMsg(packet, data, macNext, portNext)
		elif portNext:
			self.blockMsgFlow(packet, data, inPort=portNext)


	def forwardIPPacket(self, packet, data, r):
		ipDst = packet.payload.dstip
		ipSrc = packet.payload.srcip
		log.debug("Got packet srcIP:%s with macSrc:%s TO dstIP:%s macDst:%s"%(ipSrc,str(packet.src),ipDst,str(packet.dst)))

		ipPacket = packet.payload

		# Check if the packet is a ping to router
		pingToRouter = False
		if ipPacket.protocol == pkt.ipv4.ICMP_PROTOCOL:
			for k in self.routingPorts[r]["subnets"]:
				if self.routingPorts[r]["subnets"][k]["ip"] == ipDst:
					pingToRouter = True

		# Ping to the router
		if pingToRouter:
	 		icmp_packet = ipPacket.payload
		 	if icmp_packet.type == pkt.TYPE_ECHO_REQUEST:
		 		log.debug("Recived icmp request to router %r. Sending echo reply."%str(ipDst))
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
			if self.routingPorts[r]["mac"] == str(packet.dst):
				if(r == 4):  # Firewall 1
					self.firewall(packet, data, r)
				else:		# Any router
					self.router(packet, data, r)


	def _handle_PacketIn(self,event):
		log.debug("\nEvent from: %r"%dpid_to_str(event.dpid))
		packet = event.parsed
		if not packet.parsed:
			log.warning("Incomplete packet. Ignored.")
			return
		data = event.ofp
		if dpid_to_str(event.dpid) not in self.switchDPID.keys():
			log.debug("ERROR: Unexpected event DPID:"+ dpid_to_str(event.dpid))
			return
		r = self.switchDPID[dpid_to_str(event.dpid)]

		# ARP
		if packet.type == pkt.ethernet.ARP_TYPE:
			self.arp(packet,data,r)
		# IP
		elif packet.type == pkt.ethernet.IP_TYPE:
			self.forwardIPPacket(packet,data,r)

def launch ():
	def start_switch (event):
		log.debug("Controlling %s" % (event.connection,))
		Controller(event.connection)
	core.openflow.addListenerByName("ConnectionUp", start_switch)
