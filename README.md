# SNM_SDN
Bogatu Mihai-Alexandru, Ionescu Mihai


In order to execute the SDN project, firstly, the controller.py file
must be placed in the ~/pox/pox/misc directory.


To run the topology:

sudo mn -c; 
clear;
sudo mn --custom topology.py --topo mytopo --mac --controller=remote,ip=127.0.0.1,port=6633

To run the controller:

sudo ./pox.py log.level --DEBUG misc.controller misc.full_payload


To perform the attacks:

python attacks.py [ xmas / no-flags / syn-fin / urg / udp-flood / syn-flood / icmp-flood / land ]