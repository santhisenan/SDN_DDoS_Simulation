from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, RemoteController,OVSSwitch

import random
import threading

# Create and start mininet topology
tree_topo = TreeTopo(depth=3, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController,switch=OVSSwitch)
net.start()

episode_count = 100
episode_length = 10
no_of_hosts = 8
victim_host_ip = '10.0.0.' + str(no_of_hosts)
spoofed_ip = '10.1.1.1'

# Command line tool hping3 is used to simulate DDoS
def ddos_flood(host):
    # Attack the last host with IP 10.0.0.4
    # timout command is used to abort the hping3 command after the attack was performed for the specifed time
    host.cmd('timeout ' + str(episode_length) + 's hping3 --flood ' + ' -a '+ spoofed_ip +' '+ victim_host_ip)
    host.cmd('killall hping3')


def ddos_benign(host):
    # Send benign packets to victim
    host.cmd('timeout ' + str(episode_length) + 's hping3 ' + victim_host_ip)
    host.cmd('killall hping3')

# In each episode Randomly select attacker and bengin user 
for i in range(episode_count):
    print("Episode "+str(i))
    attacking_host_id = random.randint(0, no_of_hosts - 2) # select a random host in between 1 and no_of_hosts - 1
    attacking_host = net.hosts[attacking_host_id]

    benign_host_id = random.choice([i for i in range(0, no_of_hosts - 2) if i not in [attacking_host_id]])
    benign_host = net.hosts[benign_host_id]
    print("host" + str(attacking_host_id) + " is attacking and host" + str(benign_host_id) + " is sending normal requests")

    # Create seperate threads for attacker and benign user
    t1 = threading.Thread(target=ddos_benign, args=(benign_host,))
    t2 = threading.Thread(target=ddos_flood, args=(attacking_host,)) 
 
    t1.start()
    t2.start()
    
    t1.join()
    t2.join()


net.stop()
