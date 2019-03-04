from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, OVSKernelSwitch, RemoteController
import time
import random
# from random import choice
import threading

tree_topo = TreeTopo(depth=2, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController)
net.start()

episode_count = 100
episode_length = 10
no_of_hosts = 4
victim_host_ip = '10.0.0.' + str(no_of_hosts)
spoofed_ip = '10.1.1.1'

def ddos_flood(host):
    # Attack the last host with IP 10.0.0.4
    # timout command is used to abort the hping3 command after the attack was performed for the specifed time
    host.cmd('timeout ' + str(episode_length) + 's hping3 -1 --flood -a '+ spoofed_ip +' '+ victim_host_ip)

def ddos_benign(host):
    host.cmd('timeout ' + str(episode_length) + 's hping3 -1 --fast '+ victim_host_ip)
   
for i in range(episode_count):
    attacking_host_id = random.randint(0, no_of_hosts - 1) # select a random host in between 1 and no_of_hosts - 1
    attacking_host = net.hosts[attacking_host_id]

    benign_host_id = random.choice([i for i in range(0, no_of_hosts - 1) if i not in [attacking_host_id]])
    benign_host = net.hosts[benign_host_id]

    t1 = threading.Thread(target=ddos_benign, args=(benign_host,)) 
    t1.start()
    ddos_flood(attacking_host)

    t1.join()

net.stop()
