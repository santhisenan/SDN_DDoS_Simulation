from mininet.net import Mininet
from mininet.topolib import TreeTopo
from mininet.node import Controller, OVSKernelSwitch, RemoteController
import time
import random

tree_topo = TreeTopo(depth=2, fanout=2)
net = Mininet(topo=tree_topo, controller=RemoteController)
net.start()

episode_count = 100
episode_length = 10
no_of_hosts = 4
victim_host_ip = '10.0.0.' + str(no_of_hosts)
spoofed_ip = '10.1.1.1'

for i in range(episode_count):
    rand_host = random.randint(0, no_of_hosts - 1) # select a random host in between 1 and no_of_hosts - 1
    host = net.hosts[rand_host]
    # Attack the last host with IP 10.0.0.4
    # timout command is used to abort the hping3 command after the attack was performed for the specifed time
    host.cmd('timeout ' + str(episode_length) + 's hping3 -1 --flood -a '+ spoofed_ip +' '+ victim_host_ip) 


net.stop()
